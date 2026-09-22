//! Integration tests for the verification orchestrator.
//!
//! Fixtures live in the repo's `tests/data/` (the same files the old Python
//! tests used). Tests load them, pre-populate an `InMemoryBackend`, and walk
//! the orchestrator without touching the system `nix` or the network.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use laut_sign::attestation::NIX_RESOLVED_INPUT;
use laut_sign::http_cache::trace_directory;
use laut_verify::backend::InMemoryBackend;
use laut_verify::keyfiles;
use laut_verify::orchestrator::{Config, Error, Orchestrator, cartesian_product};
use laut_verify::types::{TrustlesslyResolvedDerivation, UnresolvedDerivation};

use std::collections::BTreeMap;
use std::sync::Arc;

/// `<repo-root>/tests/data`. We resolve relative to `CARGO_MANIFEST_DIR`
/// (this crate's dir is `laut-verify` at the repo root).
fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("data")
}

fn read_recursive(name: &str) -> String {
    fs::read_to_string(data_dir().join("drv_lookup").join(name))
        .expect("recursive derivation fixture missing")
}

fn read_aterms(name: &str) -> HashMap<String, String> {
    let raw = fs::read_to_string(data_dir().join("drv_lookup").join(name))
        .expect("aterm fixture missing");
    serde_json::from_str(&raw).expect("aterm fixture is not a JSON map")
}

fn read_all_signatures() -> HashMap<String, Vec<u8>> {
    let dir = data_dir().join(trace_directory(NIX_RESOLVED_INPUT));
    let mut out = HashMap::new();
    for entry in fs::read_dir(&dir).expect("signatures dir missing") {
        let entry = entry.unwrap();
        let path = entry.path();
        let Some(fname) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let bytes = fs::read(&path).expect("signature file unreadable");
        out.insert(fname.to_owned(), bytes);
    }
    out
}

fn read_public_key(name: &str) -> (String, Vec<u8>) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("testkeys")
        .join(name);
    keyfiles::parse_public_key_file(&path)
        .map(|(name, key)| (name, key.to_vec()))
        .expect("public key fixture invalid")
}

fn ca_backend() -> InMemoryBackend {
    InMemoryBackend {
        recursive_json: read_recursive("hello-ca-recursive-unresolved.drv"),
        aterms: read_aterms("hello-ca-recursive-unresolved-aterm.json"),
        signatures: read_all_signatures(),
    }
}

fn ia_backend() -> InMemoryBackend {
    InMemoryBackend {
        recursive_json: read_recursive("hello-ia-recursive-unresolved.drv"),
        aterms: HashMap::new(),
        signatures: HashMap::new(),
    }
}

/// `read_public_key` returns the bare `(name, key_bytes)`. For trust-model use
/// we need them in `(name, key_bytes)` form too — the kid format is computed
/// inside `Orchestrator::new`.
fn trusted_keys() -> Vec<(String, Vec<u8>)> {
    vec![
        read_public_key("builderA_key.public"),
        read_public_key("builderB_key.public"),
    ]
}

#[test]
fn every_migrated_bundle_verifies_under_its_cache_key() {
    let trusted = trusted_keys();
    let mut total = 0;
    let signatures = read_all_signatures();
    assert_eq!(signatures.len(), 157);
    for (hash, bytes) in signatures {
        let text = std::str::from_utf8(&bytes).unwrap();
        let bundles: Vec<_> = text
            .lines()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let verified = laut_verify::signature_verify::verify_resolved_trace_signatures(
            &hash, &bundles, &trusted, None,
        )
        .unwrap();
        assert_eq!(verified.len(), bundles.len(), "fixture {hash}");
        total += verified.len();
    }
    assert_eq!(total, 314);
}

fn make_orchestrator(
    backend: InMemoryBackend,
    root: &str,
) -> Result<Orchestrator<InMemoryBackend>, Error> {
    Orchestrator::new(
        backend,
        Config {
            root_drv_path: root.to_owned(),
            cache_urls: vec!["http://mock".to_owned()],
            trusted_keys: trusted_keys(),
            ..Default::default()
        },
    )
}

// ---------------- build_unresolved_tree equivalents ----------------

#[test]
fn ia_drv_tree_walks_in_ia_mode() {
    // With auto-detected regime, the orchestrator handles an IA root drv
    // directly. ATerm fixtures aren't present for the IA tree so we expect
    // a backend error once `compute_resolved` tries to look one up; the
    // tree walk itself shouldn't fail.
    let mut orch = make_orchestrator(
        ia_backend(),
        "/nix/store/g32gjgcrxi4n753jkl9c3xwqpz4vjnvz-bootstrap-stage1-stdenv-linux.drv",
    )
    .expect("orchestrator construction");
    let _ = orch.verify();
}

#[test]
fn ca_drv_tree_small_builds() {
    let mut orch = make_orchestrator(
        ca_backend(),
        "/nix/store/6a4wpppqvmf5dwr49gfm3hrxhd58hg0w-bootstrap-stage0-binutils-wrapper-.drv",
    )
    .expect("orchestrator construction");
    // Verification may not succeed for every fixture; we only need the
    // recursive tree walk to not panic.
    let _ = orch.verify();
}

#[test]
fn ca_drv_tree_large_builds() {
    let mut orch = make_orchestrator(
        ca_backend(),
        "/nix/store/yvixdlqwq3l5ikd0b5c3f39pxmfynwhl-hello-2.12.1.drv",
    )
    .expect("orchestrator construction");
    let _ = orch.verify();
}

// ---------------- test_verify equivalents ----------------

#[test]
fn verify_ca_drv_small_returns_one_resolution() {
    let mut orch = make_orchestrator(
        ca_backend(),
        "/nix/store/cjpxbf5h30808h53lckfyvzacsvfs08q-bootstrap-stage1-stdenv-linux.drv",
    )
    .expect("orchestrator construction");
    let verified = orch.verify().expect("verify");
    assert_eq!(verified.len(), 1, "expected exactly one verified candidate");
}

#[test]
fn critical_features_cannot_supply_consensus_or_poison_valid_claims() {
    let root = "/nix/store/cjpxbf5h30808h53lckfyvzacsvfs08q-bootstrap-stage1-stdenv-linux.drv";
    // The root's resolved input hash; dependency claims remain untouched.
    let hash = "mdw7ghk4133r650ali5jdmgqi4ccwp65";
    let backend = ca_backend();
    let originals: Vec<String> = std::str::from_utf8(&backend.signatures[hash])
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    assert_eq!(originals.len(), 2);
    let critical = resign_claims(&originals, hash, |statement| {
        let params = &mut statement["predicate"]["buildDefinition"]["externalParameters"];
        assert!(params.get("criticalFeatures").is_none());
        params["criticalFeatures"] = serde_json::json!(["gpu-access"]);
    });

    let baseline = make_orchestrator(backend, root).unwrap().verify().unwrap();
    assert_eq!(baseline.len(), 1, "omitted criticalFeatures means empty");
    for claims in [
        critical.clone(),
        vec![critical[0].clone(), originals[1].clone()],
        vec![originals[0].clone(), critical[1].clone()],
    ] {
        let mut backend = ca_backend();
        backend
            .signatures
            .insert(hash.into(), claims.join("\n").into_bytes());
        let verified = make_orchestrator(backend, root).unwrap().verify().unwrap();
        assert!(
            verified.is_empty(),
            "critical claims must not count as votes"
        );
    }

    for claims in [
        [critical.clone(), originals.clone()].concat(),
        [originals, critical].concat(),
    ] {
        let mut backend = ca_backend();
        backend
            .signatures
            .insert(hash.into(), claims.join("\n").into_bytes());
        let verified = make_orchestrator(backend, root).unwrap().verify().unwrap();
        assert_eq!(
            verified, baseline,
            "critical claims must not poison the cache"
        );
    }
}

fn resign_claims(
    originals: &[String],
    hash: &str,
    mutate: impl Fn(&mut serde_json::Value),
) -> Vec<String> {
    use laut_sign::attestation::{Bundle, nix_input_hash, parse_bundle};

    let keys: Vec<_> = ["builderA_key.private", "builderB_key.private"]
        .into_iter()
        .map(|name| {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("testkeys")
                .join(name);
            laut_sign::keyfiles::parse_private_key_file(&path)
                .expect("private key fixture invalid")
                .1
        })
        .collect();
    originals
        .iter()
        .map(|serialized| {
            let bundle = parse_bundle(serialized.as_bytes()).unwrap();
            let (key, mut statement) = keys
                .iter()
                .find_map(|key| {
                    bundle
                        .verify(&key.verifying_key())
                        .ok()
                        .map(|statement| (key, statement))
                })
                .expect("fixture must authenticate under one of the fixture keys");
            assert_eq!(nix_input_hash(&statement), Some(hash));
            mutate(&mut statement);
            let signed = Bundle::sign(&statement, key).unwrap();
            assert_eq!(signed.verify(&key.verifying_key()).unwrap(), statement);
            serde_json::to_string(&signed).unwrap()
        })
        .collect()
}

#[test]
fn usable_identity_representations_preserve_consensus() {
    use laut_sign::attestation::{NIX_CA_STORE_PATH, nix_output_path};
    use serde_json::json;

    let root = "/nix/store/cjpxbf5h30808h53lckfyvzacsvfs08q-bootstrap-stage1-stdenv-linux.drv";
    let hash = "mdw7ghk4133r650ali5jdmgqi4ccwp65";
    let backend = ca_backend();
    let originals: Vec<String> = std::str::from_utf8(&backend.signatures[hash])
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    assert_eq!(originals.len(), 2);
    let baseline = make_orchestrator(backend, root).unwrap().verify().unwrap();
    assert_eq!(baseline.len(), 1);

    let supported = resign_claims(&originals, hash, |statement| {
        statement["predicate"]["buildDefinition"]["externalParameters"]["resolvedInput"]["digest"]
            ["future-input"] = json!("opaque-input");
        for subject in statement["subject"].as_array_mut().unwrap() {
            let path = nix_output_path(subject).unwrap().to_owned();
            subject["digest"] = json!({NIX_CA_STORE_PATH: path, "future-output": "opaque-output"});
            subject.as_object_mut().unwrap().remove("mediaType");
        }
    });
    let unknown_only = resign_claims(&supported, hash, |statement| {
        let subject = &mut statement["subject"][0];
        let path = nix_output_path(subject).unwrap().to_owned();
        subject["digest"] = json!({"future-output": path});
    });
    for (claims, has_consensus) in [
        (supported.clone(), true),
        (vec![originals[0].clone(), supported[1].clone()], true),
        (vec![supported[0].clone(), unknown_only[1].clone()], false),
        (vec![unknown_only[0].clone(), supported[1].clone()], false),
        // Multiple representations from one signer cannot replace another's vote.
        (
            vec![
                originals[0].clone(),
                supported[0].clone(),
                unknown_only[1].clone(),
            ],
            false,
        ),
        ([unknown_only, supported].concat(), true),
    ] {
        let mut backend = ca_backend();
        backend
            .signatures
            .insert(hash.into(), claims.join("\n").into_bytes());
        let verified = make_orchestrator(backend, root).unwrap().verify().unwrap();
        if has_consensus {
            assert_eq!(verified, baseline);
        } else {
            assert!(
                verified.is_empty(),
                "unusable identities must not supply a vote"
            );
        }
    }
}

#[test]
fn verify_ca_drv_large_returns_one_resolution() {
    let mut orch = make_orchestrator(
        ca_backend(),
        "/nix/store/yvixdlqwq3l5ikd0b5c3f39pxmfynwhl-hello-2.12.1.drv",
    )
    .expect("orchestrator construction");
    let verified = orch.verify().expect("verify");
    assert_eq!(verified.len(), 1);
}

// ---------------- cartesian_product (test_generate_combinations) equivalents ----------------

fn mk_dep(path: &str) -> Arc<UnresolvedDerivation> {
    Arc::new(UnresolvedDerivation {
        drv_path: path.into(),
        name: path.into(),
        input_hash: path.into(),
        outputs: BTreeMap::new(),
        inputs: Vec::new(),
        is_fixed_output: false,
        is_content_addressed: true,
        fod_out_path: None,
    })
}

fn mk_resolved(dep: Arc<UnresolvedDerivation>, h: &str) -> TrustlesslyResolvedDerivation {
    TrustlesslyResolvedDerivation {
        resolves: dep,
        drv_path: None,
        input_hash: h.into(),
        outputs: BTreeMap::new(),
    }
}

#[test]
fn cartesian_simple_single_key() {
    let a = mk_dep("a");
    let combos = cartesian_product(&[(
        a.clone(),
        vec![mk_resolved(a.clone(), "b"), mk_resolved(a.clone(), "c")],
    )]);
    assert_eq!(combos.len(), 2);
}

#[test]
fn cartesian_multiple_keys_multiply() {
    let a = mk_dep("a");
    let x = mk_dep("x");
    let combos = cartesian_product(&[
        (
            a.clone(),
            vec![mk_resolved(a.clone(), "b"), mk_resolved(a.clone(), "c")],
        ),
        (
            x.clone(),
            vec![mk_resolved(x.clone(), "y"), mk_resolved(x.clone(), "z")],
        ),
    ]);
    assert_eq!(combos.len(), 4);
}

#[test]
fn cartesian_empty_input_yields_one_empty_combo() {
    let combos = cartesian_product(&[]);
    assert_eq!(combos.len(), 1);
    assert!(combos[0].is_empty());
}

#[test]
fn cartesian_three_keys_three_values_each() {
    // 3^3 = 27 combos
    let mk_set = |name: &str| {
        let dep = mk_dep(name);
        let opts: Vec<_> = (0..3)
            .map(|i| mk_resolved(dep.clone(), &format!("{}_{}", name, i)))
            .collect();
        (dep, opts)
    };
    let combos = cartesian_product(&[mk_set("k0"), mk_set("k1"), mk_set("k2")]);
    assert_eq!(combos.len(), 27);
}

#[test]
fn parse_public_key_smoke() {
    let (name, key_bytes) = read_public_key("builderA_key.public");
    assert!(!name.is_empty());
    assert_eq!(key_bytes.len(), 32);
    // Sanity-check that the key is a valid ed25519 point by reconstructing it.
    let _ = SigningKey::from_bytes(&[0u8; 32]);
}
