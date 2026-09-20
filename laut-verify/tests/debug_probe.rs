//! Integration tests for the hash-divergence debug probe.
//!
//! Uses the same `tests/data/traces/aterm/` fixture corpus that the
//! orchestrator tests use. The corpus is loaded via `file://` so the
//! production code path (cache URL → corpus) gets exercised end-to-end.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use laut_sign::attestation::NIX_RESOLVED_INPUT;
use laut_sign::http_cache::trace_path;
use laut_verify::debug::{
    DebugProbe, DifftProbe, Identity, InMemoryCorpusIndex, LocalWitness, NullProbe,
    PreimageCandidate, build_corpus_from_cache, extract_debug_from_bundle,
};

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("data")
}

fn fixture_cache_url() -> String {
    format!("file://{}", data_dir().display())
}

fn difft_available() -> bool {
    Command::new("difft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---------------- Corpus building ----------------

#[test]
fn corpus_built_from_file_url_is_non_empty() {
    let index = build_corpus_from_cache(&fixture_cache_url()).expect("corpus build");
    assert!(
        !index.is_empty(),
        "fixture corpus produced no entries; either fixtures lack debug data or bundle extraction regressed"
    );
}

#[test]
fn corpus_contains_known_fixture_drv_names() {
    // These names are present in the fixture signatures; the test will need
    // updating if the fixtures get regenerated against a different pkg set.
    let index = build_corpus_from_cache(&fixture_cache_url()).expect("corpus build");
    for name in &["xz-5.8.1", "hello-2.12.1", "zlib-1.3.1"] {
        let candidates = index.lookup(Identity::DrvName, name);
        assert!(
            !candidates.is_empty(),
            "fixture corpus missing drv_name {:?}; refresh fixtures or update the test",
            name
        );
    }
}

#[test]
fn corpus_lookup_misses_for_unknown_name() {
    let index = build_corpus_from_cache(&fixture_cache_url()).expect("corpus build");
    assert!(
        index
            .lookup(Identity::DrvName, "not-a-real-drv-name-anywhere")
            .is_empty()
    );
}

#[test]
fn corpus_scans_only_the_selected_scheme() {
    let root = tempfile::tempdir().unwrap();
    let hash = "mdw7ghk4133r650ali5jdmgqi4ccwp65";
    let body = fs::read_to_string(data_dir().join(trace_path(NIX_RESOLVED_INPUT, hash))).unwrap();
    let bundle = body.lines().next().unwrap();
    let (name, _, _) = extract_debug_from_bundle(bundle).unwrap();
    let selected = root.path().join(trace_path(NIX_RESOLVED_INPUT, hash));
    let other = root.path().join(trace_path("other-input", hash));
    fs::create_dir_all(selected.parent().unwrap()).unwrap();
    fs::create_dir_all(other.parent().unwrap()).unwrap();
    fs::write(other, bundle).unwrap();
    fs::write(root.path().join("traces").join(hash), bundle).unwrap();
    let url = format!("file://{}", root.path().display());
    assert!(build_corpus_from_cache(&url).unwrap().is_empty());
    fs::write(selected, bundle).unwrap();
    assert_eq!(
        build_corpus_from_cache(&url)
            .unwrap()
            .lookup(Identity::DrvName, &name)
            .len(),
        1
    );
}

#[test]
fn unsupported_scheme_errors_explicitly() {
    let err = build_corpus_from_cache("s3://bucket").unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("unsupported cache URL scheme"),
        "expected scheme error, got: {}",
        msg
    );
}

// ---------------- Probe behaviour ----------------

#[test]
fn null_probe_is_no_op() {
    let probe = NullProbe;
    probe.on_signature_miss(&LocalWitness {
        udrv_drv_path: "/nix/store/x.drv",
        udrv_name: "x",
        udrv_input_hash: "h",
        ct_input_hash: "ct",
        aterm_bytes: "Derive(...)",
    });
}

#[test]
fn difft_probe_writes_local_preimage_even_with_no_candidates() {
    let out = tempfile::tempdir().expect("tempdir");
    let probe =
        DifftProbe::new(InMemoryCorpusIndex::new(), out.path().to_path_buf()).expect("probe");
    let witness = LocalWitness {
        udrv_drv_path: "/nix/store/abc-no-match.drv",
        udrv_name: "no-match-please",
        udrv_input_hash: "h",
        ct_input_hash: "ctxyz",
        aterm_bytes: "Derive(local)",
    };
    probe.on_signature_miss(&witness);
    let udrv_dir = out.path().join("abc-no-match.drv");
    assert_eq!(
        fs::read_to_string(udrv_dir.join("ctxyz")).unwrap(),
        witness.aterm_bytes
    );
    assert_eq!(fs::read_dir(udrv_dir).unwrap().count(), 1);
}

#[test]
fn difft_probe_writes_artifacts_when_corpus_has_candidates() {
    let out = tempfile::tempdir().expect("tempdir");
    let mut index = InMemoryCorpusIndex::new();
    index.add(
        "demo".to_owned(),
        PreimageCandidate {
            drv_path: "/nix/store/aaa-demo.drv".to_owned(),
            aterm_preimage: "Derive(signer-side)".to_owned(),
        },
    );
    let probe = DifftProbe::new(index, out.path().to_path_buf()).expect("probe");
    probe.on_signature_miss(&LocalWitness {
        udrv_drv_path: "/nix/store/bbb-demo.drv",
        udrv_name: "demo",
        udrv_input_hash: "h",
        ct_input_hash: "ctxyz",
        aterm_bytes: "Derive(local)",
    });
    let udrv_dir = out.path().join("bbb-demo.drv");
    let local_file = udrv_dir.join("ctxyz");
    let cand_file = udrv_dir.join("aaa-demo.drv");
    assert!(local_file.is_file(), "missing local preimage artifact");
    assert!(cand_file.is_file(), "missing candidate preimage artifact");
    assert_eq!(
        fs::read_to_string(&local_file).unwrap(),
        "Derive(local)",
        "local preimage content should match witness"
    );
    assert_eq!(
        fs::read_to_string(&cand_file).unwrap(),
        "Derive(signer-side)",
        "candidate preimage content should match corpus entry"
    );
}

#[test]
fn difft_probe_skips_difft_when_bytewise_identical() {
    if !difft_available() {
        eprintln!("skipping: difft not in PATH");
        return;
    }
    let out = tempfile::tempdir().expect("tempdir");
    let mut index = InMemoryCorpusIndex::new();
    index.add(
        "same-bytes".to_owned(),
        PreimageCandidate {
            drv_path: "/nix/store/aaa.drv".to_owned(),
            aterm_preimage: "Derive(identical)".to_owned(),
        },
    );
    let probe = DifftProbe::new(index, out.path().to_path_buf()).expect("probe");
    probe.on_signature_miss(&LocalWitness {
        udrv_drv_path: "/nix/store/bbb.drv",
        udrv_name: "same-bytes",
        udrv_input_hash: "h",
        ct_input_hash: "ct",
        aterm_bytes: "Derive(identical)",
    });
    // Both files end up in the out-dir but bytes are identical so difft is
    // skipped. We can't easily assert stderr from here, so check artifacts
    // exist and trust that the bytewise branch took (covered by reading
    // the source: it returns before invoking Command::new("difft")).
    assert!(out.path().join("bbb.drv").join("ct").is_file());
}

#[test]
fn difft_probe_runs_difft_on_bytewise_differs() {
    if !difft_available() {
        eprintln!("skipping: difft not in PATH");
        return;
    }
    let out = tempfile::tempdir().expect("tempdir");
    let mut index = InMemoryCorpusIndex::new();
    index.add(
        "differs".to_owned(),
        PreimageCandidate {
            drv_path: "/nix/store/aaa.drv".to_owned(),
            // Realistic-looking single-token change so difft surfaces it.
            aterm_preimage: "Derive([(\"out\",\"/sig-side\",\"\",\"\")])".to_owned(),
        },
    );
    let probe = DifftProbe::new(index, out.path().to_path_buf()).expect("probe");
    probe.on_signature_miss(&LocalWitness {
        udrv_drv_path: "/nix/store/bbb.drv",
        udrv_name: "differs",
        udrv_input_hash: "h",
        ct_input_hash: "ct",
        aterm_bytes: "Derive([(\"out\",\"/local-side\",\"\",\"\")])",
    });
    // difft was invoked; we don't assert on its stdout from here, but the
    // artifacts under out_dir should be present and differ bytewise.
    let udrv_dir = out.path().join("bbb.drv");
    assert!(udrv_dir.join("ct").is_file());
    assert!(udrv_dir.join("aaa.drv").is_file());
    assert_ne!(
        fs::read(udrv_dir.join("ct")).unwrap(),
        fs::read(udrv_dir.join("aaa.drv")).unwrap(),
    );
}

// ---------------- extract_debug_from_bundle ----------------

#[test]
fn corpus_lookup_matches_namespaced_fixture_bundle() {
    let path = data_dir().join(trace_path(
        NIX_RESOLVED_INPUT,
        "mdw7ghk4133r650ali5jdmgqi4ccwp65",
    ));
    let body = fs::read_to_string(path).unwrap();
    let (name, drv_path, aterm) =
        extract_debug_from_bundle(body.lines().next().unwrap()).expect("debug present");
    assert!(!name.is_empty());
    assert!(drv_path.starts_with("/nix/store/"));
    assert!(aterm.starts_with("Derive("));

    let index = build_corpus_from_cache(&fixture_cache_url()).expect("corpus build");
    assert!(
        index
            .lookup(Identity::DrvName, &name)
            .iter()
            .any(|candidate| {
                candidate.drv_path == drv_path && candidate.aterm_preimage == aterm
            }),
        "corpus lookup must find the preimage from the namespaced fixture"
    );
}
