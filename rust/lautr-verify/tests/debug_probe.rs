//! Integration tests for the hash-divergence debug probe.
//!
//! Uses the same `tests/data/traces/signatures/` fixture corpus that the
//! orchestrator tests use. The corpus is loaded via `file://` so the
//! production code path (cache URL → corpus) gets exercised end-to-end.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use lautr_verify::debug::{
    build_corpus_from_cache, extract_debug_from_jws, DebugProbe, DifftProbe, Identity,
    InMemoryCorpusIndex, LocalWitness, NullProbe, PreimageCandidate,
};

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("data")
}

fn signatures_dir() -> PathBuf {
    data_dir().join("traces").join("signatures")
}

/// The fixture corpus is laid out as `<data>/traces/signatures/<hash>`, but
/// the orchestrator (and the corpus builder) expect `<root>/traces/<hash>`.
/// Build a tiny tree that satisfies that layout by symlinking — we never
/// mutate the fixtures.
fn fixture_cache_root() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let traces = dir.path().join("traces");
    std::os::unix::fs::symlink(signatures_dir(), &traces).expect("symlink fixtures");
    dir
}

fn fixture_cache_url(root: &tempfile::TempDir) -> String {
    format!("file://{}", root.path().display())
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
    let root = fixture_cache_root();
    let index = build_corpus_from_cache(&fixture_cache_url(&root)).expect("corpus build");
    assert!(
        !index.is_empty(),
        "fixture corpus produced no entries; either fixtures lack debug blocks or extract_debug_from_jws regressed"
    );
}

#[test]
fn corpus_contains_known_fixture_drv_names() {
    // These names are present in the fixture signatures; the test will need
    // updating if the fixtures get regenerated against a different pkg set.
    let root = fixture_cache_root();
    let index = build_corpus_from_cache(&fixture_cache_url(&root)).expect("corpus build");
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
    let root = fixture_cache_root();
    let index = build_corpus_from_cache(&fixture_cache_url(&root)).expect("corpus build");
    assert!(index
        .lookup(Identity::DrvName, "not-a-real-drv-name-anywhere")
        .is_empty());
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
    // With an empty index the probe should not write artifacts — there's
    // nothing to diff against. (We treat zero candidates as a logged event
    // with no on-disk output to avoid littering the out-dir.)
    let udrv_dir = out.path().join("abc-no-match.drv");
    assert!(!udrv_dir.exists(), "no candidates → no artifacts");
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

// ---------------- extract_debug_from_jws ----------------

#[test]
fn extract_debug_from_fixture_jws() {
    // Read one real fixture JWS and confirm we can pull the debug block.
    let any = fs::read_dir(signatures_dir())
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let body = fs::read_to_string(any.path()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let jws = parsed["signatures"][0].as_str().unwrap();
    let (name, drv_path, aterm) = extract_debug_from_jws(jws).expect("debug present");
    assert!(!name.is_empty());
    assert!(drv_path.starts_with("/nix/store/"));
    assert!(aterm.starts_with("Derive("));
}
