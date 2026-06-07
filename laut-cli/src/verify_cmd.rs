//! Verify command handler. Behind `--features verify`.
//!
//! Resolves flake-ref targets via `nix eval --raw <ref>.drvPath`, loads each
//! trusted public key, then hands everything to
//! [`laut_verify::orchestrator`]. Exit code `118` matches the Python CLI's
//! "verification failed" code so post-build hooks can distinguish failure
//! from a hard error.

use std::path::Path;
use std::process::{Command, ExitCode};

use laut_verify::backend::RealBackend;
use laut_verify::debug::{build_corpus_from_cache, DebugProbe, DifftProbe, NullProbe};
use laut_verify::keyfiles;
use laut_verify::orchestrator::{Config, Orchestrator};

use crate::cli::VerifyArgs;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("verifier: {0}")]
    Orchestrator(#[from] laut_verify::orchestrator::Error),
    #[error("keyfile: {0}")]
    Keyfile(#[from] keyfiles::Error),
    #[error("debug corpus: {0}")]
    DebugCorpus(#[from] laut_verify::debug::CorpusError),
    #[error("temp dir: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid target {target:?}: must be a /nix/store/*.drv path or a flake reference (pkg#attr)")]
    InvalidTarget { target: String },
    #[error("derivation file {0:?} does not exist")]
    DerivationMissing(String),
    #[error("flake resolution failed for {target:?}: exit {code}: {stderr}")]
    FlakeResolveFailed {
        target: String,
        code: i32,
        stderr: String,
    },
    #[error("flake resolution for {0:?} produced non-UTF8 output")]
    FlakeResolveNonUtf8(String),
}

pub fn run(args: VerifyArgs) -> Result<ExitCode, Error> {
    let mut trusted_keys: Vec<(String, Vec<u8>)> = Vec::with_capacity(args.trusted_key.len());
    for key_path in &args.trusted_key {
        let (name, key) = keyfiles::parse_public_key_file(key_path)?;
        trusted_keys.push((name, key.to_vec()));
    }

    let drv_path = resolve_target(&args.target)?;

    let probe: Box<dyn DebugProbe> = match &args.debug_preimage_corpus {
        Some(corpus_url) => {
            let index = build_corpus_from_cache(corpus_url)?;
            let out_dir = args
                .debug_out_dir
                .clone()
                .unwrap_or_else(std::env::temp_dir);
            Box::new(DifftProbe::new(index, out_dir)?)
        }
        None => Box::new(NullProbe),
    };

    let cfg = Config {
        root_drv_path: drv_path.clone(),
        cache_urls: args.cache,
        trusted_keys,
        allow_ia: false,
        debug_probe: probe,
    };
    let mut orch = Orchestrator::new(RealBackend, cfg)?;
    let verified = orch.verify()?;

    if let Some(first) = verified.first() {
        println!("successfully resolved {} to {}", args.target, first);
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("failed to resolve {}", args.target);
        Ok(ExitCode::from(118))
    }
}

fn resolve_target(target: &str) -> Result<String, Error> {
    if target.starts_with("/nix/store/") && target.ends_with(".drv") {
        if !Path::new(target).exists() {
            return Err(Error::DerivationMissing(target.to_owned()));
        }
        return Ok(target.to_owned());
    }
    if target.contains('#') {
        return resolve_flake(target);
    }
    Err(Error::InvalidTarget {
        target: target.to_owned(),
    })
}

fn resolve_flake(flake_ref: &str) -> Result<String, Error> {
    let output = Command::new("nix")
        .args(["eval", "--raw", &format!("{}.drvPath", flake_ref)])
        .output()?;
    if !output.status.success() {
        return Err(Error::FlakeResolveFailed {
            target: flake_ref.to_owned(),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| Error::FlakeResolveNonUtf8(flake_ref.to_owned()))?;
    Ok(stdout.trim().to_owned())
}
