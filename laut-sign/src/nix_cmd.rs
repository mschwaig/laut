//! Subprocess wrappers around the `nix` and `nix-store` CLIs.
//!
//! Returning JSON as a string (rather than a parsed `serde_json::Value`)
//! keeps PyO3 wiring trivial — the Python side does the `json.loads` and the
//! `@lru_cache` on top.

use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{cmd} failed (exit {code}): {stderr}")]
    Failed {
        cmd: String,
        code: i32,
        stderr: String,
    },
    #[error("io error invoking {cmd}: {source}")]
    Io {
        cmd: String,
        #[source]
        source: std::io::Error,
    },
    #[error("output of {0} is not valid UTF-8")]
    NonUtf8(&'static str),
}

fn run(cmd: &str, args: &[&str]) -> Result<Vec<u8>, Error> {
    let output = Command::new(cmd).args(args).output().map_err(|source| {
        Error::Io {
            cmd: cmd.to_owned(),
            source,
        }
    })?;
    if !output.status.success() {
        return Err(Error::Failed {
            cmd: format!("{} {}", cmd, args.join(" ")),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(output.stdout)
}

fn run_utf8(cmd: &str, args: &[&str], label: &'static str) -> Result<String, Error> {
    let stdout = run(cmd, args)?;
    String::from_utf8(stdout).map_err(|_| Error::NonUtf8(label))
}

const NIX_FEATURES: &str = "--extra-experimental-features";

/// `nix derivation show <drv>` — returns the raw JSON.
pub fn derivation_show(drv_path: &str) -> Result<String, Error> {
    run_utf8(
        "nix",
        &[NIX_FEATURES, "nix-command", "derivation", "show", drv_path],
        "nix derivation show",
    )
}

/// `nix derivation show --recursive <drv>` — returns the raw JSON.
pub fn derivation_show_recursive(drv_path: &str) -> Result<String, Error> {
    run_utf8(
        "nix",
        &[
            NIX_FEATURES,
            "nix-command",
            "derivation",
            "show",
            "--recursive",
            drv_path,
        ],
        "nix derivation show --recursive",
    )
}

/// `nix store cat <drv>` — returns the derivation's ATerm representation.
pub fn derivation_aterm(drv_path: &str) -> Result<String, Error> {
    run_utf8(
        "nix",
        &[NIX_FEATURES, "nix-command", "store", "cat", drv_path],
        "nix store cat",
    )
}

/// `nix-store --query --hash <path>` — returns the trimmed `hashAlgo:hash` line.
pub fn output_hash_from_disk(out_path: &str) -> Result<String, Error> {
    let raw = run_utf8(
        "nix-store",
        &["--query", "--hash", out_path],
        "nix-store --query --hash",
    )?;
    Ok(raw.trim().to_owned())
}
