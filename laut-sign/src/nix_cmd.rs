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

/// `nix-store --query --references <path>` — returns immediate references.
pub fn output_references(out_path: &str) -> Result<Vec<String>, Error> {
    let raw = run_utf8(
        "nix-store",
        &["--query", "--references", out_path],
        "nix-store --query --references",
    )?;
    Ok(parse_references(&raw))
}

pub fn output_has_self_reference(out_path: &str) -> Result<bool, Error> {
    Ok(references_contain_path(
        &output_references(out_path)?,
        out_path,
    ))
}

fn parse_references(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn references_contain_path(references: &[String], path: &str) -> bool {
    references.iter().any(|reference| reference == path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_references_ignores_blank_lines() {
        let refs = parse_references(
            "\n/nix/store/abc-one\n  /nix/store/def-two  \n\n/nix/store/ghi-three\n",
        );

        assert_eq!(
            refs,
            vec![
                "/nix/store/abc-one",
                "/nix/store/def-two",
                "/nix/store/ghi-three",
            ]
        );
    }

    #[test]
    fn references_contain_path_matches_exact_store_path() {
        let refs =
            parse_references("/nix/store/abc-one\n/nix/store/abc-one-extra\n/nix/store/def-two\n");

        assert!(references_contain_path(&refs, "/nix/store/abc-one"));
        assert!(!references_contain_path(&refs, "/nix/store/abc"));
    }
}
