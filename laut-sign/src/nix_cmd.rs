//! Subprocess wrappers around the `nix` and `nix-store` CLIs.
//!
//! Derivation ingestion uses stored ATerm bytes. JSON is only the internal
//! `DrvJson` map returned to callers, not Nix's CLI JSON format.

use std::collections::BTreeMap;
use std::process::Command;

use nix_compat::derivation::Derivation;
use nix_compat::nixhash::CAHash;
use nix_compat::store_path::StorePath;

use crate::drv_json::{DrvJson, InputDrvRef, OutputRef};

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
    #[error("cannot serialize internal derivation map: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cannot read derivation {path}: {reason}")]
    Derivation { path: String, reason: String },
}

fn run(cmd: &str, args: &[&str]) -> Result<Vec<u8>, Error> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|source| Error::Io {
            cmd: cmd.to_owned(),
            source,
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

/// Read one stored derivation and return an internal `{drv_path: DrvJson}` map.
pub fn derivation_show(drv_path: &str) -> Result<String, Error> {
    read_derivations(drv_path, false, derivation_aterm)
}

/// Read a derivation and its input derivations into an internal JSON map.
pub fn derivation_show_recursive(drv_path: &str) -> Result<String, Error> {
    read_derivations(drv_path, true, derivation_aterm)
}

fn read_derivations(
    drv_path: &str,
    recursive: bool,
    mut read_aterm: impl FnMut(&str) -> Result<String, Error>,
) -> Result<String, Error> {
    let mut pending = vec![drv_path.to_owned()];
    let mut drvs = BTreeMap::new();
    while let Some(path) = pending.pop() {
        // The result map also serves as the visited set for shared dependencies.
        if drvs.contains_key(&path) {
            continue;
        }
        let invalid = |reason| Error::Derivation {
            path: path.clone(),
            reason,
        };
        let store_path = StorePath::<String>::from_absolute_path(path.as_bytes())
            .map_err(|e| invalid(e.to_string()))?;
        // Nix's BasicDerivation::nameFromPath removes only the final .drv suffix.
        let name = store_path
            .name()
            .strip_suffix(".drv")
            .ok_or_else(|| invalid("expected a .drv store path".into()))?
            .to_owned();
        let raw = read_aterm(&path)?;
        // Floating and resolved derivations need the non-validating parser.
        let drv = Derivation::from_aterm_bytes_unchecked(raw.as_bytes())
            .map_err(|e| invalid(format!("invalid or unsupported ATerm: {e:?}")))?;
        let input_drvs: BTreeMap<_, _> = drv
            .input_derivations
            .into_iter()
            .map(|(path, outputs)| {
                (
                    path.to_absolute_path(),
                    InputDrvRef {
                        outputs: outputs.into_iter().collect(),
                    },
                )
            })
            .collect();
        if recursive {
            pending.extend(input_drvs.keys().cloned());
        }
        let outputs = drv
            .outputs
            .into_iter()
            .map(|(name, output)| {
                let method = output
                    .ca_hash
                    .as_ref()
                    .map(|hash| match hash {
                        CAHash::Flat(_) => "flat",
                        CAHash::Nar(_) => "nar",
                        CAHash::Text(_) => "text",
                    })
                    .or_else(|| {
                        output
                            .ca_floating
                            .map(|algo| if algo.recursive { "nar" } else { "flat" })
                    });
                (
                    name,
                    OutputRef {
                        // Preserve the actual tuple path for every output, including seeded ones.
                        path: output.path.map(|p| p.to_absolute_path()),
                        hash: output.ca_hash.map(|h| h.hash().to_nix_hex_string()),
                        method: method.map(str::to_owned),
                    },
                )
            })
            .collect();
        drvs.insert(
            path,
            DrvJson {
                name,
                input_drvs,
                outputs,
            },
        );
    }
    Ok(serde_json::to_string(&drvs)?)
}

/// `nix store cat <drv>` - returns the derivation's stored ATerm representation.
pub fn derivation_aterm(drv_path: &str) -> Result<String, Error> {
    run_utf8(
        "nix",
        &[NIX_FEATURES, "nix-command", "store", "cat", drv_path],
        "nix store cat",
    )
}

/// `nix-store --query --hash <path>` - returns the trimmed `hashAlgo:hash` line.
pub fn output_hash_from_disk(out_path: &str) -> Result<String, Error> {
    let raw = run_utf8(
        "nix-store",
        &["--query", "--hash", out_path],
        "nix-store --query --hash",
    )?;
    Ok(raw.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drv_json::classify;
    use serde_json::{Value, json};

    const ROOT: &str = "/nix/store/00000000000000000000000000000000-example.drv.drv";
    const LEFT: &str = "/nix/store/11111111111111111111111111111111-left.drv";
    const RIGHT: &str = "/nix/store/22222222222222222222222222222222-right.drv";
    const SHARED: &str = "/nix/store/33333333333333333333333333333333-shared.drv";
    const HASH: &str = "894517c9163c896ec31a2adbd33c0681fd5f45b2c0ef08a64c92a03fb97f390f";

    fn aterm(outputs: &str, inputs: &[&str]) -> String {
        let inputs = inputs
            .iter()
            .map(|p| format!(r#"("{p}",["out"])"#))
            .collect::<Vec<_>>()
            .join(",");
        format!(r#"Derive([{outputs}],[{inputs}],[],"x86_64-linux","/bin/sh",[],[])"#)
    }

    #[test]
    fn direct_output_kinds_preserve_paths_and_use_store_name() {
        for stored_path in [
            "/nix/store/00000000000000000000000000000000-example",
            "/nix/store/11111111111111111111111111111111-example",
        ] {
            for (path, algo, hash, method, classification) in [
                (stored_path, "", "", None, (false, false)),
                (stored_path, "sha256", HASH, Some("flat"), (true, false)),
                (stored_path, "r:sha256", HASH, Some("nar"), (true, false)),
                ("", "r:sha256", "", Some("nar"), (false, true)),
                ("", "sha256", "", Some("flat"), (false, true)),
            ] {
                let raw = aterm(&format!(r#"("out","{path}","{algo}","{hash}")"#), &[LEFT]);
                let mut reads = 0;
                let result = read_derivations(ROOT, false, |p| {
                    assert_eq!(p, ROOT);
                    reads += 1;
                    Ok(raw.clone())
                })
                .unwrap();
                assert_eq!(reads, 1);
                let drvs: BTreeMap<String, DrvJson> = serde_json::from_str(&result).unwrap();
                assert_eq!(drvs.len(), 1);
                let drv = &drvs[ROOT];
                assert_eq!(drv.name, "example.drv");
                assert_eq!(drv.input_drvs[LEFT].outputs, ["out"]);
                assert_eq!(classify(&drv.outputs), classification);
                let output = &drv.outputs["out"];
                assert_eq!(output.path.as_deref(), (!path.is_empty()).then_some(path));
                assert_eq!(
                    output.hash,
                    (!hash.is_empty()).then(|| format!("sha256:{HASH}"))
                );
                assert_eq!(output.method.as_deref(), method);
                let value: Value = serde_json::from_str(&result).unwrap();
                assert_eq!(value[ROOT].as_object().unwrap().len(), 3);
                assert_eq!(value[ROOT]["inputDrvs"][LEFT], json!({"outputs": ["out"]}));
            }
        }
    }

    #[test]
    fn multi_output_and_env_name() {
        let raw = aterm(r#"("dev","/nix/store/11111111111111111111111111111111-example-dev","",""),("out","/nix/store/00000000000000000000000000000000-example","","")"#, &[])
            .replace(",[],[])", r#",[],[("name","ignored")])"#);
        let result = read_derivations(ROOT, false, |_| Ok(raw.clone())).unwrap();
        let drvs: BTreeMap<String, DrvJson> = serde_json::from_str(&result).unwrap();
        assert_eq!(drvs[ROOT].name, "example.drv");
        assert_eq!(drvs[ROOT].outputs.len(), 2);
        assert_eq!(
            drvs[ROOT].outputs["dev"].path.as_deref(),
            Some("/nix/store/11111111111111111111111111111111-example-dev")
        );
        assert_eq!(
            drvs[ROOT].outputs["out"].path.as_deref(),
            Some("/nix/store/00000000000000000000000000000000-example")
        );
    }

    #[test]
    fn recursive_dag_reads_each_derivation_once() {
        let mut reads = BTreeMap::new();
        let result = read_derivations(ROOT, true, |path| {
            *reads.entry(path.to_owned()).or_insert(0) += 1;
            let deps: &[&str] = match path {
                ROOT => &[LEFT, RIGHT],
                LEFT | RIGHT => &[SHARED],
                SHARED => &[],
                _ => panic!("unexpected read {path}"),
            };
            Ok(aterm(r#"("out","","r:sha256","")"#, deps))
        })
        .unwrap();
        assert_eq!(reads.len(), 4);
        assert!(reads.values().all(|&n| n == 1));
        let drvs: BTreeMap<String, DrvJson> = serde_json::from_str(&result).unwrap();
        assert_eq!(drvs.len(), 4);
        assert!(drvs[LEFT].input_drvs.contains_key(SHARED));
        assert!(drvs[RIGHT].input_drvs.contains_key(SHARED));
    }

    #[test]
    fn malformed_aterm_and_read_errors_propagate() {
        let error = read_derivations(ROOT, false, |_| Ok("not ATerm".into())).unwrap_err();
        assert!(
            matches!(error, Error::Derivation { path, reason } if path == ROOT && reason.contains("ATerm"))
        );
        let mut reads = 0;
        let error = read_derivations(ROOT, true, |path| {
            reads += 1;
            if path == ROOT {
                Ok(aterm(r#"("out","","r:sha256","")"#, &[LEFT]))
            } else {
                Err(Error::Failed {
                    cmd: "nix store cat".into(),
                    code: 1,
                    stderr: "unavailable".into(),
                })
            }
        })
        .unwrap_err();
        assert!(matches!(error, Error::Failed { code: 1, .. }));
        assert_eq!(reads, 2);
    }
}
