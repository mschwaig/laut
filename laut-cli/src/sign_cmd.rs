//! Sign / sign-and-upload command handlers.
//!
//! Translate clap args into `laut_sign::sign::SignConfig`, dispatch, and
//! pick the right exit code. Exit code `117` is preserved from the Python
//! CLI to signal "post-build hook fired on unresolved drv, nothing to do".

use std::process::ExitCode;

use laut_sign::sign::{self, SignConfig};

use crate::cli::{LogArgs, SignAndUploadArgs, SignArgs};
use laut_sign::transparency::{LogConfig, LogTrust};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Sign(#[from] sign::Error),
    #[error("{0}")]
    Transparency(#[from] laut_sign::transparency::Error),
}

pub fn run_sign(args: SignArgs) -> Result<ExitCode, Error> {
    let cfg = SignConfig {
        drv_path: path_to_string(&args.drv_path),
        out_paths: split_out_paths(&args.out_paths),
        secret_key_file: args.secret_key_file,
        include_preimage: args.include_preimage,
        log: log_config(args.log)?,
    };
    match sign::sign(&cfg)? {
        Some((_input_hash, bundle)) => {
            println!("{}", bundle);
            Ok(ExitCode::SUCCESS)
        }
        None => Ok(ExitCode::from(117)),
    }
}

pub fn run_sign_and_upload(args: SignAndUploadArgs) -> Result<ExitCode, Error> {
    let cfg = SignConfig {
        drv_path: path_to_string(&args.drv_path),
        out_paths: split_out_paths(&args.out_paths),
        secret_key_file: args.secret_key_file,
        include_preimage: args.include_preimage,
        log: log_config(args.log)?,
    };
    sign::sign_and_upload(&cfg, &args.to)?;
    Ok(ExitCode::SUCCESS)
}

fn log_config(args: LogArgs) -> Result<Option<LogConfig>, Error> {
    match args.rekor {
        None => Ok(None),
        Some(url) => Ok(Some(LogConfig {
            url,
            trust: LogTrust::from_file(&args.trusted_root.expect("clap requires log trust"))?,
        })),
    }
}

fn path_to_string(p: &std::path::Path) -> String {
    p.to_string_lossy().into_owned()
}

fn split_out_paths(blob: &str) -> Vec<String> {
    blob.split_whitespace().map(str::to_owned).collect()
}
