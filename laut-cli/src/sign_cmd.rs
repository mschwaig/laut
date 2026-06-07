//! Sign / sign-and-upload command handlers.
//!
//! Translate clap args into `laut_sign::sign::SignConfig`, dispatch, and
//! pick the right exit code. Exit code `117` is preserved from the Python
//! CLI to signal "post-build hook fired on unresolved drv, nothing to do".

use std::process::ExitCode;

use laut_sign::sign::{self, SignConfig};

use crate::cli::{SignAndUploadArgs, SignArgs};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Sign(#[from] sign::Error),
}

pub fn run_sign(args: SignArgs) -> Result<ExitCode, Error> {
    let cfg = SignConfig {
        drv_path: path_to_string(&args.drv_path),
        out_paths: split_out_paths(&args.out_paths),
        secret_key_file: args.secret_key_file,
        include_preimage: args.include_preimage,
    };
    match sign::sign(&cfg)? {
        Some((_input_hash, jws_token)) => {
            println!("{}", jws_token);
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
    };
    sign::sign_and_upload(&cfg, &args.to)?;
    Ok(ExitCode::SUCCESS)
}

fn path_to_string(p: &std::path::Path) -> String {
    p.to_string_lossy().into_owned()
}

fn split_out_paths(blob: &str) -> Vec<String> {
    blob.split_whitespace().map(str::to_owned).collect()
}
