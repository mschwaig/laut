//! `laut` — Nix build trace signature CLI.
//!
//! Subcommands: `sign`, `sign-and-upload`, and (verify-feature-gated)
//! `verify`. The orchestration lives in [`laut_sign::sign`] (and, for
//! verify, [`laut_verify::orchestrator`]); this binary is just argument
//! parsing + dispatch.

use std::process::ExitCode;

use clap::Parser;

mod cli;
mod sign_cmd;
#[cfg(feature = "verify")]
mod verify_cmd;

use cli::{Cli, Command};

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Sign(#[from] sign_cmd::Error),
    #[cfg(feature = "verify")]
    #[error("{0}")]
    Verify(#[from] verify_cmd::Error),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result: Result<ExitCode, CliError> = match cli.command {
        Command::Sign(args) => sign_cmd::run_sign(args).map_err(Into::into),
        Command::SignAndUpload(args) => sign_cmd::run_sign_and_upload(args).map_err(Into::into),
        #[cfg(feature = "verify")]
        Command::Verify(args) => verify_cmd::run(args).map_err(Into::into),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::from(1)
        }
    }
}
