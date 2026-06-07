//! clap derive definitions for the `laut` CLI surface.
//!
//! The `Verify` subcommand variant is gated on the `verify` feature so the
//! sign-only build's `laut --help` doesn't advertise a command its binary
//! cannot run.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "laut", about = "Nix build trace signature tool", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Sign a derivation and write the JWS to stdout.
    Sign(SignArgs),
    /// Sign a derivation and POST the JWS to an HTTP cache.
    #[command(name = "sign-and-upload")]
    SignAndUpload(SignAndUploadArgs),
    /// Verify signatures for a derivation or flake reference.
    #[cfg(feature = "verify")]
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
pub struct SignArgs {
    /// Path to the derivation (.drv) being signed.
    pub drv_path: PathBuf,

    /// Path to the secret key file.
    #[arg(long)]
    pub secret_key_file: PathBuf,

    /// Space-separated list of output paths. Falls back to `$OUT_PATHS`
    /// (which `nix` sets in the post-build hook).
    #[arg(long, env = "OUT_PATHS")]
    pub out_paths: String,

    /// Embed the resolved ATerm preimage in the signed JWS debug block.
    /// Test/dev only — production signers should keep this off so preimages
    /// never leak into shared caches.
    #[arg(long)]
    pub include_preimage: bool,
}

#[derive(Debug, Args)]
pub struct SignAndUploadArgs {
    /// Path to the derivation (.drv) being signed.
    pub drv_path: PathBuf,

    /// Path to the secret key file.
    #[arg(long)]
    pub secret_key_file: PathBuf,

    /// URL of the target store (e.g. http://cache:9000).
    #[arg(long = "to")]
    pub to: String,

    /// Space-separated list of output paths. Falls back to `$OUT_PATHS`.
    #[arg(long, env = "OUT_PATHS")]
    pub out_paths: String,

    /// Embed the resolved ATerm preimage in the signed JWS debug block.
    #[arg(long)]
    pub include_preimage: bool,
}

#[cfg(feature = "verify")]
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Either a derivation path (`/nix/store/....drv`) or a flake reference
    /// (`nixpkgs#hello`); the type is inferred from the format.
    pub target: String,

    /// URL of an HTTP signature cache to query. Repeatable.
    #[arg(long = "cache")]
    pub cache: Vec<String>,

    /// Path to a trusted public key file. Repeatable.
    #[arg(long = "trusted-key")]
    pub trusted_key: Vec<PathBuf>,

    /// Cache URL to scan for signer-side debug preimages. When a
    /// resolved-input-hash lookup misses, runs difft against any preimage
    /// with a matching drv-name. Requires the cache to expose a
    /// `GET /traces/` listing endpoint; production caches will refuse.
    #[arg(long)]
    pub debug_preimage_corpus: Option<String>,

    /// Directory to drop preimage artifacts into for `--debug-preimage-corpus`.
    /// Defaults to a temp dir.
    #[arg(long)]
    pub debug_out_dir: Option<PathBuf>,
}
