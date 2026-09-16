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
    /// Sign a derivation and write a Sigstore Bundle to stdout.
    Sign(SignArgs),
    /// Sign a derivation and merge its bundle into an HTTP cache.
    #[command(name = "sign-and-upload")]
    SignAndUpload(SignAndUploadArgs),
    /// Verify signatures for a derivation or flake reference.
    #[cfg(feature = "verify")]
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
pub struct SignArgs {
    #[command(flatten)]
    pub log: LogArgs,
    /// Path to the derivation (.drv) being signed.
    pub drv_path: PathBuf,

    /// Path to the secret key file.
    #[arg(long)]
    pub secret_key_file: PathBuf,

    /// Space-separated list of output paths. Falls back to `$OUT_PATHS`
    /// (which `nix` sets in the post-build hook).
    #[arg(long, env = "OUT_PATHS")]
    pub out_paths: String,

    /// Embed the resolved ATerm preimage as a signed debugging byproduct.
    /// Test/dev only — production signers should keep this off so preimages
    /// never leak into shared caches.
    #[arg(long)]
    pub include_preimage: bool,
}

#[derive(Debug, Args)]
pub struct SignAndUploadArgs {
    #[command(flatten)]
    pub log: LogArgs,
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

    /// Embed the resolved ATerm preimage as a signed debugging byproduct.
    #[arg(long)]
    pub include_preimage: bool,
}

#[derive(Debug, Args)]
pub struct LogArgs {
    /// Submit to this Rekor v2 URL and verify its inclusion response.
    #[arg(long, requires = "trusted_root")]
    pub rekor: Option<String>,

    /// Local Sigstore TrustedRoot JSON containing accepted log keys.
    #[arg(long, requires = "rekor")]
    pub trusted_root: Option<PathBuf>,
}

#[cfg(feature = "verify")]
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Require inclusion in at least one explicitly trusted Rekor v2 log.
    #[arg(long, requires = "trusted_root")]
    pub require_log: bool,

    /// Local Sigstore TrustedRoot JSON; no public roots are fetched implicitly.
    #[arg(long, requires = "require_log")]
    pub trusted_root: Option<PathBuf>,
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
