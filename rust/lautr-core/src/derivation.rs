//! Thin wrappers around snix's derivation-path primitives.

use nix_compat::derivation::calculate_derivation_path_from_aterm;
use nix_compat::store_path;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to compute upstream placeholder: {0}")]
    Placeholder(String),
    #[error("failed to compute derivation path from ATerm: {0}")]
    Path(String),
}

pub fn hash_upstream_placeholder(drv_path: &str, output_name: &str) -> Result<String, Error> {
    store_path::hash_upstream_placeholder("/nix/store/", drv_path, output_name)
        .map_err(Error::Placeholder)
}

pub fn calculate_drv_path_from_aterm(drv_name: &str, drv_aterm: &[u8]) -> Result<String, Error> {
    calculate_derivation_path_from_aterm(drv_name, drv_aterm)
        .map_err(|e| Error::Path(format!("{:?}", e)))
}
