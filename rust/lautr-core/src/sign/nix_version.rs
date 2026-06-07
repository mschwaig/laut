//! Extract the builder's nix flavor + version from the `$NIX_CONFIG` blob
//! that lix/nix exports into post-build hooks.
//!
//! The post-build hook sees a multi-line `nix.conf`-style dump of the live
//! settings. The only line we care about is `build-hook =`, which points at
//! the daemon binary and therefore embeds its store-path name (which encodes
//! both the flavor and the version).

use regex::Regex;

/// Parse `(flavor, version)` from a `$NIX_CONFIG` blob, e.g.
/// `("lix", "2.91.1")`. Returns `(None, None)` if no `build-hook` line
/// referencing a recognized binary is present.
pub fn extract_nix_version_from_nix_config(nix_config: &str) -> (Option<String>, Option<String>) {
    let re = Regex::new(
        r"/nix/store/[a-z0-9]{32}-(lix|nix)-([a-zA-Z0-9._-]+)/bin/nix",
    )
    .expect("static regex compiles");
    for line in nix_config.lines() {
        if !line.starts_with("build-hook =") {
            continue;
        }
        if let Some(caps) = re.captures(line) {
            return (
                Some(caps.get(1).unwrap().as_str().to_owned()),
                Some(caps.get(2).unwrap().as_str().to_owned()),
            );
        }
    }
    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_lix_version_from_real_dump() {
        let blob = "allow-symlinked-store = false\n\
                    build-hook = /nix/store/jxs248g15qklggm9gfyddq822vkcrfg2-lix-2.91.1/bin/nix __build-remote\n\
                    other = stuff\n";
        let (flavor, version) = extract_nix_version_from_nix_config(blob);
        assert_eq!(flavor.as_deref(), Some("lix"));
        assert_eq!(version.as_deref(), Some("2.91.1"));
    }

    #[test]
    fn returns_none_when_build_hook_line_absent() {
        let blob = "allow-symlinked-store = false\nother = stuff\n";
        let (flavor, version) = extract_nix_version_from_nix_config(blob);
        assert!(flavor.is_none());
        assert!(version.is_none());
    }

    #[test]
    fn returns_none_when_build_hook_uses_unrecognized_binary() {
        let blob = "build-hook = /usr/bin/something-else __build-remote\n";
        let (flavor, version) = extract_nix_version_from_nix_config(blob);
        assert!(flavor.is_none());
        assert!(version.is_none());
    }
}
