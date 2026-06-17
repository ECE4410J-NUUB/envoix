//! Master-key persistence.
//!
//! A self-hosted relay holds its own master key. Rather than pass it on the
//! command line (argv is world-readable and leaks into shell history), the
//! key lives in a file: generated once as 32 random bytes, stored as 64
//! lowercase hex characters with owner-only permissions, and reused after.

use std::fs;
use std::path::Path;

use envoix_relay::RelayTokenKey;

/// Load the master key from `path`, or generate and persist a new random one
/// (0600) if the file is absent. Errors on I/O failure or a malformed file.
pub fn load_or_generate(path: &Path) -> Result<RelayTokenKey, String> {
    match fs::read_to_string(path) {
        Ok(s) => {
            let key = RelayTokenKey::from_hex(s.trim())
                .ok_or_else(|| format!("{}: not 64 hex characters", path.display()))?;
            tracing::info!(path = %path.display(), "loaded existing relay master key");
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => generate(path),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn generate(path: &Path) -> Result<RelayTokenKey, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("rng: {e}"))?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    fs::write(path, &hex).map_err(|e| format!("{}: {e}", path.display()))?;
    restrict(path)?;

    tracing::info!(path = %path.display(), "generated relay master key");
    Ok(RelayTokenKey::from_bytes(bytes))
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "envoix-relay-keyfile-{}-{tag}/relay.key",
            std::process::id()
        ))
    }

    #[test]
    fn generates_and_persists_owner_only() {
        let path = tmp("gen");
        let _ = fs::remove_dir_all(path.parent().unwrap());

        load_or_generate(&path).expect("generate");
        let content = fs::read_to_string(&path).expect("file written");
        assert_eq!(content.len(), 64);
        assert!(content.chars().all(|c| c.is_ascii_hexdigit()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn reuses_existing_key() {
        let path = tmp("reuse");
        let _ = fs::remove_dir_all(path.parent().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let known = "a".repeat(64);
        fs::write(&path, &known).unwrap();

        load_or_generate(&path).expect("load");
        // Existing file is not overwritten.
        assert_eq!(fs::read_to_string(&path).unwrap(), known);

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn rejects_malformed_key() {
        let path = tmp("bad");
        let _ = fs::remove_dir_all(path.parent().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "not-hex").unwrap();

        assert!(load_or_generate(&path).is_err());

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
