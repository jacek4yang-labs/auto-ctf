//! Manifest loading + sha256 pinning for sidecar engines.

use std::path::Path;

use serde::Deserialize;

use ctf_core::error::{CoreError, Result};
use ctf_core::hash::sha256_file_hex;

#[derive(Debug, Deserialize)]
pub struct SidecarManifest {
    pub engines: std::collections::BTreeMap<String, EngineEntry>,
}

#[derive(Debug, Deserialize)]
pub struct EngineEntry {
    pub path: String,
    pub sha256: String,
    #[serde(default)]
    pub timeout_secs: u64,
    #[serde(default)]
    pub invocation: String,
}

impl SidecarManifest {
    /// Load and verify the manifest at `tools/yafu/manifest.json`-style paths.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let manifest: SidecarManifest =
            serde_json::from_str(&raw).map_err(|e| CoreError::Invalid(format!("bad manifest: {e}")))?;
        Ok(manifest)
    }

    /// Resolve an engine entry, verifying the pinned sha256 against the file.
    pub fn verified_engine(&self, root: &Path, name: &str) -> Result<EngineEntry> {
        let entry = self
            .engines
            .get(name)
            .ok_or_else(|| CoreError::Invalid(format!("engine {name} not in manifest")))?;
        let abs = if Path::new(&entry.path).is_absolute() {
            std::path::PathBuf::from(&entry.path)
        } else {
            root.join(&entry.path)
        };
        let actual = sha256_file_hex(&abs)?;
        if !actual.eq_ignore_ascii_case(&entry.sha256) {
            return Err(CoreError::Invalid(format!(
                "sidecar {} sha256 mismatch: expected {}, got {}",
                name, entry.sha256, actual
            )));
        }
        Ok(EngineEntry {
            path: abs.to_string_lossy().into_owned(),
            sha256: entry.sha256.clone(),
            timeout_secs: entry.timeout_secs,
            invocation: entry.invocation.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_verifies_yafu_binary() {
        // repo root = two levels up from this crate
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root")
            .to_path_buf();
        let manifest = SidecarManifest::load(&root.join("tools/yafu/manifest.json")).unwrap();
        let engine = manifest.verified_engine(&root, "yafu").unwrap();
        assert!(engine.path.to_lowercase().ends_with("yafu-x64.exe"));
    }

    #[test]
    fn manifest_rejects_unknown_engine() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .unwrap()
            .to_path_buf();
        let manifest = SidecarManifest::load(&root.join("tools/yafu/manifest.json")).unwrap();
        assert!(manifest.verified_engine(&root, "nope").is_err());
    }
}
