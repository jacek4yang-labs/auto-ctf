//! bkcrack sidecar runner — Biham-Kocher known-plaintext key recovery for
//! ZipCrypto (the CTF2019_zips nested-chain shape).
//!
//! Chain: outer zip -> 111.zip -> 111.zip -> ... Each encrypted layer's
//! plaintext is the next zip's local header: 50 4B 03 04 14 00 09 00 08 00
//! (10 contiguous known bytes — enough for the attack). Recovered keys are
//! reused across identical layers; decryption peels one layer per pass.

use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use ctf_core::error::{CoreError, Result};

use crate::manifest::SidecarManifest;
use crate::spawn::run_with_timeout;

#[derive(Debug, Deserialize)]
pub struct BkcrackManifest {
    pub engines: std::collections::BTreeMap<String, EngineEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EngineEntry {
    pub path: String,
    pub sha256: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    300
}

/// Recover ZipCrypto keys from known plaintext at `offset` inside `zip_bytes`
/// (written to a temp zip for `-C`). Returns the 3 hex words bkcrack prints.
pub fn recover_keys(root: &Path, zip_bytes: &[u8], entry: &str, offset: usize, known_hex: &str) -> Result<String> {
    let manifest = SidecarManifest::load(&root.join("tools/bkcrack/manifest.json"))?;
    let engine = manifest.verified_engine(root, "bkcrack")?;
    let tmp = std::env::temp_dir().join(format!("bk_known_{}.zip", std::process::id()));
    std::fs::write(&tmp, zip_bytes).map_err(|e| CoreError::Io(e))?;
    let out_path = tmp.with_extension("known");
    let args = vec![
        "-C".into(),
        tmp.to_string_lossy().into_owned(),
        "-c".into(),
        entry.to_string(),
        "-x".into(),
        offset.to_string(),
        known_hex.to_string(),
    ];
    let out = run_with_timeout(&engine.path, &args, Duration::from_secs(engine.timeout_secs))?;
    let _ = std::fs::remove_file(&tmp);
    let text = &out.stdout;
    // bkcrack prints: "Keys: 1b1c2d3e 44556677 8899aabb"
    let line = text
        .lines()
        .find(|l| l.starts_with("Keys:"))
        .ok_or_else(|| CoreError::Invalid(format!("bkcrack found no keys: {}", text.chars().take(200).collect::<String>())))?;
    Ok(line.trim_start_matches("Keys:").trim().to_string())
}

/// Decrypt an entry with recovered keys; returns the plaintext bytes.
pub fn decrypt_entry(root: &Path, zip_bytes: &[u8], entry: &str, keys: &str) -> Result<Vec<u8>> {
    let manifest = SidecarManifest::load(&root.join("tools/bkcrack/manifest.json"))?;
    let engine = manifest.verified_engine(root, "bkcrack")?;
    let tmp = std::env::temp_dir().join(format!("bk_dec_{}.zip", std::process::id()));
    std::fs::write(&tmp, zip_bytes).map_err(|e| CoreError::Io(e))?;
    let out_path = tmp.with_extension("dec");
    let mut args = vec![
        "-C".into(),
        tmp.to_string_lossy().into_owned(),
        "-c".into(),
        entry.to_string(),
        "-k".into(),
    ];
    for word in keys.split_whitespace() {
        args.push(word.to_string());
    }
    args.push("-d".into());
    args.push(out_path.to_string_lossy().into_owned());
    run_with_timeout(&engine.path, &args, Duration::from_secs(engine.timeout_secs))
        .map_err(|e| CoreError::Invalid(format!("bkcrack decrypt: {e}")))?;
    let data = std::fs::read(&out_path).map_err(|e| CoreError::Io(e))?;
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&tmp);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_pins_bkcrack() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .unwrap()
            .to_path_buf();
        let manifest = SidecarManifest::load(&root.join("tools/bkcrack/manifest.json")).unwrap();
        let engine = manifest.verified_engine(&root, "bkcrack").unwrap();
        assert!(engine.path.ends_with("bkcrack.exe"));
    }
}
