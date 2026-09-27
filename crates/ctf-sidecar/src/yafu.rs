//! yafu factorization sidecar: run `factor(N)` via the pinned binary and
//! parse the `-of` output file (same format autorsa parses: `p/base^exp`
//! rows joined by `/`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use num_bigint::BigUint;
use num_traits::One;
use num_traits::Num;

use crate::manifest::SidecarManifest;
use crate::spawn::run_with_timeout;
use ctf_core::error::{CoreError, Result};

/// Factor `n` with the manifest-pinned yafu binary. `root` is the repo root
/// that contains `tools/yafu/manifest.json`. Returns the full factor list
/// (with multiplicity) when yafu completes the factorization.
pub fn factor(root: &Path, n: &BigUint, timeout_secs: u64) -> Result<Vec<BigUint>> {
    let manifest = SidecarManifest::load(&root.join("tools/yafu/manifest.json"))?;
    let engine = manifest.verified_engine(root, "yafu")?;

    let tmp: PathBuf = std::env::temp_dir().join(format!(
        "yafu_out_{}.log",
        std::process::id() as u64 + n.bits()
    ));
    let _ = std::fs::remove_file(&tmp);

    let args = vec![
        format!("factor({n})"),
        "-of".to_string(),
        tmp.to_string_lossy().into_owned(),
    ];
    let out = run_with_timeout(&engine.path, &args, Duration::from_secs(timeout_secs))?;

    if !std::path::Path::new(&tmp).exists() {
        // yafu doesn't create the -of file for a prime input
        if ctf_core::num::is_probable_prime(n) {
            return Ok(vec![n.clone()]);
        }
        return Err(CoreError::Invalid(format!(
            "yafu produced no output file (timed_out={}, stderr={})",
            out.timed_out,
            out.stderr.chars().take(200).collect::<String>()
        )));
    }
    let text = std::fs::read_to_string(&tmp)?;
    match parse_yafu_output(&text, n) {
        Ok(f) => {
            let _ = std::fs::remove_file(&tmp);
            Ok(f)
        }
        Err(e) => Err(e), // keep temp file for debugging
    }
}

/// Parse the `-of` file format: rows like `03/17/P1/2/P3/...` where each
/// `base^exp` or plain `PN` token follows the leading timestamp/marker cells.
pub fn parse_yafu_output(text: &str, n: &BigUint) -> Result<Vec<BigUint>> {
    let mut factors: Vec<BigUint> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || !line.contains('/') {
            continue;
        }
        // timestamp rows like `08/12/26 03:00:00 v1.xx` are not factor rows
        if line.contains(':') {
            continue;
        }
        for token in line.split('/').skip(1) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            let (base, exp) = match token.split_once('^') {
                Some((b, e)) => (b, e.parse::<u32>().unwrap_or(1)),
                None => {
                    // tokens look like P33, C56, or the bare integer
                    if token.starts_with('P') || token.starts_with('C') {
                        continue;
                    }
                    (token, 1)
                }
            };
            if let Ok(f) = BigUint::from_str_radix(base, 10) {
                if f.is_one() {
                    continue;
                }
                for _ in 0..exp {
                    factors.push(f.clone());
                }
            }
        }
    }
    let product: BigUint = factors.iter().product();
    if product == *n && !factors.is_empty() {
        factors.sort();
        Ok(factors)
    } else {
        Err(CoreError::Invalid(format!(
            "yafu factorization incomplete: got {} factors, product mismatch",
            factors.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn parser_accepts_complete_output() {
        // simulate: 17 * 11^2 = 2057
        let text = "08/12/26 03:00:00 v1.xx\n\
                    2/17/P2/11^2/\n";
        let n = BigUint::from(2057u32);
        let f = parse_yafu_output(text, &n).unwrap();
        assert_eq!(f, vec![BigUint::from(11u32), BigUint::from(11u32), BigUint::from(17u32)]);
    }

    #[test]
    fn parser_rejects_incomplete() {
        let text = "2/17/\n";
        let n = BigUint::from(2057u32);
        assert!(parse_yafu_output(text, &n).is_err());
    }

    #[test]
    fn yafu_factors_a_semicomprime() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .unwrap()
            .to_path_buf();
        let p = BigUint::from(10007u32);
        let q = BigUint::from(10009u32);
        let n = &p * &q;
        let f = factor(&root, &n, 120).unwrap_or_default();
        assert_eq!(f, vec![p, q]);
    }
}
