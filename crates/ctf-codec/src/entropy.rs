//! Entropy and byte statistics.

/// Shannon entropy in bits/byte (0..=8).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Entropy of fixed-size windows; useful to locate high-entropy blobs
/// (encrypted/compressed regions) inside otherwise plain files.
pub fn entropy_profile(data: &[u8], window: usize) -> Vec<(usize, f64)> {
    data.chunks(window)
        .enumerate()
        .map(|(i, c)| (i * window, shannon_entropy(c)))
        .collect()
}

/// Byte histogram (256 entries).
pub fn histogram(data: &[u8]) -> [u64; 256] {
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    freq
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert!(shannon_entropy(b"\x00\x00\x00\x00") < 0.01);
        // 256 distinct bytes → 8.0 bits
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
        let text = b"the quick brown fox jumps over the lazy dog";
        let e = shannon_entropy(text);
        assert!(e > 3.5 && e < 5.0, "text entropy {e}");
    }

    #[test]
    fn profile_windows() {
        let data = vec![0u8; 64];
        let p = entropy_profile(&data, 16);
        assert_eq!(p.len(), 4);
        assert!(p[0].1 < 0.01);
    }
}
