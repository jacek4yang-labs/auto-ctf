//! Byte/int conversions (big-endian, matching Crypto.Util.number semantics)
//! plus small bit utilities.

use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Big-endian bytes -> BigUint (`bytes_to_long`).
pub fn bytes_to_int(b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(b)
}

/// BigUint -> minimal big-endian bytes (`long_to_bytes`).
pub fn int_to_bytes(n: &BigUint) -> Vec<u8> {
    if n.is_zero() {
        return vec![0];
    }
    n.to_bytes_be()
}

/// BigUint -> exactly `width` big-endian bytes (error when too large).
pub fn int_to_bytes_padded(n: &BigUint, width: usize) -> Option<Vec<u8>> {
    let raw = if n.is_zero() { vec![] } else { n.to_bytes_be() };
    if raw.len() > width {
        return None;
    }
    let mut out = vec![0u8; width - raw.len()];
    out.extend_from_slice(&raw);
    Some(out)
}

/// True when the byte string is mostly printable ASCII (heuristic for auto tools).
pub fn mostly_printable(b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    let printable = b
        .iter()
        .filter(|&&x| (0x20..=0x7e).contains(&x) || x == b'\n' || x == b'\r' || x == b'\t')
        .count();
    printable * 100 / b.len() >= 90
}

/// `n` in binary has `bits` set for zero too (0 bits = 0).
pub fn high_bit_index(n: &BigUint) -> usize {
    if n.is_zero() {
        return 0;
    }
    n.bits() as usize
}

/// Extract printable strings of length >= min_len (filescan primitive).
pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &c) in data.iter().enumerate() {
        if (0x20..=0x7e).contains(&c) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            if i - s >= min_len {
                out.push((s, String::from_utf8_lossy(&data[s..i]).into_owned()));
            }
            start = None;
        }
    }
    if let Some(s) = start {
        if data.len() - s >= min_len {
            out.push((s, String::from_utf8_lossy(&data[s..]).into_owned()));
        }
    }
    out
}

/// True when `x` is one (helper for test asserts).
pub fn is_one(x: &BigUint) -> bool {
    x.is_one()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let b = b"ctf-forge vector 01";
        let n = bytes_to_int(b);
        assert_eq!(int_to_bytes(&n), b);
        let padded = int_to_bytes_padded(&n, 24).unwrap();
        assert_eq!(padded.len(), 24);
        assert_eq!(&padded[24 - b.len()..], b);
    }

    #[test]
    fn zero_handling() {
        assert_eq!(int_to_bytes(&BigUint::zero()), vec![0]);
        assert_eq!(bytes_to_int(&[]), BigUint::zero());
        assert_eq!(int_to_bytes(&BigUint::one()), vec![1]);
    }

    #[test]
    fn strings_scan() {
        let data = b"abc\x00flag-marker-here\x01x";
        let found = extract_strings(data, 4);
        assert_eq!(found[0].1, "flag-marker-here");
    }
}
