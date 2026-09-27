//! Hex / Base64 / Base32 codecs (data-encoding wrappers) and xor.

use data_encoding::{BASE32, BASE64, BASE64URL, HEXLOWER, HEXUPPER};

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

pub fn hex_encode(data: &[u8], upper: bool) -> String {
    if upper {
        HEXUPPER.encode(data)
    } else {
        HEXLOWER.encode(data)
    }
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let t = s.trim();
    let t = t.strip_prefix("0x").unwrap_or(t);
    let cleaned: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err(invalid("hex length must be even"));
    }
    HEXLOWER
        .decode(cleaned.to_ascii_lowercase().as_bytes())
        .map_err(|_| invalid("bad hex"))
}

pub fn base64_encode(data: &[u8], url_safe: bool) -> String {
    if url_safe {
        BASE64URL.encode(data)
    } else {
        BASE64.encode(data)
    }
}

/// Tolerant base64 decode: strips whitespace/newlines and padding variants.
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    for dec in [&BASE64, &BASE64URL] {
        if let Ok(v) = dec.decode(cleaned.trim_end_matches('=').as_bytes()) {
            return Ok(v);
        }
        if let Ok(v) = dec.decode(cleaned.as_bytes()) {
            return Ok(v);
        }
    }
    Err(invalid("bad base64"))
}

pub fn base32_encode(data: &[u8]) -> String {
    BASE32.encode(data)
}

pub fn base32_decode(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    BASE32
        .decode(cleaned.to_ascii_uppercase().as_bytes())
        .map_err(|_| invalid("bad base32"))
}

/// XOR every byte with a single-byte key.
pub fn xor_single(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}

/// XOR with a repeating key (key must be non-empty).
pub fn xor_repeating(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(invalid("empty xor key"));
    }
    Ok(data
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let s = hex_encode(b"\xde\xad\xbe\xef", false);
        assert_eq!(s, "deadbeef");
        assert_eq!(hex_decode("DEADBEEF").unwrap(), b"\xde\xad\xbe\xef");
        assert_eq!(hex_decode("0xdeadbeef").unwrap(), b"\xde\xad\xbe\xef");
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn base64_roundtrip() {
        let s = base64_encode(b"ctf-forge", false);
        assert_eq!(base64_decode(&s).unwrap(), b"ctf-forge");
        assert_eq!(base64_decode("Y3Rm\nLWZvcmdl==").unwrap(), b"ctf-forge");
    }

    #[test]
    fn base32_roundtrip() {
        let s = base32_encode(b"forge32");
        assert_eq!(base32_decode(&s).unwrap(), b"forge32");
    }

    #[test]
    fn xor_modes() {
        assert_eq!(xor_single(b"abc", 0), b"abc");
        assert_eq!(xor_single(b"\x00\x01\x02", 0xff), b"\xff\xfe\xfd");
        let k = xor_repeating(b"aaaaaa", b"xy").unwrap();
        assert_eq!(k, b"\x19\x18\x19\x18\x19\x18");
        assert!(xor_repeating(b"a", b"").is_err());
    }
}
