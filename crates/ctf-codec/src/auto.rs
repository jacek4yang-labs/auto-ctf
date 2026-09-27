//! Auto-decode chain: repeatedly strip common encodings until the payload is
//! stable/printable. Conservative on purpose (base64/hex/base32/rot13 only).



#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer {
    Base64,
    Base64Url,
    Hex,
    Base32,
    Rot13,
}

impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Layer::Base64 => "base64",
            Layer::Base64Url => "base64url",
            Layer::Hex => "hex",
            Layer::Base32 => "base32",
            Layer::Rot13 => "rot13",
        };
        write!(f, "{s}")
    }
}

/// Result of an auto-decode run: the decoded bytes and the layer chain applied.
#[derive(Debug)]
pub struct AutoResult {
    pub data: Vec<u8>,
    pub layers: Vec<Layer>,
}

/// Candidate layers for the given bytes, in peel-priority order.
fn candidate_layers(data: &[u8]) -> Vec<Layer> {
    let mut out = Vec::new();
    if let Ok(text) = std::str::from_utf8(data) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
            if stripped.len() >= 4
                && stripped.len() % 2 == 0
                && stripped.bytes().all(|b| b.is_ascii_hexdigit())
            {
                out.push(Layer::Hex);
            }
            if trimmed.len() >= 8
                && trimmed.len() % 4 == 0
                && trimmed
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
            {
                out.push(Layer::Base64);
                out.push(Layer::Base64Url);
            }
            if trimmed.len() >= 8
                && trimmed.len() % 8 == 0
                && trimmed
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'=')
            {
                out.push(Layer::Base32);
            }
        }
    }
    out
}

fn apply(data: &[u8], layer: &Layer) -> Option<Vec<u8>> {
    use super::xcode;
    match layer {
        Layer::Hex => xcode::hex_decode(&String::from_utf8_lossy(data)).ok(),
        Layer::Base64 => xcode::base64_decode(&String::from_utf8_lossy(data)).ok(),
        Layer::Base64Url => data_encoding::BASE64URL
            .decode(String::from_utf8_lossy(data).trim().as_bytes())
            .ok(),
        Layer::Base32 => xcode::base32_decode(&String::from_utf8_lossy(data)).ok(),
        Layer::Rot13 => Some(super::classic::rot_n(data, 13)),
    }
}

/// Peel up to `max_layers` encodings: at each step try the candidate layers in
/// priority order and keep the first that decodes to something different.
/// Stops when nothing decodes. Note the documented misfire risk: pure
/// alphanumeric ASCII of length %4==0 can be mistaken for base64 — flag-shaped
/// or spaced text never triggers it.
pub fn auto_decode(data: &[u8], max_layers: usize) -> AutoResult {
    let mut layers = Vec::new();
    let mut cur = data.to_vec();
    for _ in 0..max_layers {
        let mut peeled = None;
        for layer in candidate_layers(&cur) {
            if let Some(decoded) = apply(&cur, &layer) {
                if decoded != cur {
                    peeled = Some((decoded, layer));
                    break;
                }
            }
        }
        let Some((decoded, layer)) = peeled else { break };
        cur = decoded;
        layers.push(layer);
    }
    AutoResult { data: cur, layers }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xcode::{base64_encode, hex_encode};

    #[test]
    fn peels_hex_then_b64() {
        let inner = b"plain-payload-text";
        let b64 = base64_encode(inner, false);
        let hexed = hex_encode(b64.as_bytes(), false);
        let r = auto_decode(hexed.as_bytes(), 8);
        assert_eq!(r.data, inner);
        assert_eq!(r.layers, vec![Layer::Hex, Layer::Base64]);
    }

    #[test]
    fn stops_on_plain() {
        let r = auto_decode(b"just some words here", 8);
        assert!(r.layers.is_empty());
        assert_eq!(r.data, b"just some words here");
    }
}
