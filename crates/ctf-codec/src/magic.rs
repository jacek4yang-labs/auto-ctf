//! Magic-number table, detection, and length-prefixed carving.

use ctf_core::error::{CoreError, Result};

/// Known magic prefixes (name, bytes). Custom challenge magics like `PKT1`
/// are included because the carving primitive is parameterized anyway.
pub const MAGIC_TABLE: &[(&str, &[u8])] = &[
    ("zip", b"PK\x03\x04"),
    ("zip-eocd", b"PK\x05\x06"),
    ("gzip", b"\x1f\x8b"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("gif", b"GIF87a"),
    ("gif89", b"GIF89a"),
    ("pdf", b"%PDF"),
    ("elf", b"\x7fELF"),
    ("pe", b"MZ"),
    ("sevenzip", b"7z\xbc\xaf\x27\x1c"),
    ("rar", b"Rar!"),
    ("class", b"\xca\xfe\xba\xbe"),
    ("sqlite", b"SQLite format 3\x00"),
    ("bmp", b"BM"),
    ("pkt1", b"PKT1"),
];

/// Detect magic at offset 0.
pub fn detect_magic(data: &[u8]) -> Option<&'static str> {
    MAGIC_TABLE
        .iter()
        .find(|(_, m)| data.starts_with(m))
        .map(|(name, _)| *name)
}

/// Find all offsets of a magic prefix.
pub fn find_magic_offsets(data: &[u8], magic: &[u8]) -> Vec<usize> {
    if magic.is_empty() || data.len() < magic.len() {
        return vec![];
    }
    (0..=data.len() - magic.len())
        .filter(|&i| &data[i..i + magic.len()] == magic)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

/// Carve containers laid out as `[magic][u32 seq][u32 payload_len][payload]`.
///
/// This matches the 泥坑采集器 layout (magic + 序号 + 大端长度). Returns
/// (offset, seq, payload) triples for every magic hit whose declared length
/// fits in the remaining buffer (residual/decoy containers with impossible
/// lengths are rejected, per the challenge narrative).
pub fn carve_len_prefixed(
    data: &[u8],
    magic: &[u8],
    endian: Endian,
    max_payload: usize,
) -> Result<Vec<(usize, u32, Vec<u8>)>> {
    if magic.len() + 8 > data.len() {
        return Err(CoreError::Invalid("buffer smaller than header".into()));
    }
    let mut out = Vec::new();
    for off in find_magic_offsets(data, magic) {
        let hdr_end = off + magic.len() + 8;
        if hdr_end > data.len() {
            continue; // truncated tail hit
        }
        let seq_bytes = &data[off + magic.len()..off + magic.len() + 4];
        let len_bytes = &data[off + magic.len() + 4..hdr_end];
        let (seq, len) = match endian {
            Endian::Big => (
                u32::from_be_bytes(seq_bytes.try_into().unwrap()),
                u32::from_be_bytes(len_bytes.try_into().unwrap()),
            ),
            Endian::Little => (
                u32::from_le_bytes(seq_bytes.try_into().unwrap()),
                u32::from_le_bytes(len_bytes.try_into().unwrap()),
            ),
        };
        if len as usize > max_payload || hdr_end + len as usize > data.len() {
            continue; // decoy / residual with impossible length
        }
        out.push((
            off,
            seq,
            data[hdr_end..hdr_end + len as usize].to_vec(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_known_magics() {
        assert_eq!(detect_magic(b"PK\x03\x04rest"), Some("zip"));
        assert_eq!(detect_magic(b"\x89PNG\r\n\x1a\n"), Some("png"));
        assert_eq!(detect_magic(b"plain text"), None);
    }

    #[test]
    fn find_offsets() {
        let data = b"..PKT1..x..PKT1..";
        assert_eq!(find_magic_offsets(data, b"PKT1"), vec![2, 11]);
    }

    #[test]
    fn carve_pkt1_layout() {
        // two valid containers + one decoy with absurd length
        let mut buf = Vec::new();
        buf.extend_from_slice(b"junk!");
        buf.extend_from_slice(b"PKT1");
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(b"AAAA");
        buf.extend_from_slice(b"PKT1");
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0xffffu32.to_be_bytes()); // decoy: length impossible
        buf.extend_from_slice(b"BBBB");

        let carved = carve_len_prefixed(&buf, b"PKT1", Endian::Big, 4096).unwrap();
        assert_eq!(carved.len(), 1);
        assert_eq!(carved[0].0, 5);
        assert_eq!(carved[0].1, 1);
        assert_eq!(carved[0].2, b"AAAA");
    }

    #[test]
    fn carve_respects_max_payload() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"PKT1");
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&64u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 64]);
        assert!(carve_len_prefixed(&buf, b"PKT1", Endian::Big, 32)
            .unwrap()
            .is_empty());
    }
}
