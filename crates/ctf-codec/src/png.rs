//! PNG container forensics: chunk walk, IHDR dimensions, tEXt/iTXt/zTXt text
//! extraction, and trailing-data detection after IEND (图种/append tricks).

#[derive(Debug, Clone)]
pub struct PngChunk {
    pub offset: usize,
    pub kind: String,
    pub data_range: (usize, usize),
}

/// Walk PNG chunks starting after the 8-byte signature. Returns the chunk
/// list and whether extra bytes follow IEND.
pub fn walk(data: &[u8]) -> Result<(Vec<PngChunk>, usize), String> {
    const SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    if data.len() < 8 || data[..8] != SIG {
        return Err("not a PNG".into());
    }
    let mut pos = 8usize;
    let mut chunks = Vec::new();
    let mut iend_end = 0usize;
    while pos + 8 <= data.len() {
        let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        let kind = String::from_utf8_lossy(&data[pos + 4..pos + 8]).into_owned();
        let data_start = pos + 8;
        let data_end = data_start + len;
        if data_end + 4 > data.len() {
            break; // truncated
        }
        chunks.push(PngChunk {
            offset: pos,
            kind: kind.clone(),
            data_range: (data_start, data_end),
        });
        pos = data_end + 4; // skip CRC
        if kind == "IEND" {
            iend_end = pos;
            break;
        }
    }
    Ok((chunks, iend_end))
}

/// Extract human-readable text chunks (tEXt / iTXt / zTXt raw).
pub fn extract_text(data: &[u8]) -> Vec<(String, String)> {
    let Ok((chunks, _)) = walk(data) else { return vec![] };
    let mut out = Vec::new();
    for c in chunks {
        if matches!(c.kind.as_str(), "tEXt" | "iTXt" | "zTXt") {
            let raw = &data[c.data_range.0..c.data_range.1];
            let text = String::from_utf8_lossy(raw);
            out.push((c.kind.clone(), text.chars().take(400).collect()));
        }
    }
    out
}

/// IHDR width/height (first chunk).
pub fn dimensions(data: &[u8]) -> Option<(u32, u32)> {
    let (chunks, _) = walk(data).ok()?;
    let ihdr = chunks.iter().find(|c| c.kind == "IHDR")?;
    let w = u32::from_be_bytes(data[ihdr.data_range.0..ihdr.data_range.0 + 4].try_into().ok()?);
    let h = u32::from_be_bytes(data[ihdr.data_range.0 + 4..ihdr.data_range.0 + 8].try_into().ok()?);
    Some((w, h))
}

/// Bytes after IEND (appended payload, e.g. a nested zip or script).
pub fn trailing_data(data: &[u8]) -> Option<&[u8]> {
    let (_, iend_end) = walk(data).ok()?;
    if iend_end > 0 && iend_end < data.len() {
        Some(&data[iend_end..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_png() -> Vec<u8> {
        let mut v = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        // IHDR chunk: len=13, type, 13 data bytes, crc
        v.extend_from_slice(&13u32.to_be_bytes());
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&1u32.to_be_bytes()); // width
        v.extend_from_slice(&2u32.to_be_bytes()); // height
        v.extend_from_slice(&[8, 0, 0, 0, 0]); // depth/color/compress/filter/interlace
        v.extend_from_slice(&[0, 0, 0, 0]); // fake crc
        // IEND chunk
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(b"IEND");
        v.extend_from_slice(&[0xae, 0x42, 0x60, 0x82]);
        v.extend_from_slice(b"appended-payload");
        v
    }

    #[test]
    fn walks_chunks_and_detects_trailing() {
        let png = minimal_png();
        let (chunks, iend_end) = walk(&png).unwrap();
        let kinds: Vec<&str> = chunks.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, vec!["IHDR", "IEND"]);
        assert_eq!(dimensions(&png), Some((1, 2)));
        let trail = trailing_data(&png).unwrap();
        assert_eq!(trail, b"appended-payload");
        let _ = iend_end;
    }
}
