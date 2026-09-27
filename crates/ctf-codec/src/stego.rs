//! Image stego primitives: PNG LSB extraction, JPEG segment walk,
//! appended data detection for PNG/JPEG/GIF.

/// JPEG segment markers and their names.
pub const JPEG_MARKERS: &[(&str, [u8; 2])] = &[
    ("SOI", [0xFF, 0xD8]), ("SOF0", [0xFF, 0xC0]), ("SOF2", [0xFF, 0xC2]),
    ("DHT", [0xFF, 0xC4]), ("DQT", [0xFF, 0xDB]), ("DRI", [0xFF, 0xDD]),
    ("SOS", [0xFF, 0xDA]), ("EOI", [0xFF, 0xD9]),
    ("APP0", [0xFF, 0xE0]), ("APP1", [0xFF, 0xE1]), ("APP2", [0xFF, 0xE2]),
    ("APP13", [0xFF, 0xED]), ("COM", [0xFF, 0xFE]),
];

#[derive(Debug, Clone)]
pub struct JpegSegment {
    pub marker: String,
    pub offset: usize,
    pub data: Vec<u8>,
}

/// Walk JPEG segments (markers with length fields; SOS/EOI handled specially).
pub fn walk_jpeg(data: &[u8]) -> Vec<JpegSegment> {
    let mut segments = Vec::new();
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        return segments;
    }
    segments.push(JpegSegment { marker: "SOI".into(), offset: 0, data: vec![] });
    let mut pos = 2usize;
    while pos + 1 < data.len() {
        if data[pos] != 0xFF {
            pos += 1;
            continue;
        }
        let marker = data[pos + 1];
        let name = JPEG_MARKERS.iter()
            .find(|(_, m)| m[1] == marker)
            .map(|(n, _)| n.to_string())
            .unwrap_or_else(|| format!("0x{:02X}", marker));
        if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            pos += 2; // standalone markers
            continue;
        }
        if pos + 4 > data.len() { break; }
        let seg_len = u16::from_be_bytes(data[pos + 2..pos + 4].try_into().unwrap()) as usize;
        let seg_data = data[pos + 4..(pos + 2 + seg_len).min(data.len())].to_vec();
        segments.push(JpegSegment { marker: name, offset: pos, data: seg_data });
        if marker == 0xDA { // SOS — rest of file is compressed data
            break;
        }
        pos += 2 + seg_len;
    }
    segments
}

/// Extract COM (comment) and APPn segment content from a JPEG.
pub fn jpeg_extract_text(data: &[u8]) -> Vec<(String, String)> {
    walk_jpeg(data)
        .into_iter()
        .filter(|s| s.marker == "COM" || s.marker.starts_with("APP"))
        .map(|s| {
            let text = String::from_utf8_lossy(&s.data).into_owned();
            (s.marker, text.chars().take(300).collect())
        })
        .collect()
}

/// Detect data appended after JPEG EOI marker.
pub fn jpeg_trailing_data(data: &[u8]) -> Option<&[u8]> {
    let eoi_sig = [0xFF, 0xD9];
    let mut pos = 2usize;
    // walk to find the last EOI
    let mut last_eoi = None;
    while pos + 1 < data.len() {
        if data[pos] == 0xFF && data[pos + 1] == 0xD8 {
            // SOI — skip
            pos += 2;
        } else if data[pos] == 0xFF && data[pos + 1] == 0xD9 {
            last_eoi = Some(pos + 2);
            pos += 2;
        } else {
            pos += 1;
        }
    }
    let end = last_eoi?;
    if end < data.len() {
        Some(&data[end..])
    } else {
        None
    }
}

/// Extract LSB stego from raw RGB pixel data (width * height * 3).
/// Returns one bit per pixel channel, assembled into bytes.
pub fn extract_lsb_rgb(pixel_data: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(pixel_data.len());
    for &b in pixel_data {
        bits.push(b & 1);
    }
    // pack bits into bytes
    let mut out = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit != 0 { byte |= 1 << (7 - i); }
        }
        out.push(byte);
    }
    out
}

/// PNG chunk walk: returns (chunk_type, data_offset, data_len) for each chunk.
pub fn png_chunks(data: &[u8]) -> Vec<(String, usize, usize)> {
    const SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let mut chunks = Vec::new();
    if data.len() < 8 || data[..8] != SIG {
        return chunks;
    }
    let mut pos = 8usize;
    while pos + 12 <= data.len() {
        let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        let ctype = String::from_utf8_lossy(&data[pos + 4..pos + 8]).into_owned();
        let data_start = pos + 8;
        let data_end = data_start + len;
        if data_end + 4 > data.len() { break; }
        chunks.push((ctype.clone(), data_start, len));
        pos = data_end + 4;
        if ctype == "IEND" { break; }
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpeg_segments_walk() {
        // minimal JPEG: SOI + APP0 + DQT + SOS
        let mut data = vec![0xFF, 0xD8]; // SOI
        data.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00]); // APP0 len=4
        data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x03, 0x00]); // DQT len=3
        data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]); // SOS
        data.extend_from_slice(&[0xFF, 0xD9]); // EOI
        data.extend_from_slice(b"hidden-data");
        let segs = walk_jpeg(&data);
        assert!(segs.iter().any(|s| s.marker == "SOI"));
        assert!(segs.iter().any(|s| s.marker == "APP0"));
        let trail = jpeg_trailing_data(&data);
        assert!(trail.is_some());
        assert_eq!(trail.unwrap(), b"hidden-data");
    }

    #[test]
    fn jpeg_comment_extraction() {
        let mut data = vec![0xFF, 0xD8];
        let comment = b"flag{jpeg_comment_stego}";
        let len = (comment.len() + 2) as u16;
        data.extend_from_slice(&[0xFF, 0xFE]);
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(comment);
        data.extend_from_slice(&[0xFF, 0xD9]);
        let texts = jpeg_extract_text(&data);
        assert!(texts.iter().any(|(m, t)| m == "COM" && t.contains("flag")));
    }

    #[test]
    fn lsb_extraction() {
        // pixel bytes with LSBs: 1,0,1,1,0,1,0,0 = 0b10110100 = 0xB4
        let pixels: Vec<u8> = vec![0x01, 0x02, 0x03, 0x03, 0x00, 0x03, 0x00, 0x00];
        let extracted = extract_lsb_rgb(&pixels);
        assert_eq!(extracted[0], 0xB4);
    }

    #[test]
    fn png_chunk_walk() {
        let mut data = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        // IHDR chunk: len=13, type="IHDR", 13 data bytes, crc
        data.extend_from_slice(&13u32.to_be_bytes());
        data.extend_from_slice(b"IHDR");
        data.extend_from_slice(&[0u8; 13]);
        data.extend_from_slice(&[0, 0, 0, 0]); // crc
        // IEND
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(b"IEND");
        data.extend_from_slice(&[0, 0, 0, 0]);
        let chunks = png_chunks(&data);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0, "IHDR");
        assert_eq!(chunks[1].0, "IEND");
    }
}
