//! Raw memory-image utilities: string carving and file carving.
//!
//! A CTF memory dump is usually a raw physical-memory image (DumpIt / winpmem)
//! with no container structure. The workhorses are: pull readable strings
//! (ASCII and UTF-16LE — Windows keeps most artifacts UTF-16), and carve
//! embedded files by magic + terminal marker. Everything returns file offsets
//! so the analyst can go back with a hex editor.
//!
//! Capability coverage: domain 7 (memory forensics), domain 11 (file
//! forensics: carving with end markers).

/// all byte-offsets of `needle` in `haystack` (overlapping allowed)
pub fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || haystack.len() < needle.len() {
        return out;
    }
    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
        }
    }
    out
}

/// printable ASCII runs ≥ `min_len` → (offset, string)
pub fn carve_ascii_strings(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        let printable = (0x20..=0x7e).contains(&b);
        if printable {
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

/// UTF-16LE runs ≥ `min_len` chars → (offset, string). Windows-side artifacts
/// (paths, commands, URLs) live in memory as UTF-16LE.
pub fn carve_utf16le_strings(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut units: Vec<u16> = Vec::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let u = u16::from_le_bytes([data[i], data[i + 1]]);
        let printable = (0x20..0x7f).contains(&u) || u == b'\n' as u16 || u == b'\t' as u16;
        if printable {
            if start.is_none() {
                start = Some(i);
                units.clear();
            }
            units.push(u);
            i += 2;
        } else {
            if let Some(s) = start {
                if units.len() >= min_len {
                    let text: String = units.iter().filter_map(|u| char::from_u32(*u as u32)).collect();
                    out.push((s, text));
                }
            }
            start = None;
            units.clear();
            i += 1; // slide one byte: alignment unknown
        }
    }
    if let Some(s) = start {
        if units.len() >= min_len {
            let text: String = units.iter().filter_map(|u| char::from_u32(*u as u32)).collect();
            out.push((s, text));
        }
    }
    out
}

/// terminal marker table for common embedded files
fn end_marker(magic: &[u8]) -> Option<&'static [u8]> {
    match magic {
        b"\x89PNG" => Some(b"IEND\xae\xb4\x42\x60"),
        b"GIF8" => Some(b"\x00\x3b"),
        b"\xff\xd8\xff" => Some(b"\xff\xd9"),
        b"%PDF" => Some(b"%%EOF"),
        b"PK\x03\x04" => Some(b"PK\x05\x06"), // EOCD ends the central dir
        b"7z\xbc\xaf\x27\x1c" => Some(b"\x00\x00\x00\x00\x00\x00\x1c\xaf\x27\xbc"),
        b"Rar!" => Some(b"C\x43\xcd"), // rar end marker
        _ => None,
    }
}

/// Carve files starting at every `magic` occurrence, ending at the file's
/// terminal marker (inclusive). Returns (offset, bytes). Overlaps allowed —
/// memory images keep partial copies; a carve with no terminal marker before
/// the next magic is skipped (likely overwritten remnant) when `strict`.
pub fn carve_files(data: &[u8], magic: &[u8], max_size: usize, strict: bool) -> Vec<(usize, Vec<u8>)> {
    let Some(marker) = end_marker(magic) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for start in find_all(data, magic) {
        let search_end = (start + max_size).min(data.len());
        let mut end = None;
        let mut scan = start + magic.len();
        while scan + marker.len() <= search_end {
            if &data[scan..scan + marker.len()] == marker {
                end = Some(scan + marker.len());
                break;
            }
            scan += 1;
        }
        // ZIP: EOCD is 22 bytes + comment (u16 at +20) — include it all
        let real_end = end.map(|e| {
            if magic == b"PK\x03\x04" {
                // cl lives at EOCD+20 = e−4+20 = e+16
                let cl = data
                    .get(e + 16..e + 18)
                    .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0) as usize;
                (e + 18 + cl).min(data.len())
            } else {
                e
            }
        });
        match real_end {
            Some(e) if e - start <= max_size => out.push((start, data[start..e].to_vec())),
            Some(_) => { /* over max_size */ }
            None => {
                if !strict {
                    // keep a bounded tail anyway (partial remnant can matter)
                    let e = search_end.min(start + max_size);
                    out.push((start, data[start..e].to_vec()));
                }
            }
        }
    }
    out
}

/// simple Shannon entropy of a byte slice (bits/byte, 0..=8) — used to tell
/// encrypted/compressed regions (≈8) from code/text (≈5–6)
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut hist = [0u64; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let n = data.len() as f64;
    hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// per-block entropy map (block = `block_size` bytes) → (offset, entropy)
pub fn entropy_map(data: &[u8], block_size: usize) -> Vec<(usize, f64)> {
    (0..data.len())
        .step_by(block_size.max(1))
        .map(|off| {
            let e = off + block_size.min(data.len() - off);
            (off, entropy(&data[off..e]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_and_utf16_carving() {
        let mut data = Vec::new();
        data.extend_from_slice(b"junk\x01\x02C:\\Users\\admin\\flag.txt\x00rest");
        // UTF-16LE: "C:\flag.txt"
        for b in "C:\\flag.txt".encode_utf16() {
            data.extend_from_slice(&b.to_le_bytes());
        }
        let ascii = carve_ascii_strings(&data, 8);
        assert!(ascii.iter().any(|(o, s)| s.contains("flag.txt") && *o == 6));
        let u16s = carve_utf16le_strings(&data, 6);
        assert!(u16s.iter().any(|(_, s)| s == "C:\\flag.txt"));
    }

    #[test]
    fn png_carve_with_iend() {
        let png_head = b"\x89PNG\r\n\x1a\n----data----";
        let png_end = b"IEND\xae\xb4\x42\x60";
        let mut data = b"memmemmem".to_vec();
        let off = data.len();
        data.extend_from_slice(png_head);
        data.extend_from_slice(png_end);
        data.extend_from_slice(b"more-mem");
        let carved = carve_files(&data, b"\x89PNG", 1 << 20, true);
        assert_eq!(carved.len(), 1);
        assert_eq!(carved[0].0, off);
        assert!(carved[0].1.starts_with(b"\x89PNG"));
        assert!(carved[0].1.ends_with(png_end));
    }

    #[test]
    fn zip_carve_via_eocd() {
        // local file header somewhere, EOCD as terminator
        let mut data = b"x".repeat(3);
        data.extend_from_slice(b"PK\x03\x04payload...");
        let eocd = b"PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        data.extend_from_slice(eocd);
        let carved = carve_files(&data, b"PK\x03\x04", 4096, true);
        assert_eq!(carved.len(), 1);
        assert!(carved[0].1.ends_with(eocd));
    }

    #[test]
    fn entropy_distinguishes() {
        let zeros = vec![0u8; 1024];
        assert!(entropy(&zeros) < 0.01);
        let pseudo: Vec<u8> = (0..1024).map(|i| (i * 7 + 13) as u8).collect();
        assert!(entropy(&pseudo) > 5.0);
        let m = entropy_map(&zeros, 256);
        assert_eq!(m.len(), 4);
        assert!(m.iter().all(|(_, e)| *e < 0.01));
    }

    #[test]
    fn find_all_overlapping() {
        assert_eq!(find_all(b"aaaa", b"aa"), vec![0, 1, 2]);
        assert!(find_all(b"bbb", b"zz").is_empty());
    }
}
