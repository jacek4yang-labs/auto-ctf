//! NTFS Master File Table (MFT) record parsing.
//!
//! Memory/disk forensics challenges hand out `$MFT` blobs; each 1024-byte
//! record carries the fixup array and a chain of attributes. This module
//! applies the update-sequence (fixup) protection, walks the attribute list,
//! and extracts the forensics-relevant ones:
//! - 0x10 STANDARD_INFORMATION — 4 timestamps (created/modified/mft-read/access)
//! - 0x30 FILE_NAME — parent reference, name (UTF-16LE), namespace
//! - 0x80 DATA — resident content (small files) or non-resident run sizes
//!
//! Capability coverage: domain 7 (memory/disk forensics).
//!
//! Provenance: NTFS layout is publicly documented (Linux-NTFS project docs);
//! independent implementation, no code copied.

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

pub const MFT_RECORD_SIZE: usize = 1024;
pub const ATTR_STANDARD_INFORMATION: u32 = 0x10;
pub const ATTR_FILE_NAME: u32 = 0x30;
pub const ATTR_DATA: u32 = 0x80;

#[derive(Debug, Clone, Copy)]
pub struct Ft {
    pub created: u64,
    pub modified: u64,
    pub mft_modified: u64,
    pub accessed: u64,
}

#[derive(Debug, Clone)]
pub struct FileNameAttr {
    pub parent_ref: u64,
    pub times: Ft,
    pub alloc_size: u64,
    pub real_size: u64,
    pub namespace: u8,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct DataAttr {
    pub resident: bool,
    pub content: Vec<u8>,
    pub non_resident_size: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct MftEntry {
    pub record_number: u32,
    pub in_use: bool,
    pub standard_info: Option<Ft>,
    pub file_names: Vec<FileNameAttr>,
    pub data: Option<DataAttr>,
}

fn rd_u16(d: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(d[p..p + 2].try_into().unwrap())
}
fn rd_u32(d: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(d[p..p + 4].try_into().unwrap())
}
fn rd_u64(d: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(d[p..p + 8].try_into().unwrap())
}

/// apply the update-sequence array (fixup): the last u16 of each 512-byte
/// sector is replaced by the saved values in the fixup array
fn apply_fixup(record: &mut [u8]) -> Result<()> {
    if record.len() < 48 {
        return Err(invalid("record too short"));
    }
    // MFT record header: UpdateSequenceOffset @0x04, UpdateSequenceSize @0x06
    // (count includes the check value itself)
    let usa_offset = rd_u16(record, 0x04) as usize;
    let usa_count = rd_u16(record, 0x06) as usize;
    if usa_offset == 0 || usa_count == 0 {
        return Ok(()); // no fixup
    }
    let check = rd_u16(record, usa_offset);
    for i in 1..usa_count {
        let sector_end = i * 512 - 2;
        let saved = rd_u16(record, usa_offset + i * 2);
        if sector_end + 2 > record.len() {
            return Err(invalid("fixup out of range"));
        }
        if rd_u16(record, sector_end) != check {
            return Err(invalid("fixup check value mismatch (corrupt record)"));
        }
        record[sector_end..sector_end + 2].copy_from_slice(&saved.to_le_bytes());
    }
    Ok(())
}

fn parse_file_name(body: &[u8]) -> Option<FileNameAttr> {
    if body.len() < 0x40 {
        return None;
    }
    let parent_ref = rd_u64(body, 0);
    let times = Ft {
        created: rd_u64(body, 8),
        modified: rd_u64(body, 16),
        mft_modified: rd_u64(body, 24),
        accessed: rd_u64(body, 32),
    };
    let alloc_size = rd_u64(body, 40);
    let real_size = rd_u64(body, 48);
    let name_len = body[0x40] as usize;
    let namespace = body[0x41];
    let name_end = (0x42 + name_len * 2).min(body.len());
    let units: Vec<u16> = body[0x42..name_end]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .collect();
    Some(FileNameAttr {
        parent_ref: parent_ref & 0x0000_FFFF_FFFF_FFFF,
        times,
        alloc_size,
        real_size,
        namespace,
        name: String::from_utf16_lossy(&units),
    })
}

fn parse_data_attr(content: &[u8], non_resident: bool) -> Option<DataAttr> {
    if non_resident {
        if content.len() < 0x40 {
            return None;
        }
        Some(DataAttr {
            resident: false,
            content: Vec::new(),
            non_resident_size: Some(rd_u64(content, 0x30)),
        })
    } else {
        Some(DataAttr { resident: true, content: content.to_vec(), non_resident_size: None })
    }
}

/// parse one 1024-byte MFT record ("FILE" magic + fixup + attribute chain)
pub fn parse_record(record: &[u8]) -> Result<MftEntry> {
    if record.len() < MFT_RECORD_SIZE {
        return Err(invalid("MFT record shorter than 1024"));
    }
    if &record[0..4] != b"FILE" {
        return Err(invalid("MFT record lacks FILE magic"));
    }
    let mut rec = record[..MFT_RECORD_SIZE].to_vec();
    apply_fixup(&mut rec)?;
    let attr_off = rd_u16(&rec, 0x14) as usize;
    let record_number = rd_u32(&rec, 0x2C);
    let flags = rd_u16(&rec, 0x16);
    let mut entry = MftEntry {
        record_number,
        in_use: flags & 1 != 0,
        ..Default::default()
    };
    let mut pos = attr_off;
    while pos + 8 <= rec.len() {
        let atype = rd_u32(&rec, pos);
        if atype == 0xFFFF_FFFF {
            break; // end marker
        }
        let alen = rd_u32(&rec, pos + 4) as usize;
        if alen == 0 || pos + alen > rec.len() {
            break; // corrupt tail
        }
        let non_resident = rec[pos + 8] != 0; // 0=resident, 1=non-resident
        let body = &rec[pos..pos + alen];
        match atype {
            ATTR_STANDARD_INFORMATION => {
                if body.len() >= 0x38 {
                    // times live in the VALUE at value-offset 0x18
                    let b = &body[0x18..];
                    if b.len() >= 0x20 {
                        entry.standard_info = Some(Ft {
                            created: rd_u64(b, 0),
                            modified: rd_u64(b, 8),
                            mft_modified: rd_u64(b, 16),
                            accessed: rd_u64(b, 24),
                        });
                    }
                }
            }
            ATTR_FILE_NAME => {
                if std::env::var("CTF_MFT_DEBUG").is_ok() {
                    eprintln!("[mft] FILE_NAME hit: alen={} nonres={} co={} cl={}",
                        alen, non_resident, rd_u16(body, 0x14), rd_u32(body, 0x10));
                }
                if !non_resident {
                    // resident extended header: value-length u32 @0x10,
                    // value-offset u16 @0x14 (usually 0x18)
                    let co = rd_u16(body, 0x14) as usize;
                    let cl = rd_u32(body, 0x10) as usize;
                    let end = (co + cl).min(body.len());
                    if co <= body.len() && cl > 0 {
                        if let Some(fna) = parse_file_name(&body[co..end]) {
                            entry.file_names.push(fna);
                        }
                    }
                }
            }
            ATTR_DATA => {
                if !non_resident {
                    let co = rd_u16(body, 0x14) as usize;
                    let cl = rd_u32(body, 0x10) as usize;
                    let end = (co + cl).min(body.len());
                    if co <= body.len() && cl > 0 {
                        if let Some(da) = parse_data_attr(&body[co..end], false) {
                            entry.data = Some(da);
                        }
                    }
                } else if let Some(da) = parse_data_attr(body, true) {
                    entry.data = Some(da);
                }
            }
            _ => {}
        }
        pos += alen;
    }
    Ok(entry)
}

/// scan a blob of consecutive 1024-byte records, keeping valid "FILE" entries
pub fn parse_entries(data: &[u8]) -> Result<Vec<MftEntry>> {
    if data.len() < MFT_RECORD_SIZE {
        return Err(invalid("mft blob too small"));
    }
    let mut out = Vec::new();
    for chunk in data.chunks(MFT_RECORD_SIZE) {
        if chunk.len() == MFT_RECORD_SIZE && &chunk[0..4] == b"FILE" {
            if let Ok(e) = parse_record(chunk) {
                out.push(e);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill_u16(r: &mut [u8], off: usize, v: u16) {
        r[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn fill_u32(r: &mut [u8], off: usize, v: u32) {
        r[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn fill_u64(r: &mut [u8], off: usize, v: u64) {
        r[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// build a valid 1024-byte record: header + fixup + 0x10 + 0x30 + 0x80
    pub(super) fn build_record() -> Vec<u8> {
        let mut r = vec![0u8; 1024];
        r[0..4].copy_from_slice(b"FILE");
        fill_u16(&mut r, 0x04, 0x30); // UpdateSequenceOffset
        fill_u16(&mut r, 0x06, 3); // UpdateSequenceSize (check + 2 sectors)
        fill_u16(&mut r, 0x14, 0x38); // attribute chain offset
        fill_u16(&mut r, 0x16, 1); // flags: in use
        fill_u32(&mut r, 0x2C, 12345); // record number
        // fixup: check value 0x1111 stored in the USA; sector ends hold it too
        fill_u16(&mut r, 0x30, 0x1111);
        fill_u16(&mut r, 510, 0x1111);
        fill_u16(&mut r, 1022, 0x1111);
        let mut p = 0x38usize;
        // 0x10 STANDARD_INFORMATION: resident ext header (vlen@0x10, voff@0x14=0x18),
        // content 0x20 bytes at +0x18 → attr length 0x38
        fill_u32(&mut r, p, ATTR_STANDARD_INFORMATION);
        fill_u32(&mut r, p + 4, 0x38);
        r[p + 8] = 0; // resident
        fill_u32(&mut r, p + 0x10, 0x20); // value length
        fill_u16(&mut r, p + 0x14, 0x18); // value offset
        fill_u64(&mut r, p + 0x18, 1000); // created
        fill_u64(&mut r, p + 0x20, 2000); // modified
        p += 0x38;
        // 0x30 FILE_NAME: value = 0x42 + name·2 bytes at +0x18
        let name = "flag.txt";
        let vlen = 0x42 + name.len() * 2;
        let fn_len = 0x18 + vlen;
        fill_u32(&mut r, p, ATTR_FILE_NAME);
        fill_u32(&mut r, p + 4, fn_len as u32);
        r[p + 8] = 0; // resident
        fill_u32(&mut r, p + 0x10, vlen as u32);
        fill_u16(&mut r, p + 0x14, 0x18); // value offset
        let b = p + 0x18;
        fill_u64(&mut r, b, 7); // parent ref
        fill_u64(&mut r, b + 8, 3000); // created
        fill_u64(&mut r, b + 0x30, 1024); // real size @body+0x30
        r[b + 0x40] = name.len() as u8;
        r[b + 0x41] = 1; // namespace DOS
        for (i, u) in name.encode_utf16().enumerate() {
            fill_u16(&mut r, b + 0x42 + i * 2, u);
        }
        p += fn_len;
        // 0x80 DATA (resident): value at +0x18
        let content = b"DASCTF{mft_carve}";
        let d_len = 0x18 + content.len();
        fill_u32(&mut r, p, ATTR_DATA);
        fill_u32(&mut r, p + 4, d_len as u32);
        r[p + 8] = 0; // resident
        fill_u32(&mut r, p + 0x10, content.len() as u32);
        fill_u16(&mut r, p + 0x14, 0x18); // value offset
        r[p + 0x18..p + 0x18 + content.len()].copy_from_slice(content);
        p += d_len;
        fill_u32(&mut r, p, 0xFFFF_FFFF); // end marker
        r
    }

    #[test]
    fn parses_record_with_fixup() {
        let rec = build_record();
        let e = parse_record(&rec).expect("parse");
        assert_eq!(e.record_number, 12345);
        assert!(e.in_use);
        let si = e.standard_info.unwrap();
        assert_eq!(si.created, 1000);
        assert_eq!(si.modified, 2000);
        let fn0 = &e.file_names[0];
        assert_eq!(fn0.name, "flag.txt");
        assert_eq!(fn0.parent_ref, 7);
        assert_eq!(fn0.times.created, 3000);
        assert_eq!(fn0.real_size, 1024);
        let d = e.data.unwrap();
        assert!(d.resident);
        assert_eq!(d.content, b"DASCTF{mft_carve}");
    }

    #[test]
    fn scan_entries_from_blob() {
        let mut blob = vec![0u8; 1024]; // non-FILE filler
        blob.extend(build_record());
        blob.extend(vec![0xFFu8; 1024]);
        let entries = parse_entries(&blob).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_names[0].name, "flag.txt");
    }

    #[test]
    fn rejects_corrupt_record() {
        let mut rec = build_record();
        rec[0..4].copy_from_slice(b"BAAD");
        assert!(parse_record(&rec).is_err());
        // fixup mismatch: change the sector-end check value
        let mut rec2 = build_record();
        rec2[510..512].copy_from_slice(&0x2222u16.to_le_bytes());
        assert!(parse_record(&rec2).is_err());
    }
}

#[cfg(test)]
mod walk_debug {
    use super::tests::build_record;
    use super::*;

    #[test]
    fn walk_attributes_debug() {
        let rec = build_record();
        let mut rec = rec.clone();
        apply_fixup(&mut rec).unwrap();
        let mut pos = rd_u16(&rec, 0x14) as usize;
        eprintln!("attr chain from 0x{:x}", pos);
        for _ in 0..8 {
            let t = rd_u32(&rec, pos);
            let alen = rd_u32(&rec, pos + 4) as usize;
            let nonres = rec[pos + 8];
            let co = rd_u16(&rec, pos + 0x14) as usize;
            eprintln!("  attr type=0x{:x} len={} nonres={} co={}", t, alen, nonres, co);
            if t == 0xFFFF_FFFF || alen == 0 { break; }
            pos += alen;
        }
    }
}
