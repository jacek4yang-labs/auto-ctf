//! Disk image forensics: partition tables (MBR/GPT) and FAT32 filesystem
//! walking.
//!
//! CTF disk challenges hand out raw images (sometimes disguised as .zip —
//! the 华为杯 2024 Draw_what_you_like "压缩包" was a block image). This
//! module: partition discovery (MBR + GPT), FAT32 boot-parameter parsing,
//! directory walking with long-file-name (LFN) support and cluster-chain
//! file reads.
//!
//! Capability coverage: disk forensics (partition tables, FAT32).
//!
//! Provenance: Microsoft's FAT32/GPT specifications are public
//! (Microsoft UEFI / FAT32 spec); independent implementation, no code copied.

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

// ---------------------------------------------------------------------------
// MBR / GPT
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Partition {
    /// 0 for MBR parts, entry index for GPT
    pub index: usize,
    pub kind: String,
    pub start_lba: u64,
    pub num_sectors: u64,
    /// GPT only: partition name (UTF-16LE)
    pub name: Option<String>,
}

fn well_known_guid(g: &[u8; 16]) -> String {
    // mixed-endian GUID: first 3 fields LE
    let d1 = u32::from_le_bytes(g[0..4].try_into().unwrap());
    let d2 = u16::from_le_bytes(g[4..6].try_into().unwrap());
    let d3 = u16::from_le_bytes(g[6..8].try_into().unwrap());
    match format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1, d2, d3, g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
    .as_str()
    {
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => "EFI System".into(),
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => "Microsoft basic data".into(),
        "e75caf8f-f680-4cee-8832-34e77559e33e" => "Linux x86-64 root".into(),
        "0fc63daf-8483-4772-8e79-3d69d8477de4" => "Linux filesystem".into(),
        other => other.to_string(),
    }
}

/// parse MBR (LBA 0) and, if a GPT protective partition is present, the
/// GPT header + entries (LBA 1 and following). Sector size assumed 512.
pub fn parse_partitions(data: &[u8]) -> Result<Vec<Partition>> {
    if data.len() < 512 {
        return Err(invalid("image smaller than one sector"));
    }
    if data[510] != 0x55 || data[511] != 0xAA {
        return Err(invalid("missing 0x55AA boot signature"));
    }
    let mut out = Vec::new();
    let mut has_gpt = false;
    for i in 0..4 {
        let e = 0x1BE + i * 16;
        let kind = data[e + 4];
        let lba = u32::from_le_bytes(data[e + 8..e + 12].try_into().unwrap()) as u64;
        let nsec = u32::from_le_bytes(data[e + 12..e + 16].try_into().unwrap()) as u64;
        if kind == 0 || nsec == 0 {
            continue;
        }
        if kind == 0xEE {
            has_gpt = true;
        }
        let kind_name = match kind {
            0x01 => "FAT12",
            0x04 | 0x06 | 0x0B | 0x0C => "FAT",
            0x07 => "NTFS/exFAT",
            0x83 => "Linux",
            0xEE => "GPT protective",
            _ => "other",
        };
        out.push(Partition {
            index: i,
            kind: kind_name.into(),
            start_lba: lba,
            num_sectors: nsec,
            name: None,
        });
    }
    if has_gpt && data.len() > 512 + 92 {
        // GPT header at LBA 1
        let g = &data[512..];
        if &g[0..8] == b"EFI PART" {

            // GPT header fields are little-endian per the UEFI spec
            let num_entries = u32::from_le_bytes(g[0x50..0x54].try_into().unwrap()) as usize;
            let entry_size = u32::from_le_bytes(g[0x54..0x58].try_into().unwrap()) as usize;
            let entries_lba = u64::from_le_bytes(g[0x48..0x50].try_into().unwrap());
            let ent_base = entries_lba as usize * 512;
            out.clear(); // GPT replaces MBR partitions
            for i in 0..num_entries {
                let e = ent_base + i * entry_size;
                if e + 128 > data.len() {
                    break;
                }
                let type_guid: [u8; 16] = data[e..e + 16].try_into().unwrap();

                if type_guid.iter().all(|&b| b == 0) {
                    continue;
                }
                let first = u64::from_le_bytes(data[e + 32..e + 40].try_into().unwrap());
                let last = u64::from_le_bytes(data[e + 40..e + 48].try_into().unwrap());
                let name_units: Vec<u16> = data[e + 56..e + 128]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                    .take_while(|&u| u != 0)
                    .collect();
                out.push(Partition {
                    index: i,
                    kind: well_known_guid(&type_guid),
                    start_lba: first,
                    num_sectors: last.saturating_sub(first) + 1,
                    name: Some(String::from_utf16_lossy(&name_units)),
                });
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// FAT32
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FatEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u32,
    pub cluster: u32,
}

pub struct Fat32<'a> {
    data: &'a [u8],
    bytes_per_sector: usize,
    sectors_per_cluster: usize,
    reserved: usize,
    num_fats: usize,
    fat_size_sectors: u64,
    root_cluster: u32,
}

impl<'a> Fat32<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Fat32<'a>> {
        if data.len() < 512 || data[510] != 0x55 || data[511] != 0xAA {
            return Err(invalid("FAT32: missing boot signature"));
        }
        let bps = u16::from_le_bytes(data[0x0B..0x0D].try_into().unwrap()) as usize;
        let spc = data[0x0D] as usize;
        let reserved = u16::from_le_bytes(data[0x0E..0x10].try_into().unwrap()) as usize;
        let num_fats = data[0x10] as usize;
        let fat_size = u32::from_le_bytes(data[0x24..0x28].try_into().unwrap()) as u64;
        let root = u32::from_le_bytes(data[0x2C..0x30].try_into().unwrap());
        if bps == 0 || spc == 0 || num_fats == 0 || fat_size == 0 {
            return Err(invalid("FAT32: degenerate BPB"));
        }
        Ok(Fat32 {
            data,
            bytes_per_sector: bps,
            sectors_per_cluster: spc,
            reserved,
            num_fats,
            fat_size_sectors: fat_size,
            root_cluster: root,
        })
    }

    fn cluster_off(&self, cluster: u32) -> Result<usize> {
        let data_start = (self.reserved + self.num_fats * self.fat_size_sectors as usize)
            * self.bytes_per_sector;
        let off = data_start
            + (cluster as usize - 2) * self.sectors_per_cluster * self.bytes_per_sector;
        if off >= self.data.len() {
            return Err(invalid("cluster beyond image"));
        }
        Ok(off)
    }

    fn fat_entry(&self, cluster: u32) -> u32 {
        let fat_off = self.reserved * self.bytes_per_sector;
        let e = fat_off + cluster as usize * 4;
        u32::from_le_bytes(self.data[e..e + 4].try_into().unwrap()) & 0x0FFF_FFFF
    }

    /// read the full byte chain of a cluster (follows FAT links)
    pub fn read_chain(&self, start: u32) -> Result<Vec<u8>> {
        let cl_size = self.sectors_per_cluster * self.bytes_per_sector;
        let mut out = Vec::new();
        let mut c = start;
        let mut hops = 0;
        loop {
            hops += 1;
            if hops > 1_000_000 || (c < 2 && hops > 1) {
                return Err(invalid("cluster chain cycle/corrupt"));
            }
            let off = self.cluster_off(c)?;
            let end = (off + cl_size).min(self.data.len());
            out.extend_from_slice(&self.data[off..end]);
            c = self.fat_entry(c);
            if c >= 0x0FFF_FFF8 {
                break; // end of chain
            }
        }
        Ok(out)
    }

    /// walk a directory cluster chain, decoding short + long file names
    pub fn read_dir(&self, start: u32) -> Result<Vec<FatEntry>> {
        let raw = self.read_chain(start)?;
        let mut out = Vec::new();
        let mut lfn: Vec<u16> = Vec::new();
        let mut i = 0usize;
        while i + 32 <= raw.len() {
            let e = &raw[i..i + 32];
            i += 32;
            let first = e[0];
            if first == 0x00 {
                break; // end of directory
            }
            if first == 0xE5 {
                lfn.clear();
                continue; // deleted
            }
            let attr = e[0x0B];
            if attr == 0x0F {
                // LFN entry: sequence byte, 13 UTF-16 chars
                let seq = (first & 0x3F) as usize;
                if seq == 0 {
                    lfn.clear();
                    continue;
                }
                let mut chunk: Vec<u16> = Vec::new();
                chunk.extend(e[1..11].chunks_exact(2).map(|b| u16::from_le_bytes(b.try_into().unwrap())));
                chunk.extend(e[14..26].chunks_exact(2).map(|b| u16::from_le_bytes(b.try_into().unwrap())));
                chunk.extend(e[28..32].chunks_exact(2).map(|b| u16::from_le_bytes(b.try_into().unwrap())));
                // LFN entries appear in descending sequence order
                if lfn.len() < (seq - 1) * 13 {
                    lfn.resize((seq - 1) * 13, 0);
                }
                let insert_at = (seq - 1) * 13;
                while lfn.len() < insert_at + 13 {
                    lfn.push(0);
                }
                for (k, &u) in chunk.iter().enumerate() {
                    lfn[insert_at + k] = u;
                }
                continue;
            }
            if attr & 0x08 != 0 {
                lfn.clear();
                continue; // volume label
            }
            let short = {
                let base = &e[0..8];
                let base_s: String = base
                    .iter()
                    .take_while(|&&b| b != 0x20 && b != 0)
                    .map(|&b| b as char)
                    .collect();
                let ext: String = e[8..11]
                    .iter()
                    .take_while(|&&b| b != 0x20 && b != 0)
                    .map(|&b| b as char)
                    .collect();
                if ext.is_empty() {
                    base_s
                } else {
                    format!("{}.{}", base_s, ext)
                }
            };
            let name = if lfn.is_empty() {
                short
            } else {
                let units: Vec<u16> = lfn.iter().cloned().take_while(|&u| u != 0 && u != 0xFFFF).collect();
                String::from_utf16_lossy(&units)
            };
            lfn.clear();
            let cluster = (u16::from_le_bytes(e[0x14..0x16].try_into().unwrap()) as u32) << 16
                | u16::from_le_bytes(e[0x1A..0x1C].try_into().unwrap()) as u32;
            let size = u32::from_le_bytes(e[0x1C..0x20].try_into().unwrap());
            out.push(FatEntry {
                name,
                is_dir: attr & 0x10 != 0,
                size,
                cluster,
            });
        }
        Ok(out)
    }

    /// convenience: root directory listing
    pub fn root_dir(&self) -> Result<Vec<FatEntry>> {
        self.read_dir(self.root_cluster)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECTOR: usize = 512;
    const SPC: usize = 1;
    const RESERVED: usize = 8;
    const FATS: usize = 2;
    const FAT_SECTORS: usize = 2;

    /// build a tiny FAT32 image: root dir with an LFN file entry + data
    fn build_fat32() -> Vec<u8> {
        let data_start = (RESERVED + FATS * FAT_SECTORS) * SECTOR;
        let total = data_start + 8 * SECTOR;
        let mut d = vec![0u8; total];

        d[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        d[0x0B..0x0D].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        d[0x0D] = SPC as u8;
        d[0x0E..0x10].copy_from_slice(&(RESERVED as u16).to_le_bytes());
        d[0x10] = FATS as u8;
        d[0x24..0x28].copy_from_slice(&(FAT_SECTORS as u32).to_le_bytes());
        d[0x2C..0x30].copy_from_slice(&2u32.to_le_bytes()); // root = cluster 2
        d[510] = 0x55;
        d[511] = 0xAA;

        let cluster_byte = |c: usize| data_start + (c - 2) * SPC * SECTOR;
        let fat = RESERVED * SECTOR;
        let set_fat = |d: &mut Vec<u8>, c: usize, v: u32| {
            d[fat + c * 4..fat + c * 4 + 4].copy_from_slice(&v.to_le_bytes());
        };
        set_fat(&mut d, 2, 0x0FFF_FFFF);
        set_fat(&mut d, 4, 0x0FFF_FFFF);

        let content = b"DASCTF{fat32_forensics}";

        // root dir cluster (cluster 2): LFN entries + short entry
        let root_off = cluster_byte(2);
        let name = "flag_report_2024.txt";
        let units: Vec<u16> = name.encode_utf16().collect();
        // LFN: seq 2 first, then seq 1 (chars 0..12); 0x40 marks the last
        for seq in [2usize, 1] {
            let mut e = vec![0u8; 32];
            e[0] = if seq == 2 { 0x40 | 2 } else { 1 };
            e[0x0B] = 0x0F;
            e[0x0D] = 0x2A;
            let mut chars: Vec<u16> = Vec::new();
            let range = if seq == 1 { 0..13 } else { 13..26 };
            for i in range {
                chars.push(*units.get(i).unwrap_or(&0xFFFF));
            }
            for (k, u) in chars.iter().enumerate() {
                let pos = if k < 5 {
                    1 + k * 2
                } else if k < 11 {
                    14 + (k - 5) * 2
                } else {
                    28 + (k - 11) * 2
                };
                e[pos..pos + 2].copy_from_slice(&u.to_le_bytes());
            }
            let dst = root_off + if seq == 2 { 0 } else { 32 };
            d[dst..dst + 32].copy_from_slice(&e);
        }
        // short entry: 8.3 name "FLAG_R~1TXT"
        let mut se = vec![0u8; 32];
        se[0..11].copy_from_slice(b"FLAG_R~1TXT");
        se[0x0B] = 0x20;
        se[0x1A..0x1C].copy_from_slice(&4u16.to_le_bytes());
        se[0x1C..0x20].copy_from_slice(&(content.len() as u32).to_le_bytes());
        d[root_off + 64..root_off + 96].copy_from_slice(&se);

        // file data in cluster 4
        let fo = cluster_byte(4);
        d[fo..fo + content.len()].copy_from_slice(content);
        d
    }

    #[test]
    fn fat32_walks_root_with_lfn() {
        let img = build_fat32();
        let fs = Fat32::parse(&img).expect("parse");
        let entries = fs.root_dir().expect("root");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "flag_report_2024.txt");
        assert_eq!(entries[0].cluster, 4);
        assert_eq!(entries[0].size, content_len());
    }

    fn content_len() -> u32 {
        23
    }

    #[test]
    fn fat32_reads_file_chain() {
        let img = build_fat32();
        let fs = Fat32::parse(&img).expect("parse");
        let content = fs.read_chain(4).expect("chain");
        assert!(content.starts_with(b"DASCTF{fat32_forensics}"));
    }

    #[test]
    fn mbr_parses_partitions() {
        let mut d = vec![0u8; 512];
        d[510] = 0x55;
        d[511] = 0xAA;
        let e1 = 0x1BE;
        d[e1 + 4] = 0x07; // NTFS
        d[e1 + 8..e1 + 12].copy_from_slice(&2048u32.to_le_bytes());
        d[e1 + 12..e1 + 16].copy_from_slice(&1024u32.to_le_bytes());
        let e2 = 0x1CE;
        d[e2 + 4] = 0xEE; // GPT protective
        d[e2 + 8..e2 + 12].copy_from_slice(&4096u32.to_le_bytes());
        d[e2 + 12..e2 + 16].copy_from_slice(&1024u32.to_le_bytes());
        let parts = parse_partitions(&d).expect("parse");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].kind, "NTFS/exFAT");
        assert_eq!(parts[0].start_lba, 2048);
        assert_eq!(parts[1].kind, "GPT protective");
    }

    #[test]
    fn gpt_replaces_mbr_entries() {
        let mut d = vec![0u8; 4 * 512];
        d[510] = 0x55;
        d[511] = 0xAA;
        // protective MBR entry
        d[0x1BE + 4] = 0xEE;
        d[0x1BE + 12..0x1BE + 16].copy_from_slice(&3u32.to_le_bytes());
        // GPT header at LBA 1 (all fields little-endian per UEFI spec)
        let g = 512;
        d[g..g + 8].copy_from_slice(b"EFI PART");
        d[g + 0x48..g + 0x50].copy_from_slice(&2u64.to_le_bytes()); // entries LBA 2
        d[g + 0x50..g + 0x54].copy_from_slice(&2u32.to_le_bytes()); // 2 entries
        d[g + 0x54..g + 0x58].copy_from_slice(&128u32.to_le_bytes()); // entry size
        // entries at LBA 2
        let ent = 2 * 512;
        // MS basic data GUID (mixed-endian)
        d[ent..ent + 4].copy_from_slice(&0xEBD0A0A2u32.to_le_bytes());
        d[ent + 4..ent + 6].copy_from_slice(&0xB9E5u16.to_le_bytes());
        d[ent + 6..ent + 8].copy_from_slice(&0x4433u16.to_le_bytes());
        d[ent + 8..ent + 16].copy_from_slice(&[0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7]);
        d[ent + 32..ent + 40].copy_from_slice(&2048u64.to_le_bytes());
        d[ent + 40..ent + 48].copy_from_slice(&4095u64.to_le_bytes());
        let uname: Vec<u8> = "CTF-data".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        d[ent + 56..ent + 56 + uname.len()].copy_from_slice(&uname);
        // entry 2: EFI system
        let e2 = ent + 128;
        d[e2..e2 + 4].copy_from_slice(&0xC12A7328u32.to_le_bytes());
        d[e2 + 4..e2 + 6].copy_from_slice(&0xF81Fu16.to_le_bytes());
        d[e2 + 6..e2 + 8].copy_from_slice(&0x11D2u16.to_le_bytes());
        d[e2 + 8..e2 + 16].copy_from_slice(&[0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B]);
        d[e2 + 32..e2 + 40].copy_from_slice(&4096u64.to_le_bytes());
        d[e2 + 40..e2 + 48].copy_from_slice(&8191u64.to_le_bytes());

        let parts = parse_partitions(&d).expect("parse");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].kind, "Microsoft basic data");
        assert_eq!(parts[0].name.as_deref(), Some("CTF-data"));
        assert_eq!(parts[0].start_lba, 2048);
        assert_eq!(parts[1].kind, "EFI System");
    }

    #[test]
    fn rejects_bad_boot_signature() {
        assert!(parse_partitions(&[0u8; 512]).is_err());
    }
}
