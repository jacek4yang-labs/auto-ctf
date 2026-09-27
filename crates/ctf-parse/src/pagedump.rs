//! Windows 64-bit kernel crash dump (PAGEDU64) header + KDBG locating.
//!
//! Full memory dumps start with the "PAGE"/"DU64" signature header carrying
//! the debugger data anchors (DirectoryTableBase, PsLoadedModuleList,
//! PsActiveProcessHead), the physical memory run map, and — somewhere in the
//! first pages — the "KDBG" marker volatility-style tools scan for. This
//! module parses the documented header fields, the physical run map (→ a
//! virtual→file physical-memory reader), and locates KDBG offsets.
//!
//! Capability coverage: domain 7 (memory forensics — kernel dumps).
//!
//! Provenance: layout from public documentation/research on the crash dump
//! format (rekall/volatility research); independent implementation, no code
//! copied. Field offsets beyond the documented header are NOT guessed — the
//! KDBG block is only located by signature, not interpreted.

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

#[derive(Debug, Clone)]
pub struct PhysicalRun {
    /// start physical page frame number
    pub base_page: u64,
    /// pages in this run
    pub page_count: u64,
}

#[derive(Debug, Clone)]
pub struct PageDump {
    pub major_version: u32,
    pub minor_version: u32,
    pub directory_table_base: u64,
    pub ps_loaded_module_list: u64,
    pub ps_active_process_head: u64,
    pub machine_image_type: u32,
    pub number_of_processors: u32,
    pub physical_runs: Vec<PhysicalRun>,
    /// offsets of "KDBG" signatures found in the dump
    pub kdbg_offsets: Vec<usize>,
    pub data: Vec<u8>,
}

fn rd_u32(d: &[u8], p: usize) -> Result<u32> {
    d.get(p..p + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| invalid("pagedump truncated (u32)"))
}

fn rd_u64(d: &[u8], p: usize) -> Result<u64> {
    d.get(p..p + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| invalid("pagedump truncated (u64)"))
}

impl PageDump {
    pub fn parse(data: &[u8]) -> Result<PageDump> {
        if data.len() < 0x100 {
            return Err(invalid("dump shorter than header"));
        }
        // Signature "PAGE" (0x45474150 LE) + ValidDump "DU64" (0x34365544 LE)
        let sig = rd_u32(data, 0)?;
        let valid = rd_u32(data, 4)?;
        if sig != 0x4547_4150 || valid != 0x3436_5544 {
            return Err(invalid("not a 64-bit crash dump (PAGE/DU64)"));
        }
        let major = rd_u32(data, 8)?;
        let minor = rd_u32(data, 12)?;
        let dtb = rd_u64(data, 0x10)?;
        let pfn_db = rd_u64(data, 0x18)?;
        let _ = pfn_db;
        let plml = rd_u64(data, 0x20)?;
        let paph = rd_u64(data, 0x28)?;
        let machine = rd_u32(data, 0x30)?;
        let ncpu = rd_u32(data, 0x34)?;
        // PhysicalMemoryBlock at 0x88: NumberOfRuns u32, runs {BasePage u64, PageCount u64}
        let num_runs = rd_u32(data, 0x88)? as usize;
        let mut runs = Vec::with_capacity(num_runs.min(4096));
        for i in 0..num_runs {
            let base = 0x8C + i * 16;
            let bp = rd_u64(data, base)?;
            let pc = rd_u64(data, base + 8)?;
            if bp == 0 && pc == 0 {
                break;
            }
            runs.push(PhysicalRun { base_page: bp, page_count: pc });
        }
        // KDBG signature scan over the whole image (bounded by file size)
        let kdbg_offsets = crate::rawmem::find_all(data, b"KDBG");
        Ok(PageDump {
            major_version: major,
            minor_version: minor,
            directory_table_base: dtb,
            ps_loaded_module_list: plml,
            ps_active_process_head: paph,
            machine_image_type: machine,
            number_of_processors: ncpu,
            physical_runs: runs,
            kdbg_offsets,
            data: data.to_vec(),
        })
    }

    /// total physical pages described by the run map
    pub fn total_pages(&self) -> u64 {
        self.physical_runs.iter().map(|r| r.page_count).sum()
    }

    /// read `len` bytes of *physical* memory through the run map:
    /// dumps written by DumpIt-style tools concatenate the runs, so the file
    /// offset of run r's start = 0x1000·Σ(page_count of runs before r).
    pub fn read_physical(&self, phys_addr: u64, len: usize) -> Option<Vec<u8>> {
        let page = phys_addr / 0x1000;
        // PAGEDU64 files carry a 0x2000-byte header before the physical data
        const HEADER_SIZE: u64 = 0x2000;
        let mut file_off = HEADER_SIZE;
        for r in &self.physical_runs {
            let run_span = r.page_count * 0x1000;
            if page >= r.base_page && page < r.base_page + r.page_count {
                let inner = (phys_addr - r.base_page * 0x1000) as usize;
                let off = file_off as usize + inner;
                #[cfg(test)]
                eprintln!("[pd] hit run base={} off={:#x} len={} datalen={:#x}", r.base_page, off, len, self.data.len());
                return self.data.get(off..off + len).map(|b| b.to_vec());
            }
            file_off += run_span;
        }
        #[cfg(test)]
        if std::env::var("CTF_LLL_DEBUG").is_ok() {
            eprintln!("[pd] miss: phys={} runs={:?} file_off_so_far={}", phys_addr, self.physical_runs, file_off);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_pagedump() -> Vec<u8> {
        // dump data area: run1 (256 pages) + run2 (256 pages) after the header
        let mut d = vec![0u8; 0x2000 + 2 * 0x100000]; // header + 2 runs
        // header
        d[0..4].copy_from_slice(&0x4547_4150u32.to_le_bytes()); // "PAGE"
        d[4..8].copy_from_slice(&0x3436_5544u32.to_le_bytes()); // "DU64"
        d[8..12].copy_from_slice(&10u32.to_le_bytes()); // major
        d[12..16].copy_from_slice(&0u32.to_le_bytes()); // minor
        d[0x10..0x18].copy_from_slice(&0x1AB000u64.to_le_bytes()); // DTB
        d[0x20..0x28].copy_from_slice(&0xFFFFF800u64.to_le_bytes()); // PsLoadedModuleList
        d[0x28..0x30].copy_from_slice(&0xFFFFF700u64.to_le_bytes()); // PsActiveProcessHead
        d[0x30..0x34].copy_from_slice(&0x8664u32.to_le_bytes()); // x64
        d[0x34..0x38].copy_from_slice(&8u32.to_le_bytes()); // processors
        // physical runs at 0x88: 2 runs = pages [0..256), [300..556)
        d[0x88..0x8C].copy_from_slice(&2u32.to_le_bytes());
        d[0x8C..0x94].copy_from_slice(&0u64.to_le_bytes());
        d[0x94..0x9C].copy_from_slice(&256u64.to_le_bytes());
        d[0x9C..0xA4].copy_from_slice(&300u64.to_le_bytes());
        d[0xA4..0xAC].copy_from_slice(&256u64.to_le_bytes());
        // KDBG marker at 0x2000 (start of the data area)
        d[0x2000..0x2004].copy_from_slice(b"KDBG");
        // marker content inside run 2: physical addr = 300·0x1000 + 0x40
        // file offset of run 2 = 256 pages = 0x40000; dump data area starts at 0x2000
        let file_off = 0x2000 + 256 * 0x1000 + 0x40; // run2 file start + inner
        d[file_off..file_off + 6].copy_from_slice(b"KDBG2!");
        d
    }

    #[test]
    fn parses_header_runs_and_kdbg() {
        let data = build_pagedump();
        let pd = PageDump::parse(&data).expect("parse");
        assert_eq!(pd.directory_table_base, 0x1AB000);
        assert_eq!(pd.ps_loaded_module_list, 0xFFFFF800);
        assert_eq!(pd.machine_image_type, 0x8664);
        assert_eq!(pd.number_of_processors, 8);
        assert_eq!(pd.physical_runs.len(), 2);
        assert_eq!(pd.total_pages(), 512);
        assert!(pd.kdbg_offsets.contains(&0x2000));
    }

    #[test]
    fn physical_reader_follows_runs() {
        let data = build_pagedump();
        let pd = PageDump::parse(&data).expect("parse");
        // run 1: physical [0, 0x40000) → file [0x2000, 0x42000)
        let v1 = pd.read_physical(0x1000, 4).unwrap();
        assert_eq!(v1, vec![0, 0, 0, 0]);
        // run 2: physical [300·0x1000, +0x40000) → file [0x42000, …)
        let v2 = pd.read_physical(300 * 0x1000 + 0x40, 6).unwrap();
        assert_eq!(v2, b"KDBG2!");
        // hole between runs: physical 0x40000 (page 256) is unmapped
        assert!(pd.read_physical(256 * 0x1000, 4).is_none());
    }

    #[test]
    fn rejects_bad_signature() {
        let mut d = build_pagedump();
        d[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(PageDump::parse(&d).is_err());
        assert!(PageDump::parse(&[0u8; 10]).is_err());
    }
}
