//! Windows minidump (MDMP) parsing — user-mode process dumps.
//!
//! Parses the header + stream directory and the streams a CTF analyst needs:
//! ModuleList (image base + name), MemoryList / Memory64List (virtual→dump
//! mapping), Exception (faulting thread/address), SystemInfo, and MiscInfo
//! (ProcessId). Also provides a virtual-memory reader over the dump so carved
//! strings/scans can be address-annotated.
//!
//! Capability coverage: domain 7 (memory forensics — user dumps).
//!
//! Provenance: the minidump file format is publicly documented by Microsoft
//! and Mozilla (breakpad docs); independent implementation, no code copied.

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

pub const MINIDUMP_MAGIC: [u8; 4] = *b"MDMP";

/// stream types (MINIDUMP_STREAM_TYPE)
pub const STREAM_UNUSED: u32 = 0;
pub const STREAM_THREAD_LIST: u32 = 3;
pub const STREAM_MODULE_LIST: u32 = 4;
pub const STREAM_MEMORY_LIST: u32 = 5;
pub const STREAM_EXCEPTION: u32 = 6;
pub const STREAM_SYSTEM_INFO: u32 = 7;
pub const STREAM_MEMORY64_LIST: u32 = 9;
pub const STREAM_MISC_INFO: u32 = 15;
pub const STREAM_MEMORY_INFO_LIST: u32 = 16;

#[derive(Debug, Clone)]
pub struct StreamEntry {
    pub stream_type: u32,
    pub size: u32,
    pub rva: u32,
}

#[derive(Debug, Clone)]
pub struct Module {
    pub base_of_image: u64,
    pub size_of_image: u32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct MemoryRange {
    pub start: u64,
    pub size: u64,
    /// offset in the dump file
    pub file_rva: u64,
}

#[derive(Debug, Clone)]
pub struct ExceptionInfo {
    pub thread_id: u32,
    pub exception_code: u32,
    pub exception_address: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    pub processor_arch: u16,
    pub number_of_processors: u32,
    pub csd_version: String, // service pack string
}

#[derive(Debug, Clone)]
pub struct MiniDump {
    pub streams: Vec<StreamEntry>,
    pub modules: Vec<Module>,
    pub memory: Vec<MemoryRange>,
    pub exception: Option<ExceptionInfo>,
    pub system_info: Option<SystemInfo>,
    pub process_id: Option<u32>,
    pub data: Vec<u8>,
}

fn rd_u32(d: &[u8], p: usize) -> Result<u32> {
    d.get(p..p + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| invalid("minidump truncated (u32)"))
}

fn rd_u64(d: &[u8], p: usize) -> Result<u64> {
    d.get(p..p + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| invalid("minidump truncated (u64)"))
}

/// MINIDUMP_STRING: u32 byte-length + UTF-16LE buffer
fn rd_mstring(d: &[u8], rva: u32) -> String {
    let rva = rva as usize;
    if rva + 4 > d.len() {
        return String::new();
    }
    let len = u32::from_le_bytes(d[rva..rva + 4].try_into().unwrap()) as usize;
    let end = (rva + 4 + len).min(d.len());
    let units: Vec<u16> = d[rva + 4..end]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .collect();
    String::from_utf16_lossy(&units)
}

impl MiniDump {
    pub fn parse(data: &[u8]) -> Result<MiniDump> {
        if data.len() < 32 || data[0..4] != MINIDUMP_MAGIC {
            return Err(invalid("not a minidump (MDMP)"));
        }
        let num_streams = rd_u32(data, 8)?;
        let dir_rva = rd_u32(data, 12)? as usize;
        let mut streams = Vec::new();
        for i in 0..num_streams as usize {
            let base = dir_rva + i * 12;
            if base + 12 > data.len() {
                break;
            }
            streams.push(StreamEntry {
                stream_type: rd_u32(data, base)?,
                size: rd_u32(data, base + 4)?,
                rva: rd_u32(data, base + 8)?,
            });
        }
        let mut md = MiniDump {
            streams,
            modules: Vec::new(),
            memory: Vec::new(),
            exception: None,
            system_info: None,
            process_id: None,
            data: data.to_vec(),
        };
        let take = |streams: &[StreamEntry], t: u32| -> Option<(u32, u32)> {
            streams
                .iter()
                .find(|s| s.stream_type == t)
                .map(|s| (s.size, s.rva))
        };
        if let Some((_, rva)) = take(&md.streams, STREAM_MODULE_LIST) {
            md.parse_modules(rva as usize)?;
        }
        if let Some((_, rva)) = take(&md.streams, STREAM_MEMORY_LIST) {
            md.parse_memory_list(rva as usize)?;
        }
        if let Some((_, rva)) = take(&md.streams, STREAM_MEMORY64_LIST) {
            md.parse_memory64_list(rva as usize)?;
        }
        if let Some((_, rva)) = take(&md.streams, STREAM_EXCEPTION) {
            md.exception = md.parse_exception(rva as usize);
        }
        if let Some((_, rva)) = take(&md.streams, STREAM_SYSTEM_INFO) {
            md.system_info = md.parse_system_info(rva as usize);
        }
        if let Some((_, rva)) = take(&md.streams, STREAM_MISC_INFO) {
            // MINIDUMP_MISC_INFO: ProcessId at offset 4
            let base = rva as usize;
            if base + 8 <= data.len() {
                md.process_id = rd_u32(data, base + 4).ok();
            }
        }
        Ok(md)
    }

    fn parse_modules(&mut self, rva: usize) -> Result<()> {
        let count = rd_u32(&self.data, rva)? as usize;
        for i in 0..count {
            // MINIDUMP_MODULE is 108 bytes
            let base = rva + 4 + i * 108;
            if base + 108 > self.data.len() {
                break;
            }
            let base_of_image = rd_u64(&self.data, base)?;
            let size_of_image = rd_u32(&self.data, base + 8)?;
            // MINIDUMP_MODULE: BaseOfImage@0(8) SizeOfImage@8 CheckSum@12
            // TimeDateStamp@16 ModuleNameRva@20
            let name_rva = rd_u32(&self.data, base + 20)?;
            self.modules.push(Module {
                base_of_image,
                size_of_image,
                name: rd_mstring(&self.data, name_rva),
            });
        }
        Ok(())
    }

    fn parse_memory_list(&mut self, rva: usize) -> Result<()> {
        let count = rd_u32(&self.data, rva)? as usize;
        for i in 0..count {
            let base = rva + 4 + i * 16;
            if base + 16 > self.data.len() {
                break;
            }
            self.memory.push(MemoryRange {
                start: rd_u64(&self.data, base)?,
                size: rd_u32(&self.data, base + 8)? as u64,
                file_rva: rd_u32(&self.data, base + 12)? as u64,
            });
        }
        Ok(())
    }

    fn parse_memory64_list(&mut self, rva: usize) -> Result<()> {
        let count = rd_u64(&self.data, rva)? as usize;
        let base_rva = rd_u64(&self.data, rva + 8)?;
        let mut cursor = base_rva;
        for i in 0..count {
            let base = rva + 16 + i * 16;
            if base + 16 > self.data.len() {
                break;
            }
            let start = rd_u64(&self.data, base)?;
            let size = rd_u64(&self.data, base + 8)?;
            self.memory.push(MemoryRange { start, size, file_rva: cursor });
            cursor += size;
        }
        Ok(())
    }

    fn parse_exception(&self, rva: usize) -> Option<ExceptionInfo> {
        // MINIDUMP_EXCEPTION_STREAM: ThreadId u32, alignment u32,
        // ExceptionRecord (Code u32, Flags u32, Record u64, Address u64, ...)
        if rva + 32 > self.data.len() {
            return None;
        }
        let thread_id = rd_u32(&self.data, rva).ok()?;
        let code = rd_u32(&self.data, rva + 8).ok()?;
        let addr = rd_u64(&self.data, rva + 24).ok()?;
        Some(ExceptionInfo { thread_id, exception_code: code, exception_address: addr })
    }

    fn parse_system_info(&self, rva: usize) -> Option<SystemInfo> {
        // MINIDUMP_SYSTEM_INFO: ProcessorArchitecture u16, ..., NumberOfProcessors,
        // then Major/Minor/Build u32×3, PlatformId u32, CSDVersionRva u32
        if rva + 48 > self.data.len() {
            return None;
        }
        let arch = u16::from_le_bytes(self.data[rva..rva + 2].try_into().unwrap());
        let num_cpu = self.data[rva + 12] as u32;
        let csd_rva = rd_u32(&self.data, rva + 32 + 12).ok()?;
        Some(SystemInfo {
            processor_arch: arch,
            number_of_processors: num_cpu,
            csd_version: rd_mstring(&self.data, csd_rva),
        })
    }

    /// read `len` bytes of virtual address space from the dump (None if not mapped)
    pub fn read_virtual(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        for m in &self.memory {
            if addr >= m.start && addr + len as u64 <= m.start + m.size {
                let off = m.file_rva as usize + (addr - m.start) as usize;
                return self.data.get(off..off + len).map(|b| b.to_vec());
            }
        }
        None
    }

    /// iterate all mapped memory as (start, bytes)
    pub fn memory_slices(&self) -> Vec<(u64, &[u8])> {
        self.memory
            .iter()
            .filter_map(|m| {
                let off = m.file_rva as usize;
                let end = off.checked_add(m.size as usize)?;
                self.data.get(off..end).map(|b| (m.start, b))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// build a minimal valid minidump: module list + memory64 list + exception
    /// + misc info, with a patched stream directory.
    fn build_minidump() -> Vec<u8> {
        let mut d = Vec::new();
        // header
        d.extend_from_slice(b"MDMP");
        d.extend_from_slice(&4280u32.to_le_bytes()); // version
        let dir_rva_pos = d.len();
        d.extend_from_slice(&0u32.to_le_bytes()); // NumberOfStreams (patched)
        d.extend_from_slice(&0u32.to_le_bytes()); // StreamDirectoryRva (patched)
        d.extend_from_slice(&0u32.to_le_bytes()); // checksum
        d.extend_from_slice(&1700000000u32.to_le_bytes()); // timestamp
        d.extend_from_slice(&0u64.to_le_bytes()); // flags
        // module list stream
        let module_rva = d.len() as u32;
        d.extend_from_slice(&1u32.to_le_bytes()); // 1 module
        let name_rva = d.len() as u32 + 108; // name sits after the record
        d.extend_from_slice(&0x00400000u64.to_le_bytes()); // base @0
        d.extend_from_slice(&0x12000u32.to_le_bytes()); // size @8
        d.extend_from_slice(&0u32.to_le_bytes()); // checksum @12
        d.extend_from_slice(&0u32.to_le_bytes()); // timestamp @16
        d.extend_from_slice(&name_rva.to_le_bytes()); // name_rva @20
        d.extend_from_slice(&vec![0u8; 108 - 24]); // rest of MINIDUMP_MODULE
        let name = r"C:\Users\admin\tool.exe";
        d.extend_from_slice(&(name.len() as u32 * 2).to_le_bytes());
        for u in name.encode_utf16() {
            d.extend_from_slice(&u.to_le_bytes());
        }
        // memory64 list stream
        let mem_rva = d.len() as u32;
        let mem_start: u64 = 0x00120000;
        let mem_data: Vec<u8> = (0..64u8).collect();
        d.extend_from_slice(&1u64.to_le_bytes()); // 1 range
        let base_rva_pos = d.len();
        d.extend_from_slice(&0u64.to_le_bytes()); // BaseRVA (patched)
        d.extend_from_slice(&mem_start.to_le_bytes());
        d.extend_from_slice(&(mem_data.len() as u64).to_le_bytes());
        let base_rva = d.len() as u64;
        d.extend_from_slice(&mem_data);
        // exception stream
        let exc_rva = d.len() as u32;
        d.extend_from_slice(&4242u32.to_le_bytes()); // thread id
        d.extend_from_slice(&0u32.to_le_bytes()); // alignment
        d.extend_from_slice(&0xC0000005u32.to_le_bytes()); // access violation
        d.extend_from_slice(&0u32.to_le_bytes()); // flags
        d.extend_from_slice(&0u64.to_le_bytes()); // record
        d.extend_from_slice(&0x00012345u64.to_le_bytes()); // address
        d.extend_from_slice(&vec![0u8; 16]); // params area (parser reads fixed fields)
        // misc info stream (ProcessId at +4)
        let misc_rva = d.len() as u32;
        d.extend_from_slice(&8u32.to_le_bytes()); // size
        d.extend_from_slice(&1337u32.to_le_bytes()); // ProcessId
        // directory: 4 streams
        let dir_rva = d.len() as u32;
        for (t, rva) in [
            (STREAM_MODULE_LIST, module_rva),
            (STREAM_MEMORY64_LIST, mem_rva),
            (STREAM_EXCEPTION, exc_rva),
            (STREAM_MISC_INFO, misc_rva),
        ] {
            d.extend_from_slice(&t.to_le_bytes());
            d.extend_from_slice(&0u32.to_le_bytes()); // size unused by parser
            d.extend_from_slice(&rva.to_le_bytes());
        }
        // patch header + memory64 BaseRVA
        d[dir_rva_pos..dir_rva_pos + 4].copy_from_slice(&4u32.to_le_bytes());
        d[dir_rva_pos + 4..dir_rva_pos + 8].copy_from_slice(&dir_rva.to_le_bytes());
        d[base_rva_pos..base_rva_pos + 8].copy_from_slice(&base_rva.to_le_bytes());
        d
    }

    #[test]
    fn parses_modules_memory_exception() {
        let data = build_minidump();
        let md = MiniDump::parse(&data).expect("parse");
        assert_eq!(md.modules.len(), 1);
        assert_eq!(md.modules[0].name, "C:\\Users\\admin\\tool.exe");
        assert_eq!(md.modules[0].base_of_image, 0x00400000);
        assert_eq!(md.memory.len(), 1);
        assert_eq!(md.memory[0].start, 0x00120000);
        assert_eq!(
            md.read_virtual(0x00120010, 4).unwrap(),
            vec![0x10, 0x11, 0x12, 0x13]
        );
        assert!(md.read_virtual(0x99999900, 4).is_none());
        let exc = md.exception.clone().unwrap();
        assert_eq!(exc.thread_id, 4242);
        assert_eq!(exc.exception_code, 0xC0000005);
        assert_eq!(exc.exception_address, 0x00012345);
        assert_eq!(md.process_id, Some(1337));
        let slices = md.memory_slices();
        assert_eq!(slices[0].0, 0x00120000);
        assert_eq!(slices[0].1.len(), 64);
    }

    #[test]
    fn rejects_non_minidump() {
        assert!(MiniDump::parse(b"not a dump").is_err());
        assert!(MiniDump::parse(&[]).is_err());
    }
}
