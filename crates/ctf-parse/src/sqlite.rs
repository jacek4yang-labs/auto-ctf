//! Minimal SQLite database reader (read-only) — browser history forensics.
//!
//! CTF memory/disk forensics keeps handing out `places.sqlite` (Firefox),
//! History.db (Chrome/Safari) and friends. This module implements just enough
//! of the file format to walk a table b-tree and decode records:
//! header check, page-size handling, table interior (0x05) / leaf (0x0d)
//! pages, varints, record serial types, and overflow-page chains.
//!
//! Capability coverage: domain 7 (memory/disk forensics).
//!
//! Provenance: the SQLite file format is public documentation
//! (sqlite.org/fileformat2.html); independent implementation, no code copied.

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Row {
    pub rowid: i64,
    pub values: Vec<SqlValue>,
}

pub struct SqliteDb<'a> {
    data: &'a [u8],
    page_size: usize,
    /// usable pages (file header page count, 0 = derive from file size)
    pages: usize,
}

fn rd_u16(d: &[u8], p: usize) -> usize {
    u16::from_be_bytes(d[p..p + 2].try_into().unwrap()) as usize
}

fn rd_u32(d: &[u8], p: usize) -> Result<u32> {
    d.get(p..p + 4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
        .ok_or_else(|| invalid("sqlite truncated (u32)"))
}

/// big-endian varint (1-9 bytes; 9th byte uses all 8 bits)
fn read_varint(d: &[u8], pos: usize) -> Result<(i64, usize)> {
    let mut v: u64 = 0;
    let mut i = 0usize;
    while i < 8 {
        let b = *d.get(pos + i).ok_or_else(|| invalid("varint truncated"))?;
        v = (v << 7) | (b & 0x7f) as u64;
        i += 1;
        if b & 0x80 == 0 {
            return Ok((v as i64, i));
        }
    }
    let b = *d.get(pos + 8).ok_or_else(|| invalid("varint truncated"))?;
    v = (v << 8) | b as u64;
    Ok((v as i64, 9))
}

impl<'a> SqliteDb<'a> {
    pub fn open(data: &'a [u8]) -> Result<SqliteDb<'a>> {
        if data.len() < 100 || &data[0..16] != b"SQLite format 3\0" {
            return Err(invalid("not a SQLite 3 database"));
        }
        let page_size = rd_u16(data, 16);
        let page_size = if page_size == 1 { 65536 } else { page_size };
        if page_size < 512 || (page_size & (page_size - 1)) != 0 {
            return Err(invalid("invalid page size"));
        }
        let pages = rd_u32(data, 28)? as usize;
        let pages = if pages == 0 { data.len() / page_size } else { pages };
        Ok(SqliteDb { data, page_size, pages })
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    fn page(&self, no: usize) -> Result<&'a [u8]> {
        // pages are 1-based; page 1's b-tree header starts at offset 100
        if no == 0 || no > self.pages {
            return Err(invalid("page out of range"));
        }
        self.data
            .get((no - 1) * self.page_size..no * self.page_size)
            .ok_or_else(|| invalid("page beyond file"))
    }

    /// sqlite_master rows: (type, name, tbl_name, rootpage, sql)
    pub fn tables(&self) -> Result<Vec<(String, usize)>> {
        let mut out = Vec::new();
        for row in self.walk_table(1)? {
            if row.values.len() >= 4 {
                let t = match &row.values[0] {
                    SqlValue::Text(s) => s.clone(),
                    _ => String::new(),
                };
                if t == "table" {
                    let name = match &row.values[1] {
                        SqlValue::Text(s) => s.clone(),
                        _ => String::new(),
                    };
                    let root = match &row.values[3] {
                        SqlValue::Int(i) => *i as usize,
                        _ => 0,
                    };
                    out.push((name, root));
                }
            }
        }
        Ok(out)
    }

    /// walk a table b-tree from its root page, decoding every row
    pub fn walk_table(&self, root: usize) -> Result<Vec<Row>> {
        let mut rows = Vec::new();
        self.walk_page(root, &mut rows, 0)?;
        Ok(rows)
    }

    fn walk_page(&self, no: usize, rows: &mut Vec<Row>, depth: u32) -> Result<()> {
        if depth > 32 {
            return Err(invalid("b-tree too deep (cycle?)"));
        }
        let page = self.page(no)?;
        let hdr = if no == 1 { 100 } else { 0 };
        let ptype = page[hdr];
        let cell_count = rd_u16(page, hdr + 3) as usize;
        match ptype {
            0x05 | 0x02 => {
                // interior: right-most pointer at hdr+8, cells are (u32 child, varint key)
                let right = rd_u32(page, hdr + 8)? as usize;
                let ptr_array = hdr + 12;
                for i in 0..cell_count {
                    let cell_off = rd_u16(page, ptr_array + i * 2);
                    let child = rd_u32(page, cell_off)? as usize;
                    self.walk_page(child, rows, depth + 1)?;
                }
                self.walk_page(right, rows, depth + 1)?;
            }
            0x0d => {
                // table leaf
                let ptr_array = hdr + 8;
                for i in 0..cell_count {
                    let cell_off = rd_u16(page, ptr_array + i * 2) as usize;
                    let (rowid, values) = self.parse_leaf_cell(no, cell_off)?;
                    rows.push(Row { rowid, values });
                }
            }
            _ => return Err(invalid("unsupported b-tree page type")),
        }
        Ok(())
    }

    /// leaf table cell: varint payload-len, varint rowid, payload (+overflow)
    fn parse_leaf_cell(&self, page_no: usize, cell_off: usize) -> Result<(i64, Vec<SqlValue>)> {
        let page = self.page(page_no)?;
        let (payload_len, n1) = read_varint(page, cell_off)?;
        let (rowid, n2) = read_varint(page, cell_off + n1)?;
        let payload_start = cell_off + n1 + n2;
        let usable = self.page_size; // reserved space assumed 0 for our scope
        let max_local = usable - 35;
        let payload = if payload_len as usize <= max_local {
            page.get(payload_start..payload_start + payload_len as usize)
                .ok_or_else(|| invalid("cell payload beyond page"))?
                .to_vec()
        } else {
            // overflow chain: local prefix + 4-byte next-page pointer
            let mut local = max_local - ((payload_len as usize - max_local) % (usable - 4));
            if local > payload_len as usize {
                local = max_local;
            }
            let mut buf = page
                .get(payload_start..payload_start + local)
                .ok_or_else(|| invalid("local payload beyond page"))?
                .to_vec();
            let mut next = rd_u32(page, payload_start + local)?;
            let mut hops = 0;
            while next != 0 && buf.len() < payload_len as usize {
                hops += 1;
                if hops > self.pages {
                    return Err(invalid("overflow chain cycle"));
                }
                let op = self.page(next as usize)?;
                let n = rd_u32(op, 0)? as usize;
                let take = n.min((payload_len as usize - buf.len())).min(usable - 4);
                buf.extend_from_slice(&op[4..4 + take]);
                next = rd_u32(op, 4)?;
            }
            buf
        };
        Ok((rowid, self.decode_record(&payload)?))
    }

    /// record format: varint header-len, serial-type varints, values
    fn decode_record(&self, payload: &[u8]) -> Result<Vec<SqlValue>> {
        let (hdr_len, _) = read_varint(payload, 0)?;
        let hdr_len = hdr_len as usize;
        let mut types = Vec::new();
        let mut p = 1usize;
        while p < hdr_len {
            let (t, n) = read_varint(payload, p)?;
            types.push(t);
            p += n;
        }
        let mut body = hdr_len;
        let mut out = Vec::with_capacity(types.len());
        for t in types {
            let (len, val) = match t {
                0 => (0usize, SqlValue::Null),
                1..=6 => {
                    let n = [0usize, 1, 2, 3, 4, 6, 8][t as usize];
                    let mut bytes = [0u8; 8];
                    for (i, b) in payload.get(body..body + n).unwrap_or(&[]).iter().enumerate() {
                        bytes[8 - n + i] = *b;
                    }
                    let v = i64::from_be_bytes(bytes);
                    (n, SqlValue::Int(v))
                }
                7 => {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(payload.get(body..body + 8).unwrap_or(&[0; 8]));
                    (8usize, SqlValue::Real(f64::from_be_bytes(bytes)))
                }
                8 => (0usize, SqlValue::Int(0)),
                9 => (0usize, SqlValue::Int(1)),
                10 | 11 => (0usize, SqlValue::Null), // reserved
                n if n % 2 == 1 => {
                    let len = ((n - 13) / 2) as usize;
                    let s = payload
                        .get(body..body + len)
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                        .unwrap_or_default();
                    (len, SqlValue::Text(s))
                }
                n => {
                    let len = ((n - 12) / 2) as usize;
                    let b = payload
                        .get(body..body + len)
                        .unwrap_or(&[])
                        .to_vec();
                    (len, SqlValue::Blob(b))
                }
            };
            body += len;
            out.push(val);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// hand-build a minimal 2-table SQLite database:
    /// page1 = sqlite_master leaf, page2 = data table leaf with 3 rows
    fn build_db() -> Vec<u8> {
        let ps = 512usize;
        let mut d = vec![0u8; ps * 2];
        d[0..16].copy_from_slice(b"SQLite format 3\0");
        d[16..18].copy_from_slice(&(ps as u16).to_be_bytes());
        d[28..32].copy_from_slice(&2u32.to_be_bytes()); // 2 pages

        // ---- page 2: table leaf with rows (rowid, url) ----
        let p2 = &mut d[ps..ps * 2];
        p2[0] = 0x0d;
        p2[3..5].copy_from_slice(&2u16.to_be_bytes()); // 2 cells
        let cell_ptr_area = ps - 3 * 2;
        let mut cells: Vec<Vec<u8>> = Vec::new();
        for (rid, url) in [(1i64, "https://a.example/1"), (2, "https://b.example/very/long/url")]
            {
            // record: hdr [hdr_len, type_text(20), int] body [..]
            let mut rec_body: Vec<u8> = Vec::new();
            rec_body.push(20); // text len for "table"?? — not used; real hdr below
            rec_body.clear();
            // serial types: text(url), int(rowid dup) — keep 2 columns
            // 所有长度 < 128 → varint 都是单字节
            let url_b = url.as_bytes();
            let st_text = (url_b.len() * 2 + 13) as u8;
            let mut body: Vec<u8> = url_b.to_vec();
            body.push(0x42);
            let hdr_len = 2usize + 1; // 2 serial types + 1 byte size
            let hdr: Vec<u8> = vec![hdr_len as u8, st_text, 1];
            let hdr_len = hdr.len() as u64;
            let mut cell: Vec<u8> = ((body.len() as u64 + hdr_len)).to_varint();
            cell.extend((rid as u64).to_varint());
            cell.extend(hdr);
            cell.extend(body);
            cells.push(cell);
        }
        // cells packed from the page end, pointers in rowid order
        let mut cell_offsets = vec![0u16; cells.len()];
        let mut cur = ps;
        for (i, c) in cells.iter().enumerate().rev() {
            cur -= c.len();
            cell_offsets[i] = cur as u16;
            p2[cur..cur + c.len()].copy_from_slice(c);
        }
        for (i, o) in cell_offsets.iter().enumerate() {
            p2[8 + i * 2..8 + i * 2 + 2].copy_from_slice(&o.to_be_bytes());
        }
        let _ = cell_ptr_area;

        // ---- page 1: sqlite_master leaf with one row (table t @ root 2) ----
        let p1 = &mut d[0..ps];
        p1[100] = 0x0d;
        p1[103..105].copy_from_slice(&1u16.to_be_bytes()); // cell count @hdr+3
        // record: text "table", text "urls", text "urls", int 2, text sql
        let mut hdr: Vec<u8> = Vec::new();
        let mut body: Vec<u8> = Vec::new();
        for s in ["table", "urls", "urls"] {
            hdr.push(((s.len() * 2 + 13) as u8));
            body.extend(s.as_bytes());
        }
        hdr.push(1); // int rootpage serial
        body.push(2);
        let sql = "CREATE TABLE urls (id INTEGER, url TEXT)";
        hdr.push(((sql.len() * 2 + 13) as u8));
        body.extend(sql.as_bytes());
        let mut hdr2 = vec![(hdr.len() + 1) as u8];
        hdr2.extend(hdr);
        let hdr = hdr2;
        let mut cell: Vec<u8> = ((body.len() + hdr.len()) as u64).to_varint();
        cell.extend(1i64.to_varint());
        cell.extend(hdr);
        cell.extend(body);
        let off = ps - cell.len();
        p1[off..off + cell.len()].copy_from_slice(&cell);
        p1[108..110].copy_from_slice(&(off as u16).to_be_bytes()); // cell 0 ptr @ hdr+8=108
        d
    }

    trait VarintExt {
        fn to_varint(&self) -> Vec<u8>;
    }
    impl VarintExt for u64 {
        fn to_varint(&self) -> Vec<u8> {
            let v = *self;
            if v < 0x80 {
                return vec![v as u8];
            }
            let mut out = Vec::new();
            let mut v = v;
            // standard sqlite varint encoding (big-endian 7-bit groups)
            let mut tmp = vec![v as u8]; // 9th byte holds low 8 bits
            v >>= 8;
            while v > 0 {
                tmp.push((v & 0x7f) as u8 | 0x80);
                v >>= 7;
            }
            out = tmp;
            out
        }
    }
    impl VarintExt for i64 {
        fn to_varint(&self) -> Vec<u8> {
            (*self as u64).to_varint()
        }
    }

    #[test]
    fn reads_tables_and_rows() {
        let data = build_db();
        let db = SqliteDb::open(&data).expect("open");
        assert_eq!(db.page_size(), 512);
        let tables = db.tables().expect("tables");
        assert!(tables.iter().any(|(n, r)| n == "urls" && *r == 2), "tables = {:?}", tables);
        let rows = db.walk_table(2).expect("rows");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].rowid, 1);
        match &rows[0].values[0] {
            SqlValue::Text(s) => assert_eq!(s, "https://a.example/1"),
            o => panic!("unexpected value {:?}", o),
        }
        match &rows[1].values[0] {
            SqlValue::Text(s) => assert!(s.starts_with("https://b.example")),
            o => panic!("unexpected value {:?}", o),
        }
    }

    #[test]
    fn rejects_non_sqlite() {
        assert!(SqliteDb::open(b"not a database at all...........").is_err());
    }
}
