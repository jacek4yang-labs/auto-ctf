//! ctf-forge — unified CLI over the ctf-forge crate set.
//!
//! Subcommands mirror the WIDE MCP tool enum so CLI and MCP stay 1:1:
//! codec, crypto_rsa, prng, filescan, sidecar_run, flag_extract.
//! (parse / net_session are P1 and reported as unimplemented.)

use std::path::PathBuf;
use std::process::exit;

use clap::{Parser, Subcommand, ValueEnum};
use num_bigint::{BigInt, BigUint};
use num_traits::Num;
use serde_json::{json, Value};

mod ctf2client;
mod solve;
use ctf2client::Ctf2Cmd;

use ctf_codec::classic;
use ctf_codec::xcode;
use ctf_crypto::rsa::{auto_attack, RsaParams};
use ctf_crypto::{lcg, mt19937};

#[derive(Parser)]
#[command(name = "ctf-forge", version, about = "CTF solver toolkit (capability-organized)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
#[command(rename_all = "snake")]
enum Cmd {
    /// codec(op=hex|unhex|b64|unb64|b32|unb32|rot|xor|rev|swap|auto|entropy)
    Codec {
        #[arg(long)]
        op: CodecOp,
        #[arg(long)]
        infile: Option<PathBuf>,
        #[arg(long)]
        data: Option<String>,
        #[arg(long, default_value_t = 0)]
        shift: i32,
        #[arg(long)]
        key: Option<String>,
    },
    /// crypto_rsa(attack=auto|decrypt|wiener|fermat|low_e|common_modulus|hastad|pollard_rho|p1|dp_dq|rabin|factor_yafu)
    CryptoRsa {
        #[arg(long, default_value = "auto")]
        attack: RsaAttack,
        #[arg(long)]
        params: PathBuf,
    },
    /// lattice — LLL reduction + Coppersmith small_roots (pure Rust, exact)
    Lattice {
        #[arg(long, default_value = "small_roots")]
        op: LatticeOp,
        #[arg(long)]
        params: PathBuf,
    },
    /// forensics — memory/disk/traffic parsing (minidump, pagedump, mft, sqlite, pcap)
    Forensics {
        #[arg(long)]
        op: ForensicsOp,
        #[arg(long)]
        file: PathBuf,
        /// root page (sqlite walk_table)
        #[arg(long, default_value_t = 1)]
        root: usize,
    },
    /// prng(kind=lcg|mt19937)
    Prng {
        #[arg(long)]
        kind: PrngKind,
        #[arg(long)]
        params: PathBuf,
    },
    /// filescan(op=magic|strings|entropy|carve)
    Filescan {
        #[arg(long)]
        op: FilescanOp,
        #[arg(long)]
        infile: PathBuf,
        #[arg(long, default_value = "PKT1")]
        magic: String,
        #[arg(long, default_value = "big")]
        endian: String,
        #[arg(long, default_value_t = 4096)]
        max_payload: usize,
        #[arg(long, default_value_t = 4)]
        min_len: usize,
    },
    /// sidecar_run(engine=yafu)
    SidecarRun {
        #[arg(long)]
        engine: SidecarEngine,
        #[arg(long)]
        n: String,
        #[arg(long, default_value_t = 300)]
        timeout: u64,
    },
    /// solve — run the decision tree on one challenge directory (files/ inside)
    Solve {
        #[arg(long)]
        dir: PathBuf,
    },
    /// bulk — sweep a ground tree: <root>/<chapter>/<challenge>/files/
    Bulk {
        #[arg(long)]
        root: PathBuf,
        #[arg(long, default_value_t = 1000000)]
        limit: usize,
        #[arg(long, default_value_t = false)]
        rescan: bool,
        /// skip the yafu sidecar inside auto (fast sweep)
        #[arg(long, default_value_t = false)]
        fast: bool,
    },
    /// ctf2 — native platform I/O (Open API read surface; PAT via $CTF2_TOKEN or api-key.txt)
    Ctf2 {
        #[command(subcommand)]
        cmd: Ctf2Cmd,
    },
    /// flag_extract — hand-rolled flag{...} scanner over a file or text
    FlagExtract {
        #[arg(long)]
        infile: Option<PathBuf>,
        #[arg(long)]
        data: Option<String>,
        #[arg(long, default_value = "flag,FLAG,ctf,CTF,dasctf,DASCTF")]
        prefixes: String,
    },
}

#[derive(ValueEnum, Clone)]
#[value(rename_all = "snake")]
enum ForensicsOp {
    /// minidump (MDMP): modules / memory / exception
    Minidump,
    /// kernel dump (PAGEDU64): header + KDBG + physical runs
    Pagedump,
    /// NTFS $MFT: all FILE records (names/times/resident data)
    Mft,
    /// sqlite: list tables and read --root table
    Sqlite,
    /// raw memory image: ASCII/UTF16 string carving + PNG/ZIP carving
    Memscan,
    /// pcap/pcapng: packet count + USB HID keyboard decode + HTTP/DNS
    Pcap,
}

#[derive(ValueEnum, Clone)]
#[value(rename_all = "snake")]
enum LatticeOp {
    SmallRoots,
    Lll,
}

#[derive(ValueEnum, Clone)]
#[value(rename_all = "snake")]
enum CodecOp {
    Hex,
    Unhex,
    B64,
    Unb64,
    B32,
    Unb32,
    Rot,
    Xor,
    Rev,
    Swap,
    Auto,
    Entropy,
}

#[derive(ValueEnum, Clone)]
#[value(rename_all = "snake")]
enum RsaAttack {
    Auto,
    Decrypt,
    Wiener,
    Fermat,
    LowE,
    CommonModulus,
    Hastad,
    PollardRho,
    P1,
    DpDq,
    Rabin,
    SchmidtSamoa,
    FactorYafu,
}

#[derive(ValueEnum, Clone)]
#[value(rename_all = "snake")]
enum PrngKind {
    Lcg,
    Mt19937,
}

#[derive(ValueEnum, Clone)]
#[value(rename_all = "snake")]
enum FilescanOp {
    Magic,
    Strings,
    Entropy,
    Carve,
}

#[derive(ValueEnum, Clone)]
#[value(rename_all = "snake")]
enum SidecarEngine {
    Yafu,
}

fn read_input(infile: &Option<PathBuf>, data: &Option<String>) -> Vec<u8> {
    if let Some(p) = infile {
        return std::fs::read(p).unwrap_or_default();
    }
    data.clone().unwrap_or_default().into_bytes()
}

fn parse_big(s: &str) -> BigUint {
    let t = s.trim();
    let bad = |what: &str| -> ! { out_err(format!("bad {what} param: {t:?}")) };
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        BigUint::from_str_radix(h, 16).unwrap_or_else(|_| bad("hex"))
    } else {
        BigUint::from_str_radix(t, 10).unwrap_or_else(|_| bad("decimal"))
    }
}

fn parse_params(path: &PathBuf) -> RsaParams {
    let text = std::fs::read_to_string(path).expect("params file");
    let mut p = RsaParams::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "n" => p.n = Some(parse_big(v)),
            "e" => p.e = Some(parse_big(v)),
            "c" => p.c = Some(parse_big(v)),
            "d" => p.d = Some(parse_big(v)),
            "p" => p.p = Some(parse_big(v)),
            "q" => p.q = Some(parse_big(v)),
            "dp" => p.dp = Some(parse_big(v)),
            "dq" => p.dq = Some(parse_big(v)),
            "c1" => p.c1 = Some(parse_big(v)),
            "c2" => p.c2 = Some(parse_big(v)),
            "e1" => p.e1 = Some(parse_big(v)),
            "e2" => p.e2 = Some(parse_big(v)),
            "cs" => p.cs = Some(v.split(',').map(|x| parse_big(x.trim())).collect()),
            "ns" => p.ns = Some(v.split(',').map(|x| parse_big(x.trim())).collect()),
            _ => {}
        }
    }
    p
}

fn out_json(v: Value) -> ! {
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
    exit(0)
}

fn out_err(e: String) -> ! {
    eprintln!("error: {e}");
    exit(1)
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Codec { op, infile, data, shift, key } => codec_cmd(op, infile, data, shift, key),
        Cmd::CryptoRsa { attack, params } => rsa_cmd(attack, params),
        Cmd::Lattice { op, params } => lattice_cmd(op, params),
        Cmd::Forensics { op, file, root } => forensics_cmd(op, file, root),
        Cmd::Prng { kind, params } => prng_cmd(kind, params),
        Cmd::Filescan { op, infile, magic, endian, max_payload, min_len } => {
            filescan_cmd(op, infile, magic, endian, max_payload, min_len)
        }
        Cmd::SidecarRun { engine, n, timeout } => sidecar_cmd(engine, n, timeout),
        Cmd::FlagExtract { infile, data, prefixes } => flag_cmd(infile, data, prefixes),
        Cmd::Solve { dir } => match solve::solve_dir(&dir) {
            Ok(v) => out_json(v),
            Err(e) => out_err(e),
        },
        Cmd::Bulk { root, limit, rescan, fast } => out_json(solve::bulk(&root, limit, rescan, fast)),
        Cmd::Ctf2 { cmd } => ctf2client::run(cmd),
    }
}

fn codec_cmd(op: CodecOp, infile: Option<PathBuf>, data: Option<String>, shift: i32, key: Option<String>) {
    let input = read_input(&infile, &data);
    match op {
        CodecOp::Hex => out_json(json!({"result": xcode::hex_encode(&input, false)})),
        CodecOp::Unhex => match xcode::hex_decode(&String::from_utf8_lossy(&input)) {
            Ok(b) => out_json(json!({"result": String::from_utf8_lossy(&b)})),
            Err(e) => out_err(e.to_string()),
        },
        CodecOp::B64 => out_json(json!({"result": xcode::base64_encode(&input, false)})),
        CodecOp::Unb64 => match xcode::base64_decode(&String::from_utf8_lossy(&input)) {
            Ok(b) => out_json(json!({"result": String::from_utf8_lossy(&b)})),
            Err(e) => out_err(e.to_string()),
        },
        CodecOp::B32 => out_json(json!({"result": xcode::base32_encode(&input)})),
        CodecOp::Unb32 => match xcode::base32_decode(&String::from_utf8_lossy(&input)) {
            Ok(b) => out_json(json!({"result": String::from_utf8_lossy(&b)})),
            Err(e) => out_err(e.to_string()),
        },
        CodecOp::Rot => out_json(json!({"result": String::from_utf8_lossy(&classic::rot_n(&input, shift))})),
        CodecOp::Xor => {
            let k = key.unwrap_or_else(|| "0".into());
            let kb = if let Some(h) = k.strip_prefix("0x") {
                xcode::hex_decode(h).unwrap_or_else(|_| k.clone().into_bytes())
            } else {
                k.into_bytes()
            };
            match xcode::xor_repeating(&input, &kb) {
                Ok(b) => out_json(json!({
                    "result_hex": xcode::hex_encode(&b, false),
                    "result_text": String::from_utf8_lossy(&b),
                })),
                Err(e) => out_err(e.to_string()),
            }
        }
        CodecOp::Rev => out_json(json!({"result": String::from_utf8_lossy(&classic::reverse_bytes(&input))})),
        CodecOp::Swap => out_json(json!({"result": String::from_utf8_lossy(&classic::swap_adjacent(&input))})),
        CodecOp::Auto => {
            let r = ctf_codec::auto_decode(&input, 16);
            out_json(json!({
                "layers": r.layers.iter().map(|l| l.to_string()).collect::<Vec<_>>(),
                "result_hex": xcode::hex_encode(&r.data, false),
                "result_text": String::from_utf8_lossy(&r.data),
            }))
        }
        CodecOp::Entropy => out_json(json!({"entropy_bits": ctf_codec::entropy::shannon_entropy(&input)})),
    }
}

fn rsa_cmd(attack: RsaAttack, params: PathBuf) {
    let p = parse_params(&params);
    let outcome: Result<Value, String> = (|| -> Result<Value, String> {
        let e = p.e.clone().unwrap_or_else(|| BigUint::from(65537u32));
        let n = p.n.clone().unwrap_or_else(|| BigUint::from(0u32));
        match attack {
            RsaAttack::Auto => auto_attack(&p).map(m_json).map_err(|e| e.to_string()),
            RsaAttack::Decrypt => match (&p.c, &p.d, &p.n) {
                (Some(c), Some(d), Some(n)) => ctf_crypto::rsa::decrypt(c, d, n).map(m_json).map_err(|e| e.to_string()),
                _ => Err("decrypt needs c, d, n".into()),
            },
            RsaAttack::Wiener => ctf_crypto::rsa::wiener(&e, &n)
                .map(m_json)
                .ok_or_else(|| "wiener found nothing".to_string()),
            RsaAttack::Fermat => ctf_crypto::rsa::fermat(&n, 1_000_000)
                .map(|(a, b)| factors_json(&[a, b]))
                .ok_or_else(|| "fermat found nothing".to_string()),
            RsaAttack::LowE => match (&p.c, &e, &n) {
                (Some(c), e, n) => ctf_crypto::rsa::low_e(c, e, n, 1_000_000)
                    .map(m_json)
                    .ok_or_else(|| "low_e found nothing".to_string()),
                _ => Err("low_e needs c, e, n".into()),
            },
            RsaAttack::CommonModulus => match (&p.c1, &p.c2, &p.e1, &p.e2, &p.n) {
                (Some(c1), Some(c2), Some(e1), Some(e2), Some(n)) => {
                    ctf_crypto::rsa::common_modulus(c1, c2, e1, e2, n).map(m_json).map_err(|e| e.to_string())
                }
                _ => Err("common_modulus needs c1,c2,e1,e2,n".into()),
            },
            RsaAttack::Hastad => match (&p.cs, &p.ns, &e) {
                (Some(cs), Some(ns), e) => {
                    ctf_crypto::rsa::hastad_broadcast(cs, ns, e).map(m_json).map_err(|e| e.to_string())
                }
                _ => Err("hastad needs cs,ns,e".into()),
            },
            RsaAttack::PollardRho => ctf_crypto::rsa::factor_rho(&n, 16)
                .map(|(a, b)| factors_json(&[a, b]))
                .ok_or_else(|| "rho found nothing".to_string()),
            RsaAttack::P1 => ctf_crypto::rsa::factor_p1(&n, 100_000)
                .map(|(a, b)| factors_json(&[a, b]))
                .ok_or_else(|| "p-1 found nothing".to_string()),
            RsaAttack::DpDq => match (&p.p, &p.q, &p.dp, &p.dq, &p.c) {
                (Some(pp), Some(qq), Some(dp), Some(dq), Some(c)) => {
                    ctf_crypto::rsa::dpdq(pp, qq, dp, dq, c).map(m_json).map_err(|e| e.to_string())
                }
                _ => Err("dp_dq needs p,q,dp,dq,c".into()),
            },
            RsaAttack::Rabin => match (&p.c, &p.p, &p.q) {
                (Some(c), Some(pp), Some(qq)) => ctf_crypto::rsa::rabin(c, pp, qq)
                    .map(|roots| json!({"roots": roots.iter().map(|x| x.to_string()).collect::<Vec<_>>()}))
                    .map_err(|e| e.to_string()),
                _ => Err("rabin needs c,p,q".into()),
            },
            RsaAttack::SchmidtSamoa => match (&p.c, &p.p, &p.q) {
                (Some(c), Some(pp), Some(qq)) => ctf_crypto::rsa::schmidt_samoa(c, pp, qq)
                    .map(m_json)
                    .map_err(|e| e.to_string()),
                _ => Err("schmidt_samoa needs c,p,q".into()),
            },
            RsaAttack::FactorYafu => ctf_crypto::rsa::factor_yafu(&n, 300)
                .map(|f| factors_json(&f))
                .map_err(|e| e.to_string()),
        }
    })();
    match outcome {
        Ok(v) => out_json(v),
        Err(e) => out_err(e),
    }
}

fn lattice_cmd(op: LatticeOp, params: PathBuf) {
    let text = match std::fs::read_to_string(&params) {
        Ok(t) => t,
        Err(e) => {
            out_err(format!("cannot read params file: {}", e));
            return;
        }
    };
    let v: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            out_err(format!("params JSON parse: {}", e));
            return;
        }
    };
    match op {
        LatticeOp::SmallRoots => {
            let parse_ints = |key: &str| -> Result<Vec<BigInt>, String> {
                v.get(key)
                    .and_then(|x| x.as_array())
                    .ok_or_else(|| format!("missing array '{}'", key))?
                    .iter()
                    .map(|x| {
                        x.as_str()
                            .map(|s| s.parse::<BigInt>().map_err(|_| format!("bad int '{}'", s)))
                            .unwrap_or_else(|| {
                                x.as_i64()
                                    .map(|i| Ok(BigInt::from(i)))
                                    .unwrap_or_else(|| Err(format!("bad int in '{}'", key)))
                            })
                    })
                    .collect()
            };
            let f = match parse_ints("poly") {
                Ok(f) => f,
                Err(e) => {
                    out_err(e);
                    return;
                }
            };
            let n_str = v.get("n").and_then(|x| x.as_str()).unwrap_or("");
            let n = match n_str
                .strip_prefix("0x")
                .map(|h| BigUint::from_str_radix(h, 16))
                .unwrap_or_else(|| n_str.parse::<BigUint>())
            {
                Ok(n) => n,
                Err(_) => match n_str.parse::<u128>() {
                    Ok(x) => BigUint::from(x),
                    Err(_) => {
                        out_err("missing/invalid 'n'".to_string());
                        return;
                    }
                },
            };
            let (bn, bd) = (
                v.get("beta_num").and_then(|x| x.as_u64()).unwrap_or(1),
                v.get("beta_den").and_then(|x| x.as_u64()).unwrap_or(1),
            );
            let x_bits = v.get("x_bits").and_then(|x| x.as_u64()).unwrap_or(16) as u32;
            let m = v.get("m").and_then(|x| x.as_u64()).unwrap_or(2) as usize;
            let t = v.get("t").and_then(|x| x.as_u64()).unwrap_or(1) as usize;
            match ctf_crypto::lattice::small_roots(&f, &n, (bn, bd), x_bits, m, t) {
                Ok(roots) => {
                    let arr: Vec<Value> = roots
                        .iter()
                        .map(|r| match &r.factor {
                            Some(fac) => json!({"x0": r.x0.to_string(), "factor": fac.to_string()}),
                            None => json!({"x0": r.x0.to_string(), "factor": null}),
                        })
                        .collect();
                    out_json(json!({"roots": arr}));
                }
                Err(e) => out_err(e.to_string()),
            }
        }
        LatticeOp::Lll => {
            out_err("lll op: use small_roots (standalone basis reduction lands with the lattice track)".to_string());
        }

    }
}
fn forensics_cmd(op: ForensicsOp, file: PathBuf, root: usize) {
    let data = match std::fs::read(&file) {
        Ok(d) => d,
        Err(e) => {
            out_err(format!("cannot read: {}", e));
            return;
        }
    };
    match op {
        ForensicsOp::Minidump => match ctf_parse::minidump::MiniDump::parse(&data) {
            Ok(md) => {
                let modules: Vec<Value> = md
                    .modules
                    .iter()
                    .map(|m| {
                        json!({
                            "name": m.name,
                            "base": format!("{:#x}", m.base_of_image),
                            "size": format!("{:#x}", m.size_of_image),
                        })
                    })
                    .collect();
                let ranges: Vec<Value> = md
                    .memory
                    .iter()
                    .map(|m| {
                        json!({
                            "start": format!("{:#x}", m.start),
                            "size": m.size,
                            "file_rva": m.file_rva,
                        })
                    })
                    .collect();
                out_json(json!({
                    "modules": modules,
                    "memory_ranges": ranges,
                    "exception": md.exception.as_ref().map(|e| json!({
                        "thread_id": e.thread_id,
                        "code": format!("{:#x}", e.exception_code),
                        "address": format!("{:#x}", e.exception_address),
                    })),
                    "process_id": md.process_id,
                }));
            }
            Err(e) => out_err(e.to_string()),
        },
        ForensicsOp::Pagedump => match ctf_parse::pagedump::PageDump::parse(&data) {
            Ok(pd) => {
                let runs: Vec<Value> = pd
                    .physical_runs
                    .iter()
                    .map(|r| json!({"base_page": r.base_page, "pages": r.page_count}))
                    .collect();
                out_json(json!({
                    "version": [pd.major_version, pd.minor_version],
                    "directory_table_base": format!("{:#x}", pd.directory_table_base),
                    "ps_loaded_module_list": format!("{:#x}", pd.ps_loaded_module_list),
                    "ps_active_process_head": format!("{:#x}", pd.ps_active_process_head),
                    "machine": format!("{:#x}", pd.machine_image_type),
                    "processors": pd.number_of_processors,
                    "physical_runs": runs,
                    "total_pages": pd.total_pages(),
                    "kdbg_offsets": pd.kdbg_offsets.iter().map(|o| format!("{:#x}", o)).collect::<Vec<_>>(),
                }));
            }
            Err(e) => out_err(e.to_string()),
        },
        ForensicsOp::Mft => match ctf_parse::mft::parse_entries(&data) {
            Ok(entries) => {
                let list: Vec<Value> = entries
                    .iter()
                    .map(|e| {
                        let name = e.file_names.first().map(|f| f.name.clone()).unwrap_or_default();
                        let content = e
                            .data
                            .as_ref()
                            .filter(|d| d.resident)
                            .map(|d| String::from_utf8_lossy(&d.content).into_owned());
                        json!({
                            "record": e.record_number,
                            "in_use": e.in_use,
                            "name": name,
                            "created": e.standard_info.as_ref().map(|t| t.created).unwrap_or(0),
                            "resident_data": content,
                        })
                    })
                    .collect();
                out_json(json!({"records": list}));
            }
            Err(e) => out_err(e.to_string()),
        },
        ForensicsOp::Sqlite => match ctf_parse::sqlite::SqliteDb::open(&data) {
            Ok(db) => match db.tables() {
                Ok(tables) => {
                    let names: Vec<Value> = tables
                        .iter()
                        .map(|(n, r)| json!({"name": n, "root": r}))
                        .collect();
                    match db.walk_table(root) {
                        Ok(rows) => {
                            let rows_json: Vec<Value> = rows
                                .iter()
                                .map(|r| {
                                    let vals: Vec<Value> = r
                                        .values
                                        .iter()
                                        .map(|v| match v {
                                            ctf_parse::sqlite::SqlValue::Null => json!(null),
                                            ctf_parse::sqlite::SqlValue::Int(i) => json!(i),
                                            ctf_parse::sqlite::SqlValue::Real(f) => json!(f),
                                            ctf_parse::sqlite::SqlValue::Text(s) => json!(s),
                                            ctf_parse::sqlite::SqlValue::Blob(b) => json!(b.iter().map(|x| format!("{:02x}", x)).collect::<String>()),
                                        })
                                        .collect();
                                    json!({"rowid": r.rowid, "values": vals})
                                })
                                .collect();
                            out_json(json!({"tables": names, "root_rows": rows_json}));
                        }
                        Err(e) => out_json(json!({"tables": names, "walk_error": e.to_string()})),
                    }
                }
                Err(e) => out_err(e.to_string()),
            },
            Err(e) => out_err(e.to_string()),
        },
        ForensicsOp::Memscan => {
            let ascii = ctf_parse::rawmem::carve_ascii_strings(&data, 8);
            let u16s = ctf_parse::rawmem::carve_utf16le_strings(&data, 6);
            let png = ctf_parse::rawmem::carve_files(&data, b"\x89PNG", 16 << 20, true);
            let zip = ctf_parse::rawmem::carve_files(&data, b"PK\x03\x04", 16 << 20, true);
            out_json(json!({
                "ascii_strings": ascii.len(),
                "utf16_strings": u16s.len(),
                "utf16_samples": u16s.iter().take(20).map(|(o, s)| json!({"offset": o, "text": s})).collect::<Vec<_>>(),
                "png_carved": png.len(),
                "zip_carved": zip.len(),
                "zip_offsets": zip.iter().map(|(o, _)| o).collect::<Vec<_>>(),
                "entropy_sample": ctf_parse::rawmem::entropy(&data[..(64 * 1024).min(data.len())]),
            }));
        }
        ForensicsOp::Pcap => match ctf_parse::pcap::parse_any(&data) {
            Ok(packets) => {
                let hid = ctf_parse::pcap::usb_keyboard_decode(&packets);
                // DNS over UDP/53
                let mut dns_msgs = Vec::new();
                for p in &packets {
                    if let Some((_, _, sport, dport, payload)) = ctf_parse::pcap::parse_frame(&p.data) {
                        // DNS over UDP/53
                        if (sport == 53 || dport == 53) && payload.len() >= 12 {
                            if let Some(m) = ctf_parse::netproto::parse_dns(&payload) {
                                dns_msgs.push(json!({
                                    "txid": format!("{:#x}", m.transaction_id),
                                    "response": m.is_response,
                                    "questions": m.questions,
                                    "answers": m.answers.iter().map(|a| json!({
                                        "name": a.name, "type": a.rtype, "data": a.data,
                                    })).collect::<Vec<_>>(),
                                }));
                            }
                        }
                    }
                }
                out_json(json!({
                    "packets": packets.len(),
                    "usb_keyboard_text": hid,
                    "dns": dns_msgs,
                }));
            }
            Err(e) => out_err(e.to_string()),
        },
    }
}



fn m_json(m: BigUint) -> Value {
    json!({
        "m_dec": m.to_string(),
        "m_hex": format!("{m:x}"),
        "m_bytes": String::from_utf8_lossy(&ctf_core::bytes::int_to_bytes(&m)),
    })
}

fn factors_json(f: &[BigUint]) -> Value {
    let mut sorted: Vec<&BigUint> = f.iter().collect();
    sorted.sort();
    json!({"factors": sorted.iter().map(|x| x.to_string()).collect::<Vec<_>>()})
}

fn prng_cmd(kind: PrngKind, params: PathBuf) {
    let text = std::fs::read_to_string(&params).expect("params file");
    let mut map = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let get = |k: &str| map.get(k).cloned();
    match kind {
        PrngKind::Lcg => {
            let (a, b, m) = match (get("a"), get("b"), get("m")) {
                (Some(a), Some(b), Some(m)) => (parse_big(&a), parse_big(&b), parse_big(&m)),
                _ => out_err("lcg needs a,b,m".into()),
            };
            let Some(x) = get("x").map(|v| parse_big(&v)) else {
                out_err("lcg needs x".into())
            };
            let next = lcg::predict_next(&x, &a, &b, &m, 1)[0].clone();
            let prev = lcg::step_back(&x, &a, &b, &m).ok();
            out_json(json!({"next": next.to_string(), "prev": prev.map(|v| v.to_string())}))
        }
        PrngKind::Mt19937 => {
            let Some(outputs) = get("outputs") else {
                out_err("mt19937 needs outputs=csv-of-u32".into())
            };
            let vals: Vec<u32> = outputs
                .split(',')
                .filter_map(|t| t.trim().parse().ok())
                .collect();
            let mut predictor = match mt19937::MtPredictor::new(&vals) {
                Some(pr) => pr,
                None => out_err("need at least 624 outputs".into()),
            };
            let preds: Vec<u32> = (0..3).map(|_| predictor.next_u32()).collect();
            out_json(json!({"next3": preds}))
        }
    }
}

fn filescan_cmd(op: FilescanOp, infile: PathBuf, magic: String, endian: String, max_payload: usize, min_len: usize) {
    let data = std::fs::read(&infile).unwrap_or_default();
    let endian = if endian == "little" { ctf_codec::Endian::Little } else { ctf_codec::Endian::Big };
    match op {
        FilescanOp::Magic => {
            let detected = ctf_codec::detect_magic(&data);
            let mut hits = Vec::new();
            for (name, m) in ctf_codec::MAGIC_TABLE {
                let offs = ctf_codec::magic::find_magic_offsets(&data, m);
                if !offs.is_empty() {
                    hits.push(json!({"name": name, "offsets": offs}));
                }
            }
            out_json(json!({"at_zero": detected, "hits": hits}))
        }
        FilescanOp::Strings => {
            let found = ctf_core::bytes::extract_strings(&data, min_len);
            let arr: Vec<Value> = found
                .into_iter()
                .take(2000)
                .map(|(o, s)| json!({"offset": o, "text": s}))
                .collect();
            out_json(json!({"strings": arr}))
        }
        FilescanOp::Entropy => {
            let profile: Vec<Value> = ctf_codec::entropy::entropy_profile(&data, 4096)
                .into_iter()
                .take(512)
                .map(|(o, e)| json!({"offset": o, "entropy": (e * 1000.0).round() / 1000.0}))
                .collect();
            out_json(json!({
                "total_entropy": ctf_codec::entropy::shannon_entropy(&data),
                "windows": profile,
            }))
        }
        FilescanOp::Carve => match ctf_codec::carve_len_prefixed(&data, magic.as_bytes(), endian, max_payload) {
            Ok(found) => {
                let arr: Vec<Value> = found
                    .into_iter()
                    .map(|(o, seq, payload)| json!({
                        "offset": o,
                        "seq": seq,
                        "len": payload.len(),
                        "payload_hex": ctf_codec::xcode::hex_encode(&payload, false),
                    }))
                    .collect();
                out_json(json!({"carved": arr}))
            }
            Err(e) => out_err(e.to_string()),
        },
    }
}

fn sidecar_cmd(engine: SidecarEngine, n: String, timeout: u64) {
    match engine {
        SidecarEngine::Yafu => match ctf_crypto::rsa::factor_yafu(&parse_big(&n), timeout) {
            Ok(f) => out_json(json!({"factors": f.iter().map(|x| x.to_string()).collect::<Vec<_>>()})),
            Err(e) => out_err(e.to_string()),
        },
    }
}

/// Hand-rolled flag scanner: {prefix}{ balanced braces }, no regex dep.
/// Raw candidates are for interactive use only; persisted artifacts must
/// store the redacted form (FLAG_REDACTED) per repo policy.
fn flag_cmd(infile: Option<PathBuf>, data: Option<String>, prefixes: String) {
    let input = read_input(&infile, &data);
    let text = String::from_utf8_lossy(&input);
    let prefixes: Vec<String> = prefixes.split(',').map(|s| s.trim().to_string()).collect();
    let mut found = Vec::new();
    for pref in &prefixes {
        let lower = text.to_lowercase();
        let pl = pref.to_lowercase();
        let mut from = 0usize;
        while let Some(pos) = lower[from..].find(&pl) {
            let abs = from + pos;
            let rest = &text[abs + pref.len()..];
            if let Some(open_rel) = rest.find('{') {
                if open_rel <= 2 {
                    if let Some(close_rel) = rest[open_rel..].find('}') {
                        found.push(format!("{pref}{}", &rest[..open_rel + close_rel + 1]));
                    }
                }
            }
            from = abs + pref.len().max(1);
            if from >= text.len() || found.len() >= 100 {
                break;
            }
        }
        if found.len() >= 100 {
            break;
        }
    }
    let redacted: Vec<String> = found
        .iter()
        .map(|f| format!("{}{{FLAG_REDACTED}}", f.split('{').next().unwrap_or("flag")))
        .collect();
    out_json(json!({"count": found.len(), "raw": found, "redacted": redacted}))
}
