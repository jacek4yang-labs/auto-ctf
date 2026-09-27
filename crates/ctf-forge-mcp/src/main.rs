//! ctf-forge-mcp — stdio MCP (Model Context Protocol) server exposing the
//! WIDE tool enum of ctf-forge. JSON-RPC 2.0 over stdin/stdout, hand-rolled on
//! serde_json (rmcp intentionally unused in v0 — see docs/DEPS.md).
//!
//! Tools: codec, crypto_rsa, prng, filescan, sidecar_run, flag_extract.
//! parse and net_session are P1: advertised as unavailable until implemented.
//! The server never touches CTF2 MCP / network — platform I/O stays with the
//! official ctf2 MCP or the auto-ctf fallback client.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use num_bigint::BigUint;
use num_traits::Num;
use serde::Deserialize;
use serde_json::{json, Value};

use ctf_codec::{classic, xcode};
use ctf_crypto::rsa::{auto_attack, RsaParams};
use ctf_crypto::{lcg, mt19937};

#[derive(Deserialize)]
struct Rpc {
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

fn reply(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn reply_err(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

const TOOLS: &[(&str, &str)] = &[
    (
        "codec",
        "Encoding/transform toolbox. ops: hex|unhex|b64|unb64|b32|unb32|rot|xor|rev|swap|auto|entropy. Input: {op, data?, infile?, shift?, key?}",
    ),
    (
        "crypto_rsa",
        "RSA attacks with auto decision tree. {attack: auto|decrypt|wiener|fermat|low_e|common_modulus|hastad|pollard_rho|p1|dp_dq|rabin|factor_yafu, params:{c,e,n,d,p,q,dp,dq,c1,c2,e1,e2,cs,ns}}",
    ),
    (
        "prng",
        "PRNG recovery. kind=lcg: {a,b,m,x} -> next/prev; kind=mt19937: {outputs:[624 u32]} -> next3",
    ),
    (
        "filescan",
        "File forensics. ops: magic|strings|entropy|carve. {op, path, magic?, endian?, max_payload?, min_len?}",
    ),
    (
        "sidecar_run",
        "Run a pinned sidecar engine. {engine:'yafu', n} -> factors",
    ),
    (
        "flag_extract",
        "Flag candidate scanner (no regex dep). {text?|path?, prefixes?}. Returns raw + redacted candidates.",
    ),
    (
        "parse",
        "Structured file parsing. fmt=elf: {path} -> symbols/GOT/PLT (goblin).",
    ),
    (
        "net_session",
        "Stateful TCP tube (ctf-tube). ops: connect {host,port} -> session; send {session, text|hex}; recvuntil {session, delim, timeout_ms?}; recv {session}; close {session}.",
    ),
];

fn tool_schemas() -> Value {
    Value::Array(
        TOOLS
            .iter()
            .map(|(name, desc)| {
                json!({
                    "name": name,
                    "description": desc,
                    "inputSchema": {"type": "object", "additionalProperties": true},
                })
            })
            .collect(),
    )
}

fn parse_big(s: &str) -> Result<BigUint, String> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        BigUint::from_str_radix(h, 16).map_err(|e| e.to_string())
    } else {
        BigUint::from_str_radix(t, 10).map_err(|e| e.to_string())
    }
}

fn opt_big(params: &Value, key: &str) -> Option<BigUint> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .and_then(|s| parse_big(s).ok())
}

fn opt_string_list(params: &Value, key: &str) -> Option<Vec<BigUint>> {
    params.get(key).and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|x| x.as_str())
            .filter_map(|s| parse_big(s).ok())
            .collect()
    })
}

fn tool_call(name: &str, params: &Value) -> Result<Value, String> {
    match name {
        "codec" => {
            let op = params
                .get("op")
                .and_then(|v| v.as_str())
                .ok_or("codec needs op")?;
            let data: Vec<u8> = match params.get("data").and_then(|v| v.as_str()) {
                Some(s) => s.as_bytes().to_vec(),
                None => match params.get("infile").and_then(|v| v.as_str()) {
                    Some(p) => std::fs::read(p).map_err(|e| e.to_string())?,
                    None => return Err("codec needs data or infile".into()),
                },
            };
            let shift = params.get("shift").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let key = params.get("key").and_then(|v| v.as_str()).map(String::from);
            match op {
                "hex" => Ok(json!({"result": xcode::hex_encode(&data, false)})),
                "unhex" => Ok(json!({"result": String::from_utf8_lossy(&xcode::hex_decode(&String::from_utf8_lossy(&data)).map_err(|e| e.to_string())?)})),
                "b64" => Ok(json!({"result": xcode::base64_encode(&data, false)})),
                "unb64" => Ok(json!({"result": String::from_utf8_lossy(&xcode::base64_decode(&String::from_utf8_lossy(&data)).map_err(|e| e.to_string())?)})),
                "b32" => Ok(json!({"result": xcode::base32_encode(&data)})),
                "unb32" => Ok(json!({"result": String::from_utf8_lossy(&xcode::base32_decode(&String::from_utf8_lossy(&data)).map_err(|e| e.to_string())?)})),
                "rot" => Ok(json!({"result": String::from_utf8_lossy(&classic::rot_n(&data, shift))})),
                "xor" => {
                    let k = key.ok_or("xor needs key")?;
                    let kb = match k.strip_prefix("0x") {
                        Some(h) => xcode::hex_decode(h).map_err(|e| e.to_string())?,
                        None => k.into_bytes(),
                    };
                    let out = xcode::xor_repeating(&data, &kb).map_err(|e| e.to_string())?;
                    Ok(json!({
                        "result_hex": xcode::hex_encode(&out, false),
                        "result_text": String::from_utf8_lossy(&out),
                    }))
                }
                "rev" => Ok(json!({"result": String::from_utf8_lossy(&classic::reverse_bytes(&data))})),
                "swap" => Ok(json!({"result": String::from_utf8_lossy(&classic::swap_adjacent(&data))})),
                "auto" => {
                    let r = ctf_codec::auto_decode(&data, 16);
                    Ok(json!({
                        "layers": r.layers.iter().map(|l| l.to_string()).collect::<Vec<_>>(),
                        "result_text": String::from_utf8_lossy(&r.data),
                        "result_hex": xcode::hex_encode(&r.data, false),
                    }))
                }
                "entropy" => Ok(json!({"entropy_bits": ctf_codec::entropy::shannon_entropy(&data)})),
                other => Err(format!("unknown codec op: {other}")),
            }
        }
        "crypto_rsa" => {
            let attack = params
                .get("attack")
                .and_then(|v| v.as_str())
                .unwrap_or("auto");
            let ps = params.get("params").cloned().unwrap_or(json!({}));
            let p = RsaParams {
                n: opt_big(&ps, "n"),
                e: opt_big(&ps, "e"),
                c: opt_big(&ps, "c"),
                d: opt_big(&ps, "d"),
                p: opt_big(&ps, "p"),
                q: opt_big(&ps, "q"),
                dp: opt_big(&ps, "dp"),
                dq: opt_big(&ps, "dq"),
                c1: opt_big(&ps, "c1"),
                c2: opt_big(&ps, "c2"),
                e1: opt_big(&ps, "e1"),
                e2: opt_big(&ps, "e2"),
                cs: opt_string_list(&ps, "cs"),
                ns: opt_string_list(&ps, "ns"),
                sum_a: opt_big(&ps, "sum_a"),
                sum_b: opt_big(&ps, "sum_b"),
            };
            let e_default = p.e.clone().unwrap_or_else(|| BigUint::from(65537u32));
            let n_default = p.n.clone().unwrap_or_default();
            let m = match attack {
                "auto" => auto_attack(&p).map_err(|e| e.to_string())?,
                "decrypt" => ctf_crypto::rsa::decrypt(
                    p.c.as_ref().ok_or("need c")?,
                    p.d.as_ref().ok_or("need d")?,
                    p.n.as_ref().ok_or("need n")?,
                )
                .map_err(|e| e.to_string())?,
                "wiener" => ctf_crypto::rsa::wiener(&e_default, &n_default)
                    .ok_or("wiener found nothing")?,
                "fermat" => ctf_crypto::rsa::fermat(&n_default, 1_000_000)
                    .map(|(a, b)| a * b)
                    .ok_or("fermat found nothing")?,
                "low_e" => ctf_crypto::rsa::low_e(
                    p.c.as_ref().ok_or("need c")?,
                    &e_default,
                    &n_default,
                    1_000_000,
                )
                .ok_or("low_e found nothing")?,
                "common_modulus" => ctf_crypto::rsa::common_modulus(
                    p.c1.as_ref().ok_or("need c1")?,
                    p.c2.as_ref().ok_or("need c2")?,
                    p.e1.as_ref().ok_or("need e1")?,
                    p.e2.as_ref().ok_or("need e2")?,
                    p.n.as_ref().ok_or("need n")?,
                )
                .map_err(|e| e.to_string())?,
                "hastad" => ctf_crypto::rsa::hastad_broadcast(
                    p.cs.as_ref().ok_or("need cs")?,
                    p.ns.as_ref().ok_or("need ns")?,
                    &e_default,
                )
                .map_err(|e| e.to_string())?,
                "pollard_rho" => ctf_crypto::rsa::factor_rho(&n_default, 16)
                    .map(|(a, b)| a * b)
                    .ok_or("rho found nothing")?,
                "p1" => ctf_crypto::rsa::factor_p1(&n_default, 100_000)
                    .map(|(a, b)| a * b)
                    .ok_or("p-1 found nothing")?,
                "dp_dq" => ctf_crypto::rsa::dpdq(
                    p.p.as_ref().ok_or("need p")?,
                    p.q.as_ref().ok_or("need q")?,
                    p.dp.as_ref().ok_or("need dp")?,
                    p.dq.as_ref().ok_or("need dq")?,
                    p.c.as_ref().ok_or("need c")?,
                )
                .map_err(|e| e.to_string())?,
                "rabin" => ctf_crypto::rsa::rabin(
                    p.c.as_ref().ok_or("need c")?,
                    p.p.as_ref().ok_or("need p")?,
                    p.q.as_ref().ok_or("need q")?,
                )
                .map(|r| r[0].clone())
                .map_err(|e| e.to_string())?,
                "factor_yafu" => ctf_crypto::rsa::factor_yafu(&n_default, 300)
                    .map(|f| f.iter().product())
                    .map_err(|e| e.to_string())?,
                other => return Err(format!("unknown attack: {other}")),
            };
            Ok(json!({
                "m_dec": m.to_string(),
                "m_hex": format!("{m:x}"),
                "m_bytes": String::from_utf8_lossy(&ctf_core::bytes::int_to_bytes(&m)),
            }))
        }
        "prng" => {
            let kind = params
                .get("kind")
                .and_then(|v| v.as_str())
                .ok_or("prng needs kind")?;
            match kind {
                "lcg" => {
                    let a = opt_big(params, "a").ok_or("lcg needs a")?;
                    let b = opt_big(params, "b").ok_or("lcg needs b")?;
                    let m = opt_big(params, "m").ok_or("lcg needs m")?;
                    let x = opt_big(params, "x").ok_or("lcg needs x")?;
                    let next = lcg::predict_next(&x, &a, &b, &m, 1)[0].clone();
                    let prev = lcg::step_back(&x, &a, &b, &m).ok();
                    Ok(json!({"next": next.to_string(), "prev": prev.map(|v| v.to_string())}))
                }
                "mt19937" => {
                    let outputs: Vec<u32> = params
                        .get("outputs")
                        .and_then(|v| v.as_array())
                        .ok_or("mt19937 needs outputs")?
                        .iter()
                        .filter_map(|v| v.as_u64().map(|x| x as u32))
                        .collect();
                    let mut predictor =
                        mt19937::MtPredictor::new(&outputs).ok_or("need >= 624 outputs")?;
                    Ok(json!({"next3": [
                        predictor.next_u32(),
                        predictor.next_u32(),
                        predictor.next_u32(),
                    ]}))
                }
                other => Err(format!("unknown prng kind: {other}")),
            }
        }
        "filescan" => {
            let op = params
                .get("op")
                .and_then(|v| v.as_str())
                .ok_or("filescan needs op")?;
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("filescan needs path")?;
            let data = std::fs::read(PathBuf::from(path)).map_err(|e| e.to_string())?;
            match op {
                "magic" => {
                    let mut hits = Vec::new();
                    for (name, m) in ctf_codec::MAGIC_TABLE {
                        let offs = ctf_codec::magic::find_magic_offsets(&data, m);
                        if !offs.is_empty() {
                            hits.push(json!({"name": name, "offsets": offs}));
                        }
                    }
                    Ok(json!({"at_zero": ctf_codec::detect_magic(&data), "hits": hits}))
                }
                "strings" => {
                    let min_len = params.get("min_len").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
                    let found = ctf_core::bytes::extract_strings(&data, min_len);
                    Ok(json!({"strings": found.into_iter().take(2000)
                        .map(|(o, s)| json!({"offset": o, "text": s}))
                        .collect::<Vec<_>>()}))
                }
                "entropy" => Ok(json!({
                    "total_entropy": ctf_codec::entropy::shannon_entropy(&data),
                    "windows": ctf_codec::entropy::entropy_profile(&data, 4096)
                        .into_iter().take(512)
                        .map(|(o, e)| json!({"offset": o, "entropy": e}))
                        .collect::<Vec<_>>(),
                })),
                "carve" => {
                    let magic = params
                        .get("magic")
                        .and_then(|v| v.as_str())
                        .unwrap_or("PKT1")
                        .as_bytes()
                        .to_vec();
                    let endian = match params.get("endian").and_then(|v| v.as_str()) {
                        Some("little") => ctf_codec::Endian::Little,
                        _ => ctf_codec::Endian::Big,
                    };
                    let max_payload =
                        params.get("max_payload").and_then(|v| v.as_u64()).unwrap_or(4096) as usize;
                    let carved = ctf_codec::carve_len_prefixed(&data, &magic, endian, max_payload)
                        .map_err(|e| e.to_string())?;
                    Ok(json!({"carved": carved.into_iter()
                        .map(|(o, seq, payload)| json!({
                            "offset": o, "seq": seq, "len": payload.len(),
                            "payload_hex": xcode::hex_encode(&payload, false),
                        }))
                        .collect::<Vec<_>>()}))
                }
                other => Err(format!("unknown filescan op: {other}")),
            }
        }
        "sidecar_run" => {
            let engine = params
                .get("engine")
                .and_then(|v| v.as_str())
                .unwrap_or("yafu");
            if engine != "yafu" {
                return Err(format!("unknown sidecar engine: {engine}"));
            }
            let n = opt_big(params, "n").ok_or("sidecar_run needs n")?;
            let factors = ctf_crypto::rsa::factor_yafu(&n, 300).map_err(|e| e.to_string())?;
            Ok(json!({"factors": factors.iter().map(|x| x.to_string()).collect::<Vec<_>>()}))
        }
        "flag_extract" => {
            let text = match params.get("text").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => {
                    let path = params.get("path").and_then(|v| v.as_str()).ok_or("flag_extract needs text or path")?;
                    String::from_utf8_lossy(&std::fs::read(path).map_err(|e| e.to_string())?).into_owned()
                }
            };
            let prefixes = params
                .get("prefixes")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).map(String::from).collect::<Vec<_>>())
                .unwrap_or_else(|| vec!["flag".into(), "FLAG".into(), "ctf".into(), "CTF".into(), "dasctf".into(), "DASCTF".into()]);
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
            Ok(json!({"count": found.len(), "raw": found, "redacted": redacted}))
        }
        "parse" => {
            let fmt = params.get("fmt").and_then(|v| v.as_str()).unwrap_or("elf");
            if fmt != "elf" {
                return Err(format!("unknown parse fmt: {fmt}"));
            }
            let path = params.get("path").and_then(|v| v.as_str()).ok_or("parse needs path")?;
            let data = std::fs::read(path).map_err(|e| e.to_string())?;
            let syms = ctf_pwn::elf_symbols(&data).map_err(|e| e.to_string())?;
            let plt = ctf_pwn::elf_plt_entries(&data).unwrap_or_default();
            Ok(json!({
                "functions": syms.functions.iter().map(|(n, a)| json!({"name": n, "addr": a})).take(300).collect::<Vec<_>>(),
                "got_entries": syms.got_entries.iter().map(|(n, a)| json!({"name": n, "addr": a})).take(300).collect::<Vec<_>>(),
                "plt": plt.iter().map(|(n, a)| json!({"name": n, "got": a})).take(300).collect::<Vec<_>>(),
            }))
        }
        "net_session" => {
            use std::collections::BTreeMap;
            use std::sync::{Mutex, OnceLock};
            static SESSIONS: OnceLock<Mutex<BTreeMap<String, ctf_tube::Tube>>> = OnceLock::new();
            let sessions = SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()));
            let op = params.get("op").and_then(|v| v.as_str()).ok_or("net_session needs op")?;
            match op {
                "connect" => {
                    let host = params.get("host").and_then(|v| v.as_str()).ok_or("connect needs host")?;
                    let port = params.get("port").and_then(|v| v.as_u64()).ok_or("connect needs port")? as u16;
                    let tube = ctf_tube::Tube::remote(host, port).map_err(|e| e.to_string())?;
                    let id = format!("s{}", sessions.lock().unwrap().len() + 1);
                    sessions.lock().unwrap().insert(id.clone(), tube);
                    Ok(json!({"session": id}))
                }
                "send" => {
                    let id = params.get("session").and_then(|v| v.as_str()).ok_or("send needs session")?;
                    let mut map = sessions.lock().unwrap();
                    let tube = map.get_mut(id).ok_or("unknown session")?;
                    if let Some(text) = params.get("text").and_then(|v| v.as_str()) {
                        tube.send_text(text).map_err(|e| e.to_string())?;
                    } else if let Some(hex) = params.get("hex").and_then(|v| v.as_str()) {
                        let bytes = ctf_codec::xcode::hex_decode(hex).map_err(|e| e.to_string())?;
                        tube.send(&bytes).map_err(|e| e.to_string())?;
                    } else {
                        return Err("send needs text or hex".into());
                    }
                    Ok(json!({"sent": true}))
                }
                "sendline" => {
                    let id = params.get("session").and_then(|v| v.as_str()).ok_or("sendline needs session")?;
                    let mut map = sessions.lock().unwrap();
                    let tube = map.get_mut(id).ok_or("unknown session")?;
                    let text = params.get("text").and_then(|v| v.as_str()).ok_or("sendline needs text")?;
                    tube.sendline(text.as_bytes()).map_err(|e| e.to_string())?;
                    Ok(json!({"sent": true}))
                }
                "recvuntil" | "recv" => {
                    let id = params.get("session").and_then(|v| v.as_str()).ok_or("recv needs session")?;
                    let mut map = sessions.lock().unwrap();
                    let tube = map.get_mut(id).ok_or("unknown session")?;
                    if let Some(ms) = params.get("timeout_ms").and_then(|v| v.as_u64()) {
                        tube.set_timeout(std::time::Duration::from_millis(ms));
                    }
                    let data = if op == "recvuntil" {
                        let delim = params.get("delim").and_then(|v| v.as_str()).ok_or("recvuntil needs delim")?;
                        tube.recvuntil(delim.as_bytes()).map_err(|e| e.to_string())?
                    } else {
                        tube.recv().map_err(|e| e.to_string())?
                    };
                    Ok(json!({
                        "hex": ctf_codec::xcode::hex_encode(&data, false),
                        "text": String::from_utf8_lossy(&data),
                    }))
                }
                "close" => {
                    let id = params.get("session").and_then(|v| v.as_str()).ok_or("close needs session")?;
                    sessions.lock().unwrap().remove(id);
                    Ok(json!({"closed": true}))
                }
                other => Err(format!("unknown net_session op: {other}")),
            }
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

fn handle(rpc: Rpc) -> Value {
    match rpc.method.as_str() {
        "initialize" => reply(
            &rpc.id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ctf-forge", "version": env!("CARGO_PKG_VERSION")},
            }),
        ),
        "notifications/initialized" => json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        "tools/list" => reply(&rpc.id, json!({"tools": tool_schemas()})),
        "tools/call" => {
            let name = rpc.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = rpc.params.get("arguments").cloned().unwrap_or(json!({}));
            match tool_call(name, &args) {
                Ok(v) => reply(
                    &rpc.id,
                    json!({"content": [{"type": "text", "text": serde_json::to_string(&v).unwrap()}]}),
                ),
                Err(e) => reply(
                    &rpc.id,
                    json!({"content": [{"type": "text", "text": format!("error: {e}")}], "isError": true}),
                ),
            }
        }
        "ping" => reply(&rpc.id, json!({})),
        other => {
            if other.starts_with("notifications/") {
                json!({"jsonrpc": "2.0", "method": other})
            } else {
                reply_err(&rpc.id, -32601, &format!("method not found: {other}"))
            }
        }
    }
}

fn main() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Rpc>(&line) {
            Ok(rpc) => {
                let resp = handle(rpc);
                writeln!(stdout, "{resp}").ok();
                stdout.flush().ok();
            }
            Err(e) => {
                let resp = reply_err(&Value::Null, -32700, &format!("parse error: {e}"));
                writeln!(stdout, "{resp}").ok();
                stdout.flush().ok();
            }
        }
    }
}
