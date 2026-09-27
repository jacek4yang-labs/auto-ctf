# CAPABILITIES — coverage by capability (not challenge category)

Status legend: `none` | `partial` | `done` | `sidecar`.

Implementation rule: implement on demand from real CTF2 tasks, then generalize.
Do not implement the full list in one pass.

| # | Capability | Status | Where / notes |
|---|------------|--------|---------------|
| 1 | Encoding/transform | done | `ctf-codec` (hex/b64/b32, rot, vigenere, autokey, affine, morse, rail-fence, route, qwe-keyboard, phone multi-tap, xor, reverse, swap-adjacent, auto-chain) |
| 2 | Crypto math | done | `ctf-core::num` (modpow, egcd, inverse, iroot, CRT, Miller-Rabin) |
| 3 | RSA attacks | done | `ctf-crypto::rsa` — from_pq/decrypt/dp_leak/dpdq/wiener/fermat/low_e/common_modulus/hastad/rabin/rho/p-1/shared-prime + yafu sidecar; ✅ Coppersmith `lattice --op small_roots`（纯 Rust LLL+Sturm，2026-09，华为杯 insecure_padding 级实例验证）; gap: AMM/finite-field e-th roots, 多元格/apbq（Python+flint 过渡） |
| 4 | ECC/pubkey | none | on demand |
| 5 | Symmetric | partial | xor primitives only; AES via rustcrypto when a challenge needs it (DEPS entry first) |
| 6 | PRNG | done | `ctf-crypto::{lcg, mt19937}` — LCG a/b/m/seed + `recover_seed_six`（六输出盲恢复+小倍数剥离，2026-09）, MT19937 CPython-compatible + predictor |
| 7 | Hash/password | done | `ctf-core::hash` SHA-256 + MD5 (hand-rolled, vectors tested); `ctf-crypto::ntlm` MD4 + NT hash + NetNTLMv2 hashcat -m 5600 行构造（2026-09） |
| 8 | Packet parse | done | `ctf-parse::pcap` pcap/pcapng/USB HID + `netproto` HTTP(含 chunked)/DNS(TXT/压缩指针)（2026-09） |
| 9 | Net forensics | partial | pcap/pcapng 包遍历 + TCP 流重组 + HTTP 流拆分 + DNS 消息解析（2026-09）；TLS/ICMP 待做 |
| 10 | USB/HID | partial | `ctf-codec::hid` 键盘报告解码原语（2026-09）；pcapng 抽流仍缺 |
| 11 | File forensics | done | `ctf-parse::rawmem` 内存雕刻（ASCII/UTF16 字符串、PNG/GIF/JPEG/PDF/ZIP/RAR/7z magic+终止标记、熵图）+ `minidump`/`pagedump`/`mft`/`sqlite`/`regf`/`disk`(MBR/GPT/FAT32+LFN)（2026-09 内存取证强化）; rar/7z 容器仍走 sidecar |
| 12 | Image/stego | none | on demand |
| 13 | Audio/signal | none | on demand |
| 14 | Disk FS | partial | `ctf-parse::disk` — MBR/GPT 分区表 + FAT32（BPB/目录/LFN/簇链）+ `mft`（NTFS 记录）; exFAT/EXT 待做 |
| 15 | Memory primitives | none | on demand; tubes: `ctf-tube` process/remote/listen done |
| 16 | Exec formats | partial | `ctf-pwn` ELF symbols/GOT/PLT via goblin; PE/PCAP pending (ctf-parse P1) |
| 17 | Binary analysis | sidecar | vendor/reverse-mcp broker built + selftest (mock OK; real-IDA chain BLOCKED_IDA_SDK — see docs/UPSTREAM.md); 36 ida_* tools over stdio/HTTP |
| 18 | RE automation | sidecar | reverse-mcp ida_analyze/ida_deep/ida_batch workflows |
| 19 | SMT/symbolic | none | Z3 sidecar later (tools/ + manifest); no Rust SMT |
| 20 | Pwn helpers | partial | `ctf-pwn` pack/cyclic/ELF/gadget-search + Context/ROP-chain-builder/fmtstr-offset + ✅ `fmtstr` 增量/一次性 hh 写 builder（2026-09）|
| 21 | Heap helpers | none | on demand |
| 22 | Linux kernel helpers | none | on demand |
| 23 | HTTP client | done | `ctf-forge ctf2` native client (ureq+rustls) replaces the Python fallback |
| 24 | Web exploit helpers | none | per authorized CTF target only |
| 25 | App serialization parsers | none | on demand |
| 26 | Windows/AD parsers | none | on demand |
| 27 | Kerberos material parse | none | on demand |
| 28 | Structured data | partial | serde_json everywhere; no XLSX/PDF yet |
| 29 | Mobile APK/DEX | none | on demand |
| 30 | Firmware extract | none | on demand |
| 31 | Chain/EVM parse | none | on demand |
| 32 | OSINT interfaces | none | out of scope for now |
| 33 | Fuzz helpers | none | on demand |
| 34 | Pattern/YARA-like | partial | `flag_extract` scanner + strings/magic; no YARA rules |
| 35 | CTF session/flag infra | done | `ctf-forge` flag_extract + redaction policy; CTF2 platform I/O via official MCP / auto-ctf fallback |
| 36 | AWD orchestration | stub | not implemented by design; never scan/exploit non-authorized hosts |
| 37 | Generic binary utils | done | `ctf-core::bytes` (bytes↔int, strings), `ctf-codec::entropy` |

## Known gaps documented (do not require Sage)

- ~~Coppersmith / lattice small-root~~ RESOLVED 2026-09: `ctf-crypto::lattice`
  — pure-Rust exact-rational LLL + Howgrave–Graham + Sturm root isolation;
  CLI `lattice --op small_roots`; vectors in lattice.rs tests. Remaining:
  apbq/orthogonal-lattice Rust port (Python+flint transition validated),
  multivariate, BKZ.
- AMM / finite-field t-th roots for gcd(e, phi) large: `from_pq` reports a
  typed error pointing at this gap.
- Factorization of >128-bit semiprimes: yafu sidecar (`tools/yafu/manifest.json`,
  sha256-pinned) is the engine; native rho/p-1 handle small factors only.
