# UPSTREAM — verified upstream integrations (reverse-mcp + rnc)

Verified 2026-09-25 on Windows 11 x86_64 by reading the cloned sources at
`vendor/reverse-mcp` and `vendor/rnc` (shallow clones of
https://github.com/jacek4yang/reverse-mcp and https://github.com/jacek4yang/rnc;
rnc also available as sibling `D:\Workspace\rnc`). Licenses: both MIT (LICENSE
files present).

## reverse-mcp — headless IDA idalib MCP broker

- Single `reverse-mcp.exe`: broker + self-spawned workers, driving IDA through
  native **idalib** (no `idat`, no Python). One IDA ABI per build:
  `--features idalib92` / `idalib94` (mutually exclusive, enforced by build.rs).
- **Transports**: MCP over stdio (`reverse-mcp serve`) or HTTP
  (`serve --http 127.0.0.1:8750`).
- **Verified command surface** (README quick start):
  - `cargo build --release -p reverse-mcp --features idalib` (requires IDA 9.2/9.4
    + license + pinned zig c++/ninja toolchain under `toolchain/`)
  - `reverse-mcp.exe selftest` — discovery + worker + real IDA chain
  - `reverse-mcp.exe ida list` — all discovered installs + backend readiness
  - `reverse-mcp.exe doctor` — toolchain pins, backend manifests, ABI probes
  - `reverse-mcp bench` — reproducible benchmark (mock in CI, `--real-ida` mode)
- **36 tools** (from `docs/MCP_TOOLS.md`, doc sync #49 2026-09-16):
  ida_db, ida_capabilities, ida_installations, ida_jobs, ida_health,
  ida_mutation, ida_functions, ida_inspect, ida_decompile, ida_disassemble,
  ida_xrefs, ida_graph, ida_search, ida_bytes, ida_segments, ida_analysis,
  ida_metadata, ida_wasm, ida_imports, ida_fixups, ida_filemap, ida_func,
  ida_hr, ida_value, ida_insn, ida_edit, ida_types, ida_batch, ida_result,
  ida_evidence, ida_analyze, ida_deep, ida_type_recovery, ida_intel,
  ida_deobfuscate, ida_sig.
- **Key semantics**:
  - `ida_db action=open|info|save|close|list`; open returns handle `db1`, ...
    (omit `db` when exactly one open, else `db_ambiguous`).
  - Addresses hex `0x401000` or decimal. Every list/search/graph bounded;
    oversized results spill to `result_ref: rN` read via `ida_result`.
  - Timeouts: agent `timeout_ms` clamped 5s..30min; defaults 600s
    (ida_deep/ida_type_recovery/ida_intel/ida_analyze), 300s
    (ida_deobfuscate/ida_sig), 120s others. Budget hit → partial results +
    resume token (ida_deep) instead of error.
  - Optimistic concurrency: mutations take `expected_revision`;
    stale → `revision_conflict`. Unimplemented ops fail
    `capability_unavailable` (honest capabilities).
- **Build probe (this session)**: building without the `idalib` feature was
  attempted; the full feature build additionally needs the pinned
  zig c++/ninja toolchain (`toolchain/dotslash/`) and a licensed IDA install
  (`C:\Program Files\IDA Pro` present on this machine; version/license
  readiness must be confirmed via `reverse-mcp ida list`/`doctor` once an exe
  is built or downloaded). Until a working `reverse-mcp.exe` is registered:
  binary-analysis work stays `BLOCKED_IDA` per the grind rules.

## rnc — binary-safe Rust netcat

- Native `nc.exe` (statically linked CRT, no runtime deps): TCP/UDP, listen
  mode, IPv6, encodings `utf-8|gbk|gb18030|auto` handled at the Windows
  console boundary (`ReadConsoleW`/`WriteConsoleW`) without touching the code
  page. Built with Rust 1.98.1 on Windows 11 x64 (rust-toolchain.toml pins stable).
- **Crate layout**: lib + bin. Public modules: `cli` (Config), `encoding`
  (`Mode`, `Selection`, `ConsoleDecoder` — the encoding core ctf-tube reuses),
  `terminal` (Input/Output), `transport` (blocking byte pump:
  `run(Config, Sender<Event>, Receiver<Event>)`; `Event::Connected(TcpStream)`
  hands back the raw stream; `TCP_BUFFER = 256 KiB`).
- **Dependencies**: `encoding_rs 0.8.35`, `socket2 0.6`, `ctrlc 3.5`,
  `windows-sys 0.61` (console APIs) — all Windows-friendly.

## Gaps vs pwntools (what ctf-tube/ctf-pwn must implement here)

| pwntools feature | upstream coverage | this repo's plan |
|---|---|---|
| remote() / listen() TCP | rnc transport covers raw sockets | `crates/ctf-tube` Tube API over std::net + rnc encoding |
| process() tubes | not covered | `crates/ctf-tube` via std::process pipes |
| recvuntil/recvn/recvall/sendline timeouts | not covered (rnc is console-shaped) | `crates/ctf-tube` |
| encoding utf8/gbk/gb18030 | covered by rnc::encoding | reused via path dependency |
| p32/p64/u32/u64 le/be | not covered | `crates/ctf-pwn` |
| cyclic / cyclic_find | not covered | `crates/ctf-pwn` |
| ELF got/plt/symbols | not covered | `crates/ctf-pwn` (goblin, DEPS-justified) |
| ROP gadget search | not covered (IDA-side: ida_search/ida_bytes dumps) | `crates/ctf-pwn` over dump text |
| asm/shellcraft | not covered | out of scope for now (documented gap) |
| gdb debug tubes | not covered | documented gap |
| static/dynamic IDA analysis | covered by reverse-mcp (36 tools) | call via stdio MCP / HTTP 127.0.0.1:8750 |

## Integration layout

```
vendor/reverse-mcp   # IDA engine (kept intact, built behind its own features)
vendor/rnc           # IO/encoding core (path dependency from ctf-tube)
crates/ctf-tube      # pwntools-shaped Tube API (remote/listen/process + recv family)
crates/ctf-pwn       # pack/unpack, cyclic, ELF-lite (goblin), gadget search
crates/ctf-forge-mcp # thin MCP over ctf-tube + ctf-pwn; IDA stays on reverse-mcp
```

Do not link idalib into ctf-pwn; do not reimplement the decompiler.


## Seep-Reverse-Lab (vendor/seep-reverse-lab)

- https://github.com/angusdevgo/Seep-Reverse-Lab (MIT)
- 23 MCP tools wrapping Radare2 / JADX / Apktool / Frida for multi-platform RE
- Python/FastAPI MCP server — reference implementation only (policy: no Python runtime)
- **Use case**: when reverse-mcp real-IDA is BLOCKED_IDA_SDK, Radare2 headless
  analysis via seep-reverse-lab's r2 MCP tools is the alternative RE path.
- The Radare2 headless workflow (r2 -q -c "aaa; afl; pdf @main") can be
  ported to a Rust sidecar without Python (r2pipe protocol over pipe).
