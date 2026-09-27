---
name: ctf-forge
description: "Use this skill when solving CTF challenges (CTF2 platform practice/daily, competition archives, or local files) that need local primitives: encoding chains, RSA attacks, LCG/MT19937 prediction, file carving/forensics, flag extraction, or factorization via the yafu sidecar. Provides the ctf-forge Rust CLI/MCP toolkit and documents when to call platform tools vs local solvers vs the auto-ctf fallback."
license: MIT
compatibility: "Windows-first; requires cargo (rustc >= 1.88) for rebuilds; the built ctf-forge CLI runs standalone. CTF2 platform I/O needs the official ctf2 MCP connection or the auto-ctf Python fallback with $CTF2_TOKEN."
metadata:
  version: "0.1.0"
  platform: "CTF2 + generic CTF"
  homepage: "https://ctf2.dasctf.com"
---

# ctf-forge — capability-organized solver toolkit

Rust workspace (libs + unified CLI + stdio MCP) of reusable primitives for
CTF2 practice and the China Graduate Network Security Innovation Competition.
Organized by capability, not challenge category. Knowledge base in `docs/`,
challenge queue in `docs/QUEUE.json`, coverage in `docs/CAPABILITIES.md`.

## When to call what (decision path)

1. **Platform I/O (CTF2)**: use the connected official `ctf2` MCP tools
   (`ctf2_get_profile`, `ctf2_list_daily_challenges`,
   `ctf2_list_practice_grounds`, `ctf2_get_practice_challenge` —
   `files[].download_url`, `ctf2_get_my_submissions`). If MCP is missing,
   fall back to the repo's auto-ctf Python client (`src/ctf2/`,
   `$CTF2_TOKEN` or `api-key.txt`). Never call CTFd routes or admin APIs.
   - 401 = reconnect; 403 = report missing scope and STOP (never widen auth);
     429 = wait `Retry-After`.
   - Write tools (`ctf2_start_challenge_environment`, `ctf2_submit_flag`)
     only when the user explicitly asked for that action this turn. Submit
     requires confirmation=true and the exact flag; suites use `sub_flag_id`
     UUID from challenge details, never the display index.
2. **Local files / solve step**: prefer the native Rust toolkit:
   - `ctf-forge codec --op auto --data <blob>` — peel hex/base64/base32 chains
   - `ctf-forge crypto_rsa --attack auto --params p.txt` — full RSA decision
     tree (p&q / d / dp-dq / dp-leak / wiener / low-e / fermat / rho / p-1 /
     common-modulus / hastad / rabin / yafu sidecar)
   - `ctf-forge lattice --op small_roots --params p.json` — Coppersmith small
     roots (pure-Rust exact LLL + Sturm; p.json: {poly[], n, beta_num,
     beta_den, x_bits, m, t}); also `ctf_crypto::lcg::recover_seed_six`,
     `ctf_pwn::fmtstr`, `ctf_codec::hid`
   - `ctf-forge prng --kind lcg|mt19937` — parameter recovery + prediction
   - `ctf-forge filescan --op magic|strings|entropy|carve` — forensics entry
   - `ctf-forge sidecar_run --engine yafu --n <int>` — pinned factorizer
   - `ctf-forge flag_extract` — candidate scanner (redact stored flags!)
   - or the same 6 tools over stdio MCP (`ctf-forge-mcp`).
3. **Binary reverse**: headless IDA MCP (`open_database`, `decompile`,
   `list_funcs`, `xrefs`, ...) when the session advertises it. If missing,
   log `BLOCKED_IDA` and continue file-only. Do NOT vendor IDA or wrap the
   SDK in Rust.
4. **Escalation**: yafu sidecar for factorization (sha256-pinned in
   `tools/yafu/manifest.json`); Z3/Sage-class work is a documented gap —
   do not require Sage on this host.

## Reverse / Pwn workflow (Windows-first, Rust-native)

- **IDA analysis**: call the vendored `vendor/reverse-mcp` broker
  (`reverse-mcp serve` over stdio, or `serve --http 127.0.0.1:8750`) — 36
  `ida_*` tools (ida_db open/analyze → ida_functions/ida_decompile/
  ida_xrefs/ida_search/ida_bytes). If the broker/exe is unavailable:
  `BLOCKED_IDA`, continue file-only. Real-IDA build status and gaps:
  docs/UPSTREAM.md. Do NOT link idalib into ctf-pwn.
- **Tubes**: `crates/ctf-tube` — remote(host,port)/listen(port)/process(argv)
  with send/sendline/recv/recvuntil/recvn/recvall, timeouts, and rnc-derived
  utf-8/gbk/gb18030 encoding (path dependency on vendor/rnc).
- **Pwn primitives**: `crates/ctf-pwn` — p32/p64/u32/u64 le/be,
  cyclic/cyclic_find (pwntools-compatible), ELF symbols/GOT/PLT via goblin,
  ROP gadget search over reverse-mcp disassembly dumps.
- Rev: files → ida_db open → ida_analyze → decompile/xrefs → extract IO
  contract → ctf-tube remote to access_url or local process.
- Pwn: same RE pass → overflow/fmt/uaf note → cyclic offset → payload via
  ctf-tube. asm/shellcraft and gdb tubes are documented gaps.

## Rust-first policy (binding)

Pure safe Rust → Rust FFI → Rust sidecar around native tools → external
executable. No Python/SageMath runtime (references live under
`refs/oracle/`); retired Python drivers map 1:1 to Rust commands (see
docs/DEPS.md provenance table). Challenge-specific solvers are thin
composition layers over crate primitives — when tempted to write solve.py,
port the primitive into the matching crate with a unit test instead.

## When NOT to use this skill

- Platform write actions without explicit per-action user confirmation.
- Any host that is not the current authorized CTF2 environment (no scanning,
  no unsolicited AWD, no flag spraying; honor max_attempts).
- RSA inputs beyond 8192 bits (ctf-core rejects them).
- Challenges needing full SMT / multivariate lattice / AMM e-th roots —
  documented gaps (univariate Coppersmith IS covered: `lattice --op
  small_roots`, docs/CAPABILITIES.md).

## Ground rules encoded in the toolkit

- RSA input cap: 8192 bits (`ctf-core::BIT_CAP`), enforced on every entry point.
- No unsafe Rust anywhere in the workspace.
- Sidecars: sha256-pinned manifest + hard timeout; stdout parsed into JSON.
- Flags: report raw candidates interactively, but anything persisted to git
  or notes is redacted as `FLAG_REDACTED`.
- Tokens/PATs are never printed, stored in configs, or embedded in code.

## Layout

```
crates/ctf-core        numbers, errors, 8192-bit cap, bytes<->int, sha256
crates/ctf-codec       encodings, xor, classic, entropy, magic, auto-chain
crates/ctf-crypto      RSA attacks, LCG, MT19937
crates/ctf-parse       PE/ELF/ZIP/PCAP/image headers (P1 stub)
crates/ctf-net         TCP client, flag regex, expect/send (P1 stub)
crates/ctf-sidecar     spawn w/ timeout, manifest.json, yafu parser
crates/ctf-forge-cli   unified CLI (ctf-forge)
crates/ctf-forge-mcp   stdio MCP server, WIDE tools only
tools/yafu/            pinned sidecar binary + manifest.json
docs/                  CAPABILITIES / KNOWLEDGE / CHALLENGE-LOG / QUEUE.json / PROGRESS / DEPS
challenges/ctf2/       per-challenge archives: meta.json, files/, notes.md, solve/
```

Build & test: `cargo test --workspace`. CLI: `cargo run -p ctf-forge-cli -- --help`.
MCP smoke: echo the initialize/tools-list JSON-RPC lines into
`ctf-forge-mcp` and check the responses.
