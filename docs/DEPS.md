# DEPS — dependency ledger and provenance

Workspace default set (approved up front): `serde`, `thiserror`,
`num-bigint`, `num-traits`, `num-integer`, `data-encoding`, `clap`,
`serde_json` (serde family), plus `rmcp` allowed since rustc >= 1.88.

## Policy

Rust-first implementation order: pure safe Rust → Rust FFI to native
libraries → Rust sidecar around native C/C++ tools → external executable.
Python/SageMath are reference-only (kept under `refs/oracle/`), never runtime
dependencies. Every reference use records: original project, source URL,
license, algorithm used, Rust implementation location.

## Direct crates

| Crate | Used by | Justification |
|---|---|---|
| num-bigint / num-traits / num-integer | core, crypto, sidecar, pwn, cli, mcp | default set |
| thiserror | core, crypto, codec, tube, pwn | default set |
| serde / serde_json | sidecar, crypto, cli, mcp | default set |
| data-encoding | ctf-codec | default set (hex/b64/b32) |
| clap | ctf-forge-cli | default set |
| rnc (path dep `vendor/rnc`) | ctf-tube | **upstream jacek4yang/rnc** (MIT): binary-safe netcat IO + encoding vocabulary (utf-8/gbk/gb18030); reused per policy instead of reimplementing tubes from scratch |
| encoding_rs 0.8 | ctf-tube | same codec engine rnc uses for utf-8/gbk/gb18030 conversion (Apache-2.0/MIT) |
| goblin 0.9 | ctf-pwn | ELF symbol/PLT parsing ("goblin or custom lite" — well-maintained crate preferred per policy; MIT/Apache-2.0) |
| ureq 2 (json+tls, rustls) | ctf-forge-cli `ctf2` client | native HTTPS for the CTF2 Open API read surface — replaces the retired Python auto-ctf client (MIT/Apache-2.0) |
| rmcp | — | unused in v0: stdio MCP is ~120 lines on serde_json (documented decision) |

## Sidecars (external executables, sha256-pinned + timeout + parser + tests)

| Tool | Location | Status |
|---|---|---|
| yafu-x64.exe | tools/yafu/ (sha256 1e125670…) | active: research-grade factorization; native rho/p−1 cover small factors only |

## Vendored upstream engines (kept intact, not modified)

| Repo | Path | Role |
|---|---|---|
| jacek4yang/reverse-mcp (MIT) | vendor/reverse-mcp | headless IDA 9.2/9.4 idalib MCP broker; stdio or HTTP 127.0.0.1:8750; 36 ida_* tools. Build probe: mock backend builds clean (1m08s); real-IDA build BLOCKED_IDA_SDK — idalib-sys expects the full IDA SDK headers at vendor/idalib-sys/sdk/src (auto.hpp missing from the 9.2 idalib subset installed locally) |
| jacek4yang/rnc (MIT) | vendor/rnc (+ sibling D:\Workspace\rnc) | IO/encoding core reused by ctf-tube |

## Reference implementations (algorithm provenance, retired to refs/oracle/)

| Reference | Source | License | Algorithm used | Rust port |
|---|---|---|---|---|
| autorsa.zip | user-provided bundle (local refs/autorsa) | unverified — algorithm reference only, no code copied | RSA solver set (wiener/common-modulus/low-e/CRT/rabin/schmidt-samoa/dp-dq/ed-leak), Brent rho + Miller-Rabin factorizer, LCG recovery | crates/ctf-crypto/src/{rsa,lcg}.rs, crates/ctf-core/src/num.rs |
| Crypto笔记.md | user notes (local) | private notes | RSA decision tree, dp/dq, wiener, LCG, MT19937 temper, Schmidt-Samoa | crates/ctf-crypto/src/rsa.rs, crates/ctf-core/src/num.rs |
| randcrack (PyPI) | pypi.org/project/randcrack | MIT | MT19937 state cloning from 624 outputs | crates/ctf-crypto/src/mt19937.rs (independent implementation; cross-verified against CPython random outputs) |
| solve_dasbook_ch06.py / bulk_solve_crypto.py | this repo (retired) | — | challenge param extraction + decision-tree dispatch | crates/ctf-forge-cli/src/solve.rs + crates/ctf-core/src/params.rs |
| Coppersmith 1997 / Howgrave-Graham 1997 / Cohen Alg. 16.10 (LLL) | public literature (algorithm reference only, no code copied) | univariate small-roots: HG lattice + exact-rational LLL + Sturm root isolation | crates/ctf-crypto/src/lattice.rs |
| apbq-rsa orthogonal lattice (Connor McCartney, DUCTF 2023 writeup) | public writeup — Python+flint reference at work/y2024q/coppersmith.py | h_i = a_i·p + b_i·q leaks → orthogonal lattice → gcd | Rust port PENDING (naive kernel embedding returns mixed vectors; needs paper-verified formulation) |
| USB HID Usage Tables | public USB-IF specification | keycode→char mapping, shift/transition semantics | crates/ctf-codec/src/hid.rs |
| auto-ctf Python client | this repo (retired) | — | CTF2 Open API read surface | crates/ctf-forge-cli/src/ctf2client.rs |

## Deliberately NOT added

- `sha2` (hand-rolled SHA-256 + MD5 in ctf-core::hash, FIPS/RFC vectors),
- `base64` (data-encoding), `rand` (all primitives deterministic),
- `regex` (hand-rolled scanners), `tokio`/`reqwest` (ureq covers sync HTTPS),
- any Python/SageMath runtime (policy).
