# Oracle/reference implementations (NOT runtime dependencies)

Per the Rust-first policy these Python artifacts are retained only as
algorithm references and test oracles. The production paths are:

| retired here | replaced by |
|---|---|
| solve_dasbook_ch06.py | `ctf-forge solve` / `ctf-forge bulk` (crates/ctf-forge-cli/src/solve.rs) |
| bulk_solve_crypto.py | `ctf-forge bulk` (same module) |
| auto-ctf-python/src_ctf2 | `ctf-forge ctf2 ...` (crates/ctf-forge-cli/src/ctf2client.rs, ureq) |
| auto-ctf-python/tests + smoke_test.py | cargo test suites per crate |

No Python interpreter is required to build, test, or run ctf-forge.
