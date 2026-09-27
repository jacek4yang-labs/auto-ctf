//! ctf-codec — encodings, xor, classic ciphers, transforms, entropy, magic,
//! and an auto-decode chain.
//!
//! Capability coverage: domain 1 (encoding/transform), domain 11 (file
//! forensics primitives: magic/carve), domain 34 (pattern-ish helpers).

pub mod auto;
pub mod classic;
pub mod entropy;
pub mod hid;
pub mod magic;
pub mod png;
pub mod transform;
pub mod stego;
pub mod zip;
pub mod zipcrypto;
pub mod xcode;

pub use auto::auto_decode;
pub use magic::{carve_len_prefixed, detect_magic, find_magic_offsets, Endian, MAGIC_TABLE};
