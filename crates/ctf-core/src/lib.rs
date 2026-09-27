//! ctf-core — shared number theory, byte/int conversion, hashing, and the
//! 8192-bit input cap for the ctf-forge workspace.
//!
//! Capability coverage: domain 2 (crypto math), domain 7 (hash, partial),
//! domain 37 (generic binary utils).

pub mod bytes;
pub mod error;
pub mod hash;
pub mod matrix;
pub mod num;
pub mod params;

pub use error::{CoreError, Result};

/// Hard input cap for public-key material (RSA moduli, etc.).
pub const BIT_CAP: u64 = 8192;

/// Returns `Err` when `n` exceeds [`BIT_CAP`].
pub fn check_bit_cap(bits: u64) -> Result<()> {
    if bits > BIT_CAP {
        return Err(CoreError::TooLarge { bits, cap: BIT_CAP });
    }
    Ok(())
}
