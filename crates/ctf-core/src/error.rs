//! Error type shared across the workspace.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("input exceeds bit cap: {bits} bits > cap {cap} bits")]
    TooLarge { bits: u64, cap: u64 },
    #[error("no modular inverse exists (gcd = {0})")]
    NoInverse(String),
    #[error("no {k}-th root found (result not exact)")]
    NoRoot { k: u32 },
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
