//! ctf-crypto — RSA attack decision tree, LCG recovery, and MT19937 prediction.
//!
//! Attack selection follows the local decision tree in `Crypto笔记.md` and the
//! autorsa solver set. All big-integer math is safe Rust on num-bigint; inputs
//! are capped at 8192 bits by ctf-core.

pub mod lattice;
pub mod ecc;
pub mod lcg;
pub mod ntlm;
pub mod pem;
pub mod mt19937;
pub mod rsa;
