//! TrustAuto: policy-bounded automatic privilege elevation.
//!
//! The library holds everything that can be tested without privileges. The
//! only code that runs as root is `broker`, which is Linux-only.

pub mod analyze;
pub mod audit;
pub mod collect;
pub mod engine;
pub mod face;
pub mod facts;
pub mod index;
pub mod ml;
pub mod paths;
pub mod policy;
pub mod request;
pub mod risk;
pub mod shell;
pub mod switch;
pub mod transformer;

#[cfg(target_os = "linux")]
pub mod broker;

/// FNV-1a over a byte slice. An identifier for audit records and a corruption
/// check for the model. Not a cryptographic integrity guarantee: both inputs
/// are protected by root ownership.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
