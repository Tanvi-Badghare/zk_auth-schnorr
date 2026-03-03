//! # zkauth-rs
//!
//! A research-oriented Zero-Knowledge Authentication library
//! implementing Schnorr identification and the Fiat–Shamir transform.
//!
//! ⚠️ Security Notice:
//! This library is experimental and intended for research and learning.
//! It has NOT been audited and MUST NOT be used in production.

#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// Public modules
// ---------------------------------------------------------------------------

pub mod errors;
pub mod config;
pub mod crypto;
pub mod models;
pub mod protocol;
pub mod auth;

// ---------------------------------------------------------------------------
// Test-only modules
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod tests {
    pub mod test_utils.rs;  // now looks for src/tests/test_utils.rs
}

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use errors::{Result, ZkAuthError};