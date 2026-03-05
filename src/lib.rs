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

pub mod auth;
pub mod config;
pub mod crypto;
pub mod errors;
pub mod models;
pub mod protocol;

// ---------------------------------------------------------------------------
// Test utilities
// ---------------------------------------------------------------------------
//
// FIX: was #[cfg(test)] pub mod test_utils
// #[cfg(test)] makes this invisible to files in tests/ — integration tests
// compile as a separate crate and cannot see cfg(test) items from zk_auth.
// Removing the gate makes zk_auth::test_utils importable everywhere.
//
// DeterministicRng is documented as non-cryptographic and must never
// be used in production — the module-level warning enforces this.

pub mod test_utils;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use errors::{Result, ZkAuthError};
