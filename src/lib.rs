//! # zk-auth
//!
//! A research-oriented Zero-Knowledge Authentication library
//! implementing Schnorr identification and Fiat–Shamir signatures.
//!
//! ## Module Overview
//!
//! - [`crypto`] — Low-level primitives: curve operations, hashing, Schnorr, Fiat–Shamir.
//! - [`models`] — Core data types: keypairs, proofs.
//! - [`protocol`] — Registration and authentication state machines.
//! - [`auth`] — Prover / verifier roles and the end-to-end flow.
//! - [`config`] — System-wide parameters and configuration.
//! - [`errors`] — Unified error type and `Result` alias.
//!
//! ⚠️  **Experimental** — not audited, not production-ready.

// ---------------------------------------------------------------------------
// Public modules
// ---------------------------------------------------------------------------

/// Unified error types for the entire library.
pub mod errors;

/// System-wide configuration and parameters.
pub mod config;

/// Low-level cryptographic primitives.
pub mod crypto;

/// Core data structures (keypairs, proofs).
pub mod models;

/// Registration and authentication protocol logic.
pub mod protocol;

/// Prover, verifier, and the composed authentication flow.
pub mod auth;

// ---------------------------------------------------------------------------
// Test-only modules  (never compiled into the library binary)
// ---------------------------------------------------------------------------

/// Shared helpers for unit and integration tests.
#[cfg(test)]
pub mod test_utils;

// ---------------------------------------------------------------------------
// Convenience re-exports  (so downstream can write `zk_auth::Result<T>`)
// ---------------------------------------------------------------------------

pub use errors::{ZkAuthError, Result};