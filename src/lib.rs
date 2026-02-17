//! # zk-auth
//!
//! A research-oriented Zero-Knowledge Authentication library
//! implementing Schnorr identification and Fiat–Shamir signatures.
//!
//! ## Module Overview
//!
//! - [`crypto`] — Low-level primitives: curve operations, hashing, Schnorr, Fiat–Shamir  
//! - [`models`] — Core data types: keypairs, proofs  
//! - [`protocol`] — Registration and authentication logic  
//! - [`auth`] — Prover / verifier roles and full flows  
//! - [`config`] — System-wide configuration  
//! - [`errors`] — Unified error and `Result` types  
//!
//! ⚠️ **Security Notice**
//! This library is experimental and intended for research and learning.
//! It has NOT been audited and MUST NOT be used in production.

// For a crypto project, this is a strong safety signal.
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
pub mod test_utils;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use errors::{Result, ZkAuthError};
