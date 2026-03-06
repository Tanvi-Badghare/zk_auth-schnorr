//! zk_auth
//!
//! A research-oriented Zero-Knowledge Authentication framework
//! implementing the Schnorr identification protocol and
//! Fiat–Shamir signature transformation.
//!
//! # Overview
//!
//! This crate provides:
//!
//! - Schnorr zero-knowledge identification
//! - Fiat–Shamir signature scheme
//! - Ristretto255 elliptic curve abstraction
//! - Transcript-based challenge generation
//!
//! ⚠️ **Security Notice**
//!
//! This library is experimental and intended for research and learning.
//! It has **NOT been audited** and MUST NOT be used in production systems.
//!
//! ## Quick Example
//!
//! ```rust
//! use zk_auth::models::keypair::Keypair;
//! use zk_auth::protocol::registration::{RegistrationRequest, Registry};
//! use zk_auth::protocol::authentication::{AuthProof, Authenticator};
//! use rand::rngs::OsRng;
//!
//! // Generate a keypair
//! let keypair = Keypair::generate(&mut OsRng).unwrap();
//!
//! // Register
//! let req = RegistrationRequest::new("alice", &keypair, &mut OsRng).unwrap();
//! let mut registry = Registry::new();
//! registry.register(req).unwrap();
//!
//! // Authenticate
//! let mut auth = Authenticator::new(&registry);
//! let challenge = auth.issue_challenge("alice", &mut OsRng).unwrap();
//! let proof = AuthProof::new(&challenge, &keypair, &mut OsRng).unwrap();
//! let result = auth.verify(&proof, &challenge).unwrap();
//!
//! assert_eq!(result.username, "alice");
//! ```
//! # Protocol
//!
//! The protocol follows the classical Schnorr identification flow:
//!
//! ```text
//! Prover                Verifier
//!   |                      |
//!   | ---- commitment ---> |
//!   | <---- challenge ---- |
//!   | ---- response -----> |
//!   |                      |
//! ```
//!
//! Security relies on the hardness of the
//! **discrete logarithm problem over Ristretto255**.

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
