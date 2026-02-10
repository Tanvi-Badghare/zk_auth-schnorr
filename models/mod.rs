//! Core data structures for zk-auth.
//!
//! This module contains the high-level types that the rest of the library
//! uses:
//!
//! * [`Keypair`] — A public/private key pair (scalar + point).
//! * [`RegistrationProof`] — A Schnorr proof created during registration.
//! * [`AuthenticationProof`] — A Schnorr proof created during authentication.
//!
//! These types wrap the low-level cryptographic primitives from [`crate::crypto`]
//! and provide domain-specific semantics.

/// Public/private key pairs.
pub mod keypair;

/// Registration and authentication proof types.
pub mod proof;

// Re-exports for convenience.
pub use keypair::Keypair;
pub use proof::{AuthenticationProof, RegistrationProof};