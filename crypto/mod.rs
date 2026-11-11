//! Cryptographic primitives for zk-auth.
//!
//! This module provides the low-level building blocks that the rest of the
//! library composes:
//!
//! * [`hash`] — SHA-256 hashing (one-shot and transcript-based).
//! * [`curves`] — Elliptic curve operations over Ristretto (curve25519).
//! * [`schnorr`] — Schnorr identification protocol (sigma protocol).
//! * [`fiat_shamir`] — Transform interactive proofs → non-interactive via
//!   transcript hashing.
//!
//! ## Re-exports
//!
//! The most commonly used types are re-exported at the module level so
//! downstream code can write:
//! ```ignore
//! use zk_auth::crypto::{Hasher, Scalar, Point};
//! ```
//! instead of fully-qualified paths like `zk_auth::crypto::hash::Hasher`.

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

/// SHA-256 hashing (one-shot and incremental).
pub mod hash;

/// Elliptic curve operations: scalars, points, arithmetic.
pub mod curves;

/// Schnorr identification protocol (prove knowledge of a discrete log).
pub mod schnorr;

/// Fiat–Shamir transform: interactive proofs → non-interactive.
pub mod fiat_shamir;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

// Hash primitives are always available.
pub use hash::{Digest, Hasher, hash_bytes};

// Curve types will be uncommented when curves.rs is implemented.
// pub use curves::{Point, Scalar, BASEPOINT};

// Schnorr types will be uncommented when schnorr.rs is implemented.
// pub use schnorr::SchnorrProof;

// Fiat-Shamir types will be uncommented when fiat_shamir.rs is implemented.
// pub use fiat_shamir::Transcript;