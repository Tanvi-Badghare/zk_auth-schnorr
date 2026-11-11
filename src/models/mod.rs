//! Core data structures for zk-auth.
//!
//! This module contains the high-level types exposed to users of the library:
//!
//! * [`Keypair`] — A public/private key pair.
//! * [`RegistrationProof`] — Proof used during registration.
//! * [`AuthenticationProof`] — Proof used during authentication.
//!
//! These types wrap lower-level cryptographic primitives
//! and provide protocol-specific semantics.

pub mod keypair;
pub mod proof;

#[doc(inline)]
pub use keypair::Keypair;

#[doc(inline)]
pub use proof::{AuthenticationProof, RegistrationProof};
