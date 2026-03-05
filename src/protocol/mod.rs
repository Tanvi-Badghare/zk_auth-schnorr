//! Protocol layer — registration and authentication flows.
//!
//! This module defines the **public protocol boundary** of zk-auth.
//! Everything outside this module should depend ONLY on the types
//! re-exported here.
//!
//! It composes the crypto primitives (Schnorr, Fiat–Shamir,
//! Ristretto) into the two-step ZKAuth protocol:
//!
//! ```text
//! 1. Registration     — user proves knowledge of `x` and binds it to an identity.
//! 2. Authentication   — user re-proves knowledge of `x` for a fresh challenge.
//! ```
//!
//! ## Module structure
//!
//! | Sub-module        | Responsibility                                      |
//! |-------------------|-----------------------------------------------------|
//! | `registration`    | `RegistrationRequest`, `RegistrationRecord`        |
//! | `authentication`  | `AuthChallenge`, `AuthProof`, `AuthResult`         |
//!
//! ## Security Design Principles
//!
//! * **No crypto primitives leak** — callers work with protocol-level types
//!   only; raw [`Scalar`][crate::crypto::curves::Scalar] and
//!   [`Point`][crate::crypto::curves::Point] stay behind the boundary.
//! * **Errors are collapsed** — verification failures return
//!   [`ZkAuthError::VerificationFailed`][crate::errors::ZkAuthError::VerificationFailed]
//!   or [`ZkAuthError::AuthenticationFailed`][crate::errors::ZkAuthError::AuthenticationFailed]
//!   to prevent oracle attacks.
//! * **Domain separation** — every transcript begins with a distinct
//!   domain string so registration and authentication challenges
//!   can never collide.
//!
//! This separation ensures the protocol layer remains secure,
//! auditable, and resistant to misuse.

pub mod authentication;
pub mod registration;

#[doc(inline)]
pub use authentication::{AuthChallenge, AuthProof, AuthResult, Authenticator};

#[doc(inline)]
pub use registration::{RegistrationRecord, RegistrationRequest, Registry};