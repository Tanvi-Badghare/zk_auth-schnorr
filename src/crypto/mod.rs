//! Cryptographic primitives for zk-auth.
//!
//! * [`hash`] — SHA-256 hashing (one-shot and incremental).
//! * [`curves`] — Ristretto255 scalars and points.
//! * [`schnorr`] — Schnorr proof of knowledge (sigma protocol).
//! * [`fiat_shamir`] — domain-separated transcript used to derive challenges.
//!
//! The most common types are re-exported here, so downstream code can write
//! `zk_auth::crypto::{Point, Scalar, SchnorrProof, Transcript}`.
//!
//! ## Example
//!
//! ```
//! use rand::rngs::OsRng;
//! use zk_auth::crypto::{Hasher, SchnorrProof};
//! use zk_auth::models::keypair::Keypair;
//!
//! let kp = Keypair::generate(&mut OsRng).unwrap();
//!
//! // Prove knowledge of the secret key, bound to a message.
//! let proof = SchnorrProof::prove(kp.secret_key(), kp.public_key(), b"hello", &mut OsRng);
//! assert!(proof.verify(kp.public_key(), b"hello"));
//! assert!(!proof.verify(kp.public_key(), b"other message"));
//!
//! // SHA-256 digests are 32 bytes.
//! let mut h = Hasher::new();
//! h.update(b"abc");
//! assert_eq!(h.finalize().len(), 32);
//! ```

pub mod curves;
pub mod fiat_shamir;
pub mod hash;
pub mod schnorr;

pub use curves::{Point, Scalar, BASEPOINT};
pub use fiat_shamir::Transcript;
pub use hash::{hash_bytes, hash_to_scalar, Hasher};
pub use schnorr::SchnorrProof;