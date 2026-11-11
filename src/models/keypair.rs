//! Public/private key pairs for zk-auth.
//!
//! A [`Keypair`] consists of:
//! * A **secret key** (scalar `x`), kept private.
//! * A **public key** (point `Y = x * G`), shared with verifiers.
//!
//! ## Security
//!
//! The secret key is automatically zeroized when the [`Keypair`] is dropped
//! via [`ZeroizeOnDrop`][zeroize::ZeroizeOnDrop].
//! This prevents secret material from lingering in memory after use.
//!
//! ## Serialization
//!
//! ⚠️ **WARNING**: [`Keypair`] serializes **both** the public and secret keys.
//! This is convenient for demos and tests, but **do not** store serialized
//! keypairs in plaintext in production.  Use encrypted storage or a
//! dedicated keystore.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::curves::{Point, Scalar, BASEPOINT};
use crate::errors::Result;

// ---------------------------------------------------------------------------
// Keypair
// ---------------------------------------------------------------------------

/// A public/private key pair for ZKAuth.
///
/// # Zeroization
///
/// The `secret_key` field is wiped when the `Keypair` is dropped.
/// `ZeroizeOnDrop` generates a `Drop` implementation that calls
/// `zeroize()` on every field.  Do NOT also use `#[zeroize(drop)]`
/// — that attribute generates a second `Drop` impl, which is a
/// compile error ("conflicting implementations of trait `Drop`").
///
/// # Clone
///
/// `Clone` is intentionally NOT derived.  Cloning a keypair duplicates
/// the secret scalar in memory, which defeats zeroization because the
/// clone would need to be dropped separately.  If you need to share the
/// public key, call `keypair.public_key().clone()` instead.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
// FIX: The original code had BOTH `#[derive(ZeroizeOnDrop)]` AND
// `#[zeroize(drop)]` on the struct.  `ZeroizeOnDrop` already generates
// a `Drop` impl that calls zeroize().  Adding `#[zeroize(drop)]`
// generates a SECOND `Drop` impl, which Rust forbids:
//   "conflicting implementations of trait `Drop` for type `Keypair`"
// Solution: remove `#[zeroize(drop)]` entirely.  `ZeroizeOnDrop` alone
// is sufficient and correct.
pub struct Keypair {
    /// The secret scalar `x`.  Never log, print, or transmit this value.
    secret_key: Scalar,

    /// The public point `Y = x·G`.  Safe to share.
    public_key: Point,
}

impl Keypair {
    /// Generate a fresh keypair using a cryptographically secure RNG.
    ///
    /// # Arguments
    ///
    /// * `rng` — Use [`OsRng`][rand::rngs::OsRng] in production.
    ///   Use [`DeterministicRng`][crate::test_utils::DeterministicRng]
    ///   only in tests.
    pub fn generate<R: RngCore>(rng: &mut R) -> Result<Self> {
        let secret_key = Scalar::random(rng);
        let public_key = &secret_key * &BASEPOINT;
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Return a reference to the public key.  Safe to share freely.
    pub fn public_key(&self) -> &Point {
        &self.public_key
    }

    /// Return a reference to the secret key.
    ///
    /// ⚠️ **Never log, print, or transmit this value.**
    pub fn secret_key(&self) -> &Scalar {
        &self.secret_key
    }
}

// ---------------------------------------------------------------------------
// Debug — secret key is always redacted
// ---------------------------------------------------------------------------

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("secret_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::DeterministicRng;

    #[test]
    fn generate_succeeds() {
        assert!(Keypair::generate(&mut DeterministicRng::new(1)).is_ok());
    }

    #[test]
    fn public_key_equals_secret_times_basepoint() {
        let kp = Keypair::generate(&mut DeterministicRng::new(2)).unwrap();
        assert_eq!(kp.public_key(), &(kp.secret_key() * &BASEPOINT));
    }

    #[test]
    fn different_seeds_give_different_keypairs() {
        let kp1 = Keypair::generate(&mut DeterministicRng::new(10)).unwrap();
        let kp2 = Keypair::generate(&mut DeterministicRng::new(11)).unwrap();
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn debug_does_not_expose_secret_key() {
        let kp = Keypair::generate(&mut DeterministicRng::new(20)).unwrap();
        let s = format!("{:?}", kp);
        assert!(s.contains("redacted"));
        assert!(!s.contains(&hex::encode(kp.secret_key().to_bytes())));
    }

    #[test]
    fn serde_round_trip() {
        let kp = Keypair::generate(&mut DeterministicRng::new(30)).unwrap();
        let json = serde_json::to_string(&kp).unwrap();
        let recovered: Keypair = serde_json::from_str(&json).unwrap();
        assert_eq!(kp.public_key(), recovered.public_key());
        assert_eq!(kp.secret_key(), recovered.secret_key());
    }
}