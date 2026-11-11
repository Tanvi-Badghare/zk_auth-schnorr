//! Public/private key pairs for zk-auth.
//!
//! A [`Keypair`] consists of:
//! * A **secret key** (scalar `x`), kept private.
//! * A **public key** (point `Y = x * G`), shared with verifiers.
//!
//! ## Security
//!
//! The secret key is automatically zeroized when the [`Keypair`] is dropped
//! (via [`Zeroize`][zeroize::Zeroize] and [`ZeroizeOnDrop`][zeroize::ZeroizeOnDrop]).
//! This prevents it from lingering in memory.
//!
//! ## Serialization
//!
//! ⚠️ **WARNING**: [`Keypair`] serializes **both** the public and secret keys.
//! This is convenient for demos and tests, but **do not** store serialized
//! keypairs in plaintext in production.  Use encrypted storage or separate
//! the secret key into a secure keystore.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::curves::{Point, Scalar, BASEPOINT};
use crate::errors::Result;

// ---------------------------------------------------------------------------
// Keypair struct
// ---------------------------------------------------------------------------

/// A public/private key pair for zk-auth.
///
/// # Example
/// ```ignore
/// use rand::rngs::OsRng;
/// use zk_auth::models::Keypair;
///
/// let mut rng = OsRng;
/// let keypair = Keypair::generate(&mut rng)?;
///
/// println!("Public key: {}", keypair.public_key());
/// // Secret key is private; don't print it.
/// ```
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    /// The secret scalar `x`.  Kept private.
    secret_key: Scalar,

    /// The public point `Y = x * G`.  Shared with verifiers.
    public_key: Point,
}

impl Keypair {
    /// Generate a fresh keypair using a cryptographically secure RNG.
    ///
    /// The secret key `x` is chosen uniformly at random from the scalar field.
    /// The public key is computed as `Y = x * G`, where `G` is the Ristretto
    /// basepoint.
    ///
    /// # Arguments
    ///
    /// * `rng` — A source of randomness.  Use [`OsRng`][rand::rngs::OsRng]
    ///   for production, or [`DeterministicRng`][crate::test_utils::DeterministicRng]
    ///   for tests.
    ///
    /// # Example
    /// ```ignore
    /// use rand::rngs::OsRng;
    /// use zk_auth::models::Keypair;
    ///
    /// let keypair = Keypair::generate(&mut OsRng)?;
    /// ```
    pub fn generate<R: RngCore>(rng: &mut R) -> Result<Self> {
        let secret_key = Scalar::random(rng);
        let public_key = &secret_key * &BASEPOINT;
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Return a reference to the public key.
    ///
    /// This is safe to share with anyone.
    pub fn public_key(&self) -> &Point {
        &self.public_key
    }

    /// Return a reference to the secret key.
    ///
    /// ⚠️ **WARNING**: The secret key must never be transmitted or logged.
    /// Only use this when creating proofs.
    pub fn secret_key(&self) -> &Scalar {
        &self.secret_key
    }
}

// ---------------------------------------------------------------------------
// Debug impl (redact secret key)
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
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::DeterministicRng;

    // --- Key generation ---------------------------------------------------

    #[test]
    fn generate_produces_valid_keypair() {
        let mut rng = DeterministicRng::new(1);
        let keypair = Keypair::generate(&mut rng).unwrap();

        // Public key should equal secret * BASEPOINT.
        let expected_public = keypair.secret_key() * BASEPOINT;
        assert_eq!(keypair.public_key(), &expected_public);
    }

    #[test]
    fn different_rng_seeds_produce_different_keypairs() {
        let kp1 = Keypair::generate(&mut DeterministicRng::new(1)).unwrap();
        let kp2 = Keypair::generate(&mut DeterministicRng::new(2)).unwrap();

        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    // --- Accessors --------------------------------------------------------

    #[test]
    fn public_key_accessor_works() {
        let mut rng = DeterministicRng::new(10);
        let keypair = Keypair::generate(&mut rng).unwrap();
        let pk = keypair.public_key();

        // Should return a reference to the same point.
        assert_eq!(pk, &keypair.public_key);
    }

    #[test]
    fn secret_key_accessor_works() {
        let mut rng = DeterministicRng::new(11);
        let keypair = Keypair::generate(&mut rng).unwrap();
        let sk = keypair.secret_key();

        // Should return a reference to the same scalar.
        assert_eq!(sk, &keypair.secret_key);
    }

    // --- Serialization ----------------------------------------------------

    #[test]
    fn keypair_serde_round_trips() {
        let mut rng = DeterministicRng::new(20);
        let original = Keypair::generate(&mut rng).unwrap();

        let json = serde_json::to_string(&original).unwrap();
        let recovered: Keypair = serde_json::from_str(&json).unwrap();

        // Both public and secret keys should match.
        assert_eq!(original.public_key(), recovered.public_key());
        assert_eq!(original.secret_key(), recovered.secret_key());
    }

    // --- Debug ------------------------------------------------------------

    #[test]
    fn debug_does_not_print_secret_key() {
        let mut rng = DeterministicRng::new(30);
        let keypair = Keypair::generate(&mut rng).unwrap();

        let debug_str = format!("{:?}", keypair);

        // Should contain "redacted" instead of the actual secret.
        assert!(debug_str.contains("redacted"));
        assert!(!debug_str.contains(&hex::encode(keypair.secret_key().to_bytes())));
    }

    // --- Clone ------------------------------------------------------------

    #[test]
    fn keypair_clone_works() {
        let mut rng = DeterministicRng::new(40);
        let original = Keypair::generate(&mut rng).unwrap();
        let cloned = original.clone();

        assert_eq!(original.public_key(), cloned.public_key());
        assert_eq!(original.secret_key(), cloned.secret_key());
    }

    // --- Zeroize ----------------------------------------------------------

    #[test]
    fn keypair_is_zeroized_on_drop() {
        // We can't directly inspect memory after drop in safe Rust,
        // but this test documents the intent.  The Zeroize and ZeroizeOnDrop
        // derives ensure the secret_key (which is itself Zeroize) is wiped.
        let mut rng = DeterministicRng::new(50);
        let keypair = Keypair::generate(&mut rng).unwrap();
        let _public = keypair.public_key().clone();

        drop(keypair);

        // In an unsafe test or with a debugger, you'd verify memory is zeroed.
        // Here we just trust the zeroize crate.
    }
}