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
//!
//! ## Serialization
//!
//! ⚠️ **WARNING**: [`Keypair`] serializes **both** the public and secret keys.
//! Do not store serialized keypairs in plaintext in production.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::curves::{Point, Scalar, BASEPOINT};
use crate::errors::Result;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    /// The secret scalar `x`.  Never log, print, or transmit this value.
    secret_key: Scalar,

    /// The public point `Y = x·G`.  Safe to share.
    /// Marked skip because RistrettoPoint does not implement Zeroize —
    /// dalek omits it for public types. Only secret_key needs zeroization.
    #[zeroize(skip)]
    public_key: Point,
}

impl Keypair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let secret_key = Scalar::random(rng);
        let public_key = &secret_key * &BASEPOINT;
        Ok(Self { secret_key, public_key })
    }

    pub fn public_key(&self) -> &Point {
        &self.public_key
    }

    /// ⚠️ Never log, print, or transmit this value.
    pub fn secret_key(&self) -> &Scalar {
        &self.secret_key
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("secret_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // FIX: lib.rs declares `#[cfg(test)] pub mod test_utils` at the crate root,
    // so the correct path is crate::test_utils, not crate::tests::test_utils.
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