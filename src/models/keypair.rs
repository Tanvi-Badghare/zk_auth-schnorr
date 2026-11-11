//! Public/private key pairs for zk-auth.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::curves::{Point, Scalar, BASEPOINT};
use crate::errors::Result;

// ---------------------------------------------------------------------------
// Keypair
// ---------------------------------------------------------------------------

// FIX: do NOT derive Serialize/Deserialize directly on a ZeroizeOnDrop type.
// The derived Deserialize constructs a temporary that gets dropped before
// the value is returned — ZeroizeOnDrop fires on the temp and wipes the
// secret key, so serde_round_trip always fails the secret_key equality check.
//
// Fix: implement Serialize/Deserialize manually via a plain shadow struct
// that has no ZeroizeOnDrop, then move the fields into a real Keypair.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    secret_key: Scalar,
    #[zeroize(skip)]
    public_key: Point,
}

#[derive(Serialize, Deserialize)]
struct KeypairSerde {
    secret_key: Scalar,
    public_key: Point,
}

impl Serialize for Keypair {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        KeypairSerde {
            secret_key: self.secret_key.clone(),
            public_key: self.public_key.clone(),
        }
        .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for Keypair {
    fn deserialize<D: Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        let s = KeypairSerde::deserialize(de)?;
        Ok(Self {
            secret_key: s.secret_key,
            public_key: s.public_key,
        })
    }
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