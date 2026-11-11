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
//! keypairs in plaintext in production.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::curves::{Point, Scalar, BASEPOINT};
use crate::errors::Result;

/// A public/private key pair for zk-auth.
///
/// Note: `Clone` is intentionally NOT implemented to prevent
/// accidental duplication of secret material in memory.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[zeroize(drop)]
pub struct Keypair {
    /// Secret scalar `x` (private).
    secret_key: Scalar,

    /// Public key `Y = x * G`.
    public_key: Point,
}

impl Keypair {
    /// Generate a fresh keypair using a cryptographically secure RNG.
    pub fn generate<R: RngCore>(rng: &mut R) -> Result<Self> {
        let secret_key = Scalar::random(rng);
        let public_key = &secret_key * &BASEPOINT;

        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Return a reference to the public key.
    pub fn public_key(&self) -> &Point {
        &self.public_key
    }

    /// Return a reference to the secret key.
    ///
    /// ⚠️ Never log or transmit this value.
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