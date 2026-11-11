//! Schnorr Identification Protocol over Ristretto.
//!
//! Proves knowledge of a secret scalar `x` such that:
//!     P = x * G
//! without revealing `x`.

use crate::crypto::{Scalar, Point, BASEPOINT};
use crate::crypto::fiat_shamir::compute_challenge;
use rand_core::{CryptoRng, RngCore};

/// A Schnorr proof of knowledge.
///
/// Contains:
/// - commitment R
/// - response s
#[derive(Debug, Clone)]
pub struct SchnorrProof {
    pub commitment: Point,
    pub response: Scalar,
}

impl SchnorrProof {
    /// Create a new Schnorr proof.
    ///
    /// Proves knowledge of `secret` corresponding to `public`.
    pub fn prove<R: RngCore + CryptoRng>(
        secret: &Scalar,
        public: &Point,
        message: &[u8],
        rng: &mut R,
    ) -> Self {
        // Step 1: Sample random nonce
        let nonce = Scalar::random(rng);

        // Step 2: Compute commitment R = kG
        let commitment = &nonce * &BASEPOINT;

        // Step 3: Compute challenge
        let challenge = compute_challenge(&commitment, public, message);

        // Step 4: Compute response s = k + e*x
        let response = &nonce + &(&challenge * secret);

        SchnorrProof {
            commitment,
            response,
        }
    }

    /// Verify the Schnorr proof.
    ///
    /// Returns true if valid.
    pub fn verify(
        &self,
        public: &Point,
        message: &[u8],
    ) -> bool {
        // Recompute challenge
        let challenge = compute_challenge(&self.commitment, public, message);

        // Left side: sG
        let lhs = &self.response * &BASEPOINT;

        // Right side: R + eP
        let rhs = &self.commitment + &(&challenge * public);

        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn schnorr_proof_verifies() {
        let mut rng = OsRng;

        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let message = b"test message";

        let proof = SchnorrProof::prove(&secret, &public, message, &mut rng);

        assert!(proof.verify(&public, message));
    }

    #[test]
    fn schnorr_proof_fails_with_wrong_message() {
        let mut rng = OsRng;

        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof = SchnorrProof::prove(&secret, &public, b"msg1", &mut rng);

        assert!(!proof.verify(&public, b"msg2"));
    }

    #[test]
    fn schnorr_proof_fails_with_wrong_public_key() {
        let mut rng = OsRng;

        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let wrong_secret = Scalar::random(&mut rng);
        let wrong_public = &wrong_secret * &BASEPOINT;

        let proof = SchnorrProof::prove(&secret, &public, b"msg", &mut rng);

        assert!(!proof.verify(&wrong_public, b"msg"));
    }
}