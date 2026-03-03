//! Schnorr Identification Protocol over Ristretto.
//!
//! Proves knowledge of a secret scalar `x` such that:
//!     Y = x * G
//! without revealing `x`.
//!
//! ## Challenge derivation
//!
//! The challenge `e` is computed via the Fiat–Shamir `Transcript`:
//!
//! ```text
//! e = H("zkauth-schnorr-v1" || "commitment": R || "public_key": Y || "message": msg)
//! ```
//!
//! This is NOT the same domain as registration or authentication —
//! those protocols build their own transcripts and pass the resulting
//! `binding` bytes as the `message` argument here.  The separation means
//! this module is a general Schnorr primitive that the protocol layer
//! specialises via the message binding.

use rand::{CryptoRng, RngCore};
// FIX: was `use rand_core::{CryptoRng, RngCore}` — rand_core is not a direct
// dependency.  `rand` re-exports both traits and IS in Cargo.toml.

use serde::{Deserialize, Serialize};

use crate::crypto::curves::{Point, Scalar, BASEPOINT};
use crate::crypto::fiat_shamir::Transcript;
// FIX: was `use crate::crypto::fiat_shamir::compute_challenge` — that function
// does not exist.  The correct abstraction is Transcript, which the protocol
// layer constructs and passes down as `message` bytes.  The Schnorr primitive
// itself uses a minimal internal transcript so that:
//   1. prove() and verify() are self-contained.
//   2. The protocol layer controls domain separation via the message binding.

// ---------------------------------------------------------------------------
// Domain constant
// ---------------------------------------------------------------------------

/// Internal Fiat–Shamir domain for the raw Schnorr primitive.
///
/// The protocol layer (registration, authentication) wraps this by passing
/// its own domain-separated transcript digest as `message`.  This domain
/// acts as a second layer of separation so that a raw SchnorrProof cannot
/// be confused with a protocol-level proof even if the message bytes collide.
const SCHNORR_DOMAIN: &str = "zkauth-schnorr-v1";

// ---------------------------------------------------------------------------
// SchnorrProof
// ---------------------------------------------------------------------------

/// A Schnorr proof of knowledge of discrete log.
///
/// Proves that the prover knows `x` such that `Y = x·G`,
/// without revealing `x`.
///
/// # Fields
///
/// * `commitment` — `R = k·G` for a random nonce `k`
/// * `response`   — `s = k + e·x mod q`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrProof {
    pub commitment: Point,
    pub response: Scalar,
}

impl SchnorrProof {
    /// Create a Schnorr proof.
    ///
    /// Proves knowledge of `secret` such that `public = secret·G`.
    ///
    /// # Arguments
    ///
    /// * `secret`  — The prover's private scalar `x`.
    /// * `public`  — The corresponding public point `Y = x·G`.
    /// * `message` — Arbitrary binding data (typically a transcript digest
    ///               produced by the protocol layer).
    /// * `rng`     — Cryptographically secure randomness source.
    ///
    /// # Protocol
    ///
    /// ```text
    /// k  ←$ Zq                    (random nonce)
    /// R  = k·G                    (commitment)
    /// e  = H(domain ‖ R ‖ Y ‖ message)   (challenge)
    /// s  = k + e·x  (mod q)       (response)
    /// ```
    pub fn prove<R: RngCore + CryptoRng>(
        secret: &Scalar,
        public: &Point,
        message: &[u8],
        rng: &mut R,
    ) -> Self {
        // Step 1: Sample random nonce — MUST be fresh and unpredictable.
        // Reusing a nonce with two different challenges leaks `x` algebraically.
        let nonce = Scalar::random(rng);

        // Step 2: Commitment R = k·G
        let commitment = &nonce * &BASEPOINT;

        // Step 3: Fiat–Shamir challenge
        let challenge = Self::compute_challenge(&commitment, public, message);

        // Step 4: Response s = k + e·x  (mod q)
        let response = &nonce + &(&challenge * secret);

        SchnorrProof {
            commitment,
            response,
        }
    }

    /// Verify a Schnorr proof.
    ///
    /// Returns `true` if and only if `s·G == R + e·Y`.
    ///
    /// # Arguments
    ///
    /// * `public`  — The claimed public key `Y`.
    /// * `message` — The same binding data used during [`prove`][Self::prove].
    pub fn verify(&self, public: &Point, message: &[u8]) -> bool {
        // Recompute challenge from the same transcript inputs.
        let challenge = Self::compute_challenge(&self.commitment, public, message);

        // Left side:  s·G
        let lhs = &self.response * &BASEPOINT;

        // Right side: R + e·Y
        let rhs = &self.commitment + &(&challenge * public);

        // Constant-time equality from dalek — no branch on secret data.
        lhs == rhs
    }

    /// Compute the Fiat–Shamir challenge for this proof.
    ///
    /// Both `prove` and `verify` call this function so they hash
    /// exactly the same byte sequence.  This is the single source of
    /// truth for the challenge derivation.
    ///
    /// ```text
    /// e = H("zkauth-schnorr-v1"
    ///        ‖ "commitment": R
    ///        ‖ "public_key": Y
    ///        ‖ "message":    msg)
    /// ```
    fn compute_challenge(commitment: &Point, public: &Point, message: &[u8]) -> Scalar {
        let mut transcript = Transcript::new(SCHNORR_DOMAIN);
        transcript.append_point("commitment", commitment);
        transcript.append_point("public_key", public);
        transcript.append_message("message", message);
        transcript.challenge_scalar("challenge")
    }

    /// Serialize to a fixed 64-byte array: `commitment ‖ response`.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.commitment.to_bytes());
        out[32..].copy_from_slice(&self.response.to_bytes());
        out
    }

    /// Deserialize from a 64-byte array.
    pub fn from_bytes(bytes: &[u8; 64]) -> crate::errors::Result<Self> {
        let mut c_bytes = [0u8; 32];
        let mut r_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&bytes[..32]);
        r_bytes.copy_from_slice(&bytes[32..]);

        let commitment = Point::from_bytes(&c_bytes)?;
        let response   = Scalar::from_bytes(&r_bytes)?;

        Ok(Self { commitment, response })
    }

    /// Returns the serialized byte length (always 64).
    pub fn serialized_size(&self) -> usize {
        64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    // FIX: was `use rand_core::OsRng` — use rand::rngs::OsRng instead.

    #[test]
    fn schnorr_proof_verifies() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;
        let proof  = SchnorrProof::prove(&secret, &public, b"test message", &mut rng);
        assert!(proof.verify(&public, b"test message"));
    }

    #[test]
    fn wrong_message_fails() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;
        let proof  = SchnorrProof::prove(&secret, &public, b"msg1", &mut rng);
        assert!(!proof.verify(&public, b"msg2"));
    }

    #[test]
    fn wrong_public_key_fails() {
        let mut rng = OsRng;
        let secret  = Scalar::random(&mut rng);
        let public  = &secret * &BASEPOINT;
        let wrong_s = Scalar::random(&mut rng);
        let wrong_p = &wrong_s * &BASEPOINT;
        let proof   = SchnorrProof::prove(&secret, &public, b"msg", &mut rng);
        assert!(!proof.verify(&wrong_p, b"msg"));
    }

    #[test]
    fn bytes_round_trip() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;
        let proof  = SchnorrProof::prove(&secret, &public, b"msg", &mut rng);
        let bytes  = proof.to_bytes();
        let recovered = SchnorrProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof, recovered);
    }

    #[test]
    fn tampered_commitment_fails() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;
        let mut proof = SchnorrProof::prove(&secret, &public, b"msg", &mut rng);
        proof.commitment = &proof.commitment + &BASEPOINT; // shift by G
        assert!(!proof.verify(&public, b"msg"));
    }

    #[test]
    fn tampered_response_fails() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;
        let mut proof = SchnorrProof::prove(&secret, &public, b"msg", &mut rng);
        let delta = Scalar::random(&mut rng);
        proof.response = &proof.response + &delta;
        assert!(!proof.verify(&public, b"msg"));
    }
}