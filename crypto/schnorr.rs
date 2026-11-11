//! Schnorr identification protocol (non-interactive via Fiat–Shamir).
//!
//! This module implements the classic Schnorr sigma protocol, made
//! non-interactive through the Fiat–Shamir heuristic.
//!
//! ## Protocol overview
//!
//! The prover wants to prove knowledge of a secret scalar `x` such that
//! `Y = x * G`, where `G` is the basepoint and `Y` is the public key.
//!
//! **Interactive version** (3 moves):
//! 1. **Commitment**: Prover picks random `k`, sends `R = k * G`.
//! 2. **Challenge**: Verifier picks random `c`, sends `c`.
//! 3. **Response**: Prover sends `s = k + c·x`.
//! 4. **Verification**: Verifier checks `s * G = R + c * Y`.
//!
//! **Non-interactive version** (Fiat–Shamir):
//! - Replace the random challenge `c` with `c = Hash(domain || R || Y || message)`.
//! - The proof is `(R, s)`.
//! - Verifier recomputes `c` and checks the equation.
//!
//! ## API
//!
//! * [`prove`] — Generate a Schnorr proof.
//! * [`verify`] — Verify a Schnorr proof.
//! * [`SchnorrProof`] — The proof object `(R, s)`.

use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::curves::{Point, Scalar, BASEPOINT};
use super::hash::Hasher;
use crate::config::{POINT_BYTE_LEN, SCALAR_BYTE_LEN};
use crate::errors::{Result, ZkAuthError};

// ---------------------------------------------------------------------------
// SchnorrProof struct
// ---------------------------------------------------------------------------

/// A Schnorr proof: `(R, s)` where `R` is a commitment and `s` is the response.
///
/// Serializes to exactly 64 bytes: 32 for `R` (compressed point), 32 for `s` (scalar).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrProof {
    /// The commitment: `R = k * G` where `k` is the prover's random nonce.
    pub commitment: Point,

    /// The response: `s = k + c·x` where `c` is the challenge and `x` is the secret key.
    pub response: Scalar,
}

impl SchnorrProof {
    /// Serialize this proof to exactly 64 bytes.
    ///
    /// Format: `[R (32 bytes) || s (32 bytes)]`.
    pub fn to_bytes(&self) -> [u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN] {
        let mut bytes = [0u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN];
        bytes[..POINT_BYTE_LEN].copy_from_slice(&self.commitment.to_bytes());
        bytes[POINT_BYTE_LEN..].copy_from_slice(&self.response.to_bytes());
        bytes
    }

    /// Deserialize a proof from exactly 64 bytes.
    ///
    /// Returns [`ZkAuthError::DeserializationError`] if the bytes do not
    /// represent a valid proof (e.g., `R` is not a valid point).
    pub fn from_bytes(bytes: &[u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN]) -> Result<Self> {
        let r_bytes: [u8; POINT_BYTE_LEN] = bytes[..POINT_BYTE_LEN]
            .try_into()
            .map_err(|_| {
                ZkAuthError::DeserializationError("proof commitment (R) wrong length".to_string())
            })?;
        let s_bytes: [u8; SCALAR_BYTE_LEN] = bytes[POINT_BYTE_LEN..]
            .try_into()
            .map_err(|_| {
                ZkAuthError::DeserializationError("proof response (s) wrong length".to_string())
            })?;

        let commitment = Point::from_bytes(&r_bytes)?;
        let response = Scalar::from_bytes(&s_bytes)?;

        Ok(Self {
            commitment,
            response,
        })
    }

    /// Return the serialized size in bytes (always 64).
    ///
    /// This method exists so that `main.rs` and benchmarks can report
    /// proof sizes without hardcoding the constant.
    pub fn serialized_size(&self) -> usize {
        POINT_BYTE_LEN + SCALAR_BYTE_LEN
    }
}

// ---------------------------------------------------------------------------
// Proving
// ---------------------------------------------------------------------------

/// Generate a Schnorr proof of knowledge of `secret_key`.
///
/// # Arguments
///
/// * `secret_key` — The secret scalar `x` that the prover knows.
/// * `public_key` — The public key `Y = x * G`.  The caller must ensure
///   this matches `secret_key * BASEPOINT`.
/// * `message` — Arbitrary bytes to bind into the proof (prevents proof
///   from being reused for a different message).
/// * `domain` — A domain separator string (e.g., `"registration-v1"`).
///   Prevents cross-protocol attacks.
/// * `rng` — A cryptographically secure random number generator.
///
/// # Returns
///
/// A [`SchnorrProof`] that can be verified via [`verify`].
///
/// # Example
/// ```ignore
/// use rand::rngs::OsRng;
/// use zk_auth::crypto::{Scalar, BASEPOINT, schnorr};
///
/// let mut rng = OsRng;
/// let secret = Scalar::random(&mut rng);
/// let public = secret * BASEPOINT;
///
/// let proof = schnorr::prove(&secret, &public, b"hello", "example-v1", &mut rng)?;
/// assert!(schnorr::verify(&proof, &public, b"hello", "example-v1")?);
/// ```
pub fn prove<R: RngCore>(
    secret_key: &Scalar,
    public_key: &Point,
    message: &[u8],
    domain: &str,
    rng: &mut R,
) -> Result<SchnorrProof> {
    // 1. Generate random nonce k.
    let nonce = Scalar::random(rng);

    // 2. Compute commitment R = k * G.
    let commitment = &nonce * &BASEPOINT;

    // 3. Compute challenge c = Hash(domain || R || Y || message).
    let challenge = compute_challenge(domain, &commitment, public_key, message);

    // 4. Compute response s = k + c·x.
    let response = nonce + (&challenge * secret_key);

    Ok(SchnorrProof {
        commitment,
        response,
    })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a Schnorr proof.
///
/// # Arguments
///
/// * `proof` — The proof `(R, s)` to verify.
/// * `public_key` — The public key `Y` that the prover claims to know the
///   discrete log of.
/// * `message` — The same message bytes that were passed to [`prove`].
/// * `domain` — The same domain separator that was passed to [`prove`].
///
/// # Returns
///
/// `Ok(true)` if the proof is valid, `Ok(false)` if it is invalid.
///
/// # Verification equation
///
/// The verifier checks: `s * G = R + c * Y`, where `c` is recomputed as
/// `Hash(domain || R || Y || message)`.
///
/// # Example
/// ```ignore
/// # use zk_auth::crypto::schnorr;
/// # let proof = ...; // from prove()
/// # let public_key = ...;
/// let is_valid = schnorr::verify(&proof, &public_key, b"hello", "example-v1")?;
/// assert!(is_valid);
/// ```
pub fn verify(
    proof: &SchnorrProof,
    public_key: &Point,
    message: &[u8],
    domain: &str,
) -> Result<bool> {
    // 1. Recompute challenge c = Hash(domain || R || Y || message).
    let challenge = compute_challenge(domain, &proof.commitment, public_key, message);

    // 2. Compute left-hand side: s * G.
    let lhs = &proof.response * &BASEPOINT;

    // 3. Compute right-hand side: R + c * Y.
    let rhs = &proof.commitment + (&challenge * public_key);

    // 4. Check equality.
    Ok(lhs == rhs)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute the Fiat–Shamir challenge: `c = Hash(domain || R || Y || message)`.
///
/// The hash output (32 bytes) is reduced modulo the group order to produce
/// a valid scalar.  This reduction is done via `Scalar::from_bytes_mod_order`,
/// which never fails (unlike `from_bytes`, which rejects values >= the order).
fn compute_challenge(domain: &str, commitment: &Point, public_key: &Point, message: &[u8]) -> Scalar {
    let mut hasher = Hasher::new();

    // Hash in a specific order: domain, R, Y, message.
    hasher.update(domain.as_bytes());
    hasher.update(&commitment.to_bytes());
    hasher.update(&public_key.to_bytes());
    hasher.update(message);

    let digest = hasher.finalize();

    // Convert hash to scalar via reduction modulo group order.
    // This is always safe (no Result needed).
    Scalar(curve25519_dalek::Scalar::from_bytes_mod_order(digest))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::DeterministicRng;

    // --- Happy path -------------------------------------------------------

    #[test]
    fn prove_and_verify_success() {
        let mut rng = DeterministicRng::new(1);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof = prove(&secret, &public, b"test message", "test-domain", &mut rng).unwrap();
        let valid = verify(&proof, &public, b"test message", "test-domain").unwrap();

        assert!(valid, "valid proof must verify");
    }

    // --- Domain separation ------------------------------------------------

    #[test]
    fn different_domain_fails_verification() {
        let mut rng = DeterministicRng::new(2);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof = prove(&secret, &public, b"msg", "domain-A", &mut rng).unwrap();
        let valid = verify(&proof, &public, b"msg", "domain-B").unwrap();

        assert!(!valid, "proof from domain-A must not verify in domain-B");
    }

    // --- Message binding --------------------------------------------------

    #[test]
    fn different_message_fails_verification() {
        let mut rng = DeterministicRng::new(3);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof = prove(&secret, &public, b"message-A", "domain", &mut rng).unwrap();
        let valid = verify(&proof, &public, b"message-B", "domain").unwrap();

        assert!(!valid, "proof for message-A must not verify for message-B");
    }

    // --- Tampered proof ---------------------------------------------------

    #[test]
    fn tampered_commitment_fails_verification() {
        let mut rng = DeterministicRng::new(4);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let mut proof = prove(&secret, &public, b"msg", "domain", &mut rng).unwrap();

        // Tamper with the commitment.
        proof.commitment = Scalar::random(&mut rng) * BASEPOINT;

        let valid = verify(&proof, &public, b"msg", "domain").unwrap();
        assert!(!valid, "tampered commitment must fail verification");
    }

    #[test]
    fn tampered_response_fails_verification() {
        let mut rng = DeterministicRng::new(5);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let mut proof = prove(&secret, &public, b"msg", "domain", &mut rng).unwrap();

        // Tamper with the response.
        proof.response = Scalar::random(&mut rng);

        let valid = verify(&proof, &public, b"msg", "domain").unwrap();
        assert!(!valid, "tampered response must fail verification");
    }

    // --- Serialization ----------------------------------------------------

    #[test]
    fn proof_serialization_round_trips() {
        let mut rng = DeterministicRng::new(6);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof = prove(&secret, &public, b"msg", "domain", &mut rng).unwrap();
        let bytes = proof.to_bytes();
        let recovered = SchnorrProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof, recovered);
    }

    #[test]
    fn proof_serialized_size_is_64() {
        let mut rng = DeterministicRng::new(7);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof = prove(&secret, &public, b"msg", "domain", &mut rng).unwrap();
        assert_eq!(proof.serialized_size(), 64);
        assert_eq!(proof.to_bytes().len(), 64);
    }

    #[test]
    fn proof_from_bytes_rejects_wrong_length() {
        // Try to deserialize 32 bytes (should be 64).
        let short_bytes = [0u8; 32];
        // This won't even compile because from_bytes takes &[u8; 64].
        // So we test that the type signature enforces the length.

        // Instead, test that invalid point/scalar bytes are rejected.
        let mut bad_bytes = [0u8; 64];
        // Set the first 32 bytes to invalid point data.
        bad_bytes[..32].copy_from_slice(&[0xFF; 32]);

        assert!(SchnorrProof::from_bytes(&bad_bytes).is_err());
    }

    // --- Serde ------------------------------------------------------------

    #[test]
    fn proof_serde_round_trips() {
        let mut rng = DeterministicRng::new(8);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof = prove(&secret, &public, b"msg", "domain", &mut rng).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let recovered: SchnorrProof = serde_json::from_str(&json).unwrap();

        assert_eq!(proof, recovered);
    }

    // --- Edge cases -------------------------------------------------------

    #[test]
    fn empty_message_is_valid() {
        let mut rng = DeterministicRng::new(9);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof = prove(&secret, &public, b"", "domain", &mut rng).unwrap();
        let valid = verify(&proof, &public, b"", "domain").unwrap();

        assert!(valid);
    }

    #[test]
    fn empty_domain_is_valid() {
        // Empty domain is allowed (though not recommended in production).
        let mut rng = DeterministicRng::new(10);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof = prove(&secret, &public, b"msg", "", &mut rng).unwrap();
        let valid = verify(&proof, &public, b"msg", "").unwrap();

        assert!(valid);
    }

    #[test]
    fn deterministic_rng_produces_deterministic_proofs() {
        let secret = Scalar::random(&mut DeterministicRng::new(100));
        let public = &secret * &BASEPOINT;

        // Same seed → same nonce → same proof.
        let proof1 = prove(&secret, &public, b"msg", "domain", &mut DeterministicRng::new(200)).unwrap();
        let proof2 = prove(&secret, &public, b"msg", "domain", &mut DeterministicRng::new(200)).unwrap();

        assert_eq!(proof1, proof2);
    }
}