//! Schnorr identification protocol (non-interactive via Fiat–Shamir).
//!
//! This module implements the classic Schnorr sigma protocol, made
//! non-interactive through the Fiat–Shamir heuristic.

use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::curves::{Point, Scalar, BASEPOINT};
use super::hash::{Hasher, hash_to_scalar};
use crate::config::{POINT_BYTE_LEN, SCALAR_BYTE_LEN};
use crate::errors::{Result, ZkAuthError};

// ---------------------------------------------------------------------------
// SchnorrProof
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrProof {
    pub commitment: Point,
    pub response: Scalar,
}

impl SchnorrProof {
    pub fn to_bytes(&self) -> [u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN] {
        let mut bytes = [0u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN];

        bytes[..POINT_BYTE_LEN].copy_from_slice(&self.commitment.to_bytes());
        bytes[POINT_BYTE_LEN..].copy_from_slice(&self.response.to_bytes());

        bytes
    }

    pub fn from_bytes(
        bytes: &[u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN],
    ) -> Result<Self> {
        let r_bytes: [u8; POINT_BYTE_LEN] =
            bytes[..POINT_BYTE_LEN].try_into().map_err(|_| {
                ZkAuthError::DeserializationError(
                    "proof commitment (R) wrong length".to_string(),
                )
            })?;

        let s_bytes: [u8; SCALAR_BYTE_LEN] =
            bytes[POINT_BYTE_LEN..].try_into().map_err(|_| {
                ZkAuthError::DeserializationError(
                    "proof response (s) wrong length".to_string(),
                )
            })?;

        let commitment = Point::from_bytes(&r_bytes)?;
        let response = Scalar::from_bytes(&s_bytes)?;

        Ok(Self {
            commitment,
            response,
        })
    }

    pub fn serialized_size(&self) -> usize {
        POINT_BYTE_LEN + SCALAR_BYTE_LEN
    }
}

// ---------------------------------------------------------------------------
// Prove
// ---------------------------------------------------------------------------

pub fn prove<R: RngCore>(
    secret_key: &Scalar,
    public_key: &Point,
    message: &[u8],
    domain: &str,
    rng: &mut R,
) -> Result<SchnorrProof> {
    // 1. Nonce
    let nonce = Scalar::random(rng);

    // 2. Commitment
    let commitment = &nonce * &BASEPOINT;

    // 3. Challenge
    let challenge = compute_challenge(domain, &commitment, public_key, message);

    // 4. Response
    let response = nonce + (&challenge * secret_key);

    Ok(SchnorrProof {
        commitment,
        response,
    })
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

pub fn verify(
    proof: &SchnorrProof,
    public_key: &Point,
    message: &[u8],
    domain: &str,
) -> Result<bool> {
    let challenge =
        compute_challenge(domain, &proof.commitment, public_key, message);

    let lhs = &proof.response * &BASEPOINT;
    let rhs = &proof.commitment + (&challenge * public_key);

    Ok(lhs == rhs)
}

// ---------------------------------------------------------------------------
// Fiat–Shamir challenge
// ---------------------------------------------------------------------------

fn compute_challenge(
    domain: &str,
    commitment: &Point,
    public_key: &Point,
    message: &[u8],
) -> Scalar {
    let mut hasher = Hasher::new();

    // Domain separation first
    hasher.update(domain.as_bytes());

    // Transcript elements
    hasher.update(&commitment.to_bytes());
    hasher.update(&public_key.to_bytes());
    hasher.update(message);

    let digest = hasher.finalize();

    // Reduce safely using abstraction
    hash_to_scalar(&digest)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::DeterministicRng;

    #[test]
    fn prove_and_verify_success() {
        let mut rng = DeterministicRng::new(1);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof =
            prove(&secret, &public, b"test message", "test-domain", &mut rng)
                .unwrap();

        let valid =
            verify(&proof, &public, b"test message", "test-domain").unwrap();

        assert!(valid);
    }

    #[test]
    fn different_domain_fails() {
        let mut rng = DeterministicRng::new(2);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof =
            prove(&secret, &public, b"msg", "A", &mut rng).unwrap();

        let valid =
            verify(&proof, &public, b"msg", "B").unwrap();

        assert!(!valid);
    }

    #[test]
    fn different_message_fails() {
        let mut rng = DeterministicRng::new(3);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof =
            prove(&secret, &public, b"A", "domain", &mut rng).unwrap();

        let valid =
            verify(&proof, &public, b"B", "domain").unwrap();

        assert!(!valid);
    }

    #[test]
    fn tampered_proof_fails() {
        let mut rng = DeterministicRng::new(4);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let mut proof =
            prove(&secret, &public, b"msg", "domain", &mut rng).unwrap();

        proof.response = Scalar::random(&mut rng);

        let valid =
            verify(&proof, &public, b"msg", "domain").unwrap();

        assert!(!valid);
    }

    #[test]
    fn serialization_round_trip() {
        let mut rng = DeterministicRng::new(5);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let proof =
            prove(&secret, &public, b"msg", "domain", &mut rng).unwrap();

        let bytes = proof.to_bytes();
        let recovered = SchnorrProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof, recovered);
    }
}