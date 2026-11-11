//! Schnorr Identification Protocol over Ristretto.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::curves::{Point, Scalar, BASEPOINT};
use crate::crypto::fiat_shamir::Transcript;

const SCHNORR_DOMAIN: &str = "zkauth-schnorr-v1";

/// A Schnorr proof of knowledge of discrete log.
///
/// # Fields
///
/// * `commitment` — `R = k·G` for a random nonce `k`
/// * `response`   — `s = k + e·x mod q`
// FIX: do NOT derive Serialize/Deserialize — SchnorrProof contains Point and
// Scalar whose serde impls use serialize_bytes, which JSON round-trips as an
// integer sequence that cannot be deserialized back as &[u8].
// Instead, implement manually via a [u8; 64] shadow that JSON handles cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchnorrProof {
    pub commitment: Point,
    pub response: Scalar,
}

#[derive(Serialize, Deserialize)]
struct SchnorrRaw {
    commitment: [u8; 32],
    response: [u8; 32],
}

impl Serialize for SchnorrProof {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        SchnorrRaw {
            commitment: self.commitment.to_bytes(),
            response: self.response.to_bytes(),
        }
        .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for SchnorrProof {
    fn deserialize<D: Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        let raw = SchnorrRaw::deserialize(de)?;
        let commitment = Point::from_bytes(&raw.commitment)
            .map_err(|e| serde::de::Error::custom(format!("invalid commitment: {e}")))?;
        let response = Scalar::from_bytes(&raw.response)
            .map_err(|e| serde::de::Error::custom(format!("invalid response: {e}")))?;
        Ok(Self { commitment, response })
    }
}

impl SchnorrProof {
    pub fn prove<R: RngCore + CryptoRng>(
        secret: &Scalar,
        public: &Point,
        message: &[u8],
        rng: &mut R,
    ) -> Self {
        let nonce = Scalar::random(rng);
        let commitment = &nonce * &BASEPOINT;
        let challenge = Self::compute_challenge(&commitment, public, message);
        let response = &nonce + &(&challenge * secret);
        SchnorrProof { commitment, response }
    }

    pub fn verify(&self, public: &Point, message: &[u8]) -> bool {
        let challenge = Self::compute_challenge(&self.commitment, public, message);
        let lhs = &self.response * &BASEPOINT;
        let rhs = &self.commitment + &(&challenge * public);
        lhs == rhs
    }

    fn compute_challenge(commitment: &Point, public: &Point, message: &[u8]) -> Scalar {
        let mut transcript = Transcript::new(SCHNORR_DOMAIN);
        transcript.append_point("commitment", commitment);
        transcript.append_point("public_key", public);
        transcript.append_message("message", message);
        transcript.challenge_scalar("challenge")
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.commitment.to_bytes());
        out[32..].copy_from_slice(&self.response.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> crate::errors::Result<Self> {
        let mut c_bytes = [0u8; 32];
        let mut r_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&bytes[..32]);
        r_bytes.copy_from_slice(&bytes[32..]);
        let commitment = Point::from_bytes(&c_bytes)?;
        let response = Scalar::from_bytes(&r_bytes)?;
        Ok(Self { commitment, response })
    }

    pub fn serialized_size(&self) -> usize {
        64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn schnorr_proof_verifies() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;
        let proof = SchnorrProof::prove(&secret, &public, b"test message", &mut rng);
        assert!(proof.verify(&public, b"test message"));
    }

    #[test]
    fn wrong_message_fails() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;
        let proof = SchnorrProof::prove(&secret, &public, b"msg1", &mut rng);
        assert!(!proof.verify(&public, b"msg2"));
    }

    #[test]
    fn wrong_public_key_fails() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;
        let wrong_s = Scalar::random(&mut rng);
        let wrong_p = &wrong_s * &BASEPOINT;
        let proof = SchnorrProof::prove(&secret, &public, b"msg", &mut rng);
        assert!(!proof.verify(&wrong_p, b"msg"));
    }

    #[test]
    fn bytes_round_trip() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;
        let proof = SchnorrProof::prove(&secret, &public, b"msg", &mut rng);
        let bytes = proof.to_bytes();
        let recovered = SchnorrProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof, recovered);
    }

    #[test]
    fn serde_json_round_trip() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;
        let proof = SchnorrProof::prove(&secret, &public, b"msg", &mut rng);
        let json = serde_json::to_string(&proof).unwrap();
        let recovered: SchnorrProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, recovered);
    }

    #[test]
    fn tampered_commitment_fails() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;
        let mut proof = SchnorrProof::prove(&secret, &public, b"msg", &mut rng);
        proof.commitment = &proof.commitment + &BASEPOINT;
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