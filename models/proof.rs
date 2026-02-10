//! Proof types for registration and authentication.
//!
//! This module defines two proof types, both wrapping [`SchnorrProof`][crate::crypto::schnorr::SchnorrProof]:
//!
//! * [`RegistrationProof`] — Created during user registration to prove
//!   knowledge of the secret key.
//! * [`AuthenticationProof`] — Created during login to prove identity.
//!
//! ## Why separate types?
//!
//! Although both are Schnorr proofs under the hood, keeping them as distinct
//! types provides **compile-time safety**.  A [`RegistrationProof`] cannot
//! accidentally be verified as an [`AuthenticationProof`] (and vice-versa)
//! because they use different domain separators in the Fiat–Shamir challenge.
//!
//! The newtype wrapper is zero-cost at runtime.

use serde::{Deserialize, Serialize};

use crate::config::{POINT_BYTE_LEN, SCALAR_BYTE_LEN};
use crate::crypto::schnorr::SchnorrProof;
use crate::errors::Result;

// ---------------------------------------------------------------------------
// RegistrationProof
// ---------------------------------------------------------------------------

/// A zero-knowledge proof created during user registration.
///
/// This proves that the prover knows the secret key corresponding to their
/// claimed public key, without revealing the secret.
///
/// Internally, this is a Schnorr proof with domain separator `"registration"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationProof(pub(crate) SchnorrProof);

impl RegistrationProof {
    /// Serialize this proof to exactly 64 bytes.
    ///
    /// Format: `[commitment (32 bytes) || response (32 bytes)]`.
    pub fn to_bytes(&self) -> [u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN] {
        self.0.to_bytes()
    }

    /// Deserialize a proof from exactly 64 bytes.
    ///
    /// Returns an error if the bytes do not represent a valid proof.
    pub fn from_bytes(bytes: &[u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN]) -> Result<Self> {
        SchnorrProof::from_bytes(bytes).map(Self)
    }

    /// Return the serialized size in bytes (always 64).
    pub fn serialized_size(&self) -> usize {
        self.0.serialized_size()
    }

    /// Expose the inner [`SchnorrProof`] for use by the protocol layer.
    ///
    /// This is `pub(crate)` so only internal modules (protocol, auth) can
    /// access it.  External code sees only the newtype.
    pub(crate) fn inner(&self) -> &SchnorrProof {
        &self.0
    }

    /// Construct a [`RegistrationProof`] from a [`SchnorrProof`].
    ///
    /// This is `pub(crate)` so only internal modules can create it.
    pub(crate) fn from_schnorr(proof: SchnorrProof) -> Self {
        Self(proof)
    }
}

// ---------------------------------------------------------------------------
// AuthenticationProof
// ---------------------------------------------------------------------------

/// A zero-knowledge proof created during user authentication (login).
///
/// This proves that the prover knows the secret key corresponding to their
/// public key, without revealing the secret.
///
/// Internally, this is a Schnorr proof with domain separator `"authentication"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationProof(pub(crate) SchnorrProof);

impl AuthenticationProof {
    /// Serialize this proof to exactly 64 bytes.
    ///
    /// Format: `[commitment (32 bytes) || response (32 bytes)]`.
    pub fn to_bytes(&self) -> [u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN] {
        self.0.to_bytes()
    }

    /// Deserialize a proof from exactly 64 bytes.
    ///
    /// Returns an error if the bytes do not represent a valid proof.
    pub fn from_bytes(bytes: &[u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN]) -> Result<Self> {
        SchnorrProof::from_bytes(bytes).map(Self)
    }

    /// Return the serialized size in bytes (always 64).
    pub fn serialized_size(&self) -> usize {
        self.0.serialized_size()
    }

    /// Expose the inner [`SchnorrProof`] for use by the protocol layer.
    ///
    /// This is `pub(crate)` so only internal modules (protocol, auth) can
    /// access it.  External code sees only the newtype.
    pub(crate) fn inner(&self) -> &SchnorrProof {
        &self.0
    }

    /// Construct an [`AuthenticationProof`] from a [`SchnorrProof`].
    ///
    /// This is `pub(crate)` so only internal modules can create it.
    pub(crate) fn from_schnorr(proof: SchnorrProof) -> Self {
        Self(proof)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curves::{Scalar, BASEPOINT};
    use crate::crypto::schnorr;
    use crate::test_utils::DeterministicRng;

    // --- RegistrationProof ------------------------------------------------

    #[test]
    fn registration_proof_serialization_round_trips() {
        let mut rng = DeterministicRng::new(1);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let schnorr_proof =
            schnorr::prove(&secret, &public, b"test", "registration", &mut rng).unwrap();
        let proof = RegistrationProof::from_schnorr(schnorr_proof);

        let bytes = proof.to_bytes();
        let recovered = RegistrationProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof, recovered);
    }

    #[test]
    fn registration_proof_serialized_size_is_64() {
        let mut rng = DeterministicRng::new(2);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let schnorr_proof =
            schnorr::prove(&secret, &public, b"test", "registration", &mut rng).unwrap();
        let proof = RegistrationProof::from_schnorr(schnorr_proof);

        assert_eq!(proof.serialized_size(), 64);
        assert_eq!(proof.to_bytes().len(), 64);
    }

    #[test]
    fn registration_proof_from_bytes_rejects_invalid() {
        // All-zeros is not a valid Schnorr proof (invalid point).
        let bad_bytes = [0u8; 64];
        assert!(RegistrationProof::from_bytes(&bad_bytes).is_err());
    }

    #[test]
    fn registration_proof_serde_round_trips() {
        let mut rng = DeterministicRng::new(3);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let schnorr_proof =
            schnorr::prove(&secret, &public, b"test", "registration", &mut rng).unwrap();
        let proof = RegistrationProof::from_schnorr(schnorr_proof);

        let json = serde_json::to_string(&proof).unwrap();
        let recovered: RegistrationProof = serde_json::from_str(&json).unwrap();

        assert_eq!(proof, recovered);
    }

    // --- AuthenticationProof ----------------------------------------------

    #[test]
    fn authentication_proof_serialization_round_trips() {
        let mut rng = DeterministicRng::new(10);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let schnorr_proof =
            schnorr::prove(&secret, &public, b"test", "authentication", &mut rng).unwrap();
        let proof = AuthenticationProof::from_schnorr(schnorr_proof);

        let bytes = proof.to_bytes();
        let recovered = AuthenticationProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof, recovered);
    }

    #[test]
    fn authentication_proof_serialized_size_is_64() {
        let mut rng = DeterministicRng::new(11);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let schnorr_proof =
            schnorr::prove(&secret, &public, b"test", "authentication", &mut rng).unwrap();
        let proof = AuthenticationProof::from_schnorr(schnorr_proof);

        assert_eq!(proof.serialized_size(), 64);
        assert_eq!(proof.to_bytes().len(), 64);
    }

    #[test]
    fn authentication_proof_from_bytes_rejects_invalid() {
        // All-ones is likely not a valid Schnorr proof.
        let bad_bytes = [0xFFu8; 64];
        assert!(AuthenticationProof::from_bytes(&bad_bytes).is_err());
    }

    #[test]
    fn authentication_proof_serde_round_trips() {
        let mut rng = DeterministicRng::new(12);
        let secret = Scalar::random(&mut rng);
        let public = &secret * &BASEPOINT;

        let schnorr_proof =
            schnorr::prove(&secret, &public, b"test", "authentication", &mut rng).unwrap();
        let proof = AuthenticationProof::from_schnorr(schnorr_proof);

        let json = serde_json::to_string(&proof).unwrap();
        let recovered: AuthenticationProof = serde_json::from_str(&json).unwrap();

        assert_eq!(proof, recovered);
    }

    // --- Type safety ------------------------------------------------------

    #[test]
    fn registration_and_authentication_proofs_are_distinct_types() {
        // This test exists to document that the types are separate at
        // compile time.  You can't accidentally pass a RegistrationProof
        // where an AuthenticationProof is expected (and vice-versa).
        
        // The following would not compile:
        // fn takes_auth_proof(_: AuthenticationProof) {}
        // let reg_proof = RegistrationProof(...);
        // takes_auth_proof(reg_proof); // ← compile error
    }
}