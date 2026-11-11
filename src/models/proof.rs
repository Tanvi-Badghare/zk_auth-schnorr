//! Proof types for registration and authentication.

use serde::{Deserialize, Serialize};

use crate::config::{POINT_BYTE_LEN, SCALAR_BYTE_LEN};
use crate::crypto::schnorr::SchnorrProof;
use crate::errors::Result;

/// Proof created during user registration.
///
/// Internally a Schnorr proof with domain `"registration"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationProof(pub(crate) SchnorrProof);

impl RegistrationProof {
    pub fn to_bytes(&self) -> [u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN]) -> Result<Self> {
        SchnorrProof::from_bytes(bytes).map(Self)
    }

    pub fn serialized_size(&self) -> usize {
        self.0.serialized_size()
    }

    // FIX: was pub(crate) — tests/ compiles as a separate crate and cannot
    // see pub(crate) items. Changed to pub so unit_tests.rs can call
    // proof.inner().commitment for the type-distinction assertion.
    pub fn inner(&self) -> &SchnorrProof {
        &self.0
    }

    // FIX: was pub(crate) — same reason. unit_tests.rs calls
    // RegistrationProof::from_schnorr(...) directly in proof_newtypes tests.
    pub fn from_schnorr(proof: SchnorrProof) -> Self {
        Self(proof)
    }
}

/// Proof created during authentication.
///
/// Internally a Schnorr proof with domain `"authentication"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationProof(pub(crate) SchnorrProof);

impl AuthenticationProof {
    pub fn to_bytes(&self) -> [u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; POINT_BYTE_LEN + SCALAR_BYTE_LEN]) -> Result<Self> {
        SchnorrProof::from_bytes(bytes).map(Self)
    }

    pub fn serialized_size(&self) -> usize {
        self.0.serialized_size()
    }

    // FIX: was pub(crate) — same as RegistrationProof above.
    pub fn inner(&self) -> &SchnorrProof {
        &self.0
    }

    // FIX: was pub(crate) — same as RegistrationProof above.
    pub fn from_schnorr(proof: SchnorrProof) -> Self {
        Self(proof)
    }
}
