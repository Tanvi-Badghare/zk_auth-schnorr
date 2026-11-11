//! Proof types for registration and authentication.

use serde::{Deserialize, Serialize};

use crate::config::{POINT_BYTE_LEN, SCALAR_BYTE_LEN};
use crate::crypto::schnorr::SchnorrProof;
use crate::errors::Result;

/// Proof created during user registration.
///
/// A Schnorr proof over a binding message derived from the registration
/// domain (`"zkauth-registration-v1"`), the username and the public key.
/// The newtype keeps it type-distinct from [`AuthenticationProof`].
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

    // pub (not pub(crate)) because tests/ compiles as a separate crate.
    pub fn inner(&self) -> &SchnorrProof {
        &self.0
    }

    pub fn from_schnorr(proof: SchnorrProof) -> Self {
        Self(proof)
    }
}

/// Proof created during authentication.
///
/// A Schnorr proof over a binding message derived from the authentication
/// domain (`"zkauth-authentication-v1"`), the username, the public key and the
/// server-issued single-use nonce.
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

    pub fn inner(&self) -> &SchnorrProof {
        &self.0
    }

    pub fn from_schnorr(proof: SchnorrProof) -> Self {
        Self(proof)
    }
}
