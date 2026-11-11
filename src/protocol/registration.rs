//! Registration protocol.

use std::collections::HashMap;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::curves::Point;
use crate::crypto::fiat_shamir::Transcript;
use crate::errors::{Result, ZkAuthError};
use crate::models::{Keypair, RegistrationProof};

const REGISTRATION_DOMAIN: &str = "zkauth-registration-v1";
const MAX_USERNAME_LEN: usize = 128;

/// Validate a username in canonical form.
///
/// Applied both when building a request and when verifying one, because a
/// remote client can submit a request without going through
/// [`RegistrationRequest::new`].
fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() {
        return Err(ZkAuthError::InvalidConfig(
            "username must not be empty".to_string(),
        ));
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err(ZkAuthError::InvalidConfig("username too long".to_string()));
    }
    if username != username.trim() || username.chars().any(char::is_control) {
        return Err(ZkAuthError::InvalidConfig(
            "username must not contain control characters or surrounding whitespace".to_string(),
        ));
    }
    Ok(())
}

// RegistrationRequest contains `public_key: Point`. It is (de)serialised
// manually through a shadow struct that stores the key as [u8; 32], so
// decoding always validates the point.
#[derive(Debug, Clone)]
pub struct RegistrationRequest {
    pub username: String,
    pub public_key: Point,
    pub proof: RegistrationProof,
}

#[derive(Serialize, Deserialize)]
struct RegistrationRequestRaw {
    username: String,
    public_key: [u8; 32],
    proof: RegistrationProof,
}

impl Serialize for RegistrationRequest {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        RegistrationRequestRaw {
            username: self.username.clone(),
            public_key: self.public_key.to_bytes(),
            proof: self.proof.clone(),
        }
        .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for RegistrationRequest {
    fn deserialize<D: Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        let raw = RegistrationRequestRaw::deserialize(de)?;
        let public_key = Point::from_bytes(&raw.public_key)
            .map_err(|e| serde::de::Error::custom(format!("invalid public_key: {e}")))?;
        Ok(Self {
            username: raw.username,
            public_key,
            proof: raw.proof,
        })
    }
}

/// Binding message that the registration proof signs: domain, username and
/// public key.
fn registration_binding(username: &str, public_key: &Point) -> Vec<u8> {
    let mut transcript = Transcript::new(REGISTRATION_DOMAIN);
    transcript.append_message("username", username.as_bytes());
    transcript.append_point("public_key", public_key);
    transcript.challenge_bytes("binding", 64)
}

impl RegistrationRequest {
    pub fn new<R: RngCore + CryptoRng>(
        username: impl Into<String>,
        keypair: &Keypair,
        rng: &mut R,
    ) -> Result<Self> {
        let username = username.into().trim().to_string();
        validate_username(&username)?;

        let public_key = keypair.public_key().clone();
        let binding = registration_binding(&username, &public_key);

        let schnorr = crate::crypto::schnorr::SchnorrProof::prove(
            keypair.secret_key(),
            &public_key,
            &binding,
            rng,
        );

        let proof = RegistrationProof::from_schnorr(schnorr);
        Ok(Self {
            username,
            public_key,
            proof,
        })
    }

    pub fn verify(&self) -> Result<()> {
        validate_username(&self.username)?;

        // The identity element has discrete log 0, so anyone can "prove"
        // knowledge of it. Never accept it as a public key.
        if self.public_key.is_identity() {
            return Err(ZkAuthError::InvalidPoint);
        }

        let binding = registration_binding(&self.username, &self.public_key);

        if self.proof.inner().verify(&self.public_key, &binding) {
            Ok(())
        } else {
            Err(ZkAuthError::VerificationFailed)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRecord {
    pub username: String,
    pub public_key: Point,
}

#[derive(Default)]
pub struct Registry {
    records: HashMap<String, RegistrationRecord>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, request: RegistrationRequest) -> Result<()> {
        request.verify()?;

        if self.records.contains_key(&request.username) {
            return Err(ZkAuthError::UserAlreadyExists(request.username));
        }

        let record = RegistrationRecord {
            username: request.username.clone(),
            public_key: request.public_key,
        };
        self.records.insert(record.username.clone(), record);
        Ok(())
    }

    pub fn lookup(&self, username: &str) -> Option<&RegistrationRecord> {
        self.records.get(username)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn valid_request(name: &str) -> RegistrationRequest {
        let kp = Keypair::generate(&mut OsRng).unwrap();
        RegistrationRequest::new(name, &kp, &mut OsRng).unwrap()
    }

    #[test]
    fn valid_request_verifies() {
        assert!(valid_request("alice").verify().is_ok());
    }

    #[test]
    fn verify_rejects_hand_built_bad_usernames() {
        // Bypass `new` the way a remote client could via JSON.
        for bad in [
            "",
            " alice",
            "alice ",
            "ali\nce",
            &"a".repeat(MAX_USERNAME_LEN + 1),
        ] {
            let mut req = valid_request("alice");
            req.username = bad.to_string();
            assert!(req.verify().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn duplicate_username_rejected() {
        let mut registry = Registry::new();
        registry.register(valid_request("alice")).unwrap();
        assert!(matches!(
            registry.register(valid_request("alice")),
            Err(ZkAuthError::UserAlreadyExists(_))
        ));
    }
}
