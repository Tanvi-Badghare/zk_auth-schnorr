//! Registration protocol.

use std::collections::HashMap;

use rand::{CryptoRng, RngCore};
// FIX: add CryptoRng — SchnorrProof::prove requires R: RngCore + CryptoRng,
// so every caller up the chain must propagate the same bound.

use serde::{Deserialize, Serialize};

use crate::crypto::curves::Point;
use crate::crypto::fiat_shamir::Transcript;
use crate::errors::{Result, ZkAuthError};
use crate::models::{Keypair, RegistrationProof};

const REGISTRATION_DOMAIN: &str = "zkauth-registration-v1";
const MAX_USERNAME_LEN: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub username: String,
    pub public_key: Point,
    pub proof: RegistrationProof,
}

impl RegistrationRequest {
    // FIX: R: RngCore → R: RngCore + CryptoRng
    pub fn new<R: RngCore + CryptoRng>(
        username: impl Into<String>,
        keypair: &Keypair,
        rng: &mut R,
    ) -> Result<Self> {
        let username = username.into().trim().to_string();

        if username.is_empty() {
            return Err(ZkAuthError::InvalidConfig("username must not be empty".to_string()));
        }

        if username.len() > MAX_USERNAME_LEN {
            return Err(ZkAuthError::InvalidConfig("username too long".to_string()));
        }

        let public_key = keypair.public_key().clone();

        let mut transcript = Transcript::new(REGISTRATION_DOMAIN);
        transcript.append_message("username", username.as_bytes());
        transcript.append_point("public_key", &public_key);

        let binding = transcript.challenge_bytes("binding", 64);

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
        let mut transcript = Transcript::new(REGISTRATION_DOMAIN);
        transcript.append_message("username", self.username.as_bytes());
        transcript.append_point("public_key", &self.public_key);

        let binding = transcript.challenge_bytes("binding", 64);

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
}