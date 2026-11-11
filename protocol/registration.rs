//! Registration protocol.
//!
//! See module-level documentation for protocol description and security notes.

use std::collections::HashMap;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::curves::Point;
use crate::crypto::fiat_shamir::Transcript;
use crate::crypto::schnorr::SchnorrProof;
use crate::errors::{Result, ZkAuthError};
use crate::models::keypair::Keypair;

// ---------------------------------------------------------------------------
// Domain constant
// ---------------------------------------------------------------------------

/// Fiat–Shamir domain string for registration.
/// Must differ from every other protocol domain to prevent cross-protocol
/// replay attacks.
const REGISTRATION_DOMAIN: &str = "zkauth-registration-v1";

/// Maximum allowed username length to prevent memory abuse.
const MAX_USERNAME_LEN: usize = 128;

// ---------------------------------------------------------------------------
// RegistrationRequest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub username: String,
    pub public_key: Point,
    pub proof: SchnorrProof,
}

impl RegistrationRequest {
    pub fn new<R: RngCore>(
        username: impl Into<String>,
        keypair: &Keypair,
        rng: &mut R,
    ) -> Result<Self> {
        let mut username = username.into();
        username = username.trim().to_string();

        if username.is_empty() {
            return Err(ZkAuthError::InvalidConfig("username must not be empty"));
        }

        if username.len() > MAX_USERNAME_LEN {
            return Err(ZkAuthError::InvalidConfig("username too long"));
        }

        let public_key = keypair.public_key().clone();

        let mut transcript = Transcript::new(REGISTRATION_DOMAIN);
        transcript.append_message("username", username.as_bytes());
        transcript.append_point("public_key", &public_key);

        let binding = transcript.challenge_bytes("binding", 64);

        let proof = SchnorrProof::prove(
            keypair.secret_key(),
            &public_key,
            &binding,
            rng,
        );

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

        if self.proof.verify(&self.public_key, &binding) {
            Ok(())
        } else {
            Err(ZkAuthError::VerificationFailed)
        }
    }
}

// ---------------------------------------------------------------------------
// RegistrationRecord
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRecord {
    pub username: String,
    pub public_key: Point,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Registry {
    records: HashMap<String, RegistrationRecord>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, request: RegistrationRequest) -> Result<()> {
        // MUST verify proof before any state change.
        request.verify()?;

        if self.records.contains_key(&request.username) {
            return Err(ZkAuthError::UserAlreadyExists);
        }

        // NOTE:
        // This demo does not include server-issued nonces or replay protection.
        // Production systems must enforce freshness guarantees.

        let record = RegistrationRecord {
            username: request.username.clone(),
            public_key: request.public_key,
        };

        self.records.insert(request.username, record);

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