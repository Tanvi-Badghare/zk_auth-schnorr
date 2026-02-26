//! Authentication protocol.

use std::collections::{HashMap, HashSet};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::curves::Point;
use crate::crypto::fiat_shamir::Transcript;
use crate::crypto::schnorr::SchnorrProof;
use crate::errors::{Result, ZkAuthError};
use crate::models::keypair::Keypair;
use crate::protocol::registration::Registry;

// ---------------------------------------------------------------------------
// Domain constant
// ---------------------------------------------------------------------------

const AUTHENTICATION_DOMAIN: &str = "zkauth-authentication-v1";
const NONCE_LEN: usize = 32;

/// Upper bound on pending nonces to prevent unbounded memory growth.
const MAX_PENDING_NONCES: usize = 10_000;

// ---------------------------------------------------------------------------
// AuthChallenge
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub username: String,
    pub nonce: [u8; NONCE_LEN],
}

impl AuthChallenge {
    pub fn new<R: RngCore>(username: impl Into<String>, rng: &mut R) -> Self {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        Self {
            username: username.into(),
            nonce,
        }
    }
}

// ---------------------------------------------------------------------------
// AuthProof
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProof {
    pub username: String,
    pub proof: SchnorrProof,
}

impl AuthProof {
    pub fn new<R: RngCore>(
        challenge: &AuthChallenge,
        keypair: &Keypair,
        rng: &mut R,
    ) -> Result<Self> {
        let binding = build_transcript_binding(
            &challenge.username,
            keypair.public_key(),
            &challenge.nonce,
        );

        let proof = SchnorrProof::prove(
            keypair.secret_key(),
            keypair.public_key(),
            &binding,
            rng,
        );

        Ok(Self {
            username: challenge.username.clone(),
            proof,
        })
    }
}

// ---------------------------------------------------------------------------
// AuthResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthResult {
    pub username: String,
    pub session_token: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Authenticator
// ---------------------------------------------------------------------------

pub struct Authenticator<'r> {
    registry: &'r Registry,
    pending_nonces: HashMap<[u8; NONCE_LEN], String>,
    consumed_nonces: HashSet<[u8; NONCE_LEN]>,
}

impl<'r> Authenticator<'r> {
    pub fn new(registry: &'r Registry) -> Self {
        Self {
            registry,
            pending_nonces: HashMap::new(),
            consumed_nonces: HashSet::new(),
        }
    }

    pub fn issue_challenge<R: RngCore>(
        &mut self,
        username: &str,
        rng: &mut R,
    ) -> Result<AuthChallenge> {
        if self.registry.lookup(username).is_none() {
            return Err(ZkAuthError::UserNotFound);
        }

        if self.pending_nonces.len() >= MAX_PENDING_NONCES {
            return Err(ZkAuthError::AuthenticationFailed);
        }

        let challenge = AuthChallenge::new(username, rng);

        self.pending_nonces
            .insert(challenge.nonce, challenge.username.clone());

        Ok(challenge)
    }

    pub fn verify(
        &mut self,
        proof: &AuthProof,
        challenge: &AuthChallenge,
    ) -> Result<AuthResult> {
        self.verify_inner(proof, challenge)
            .map_err(|_| ZkAuthError::AuthenticationFailed)
    }

    fn verify_inner(
        &mut self,
        auth_proof: &AuthProof,
        challenge: &AuthChallenge,
    ) -> Result<AuthResult> {
        if auth_proof.username != challenge.username {
            return Err(ZkAuthError::AuthenticationFailed);
        }

        let record = self
            .registry
            .lookup(&auth_proof.username)
            .ok_or(ZkAuthError::UserNotFound)?;

        let public_key = &record.public_key;

        match self.pending_nonces.get(&challenge.nonce) {
            Some(expected_user) if expected_user == &challenge.username => {}
            _ => return Err(ZkAuthError::AuthenticationFailed),
        }

        if self.consumed_nonces.contains(&challenge.nonce) {
            return Err(ZkAuthError::AuthenticationFailed);
        }

        let binding =
            build_transcript_binding(&auth_proof.username, public_key, &challenge.nonce);

        if !auth_proof.proof.verify(public_key, &binding) {
            return Err(ZkAuthError::VerificationFailed);
        }

        self.pending_nonces.remove(&challenge.nonce);
        self.consumed_nonces.insert(challenge.nonce);

        let session_token = derive_session_token(&auth_proof.username, &challenge.nonce);

        Ok(AuthResult {
            username: auth_proof.username.clone(),
            session_token,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_transcript_binding(
    username: &str,
    public_key: &Point,
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut transcript = Transcript::new(AUTHENTICATION_DOMAIN);
    transcript.append_message("username", username.as_bytes());
    transcript.append_point("public_key", public_key);
    transcript.append_message("nonce", nonce);
    transcript.challenge_bytes("binding", 64)
}

fn derive_session_token(username: &str, nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    use crate::crypto::hash::Hasher;
    let mut h = Hasher::new();
    h.update(b"session-token-v1");
    h.update(&(username.len() as u64).to_le_bytes());
    h.update(username.as_bytes());
    h.update(nonce);
    h.finalize().to_vec()
}