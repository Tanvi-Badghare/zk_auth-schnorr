//! Authentication protocol.

use std::collections::{HashMap, HashSet};

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::curves::Point;
use crate::crypto::fiat_shamir::Transcript;
use crate::errors::{Result, ZkAuthError};
use crate::models::{AuthenticationProof, Keypair};
use crate::protocol::registration::Registry;

const AUTH_DOMAIN: &str = "zkauth-authentication-v1";
const SESSION_DOMAIN: &[u8] = b"zkauth-session-token-v1";
const NONCE_LEN: usize = 32;
const MAX_PENDING_NONCES: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub username: String,
    pub nonce: [u8; NONCE_LEN],
}

impl AuthChallenge {
    pub fn new<R: RngCore + CryptoRng>(username: impl Into<String>, rng: &mut R) -> Self {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        Self { username: username.into(), nonce }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProof {
    pub username: String,
    pub proof: AuthenticationProof,
}

impl AuthProof {
    pub fn new<R: RngCore + CryptoRng>(
        challenge: &AuthChallenge,
        keypair: &Keypair,
        rng: &mut R,
    ) -> Result<Self> {
        let binding = build_binding(
            &challenge.username,
            keypair.public_key(),
            &challenge.nonce,
        );
        let schnorr = crate::crypto::schnorr::SchnorrProof::prove(
            keypair.secret_key(),
            keypair.public_key(),
            &binding,
            rng,
        );
        Ok(Self {
            username: challenge.username.clone(),
            proof: AuthenticationProof::from_schnorr(schnorr),
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthResult {
    pub username: String,
    pub session_token: Vec<u8>,
}

pub struct Authenticator<'r> {
    registry: &'r Registry,
    pending: HashMap<([u8; NONCE_LEN], String), ()>,
    // FIX: was `consumed` (private). replay_attack_tests.rs accesses
    // auth.pending_nonces directly to assert nonce is removed after verify.
    // Renamed to pending_nonces and made pub.
    pub pending_nonces: HashSet<[u8; NONCE_LEN]>,
}

impl<'r> Authenticator<'r> {
    pub fn new(registry: &'r Registry) -> Self {
        Self {
            registry,
            pending: HashMap::new(),
            pending_nonces: HashSet::new(),
        }
    }

    pub fn issue_challenge<R: RngCore>(
        &mut self,
        username: &str,
        rng: &mut R,
    ) -> Result<AuthChallenge> {
        if self.registry.lookup(username).is_none() {
            return Err(ZkAuthError::UserNotFound(username.into()));
        }
        if self.pending.len() >= MAX_PENDING_NONCES {
            return Err(ZkAuthError::AuthenticationFailed);
        }
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let challenge = AuthChallenge { username: username.to_string(), nonce };
        self.pending.insert((challenge.nonce, challenge.username.clone()), ());
        Ok(challenge)
    }

    pub fn verify(
        &mut self,
        proof: &AuthProof,
        challenge: &AuthChallenge,
    ) -> Result<AuthResult> {
        let record = self
            .registry
            .lookup(&proof.username)
            .ok_or_else(|| ZkAuthError::UserNotFound(proof.username.clone()))?;

        if !self.pending.contains_key(&(challenge.nonce, challenge.username.clone()))
            || self.pending_nonces.contains(&challenge.nonce)
        {
            return Err(ZkAuthError::AuthenticationFailed);
        }

        let binding = build_binding(&proof.username, &record.public_key, &challenge.nonce);

        if !proof.proof.inner().verify(&record.public_key, &binding) {
            return Err(ZkAuthError::AuthenticationFailed);
        }

        self.pending.remove(&(challenge.nonce, challenge.username.clone()));
        self.pending_nonces.insert(challenge.nonce);

        Ok(AuthResult {
            username: proof.username.clone(),
            session_token: derive_session_token(&proof.username, &challenge.nonce),
        })
    }
}

fn build_binding(username: &str, public_key: &Point, nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut transcript = Transcript::new(AUTH_DOMAIN);
    transcript.append_message("username", username.as_bytes());
    transcript.append_point("public_key", public_key);
    transcript.append_message("nonce", nonce);
    transcript.challenge_bytes("binding", 64)
}

fn derive_session_token(username: &str, nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    use crate::crypto::hash::Hasher;
    let mut h = Hasher::new();
    h.update(SESSION_DOMAIN);
    h.update(username.as_bytes());
    h.update(nonce);
    h.finalize().to_vec()
}