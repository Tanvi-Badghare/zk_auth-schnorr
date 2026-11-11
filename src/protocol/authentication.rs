//! Authentication protocol.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
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
/// A challenge is only valid for this long after it is issued.
const CHALLENGE_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub username: String,
    pub nonce: [u8; NONCE_LEN],
}

impl AuthChallenge {
    pub fn new<R: RngCore + CryptoRng>(username: impl Into<String>, rng: &mut R) -> Self {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        Self {
            username: username.into(),
            nonce,
        }
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
        let binding = build_binding(&challenge.username, keypair.public_key(), &challenge.nonce);
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
    /// Issued, not yet used: (nonce, username) -> time of issue.
    pending: HashMap<([u8; NONCE_LEN], String), Instant>,
    /// Nonces already used for a successful authentication.
    consumed: HashSet<[u8; NONCE_LEN]>,
    /// Per-authenticator secret mixed into session tokens, so a token cannot
    /// be computed from the (public) username and nonce alone.
    server_key: [u8; 32],
}

impl<'r> Authenticator<'r> {
    pub fn new(registry: &'r Registry) -> Self {
        let mut server_key = [0u8; 32];
        OsRng.fill_bytes(&mut server_key);
        Self {
            registry,
            pending: HashMap::new(),
            consumed: HashSet::new(),
            server_key,
        }
    }

    /// True if `nonce` has already been used for a successful authentication.
    pub fn is_consumed(&self, nonce: &[u8; NONCE_LEN]) -> bool {
        self.consumed.contains(nonce)
    }

    fn purge_expired(&mut self) {
        self.pending
            .retain(|_, issued| issued.elapsed() <= CHALLENGE_TTL);
    }

    pub fn issue_challenge<R: RngCore + CryptoRng>(
        &mut self,
        username: &str,
        rng: &mut R,
    ) -> Result<AuthChallenge> {
        if self.registry.lookup(username).is_none() {
            return Err(ZkAuthError::UserNotFound(username.into()));
        }
        self.purge_expired();
        if self.pending.len() >= MAX_PENDING_NONCES {
            return Err(ZkAuthError::AuthenticationFailed);
        }
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let challenge = AuthChallenge {
            username: username.to_string(),
            nonce,
        };
        self.pending.insert(
            (challenge.nonce, challenge.username.clone()),
            Instant::now(),
        );
        Ok(challenge)
    }

    pub fn verify(&mut self, proof: &AuthProof, challenge: &AuthChallenge) -> Result<AuthResult> {
        let record = self
            .registry
            .lookup(&proof.username)
            .ok_or_else(|| ZkAuthError::UserNotFound(proof.username.clone()))?;

        // The proof must be for the user the challenge was issued to.
        if proof.username != challenge.username {
            return Err(ZkAuthError::AuthenticationFailed);
        }

        let key = (challenge.nonce, challenge.username.clone());
        match self.pending.get(&key) {
            Some(issued)
                if issued.elapsed() <= CHALLENGE_TTL
                    && !self.consumed.contains(&challenge.nonce) => {}
            _ => return Err(ZkAuthError::AuthenticationFailed),
        }

        let binding = build_binding(&proof.username, &record.public_key, &challenge.nonce);

        if !proof.proof.inner().verify(&record.public_key, &binding) {
            return Err(ZkAuthError::AuthenticationFailed);
        }

        self.pending.remove(&key);
        self.consumed.insert(challenge.nonce);

        Ok(AuthResult {
            username: proof.username.clone(),
            session_token: derive_session_token(
                &self.server_key,
                &proof.username,
                &challenge.nonce,
            ),
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

fn derive_session_token(server_key: &[u8; 32], username: &str, nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    use crate::crypto::hash::Hasher;
    let mut h = Hasher::new();
    h.update(SESSION_DOMAIN);
    h.update(server_key);
    h.update(&(username.len() as u64).to_le_bytes());
    h.update(username.as_bytes());
    h.update(nonce);
    h.finalize().to_vec()
}
