//! Fiat–Shamir transform: interactive → non-interactive proofs via hashing.
//!
//! The Fiat–Shamir heuristic replaces a verifier's random challenges with
//! deterministic challenges derived by hashing the protocol transcript so far.
//! This turns an interactive proof (multiple rounds of communication) into a
//! non-interactive proof (a single message).
//!
//! ## Transcript abstraction
//!
//! This module provides [`Transcript`], a generic tool for building Fiat–Shamir
//! transcripts.  It wraps [`Hasher`] and adds:
//!
//! * **Domain separation** — every transcript starts with a domain string
//!   (e.g., `"registration-v1"`) to prevent cross-protocol attacks.
//! * **Labeled inputs** — every field appended to the transcript is tagged
//!   with a label (e.g., `"public_key"`) to prevent ambiguity.
//! * **Type-safe appends** — `append_scalar`, `append_point`, etc. serialize
//!   inputs in a canonical format.
//!
//! ## Example
//! ```ignore
//! use zk_auth::crypto::{fiat_shamir::Transcript, Scalar, Point, BASEPOINT};
//!
//! let mut transcript = Transcript::new("example-protocol-v1");
//! let public_key = Scalar::random(&mut rng) * BASEPOINT;
//!
//! transcript.append_point("public_key", &public_key);
//! transcript.append_message("username", b"alice");
//!
//! let challenge: Scalar = transcript.challenge_scalar("challenge");
//! ```
//!
//! ## Note
//!
//! For the basic Schnorr protocol in this library, you don't need to use
//! [`Transcript`] directly — [`schnorr::prove`][super::schnorr::prove] and
//! [`schnorr::verify`][super::schnorr::verify] handle the transcript internally.
//! This module is provided for:
//! * Implementing more complex zero-knowledge protocols.
//! * Educational purposes (understanding Fiat–Shamir).
//! * Future extensions (e.g., batch proofs, multi-round protocols).

use super::curves::{Point, Scalar};
use super::hash::Hasher;

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Transcript {
    hasher: Hasher,
}

impl Transcript {
    pub fn new(domain: &str) -> Self {
        let mut hasher = Hasher::new();
        Self::append_bytes_with_label(&mut hasher, "dom-sep", domain.as_bytes());
        Self { hasher }
    }

    // ----------------------------
    // Appending data
    // ----------------------------

    pub fn append_message(&mut self, label: &str, data: &[u8]) {
        Self::append_bytes_with_label(&mut self.hasher, label, data);
    }

    pub fn append_scalar(&mut self, label: &str, scalar: &Scalar) {
        Self::append_bytes_with_label(&mut self.hasher, label, &scalar.to_bytes());
    }

    pub fn append_point(&mut self, label: &str, point: &Point) {
        Self::append_bytes_with_label(&mut self.hasher, label, &point.to_bytes());
    }

    // ----------------------------
    // Challenges
    // ----------------------------

    pub fn challenge_scalar(&mut self, label: &str) -> Scalar {
        let mut h = self.hasher.clone();
        Self::append_bytes_with_label(&mut h, "chal", label.as_bytes());

        let digest = h.finalize();

        // Transcript continuation
        self.hasher.update(&digest);

        Scalar::from_hash_bytes(digest)
    }

    pub fn challenge_bytes(&mut self, label: &str, len: usize) -> Vec<u8> {
        let mut h = self.hasher.clone();
        Self::append_bytes_with_label(&mut h, "chal-bytes", label.as_bytes());

        let output = Self::hash_extension(&h, len);

        let continuation = if output.len() >= 32 {
            &output[..32]
        } else {
            &output[..]
        };

        self.hasher.update(continuation);

        output
    }

    // ----------------------------
    // Helpers
    // ----------------------------

    fn append_bytes_with_label(hasher: &mut Hasher, label: &str, data: &[u8]) {
        let label_bytes = label.as_bytes();

        hasher.update(&(label_bytes.len() as u64).to_le_bytes());
        hasher.update(label_bytes);

        hasher.update(&(data.len() as u64).to_le_bytes());
        hasher.update(data);
    }

    fn hash_extension(base: &Hasher, len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(len);
        let mut counter = 0u64;

        while output.len() < len {
            let mut h = base.clone();
            h.update(&counter.to_le_bytes());

            let digest = h.finalize();

            let remaining = len - output.len();

            if remaining >= 32 {
                output.extend_from_slice(&digest);
            } else {
                output.extend_from_slice(&digest[..remaining]);
            }

            counter += 1;
        }

        output
    }
}
