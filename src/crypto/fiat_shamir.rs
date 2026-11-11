//! Fiat-Shamir transform: interactive -> non-interactive proofs via hashing.
//!
//! The Fiat-Shamir heuristic replaces a verifier's random challenge with a
//! deterministic challenge derived by hashing the protocol transcript so far.
//!
//! ## Transcript abstraction
//!
//! [`Transcript`] wraps [`Hasher`] (SHA-256) and adds:
//!
//! * **Domain separation**: every transcript starts with a domain string
//!   (e.g. `"zkauth-registration-v1"`) to prevent cross-protocol attacks.
//! * **Labeled, length-prefixed inputs**: every field is appended as
//!   `len(label) || label || len(data) || data`, so different field splits can
//!   never hash to the same bytes.
//! * **Typed appends**: `append_scalar` and `append_point` use canonical
//!   encodings.
//!
//! ## Where it is used in this crate
//!
//! * [`SchnorrProof`][super::schnorr::SchnorrProof] derives its challenge
//!   `e = H(R, Y, message)` from a transcript (domain `"zkauth-schnorr-v1"`).
//! * The registration and authentication protocols build a 64-byte *binding*
//!   (username, public key, and for authentication the server nonce) from a
//!   transcript with their own domain, and pass it to Schnorr as the message.
//!
//! ## Example
//! ```ignore
//! let mut transcript = Transcript::new("example-protocol-v1");
//! transcript.append_point("public_key", &public_key);
//! transcript.append_message("username", b"alice");
//! let challenge: Scalar = transcript.challenge_scalar("challenge");
//! ```

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

    /// Derive a challenge scalar. 64 bytes are hashed out and reduced
    /// modulo the group order, so the result is statistically uniform.
    pub fn challenge_scalar(&mut self, label: &str) -> Scalar {
        let mut h = self.hasher.clone();
        Self::append_bytes_with_label(&mut h, "chal", label.as_bytes());

        let wide_vec = Self::hash_extension(&h, 64);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&wide_vec);

        // Transcript continuation
        self.hasher.update(&wide_vec);

        Scalar::from_wide_bytes(wide)
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
