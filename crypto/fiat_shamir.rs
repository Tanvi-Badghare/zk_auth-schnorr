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
// Transcript struct
// ---------------------------------------------------------------------------

/// A Fiat–Shamir transcript builder.
///
/// Accumulates protocol messages (scalars, points, arbitrary bytes) into a
/// hash transcript, then extracts deterministic challenges.
///
/// ## Cloning
///
/// [`Transcript`] implements [`Clone`] so you can fork a transcript at any
/// point and continue in two different branches.  This is useful for protocols
/// that have conditional logic.
#[derive(Clone)]
pub struct Transcript {
    hasher: Hasher,
}

impl Transcript {
    /// Create a new transcript with the given domain separator.
    ///
    /// The domain is immediately hashed into the transcript state.  Two
    /// transcripts with different domains will produce different challenges
    /// even if all subsequent inputs are identical.
    ///
    /// # Convention
    ///
    /// Use a domain string like `"<protocol-name>-v<version>"`, e.g.,
    /// `"registration-v1"` or `"auth-v2"`.  This prevents a proof from one
    /// protocol being replayed against another.
    pub fn new(domain: &str) -> Self {
        let mut hasher = Hasher::new();
        // Hash the domain string with length prefix.
        Self::append_bytes_with_label(&mut hasher, "dom-sep", domain.as_bytes());
        Self { hasher }
    }

    // -----------------------------------------------------------------------
    // Appending data
    // -----------------------------------------------------------------------

    /// Append an arbitrary byte slice to the transcript.
    ///
    /// The `label` distinguishes this field from others (e.g., `"nonce"`,
    /// `"message"`).  Both the label and the data are length-prefixed before
    /// hashing to prevent ambiguity.
    pub fn append_message(&mut self, label: &str, data: &[u8]) {
        Self::append_bytes_with_label(&mut self.hasher, label, data);
    }

    /// Append a scalar to the transcript.
    ///
    /// The scalar is serialized to 32 bytes (canonical form) before hashing.
    pub fn append_scalar(&mut self, label: &str, scalar: &Scalar) {
        Self::append_bytes_with_label(&mut self.hasher, label, &scalar.to_bytes());
    }

    /// Append a curve point to the transcript.
    ///
    /// The point is serialized to 32 bytes (Ristretto compressed) before hashing.
    pub fn append_point(&mut self, label: &str, point: &Point) {
        Self::append_bytes_with_label(&mut self.hasher, label, &point.to_bytes());
    }

    // -----------------------------------------------------------------------
    // Extracting challenges
    // -----------------------------------------------------------------------

    /// Extract a scalar challenge from the transcript.
    ///
    /// This "consumes" the current transcript state by hashing it, then uses
    /// the result to seed the next state.  Subsequent appends will produce a
    /// different challenge.
    ///
    /// The `label` is hashed before finalization (e.g., `"challenge_1"`,
    /// `"challenge_2"`).  This ensures that calling `challenge_scalar` twice
    /// with different labels produces different scalars even if no data is
    /// appended in between.
    ///
    /// # Returns
    ///
    /// A [`Scalar`] derived from the transcript hash.  The hash output is
    /// reduced modulo the group order, so this never fails.
    pub fn challenge_scalar(&mut self, label: &str) -> Scalar {
        // Clone the hasher so we don't mutate self.hasher yet.
        let mut h = self.hasher.clone();
        Self::append_bytes_with_label(&mut h, "chal", label.as_bytes());
        let digest = h.finalize();

        // Update self.hasher with the challenge output (for transcript continuation).
        self.hasher.update(&digest);

        // Convert digest to scalar via reduction mod order (always succeeds).
        Scalar(curve25519_dalek::Scalar::from_bytes_mod_order(digest))
    }

    /// Extract arbitrary-length bytes from the transcript (for nonces, seeds, etc.).
    ///
    /// If `len <= 32`, this is a single hash.  If `len > 32`, uses hash
    /// extension: hash with counter `0`, hash with counter `1`, etc., until
    /// enough bytes are produced.
    ///
    /// The `label` works the same as in [`challenge_scalar`][Self::challenge_scalar].
    pub fn challenge_bytes(&mut self, label: &str, len: usize) -> Vec<u8> {
        // Clone hasher and append the challenge label.
        let mut h = self.hasher.clone();
        Self::append_bytes_with_label(&mut h, "chal-bytes", label.as_bytes());

        // Generate `len` bytes via hash extension.
        let output = Self::hash_extension(&h, len);

        // Update self.hasher with the first 32 bytes of output (transcript continuation).
        let digest_for_continuation = if output.len() >= 32 {
            &output[..32]
        } else {
            &output[..]
        };
        self.hasher.update(digest_for_continuation);

        output
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Append `label || data` to the hasher, both length-prefixed.
    ///
    /// Format: `label_len (8 bytes LE) || label || data_len (8 bytes LE) || data`.
    fn append_bytes_with_label(hasher: &mut Hasher, label: &str, data: &[u8]) {
        let label_bytes = label.as_bytes();
        hasher.update(&(label_bytes.len() as u64).to_le_bytes());
        hasher.update(label_bytes);
        hasher.update(&(data.len() as u64).to_le_bytes());
        hasher.update(data);
    }

    /// Hash extension: produce `len` bytes by hashing with a counter.
    ///
    /// If `len <= 32`, return `Hash(state)`.
    /// If `len > 32`, return `Hash(state || 0) || Hash(state || 1) || ...`.
    fn hash_extension(base_hasher: &Hasher, len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(len);
        let mut counter = 0u64;

        while output.len() < len {
            let mut h = base_hasher.clone();
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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BASEPOINT;
    use crate::test_utils::DeterministicRng;

    // --- Same inputs → same challenge -------------------------------------

    #[test]
    fn same_inputs_produce_same_challenge() {
        let mut t1 = Transcript::new("domain");
        t1.append_message("msg", b"hello");
        let c1 = t1.challenge_scalar("c");

        let mut t2 = Transcript::new("domain");
        t2.append_message("msg", b"hello");
        let c2 = t2.challenge_scalar("c");

        assert_eq!(c1, c2);
    }

    // --- Different domain → different challenge ---------------------------

    #[test]
    fn different_domain_produces_different_challenge() {
        let mut t1 = Transcript::new("domain-A");
        let c1 = t1.challenge_scalar("c");

        let mut t2 = Transcript::new("domain-B");
        let c2 = t2.challenge_scalar("c");

        assert_ne!(c1, c2);
    }

    // --- Different label → different challenge ----------------------------

    #[test]
    fn different_label_produces_different_challenge() {
        let mut t = Transcript::new("domain");
        let c1 = t.challenge_scalar("label-A");
        let c2 = t.challenge_scalar("label-B");

        assert_ne!(c1, c2);
    }

    // --- Different data → different challenge -----------------------------

    #[test]
    fn different_data_produces_different_challenge() {
        let mut t1 = Transcript::new("domain");
        t1.append_message("msg", b"hello");
        let c1 = t1.challenge_scalar("c");

        let mut t2 = Transcript::new("domain");
        t2.append_message("msg", b"world");
        let c2 = t2.challenge_scalar("c");

        assert_ne!(c1, c2);
    }

    // --- Order matters ----------------------------------------------------

    #[test]
    fn order_of_appends_matters() {
        let mut t1 = Transcript::new("domain");
        t1.append_message("A", b"foo");
        t1.append_message("B", b"bar");
        let c1 = t1.challenge_scalar("c");

        let mut t2 = Transcript::new("domain");
        t2.append_message("B", b"bar");
        t2.append_message("A", b"foo");
        let c2 = t2.challenge_scalar("c");

        assert_ne!(c1, c2);
    }

    // --- Append scalar/point ----------------------------------------------

    #[test]
    fn append_scalar_works() {
        let mut rng = DeterministicRng::new(1);
        let scalar = Scalar::random(&mut rng);

        let mut t1 = Transcript::new("domain");
        t1.append_scalar("s", &scalar);
        let c1 = t1.challenge_scalar("c");

        let mut t2 = Transcript::new("domain");
        t2.append_scalar("s", &scalar);
        let c2 = t2.challenge_scalar("c");

        assert_eq!(c1, c2);
    }

    #[test]
    fn append_point_works() {
        let mut rng = DeterministicRng::new(2);
        let point = Scalar::random(&mut rng) * BASEPOINT;

        let mut t1 = Transcript::new("domain");
        t1.append_point("P", &point);
        let c1 = t1.challenge_scalar("c");

        let mut t2 = Transcript::new("domain");
        t2.append_point("P", &point);
        let c2 = t2.challenge_scalar("c");

        assert_eq!(c1, c2);
    }

    // --- Challenge bytes --------------------------------------------------

    #[test]
    fn challenge_bytes_produces_correct_length() {
        let mut t = Transcript::new("domain");
        let bytes = t.challenge_bytes("nonce", 64);
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn challenge_bytes_short_length() {
        let mut t = Transcript::new("domain");
        let bytes = t.challenge_bytes("nonce", 16);
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn challenge_bytes_same_input_same_output() {
        let mut t1 = Transcript::new("domain");
        t1.append_message("msg", b"test");
        let b1 = t1.challenge_bytes("nonce", 48);

        let mut t2 = Transcript::new("domain");
        t2.append_message("msg", b"test");
        let b2 = t2.challenge_bytes("nonce", 48);

        assert_eq!(b1, b2);
    }

    // --- Clone ------------------------------------------------------------

    #[test]
    fn clone_produces_identical_challenges() {
        let mut t1 = Transcript::new("domain");
        t1.append_message("msg", b"prefix");

        let mut t2 = t1.clone();

        // Both continue identically.
        t1.append_message("msg2", b"suffix");
        t2.append_message("msg2", b"suffix");

        let c1 = t1.challenge_scalar("c");
        let c2 = t2.challenge_scalar("c");

        assert_eq!(c1, c2);
    }

    #[test]
    fn clone_diverges_after_different_appends() {
        let mut t1 = Transcript::new("domain");
        t1.append_message("msg", b"prefix");

        let mut t2 = t1.clone();

        t1.append_message("msg2", b"A");
        t2.append_message("msg2", b"B");

        let c1 = t1.challenge_scalar("c");
        let c2 = t2.challenge_scalar("c");

        assert_ne!(c1, c2);
    }

    // --- Edge cases -------------------------------------------------------

    #[test]
    fn empty_transcript_produces_challenge() {
        // Transcript with no appends, only domain.
        let mut t = Transcript::new("domain");
        let c = t.challenge_scalar("c");
        // Just verify it doesn't panic.
        assert_eq!(c.to_bytes().len(), 32);
    }

    #[test]
    fn multiple_challenges_from_same_state() {
        let mut t = Transcript::new("domain");
        t.append_message("msg", b"data");

        let c1 = t.challenge_scalar("c1");
        let c2 = t.challenge_scalar("c2");

        // Even with no appends between, different labels produce different challenges.
        assert_ne!(c1, c2);
    }
}