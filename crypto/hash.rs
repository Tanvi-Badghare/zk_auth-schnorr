//! Cryptographic hashing primitives.
//!
//! This module wraps SHA-256 (via the `sha2` crate) behind a simple,
//! consistent API. The primary use case is Fiat–Shamir transcript
//! hashing, where multiple messages are fed into a single digest.
//!
//! ## API
//!
//! * **One-shot hashing**: [`hash_bytes`] takes arbitrary bytes and
//!   returns a 32-byte digest.
//! * **Incremental (transcript) hashing**: [`Hasher`] lets you call
//!   [`update`][Hasher::update] multiple times before calling
//!   [`finalize`][Hasher::finalize].
//! * **Hash → Scalar**: [`hash_to_scalar`] securely derives a curve
//!   scalar for Schnorr / Fiat–Shamir challenges.
//!
//! ⚠️  Always use `hash_to_scalar` for challenge derivation.
//! Do NOT manually convert raw hash bytes into scalars.

use sha2::{Digest as Sha2Digest, Sha256};
use sha2::Sha512;
use curve25519_dalek::scalar::Scalar;
use crate::config::HASH_BYTE_LEN;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// A cryptographic digest: a fixed-size (32-byte) output from SHA-256.
pub type Digest = [u8; HASH_BYTE_LEN];

// ---------------------------------------------------------------------------
// Hasher (incremental / transcript-based hashing)
// ---------------------------------------------------------------------------

/// A stateful, incremental hasher backed by SHA-256.
///
/// Call [`update`][Self::update] zero or more times to feed in data,
/// then call [`finalize`][Self::finalize] to produce the digest.
/// The hasher is consumed by `finalize`.
#[derive(Clone)]
pub struct Hasher {
    inner: Sha256,
}

impl Hasher {
    /// Create a new, empty hasher.
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Feed `data` into the hash.
    /// Order matters.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consume the hasher and produce the final 32-byte digest.
    pub fn finalize(self) -> Digest {
        let output = self.inner.finalize();
        let mut digest = [0u8; HASH_BYTE_LEN];
        digest.copy_from_slice(&output);
        digest
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// One-shot hashing
// ---------------------------------------------------------------------------

/// Hash a single byte slice and return the 32-byte SHA-256 digest.
pub fn hash_bytes(data: &[u8]) -> Digest {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

// ---------------------------------------------------------------------------
// Hash → Scalar (for Fiat–Shamir challenges)
// ---------------------------------------------------------------------------

/// Hash arbitrary data into a curve scalar (mod group order).
///
/// Uses SHA-512 internally and reduces modulo the curve order
/// via `from_bytes_mod_order_wide`, ensuring uniform distribution.
///
/// ⚠️ Do NOT manually convert 32-byte hashes into scalars.
/// Always use this function for Schnorr challenges.
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    use sha2::Digest;

    let mut hasher = Sha512::new();
    hasher.update(data);
    let wide_hash = hasher.finalize(); // 64 bytes

    let mut wide_bytes = [0u8; 64];
    wide_bytes.copy_from_slice(&wide_hash);

    Scalar::from_bytes_mod_order_wide(&wide_bytes)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    // --- Known SHA-256 test vectors ---------------------------------------

    #[test]
    fn hash_bytes_empty_input() {
        let expected = hex::decode(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ).unwrap();
        let digest = hash_bytes(b"");
        assert_eq!(&digest[..], &expected[..]);
    }

    #[test]
    fn hash_bytes_abc() {
        let expected = hex::decode(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ).unwrap();
        let digest = hash_bytes(b"abc");
        assert_eq!(&digest[..], &expected[..]);
    }

    #[test]
    fn hash_bytes_long_input() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = hex::decode(
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        ).unwrap();
        let digest = hash_bytes(input);
        assert_eq!(&digest[..], &expected[..]);
    }

    // --- Incremental hashing tests ----------------------------------------

    #[test]
    fn hasher_multiple_updates_same_as_concatenated() {
        let one_shot = hash_bytes(b"abc");

        let mut incremental = Hasher::new();
        incremental.update(b"a");
        incremental.update(b"b");
        incremental.update(b"c");

        assert_eq!(one_shot, incremental.finalize());
    }

    #[test]
    fn hasher_clone_produces_identical_digest() {
        let mut h1 = Hasher::new();
        h1.update(b"prefix");

        let mut h2 = h1.clone();

        h1.update(b"suffix");
        h2.update(b"suffix");

        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn hasher_clone_diverges_after_different_updates() {
        let mut h1 = Hasher::new();
        h1.update(b"prefix");

        let mut h2 = h1.clone();

        h1.update(b"A");
        h2.update(b"B");

        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn hasher_empty_finalize() {
        let hasher = Hasher::new();
        let digest = hasher.finalize();
        assert_eq!(digest, hash_bytes(b""));
    }

    #[test]
    fn default_hasher_is_empty() {
        let h1 = Hasher::default();
        let h2 = Hasher::new();
        assert_eq!(h1.finalize(), h2.finalize());
    }

    // --- Hash → Scalar tests ----------------------------------------------

    #[test]
    fn hash_to_scalar_is_deterministic() {
        let s1 = hash_to_scalar(b"challenge");
        let s2 = hash_to_scalar(b"challenge");
        assert_eq!(s1, s2);
    }

    #[test]
    fn hash_to_scalar_differs_for_different_inputs() {
        let s1 = hash_to_scalar(b"A");
        let s2 = hash_to_scalar(b"B");
        assert_ne!(s1, s2);
    }

    #[test]
    fn hash_to_scalar_not_zero_for_typical_input() {
        let s = hash_to_scalar(b"nontrivial input");
        assert_ne!(s, Scalar::ZERO);
    }
}