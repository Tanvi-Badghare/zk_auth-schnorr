//! Cryptographic hashing primitives.
//!
//! This module wraps SHA-256 (via the `sha2` crate) behind a simple,
//! consistent API.  The primary use case is Fiat–Shamir transcript
//! hashing, where multiple messages are fed into a single digest.
//!
//! ## API
//!
//! * **One-shot hashing**: [`hash_bytes`] takes arbitrary bytes and
//!   returns a 32-byte digest.
//! * **Incremental (transcript) hashing**: [`Hasher`] lets you call
//!   [`update`][Hasher::update] multiple times before calling
//!   [`finalize`][Hasher::finalize].
//!
//! ## Example
//! ```rust
//! use zk_auth::crypto::hash::{hash_bytes, Hasher};
//!
//! // One-shot
//! let digest = hash_bytes(b"hello");
//! assert_eq!(digest.len(), 32);
//!
//! // Incremental
//! let mut hasher = Hasher::new();
//! hasher.update(b"hello");
//! hasher.update(b" ");
//! hasher.update(b"world");
//! let digest = hasher.finalize();
//! ```

use sha2::{Digest as Sha2Digest, Sha256};
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
/// The hasher is consumed by `finalize` (this matches the `sha2` API
/// and prevents accidental reuse of a finalised state).
///
/// [`Hasher`] implements [`Clone`], so you can fork a transcript:
/// ```rust
/// # use zk_auth::crypto::hash::Hasher;
/// let mut h1 = Hasher::new();
/// h1.update(b"prefix");
///
/// let mut h2 = h1.clone();
/// h1.update(b"branch_a");
/// h2.update(b"branch_b");
///
/// // h1 and h2 now have different internal states.
/// # let _d1 = h1.finalize();
/// # let _d2 = h2.finalize();
/// ```
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

    /// Feed `data` into the hash.  Can be called multiple times; the
    /// order of calls matters (this is not a commutative hash).
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consume the hasher and produce the final 32-byte digest.
    ///
    /// After calling this, the hasher is gone (it moves `self`).
    /// If you need to continue hashing, [`clone`][Self::clone] the
    /// hasher *before* calling `finalize`.
    pub fn finalize(self) -> Digest {
        let output = self.inner.finalize();
        // sha2::Digest::finalize() returns GenericArray<u8, U32>.
        // We convert it to a plain [u8; 32].
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
///
/// This is a convenience wrapper around [`Hasher`] for cases where you
/// have all the data up-front.  Equivalent to:
/// ```rust
/// # use zk_auth::crypto::hash::Hasher;
/// # let data = b"example";
/// let mut hasher = Hasher::new();
/// hasher.update(data);
/// let digest = hasher.finalize();
/// ```
pub fn hash_bytes(data: &[u8]) -> Digest {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Known test vectors for SHA-256 -----------------------------------

    #[test]
    fn hash_bytes_empty_input() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected = hex::decode(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ).unwrap();
        let digest = hash_bytes(b"");
        assert_eq!(&digest[..], &expected[..]);
    }

    #[test]
    fn hash_bytes_abc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let expected = hex::decode(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ).unwrap();
        let digest = hash_bytes(b"abc");
        assert_eq!(&digest[..], &expected[..]);
    }

    #[test]
    fn hash_bytes_long_input() {
        // SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        // = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = hex::decode(
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        ).unwrap();
        let digest = hash_bytes(input);
        assert_eq!(&digest[..], &expected[..]);
    }

    // --- Incremental (Hasher) tests ---------------------------------------

    #[test]
    fn hasher_multiple_updates_same_as_concatenated() {
        // Hashing "abc" in one shot should equal hashing "a", "b", "c"
        // separately.
        let one_shot = hash_bytes(b"abc");

        let mut incremental = Hasher::new();
        incremental.update(b"a");
        incremental.update(b"b");
        incremental.update(b"c");
        let incremental_digest = incremental.finalize();

        assert_eq!(one_shot, incremental_digest);
    }

    #[test]
    fn hasher_clone_produces_identical_digest() {
        let mut h1 = Hasher::new();
        h1.update(b"prefix");

        let mut h2 = h1.clone();

        // Both add the same suffix
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
        // Should match SHA-256 of empty string
        let expected = hash_bytes(b"");
        assert_eq!(digest, expected);
    }

    #[test]
    fn default_hasher_is_empty() {
        let h1 = Hasher::default();
        let h2 = Hasher::new();
        assert_eq!(h1.finalize(), h2.finalize());
    }
}