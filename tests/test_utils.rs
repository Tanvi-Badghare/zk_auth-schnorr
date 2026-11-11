//! Test utilities for ZKAuth.
//!
//! This module is only compiled under `#[cfg(test)]`.
//! It provides a deterministic RNG for reproducible tests.
//!
//! ## Why a deterministic RNG?
//!
//! * **Reproducibility** — the same seed produces the same key/nonce every run.
//!   A failing test is always reproducible without extra configuration.
//! * **No OS entropy dependency** — tests run identically in CI, offline, and
//!   in sandboxed environments.
//! * **Isolation** — each test picks a unique seed so tests never share state.
//!
//! ## ⚠️ NEVER use DeterministicRng in production
//!
//! The LCG used here is NOT cryptographically secure.  Its output is
//! entirely predictable from the seed.  Using it with real secret keys
//! would make those keys trivially recoverable.

use rand::{CryptoRng, RngCore};

// ---------------------------------------------------------------------------
// DeterministicRng
// ---------------------------------------------------------------------------

/// A seeded, deterministic pseudo-random number generator for tests.
///
/// Implemented as a 64-bit LCG (linear congruential generator) with
/// Knuth's constants.  Fast, simple, and fully reproducible.
///
/// # Example
///
/// ```ignore
/// use zk_auth::test_utils::DeterministicRng;
/// use zk_auth::models::keypair::Keypair;
///
/// let keypair = Keypair::generate(&mut DeterministicRng::new(42)).unwrap();
/// ```
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    /// Create a new RNG with the given seed.
    ///
    /// Different seeds produce different, independent byte streams.
    /// Use a distinct seed for each test to avoid accidental correlation.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Advance the LCG state and return the next 64-bit value.
    ///
    /// Constants: multiplier = 6364136223846793005 (Knuth),
    ///            increment  = 1442695040888963407
    /// This is the same LCG used by many standard libraries.
    #[inline]
    fn next_u64_inner(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }
}

// ---------------------------------------------------------------------------
// RngCore impl
// ---------------------------------------------------------------------------

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        (self.next_u64_inner() >> 32) as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.next_u64_inner()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let val = self.next_u64_inner().to_le_bytes();
            let chunk = (dest.len() - i).min(8);
            dest[i..i + chunk].copy_from_slice(&val[..chunk]);
            i += chunk;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CryptoRng marker
// ---------------------------------------------------------------------------
//
// DeterministicRng is NOT cryptographically secure.  We implement CryptoRng
// only so that it satisfies the `R: RngCore + CryptoRng` bounds on
// Schnorr::prove and Keypair::generate in test contexts.
//
// This is a deliberate, contained lie: the marker tells the type system
// "this is safe to use for crypto", but we document clearly that it is NOT.
// The alternative — removing CryptoRng from production function bounds — would
// weaken the security API for all callers.
//
// Tests are safe here because they use DeterministicRng with fixed seeds and
// never handle real secret keys.

impl CryptoRng for DeterministicRng {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_produces_same_bytes() {
        let mut r1 = DeterministicRng::new(42);
        let mut r2 = DeterministicRng::new(42);

        let mut b1 = [0u8; 64];
        let mut b2 = [0u8; 64];
        r1.fill_bytes(&mut b1);
        r2.fill_bytes(&mut b2);

        assert_eq!(b1, b2);
    }

    #[test]
    fn different_seeds_produce_different_bytes() {
        let mut r1 = DeterministicRng::new(1);
        let mut r2 = DeterministicRng::new(2);

        let mut b1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        r1.fill_bytes(&mut b1);
        r2.fill_bytes(&mut b2);

        assert_ne!(b1, b2);
    }

    #[test]
    fn fill_bytes_fills_non_power_of_two_lengths() {
        let mut rng = DeterministicRng::new(99);
        let mut buf = [0u8; 37]; // not a multiple of 8
        rng.fill_bytes(&mut buf);
        // Should not panic and should produce non-zero output.
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn next_u32_and_u64_advance_state() {
        let mut rng = DeterministicRng::new(7);
        let a = rng.next_u64();
        let b = rng.next_u64();
        assert_ne!(a, b);
    }
}