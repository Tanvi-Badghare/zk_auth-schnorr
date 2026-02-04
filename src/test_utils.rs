//! Shared test helpers for the zk-auth crate.
//!
//! This module is compiled **only** during `cargo test` (gated by
//! `#[cfg(test)]` in `lib.rs`).  It provides:
//!
//! * Instant, pre-validated [`ZkAuthConfig`] factories.
//! * A **deterministic** RNG for reproducible tests.
//! * A **weak** (constant-output) RNG for testing that the protocol
//!   rejects bad randomness.
//! * Dummy username constants so tests don't scatter string literals.
//!
//! ### What is NOT here
//! Keypair / proof fixtures live in the individual module tests or in
//! `tests/` once `models/keypair.rs` exists.  Putting them here would
//! create a compile-time dependency on a module that may not be ready.

use rand::RngCore;
use crate::config::ZkAuthConfig;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// A dummy username used across tests.  Short, ASCII, well under any
/// `max_username_len` limit.
pub const DUMMY_USERNAME: &str = "alice";

/// A second dummy username for any test that needs two distinct users
/// (e.g. registration collision, multi-party flows).
pub const DUMMY_USERNAME_2: &str = "bob";

/// The domain separator written into every test config by default.
/// Distinct from the production default so a test proof can never
/// accidentally pass a production verifier (or vice-versa).
pub const TEST_DOMAIN: &str = "zk-auth-test-v0.1";

// ---------------------------------------------------------------------------
// Config factories
// ---------------------------------------------------------------------------

/// Return a [`ZkAuthConfig`] that is valid, uses [`TEST_DOMAIN`], and
/// is identical to the library default in every other respect.
///
/// This is the single most common setup call in tests — one line,
/// zero allocation overhead worth worrying about.
pub fn test_config() -> ZkAuthConfig {
    let cfg = ZkAuthConfig::with_domain(TEST_DOMAIN);
    // Sanity: blow up at test-setup time, not deep inside crypto.
    cfg.validate().expect("test_config must be valid");
    cfg
}

/// Same as [`test_config`], but lets the caller pick the domain
/// separator.  Useful when a test specifically needs two configs with
/// *different* domains to prove domain-separation works.
pub fn test_config_with_domain(domain: &str) -> ZkAuthConfig {
    let cfg = ZkAuthConfig::with_domain(domain);
    cfg.validate().expect("test_config_with_domain must be valid");
    cfg
}

// ---------------------------------------------------------------------------
// Deterministic RNG
// ---------------------------------------------------------------------------

/// A simple, seeded pseudo-random number generator backed by a
/// **Linear Congruential Generator** (LCG).
///
/// ### Why
/// Real RNG (`OsRng`) is non-deterministic — the same test can produce
/// different scalars on every run, making failures impossible to
/// reproduce.  A seeded LCG gives byte-for-byte identical output for a
/// given seed, so every test run is identical.
///
/// ### Constants
/// The multiplier and increment are from Knuth (TAOCP vol. 2) and are
/// the same ones used inside the PCG family.  They are well-studied and
/// have a full period of 2⁶⁴.
///
/// ### Security
/// **Do not use outside tests.**  LCGs are trivially breakable.
pub struct DeterministicRng {
    state: u64,
}

/// LCG multiplier (Knuth).
const LCG_A: u64 = 6_364_136_223_846_793_005;
/// LCG increment (Knuth).  Must be odd.
const LCG_C: u64 = 1_442_695_040_888_963_407;

impl DeterministicRng {
    /// Create a new deterministic RNG with the given seed.
    /// Seed `0` is valid; the LCG will still produce a full-period
    /// sequence.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Advance the internal state by one step and return the new value.
    fn next_state(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(LCG_A).wrapping_add(LCG_C);
        self.state
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        // Take the upper 32 bits — they have better statistical properties
        // in an LCG than the lower bits.
        (self.next_state() >> 32) as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.next_state()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Fill eight bytes at a time from successive LCG outputs.
        let mut i = 0;
        while i + 8 <= dest.len() {
            dest[i..i + 8].copy_from_slice(&self.next_state().to_le_bytes());
            i += 8;
        }
        // Handle the remaining 0-7 bytes with one more LCG step.
        if i < dest.len() {
            let remaining = dest.len() - i;  // cache length before mutable borrow
            let tail = self.next_state().to_le_bytes();
            dest[i..].copy_from_slice(&tail[..remaining]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Weak (constant-output) RNG
// ---------------------------------------------------------------------------

/// An RNG that always writes the **same byte** to its output buffer.
///
/// ### Why
/// Several attack simulations (e.g. `attacks/weak_rng_attack.rs`) need
/// to demonstrate what happens when the randomness source is
/// compromised or broken.  A constant-output RNG is the simplest model
/// of a completely broken source.
///
/// ### Security
/// **Do not use outside tests.**  This produces zero entropy.
pub struct WeakRng {
    /// The byte that `fill_bytes` will write everywhere.
    pub byte: u8,
}

impl WeakRng {
    /// Create a weak RNG that always outputs `byte`.
    /// The default (and most common) choice is `0x00`.
    pub fn new(byte: u8) -> Self {
        Self { byte }
    }

    /// Shortcut: a weak RNG that outputs all zeros.
    pub fn zeros() -> Self {
        Self::new(0x00)
    }
}

impl RngCore for WeakRng {
    fn next_u32(&mut self) -> u32 {
        // All four bytes are the same constant.
        u32::from_le_bytes([self.byte; 4])
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([self.byte; 8])
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = self.byte;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unit tests  (run with `cargo test`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- config factories -------------------------------------------------

    #[test]
    fn test_config_is_valid() {
        let cfg = test_config();
        assert_eq!(cfg.fiat_shamir.domain_separator, TEST_DOMAIN);
    }

    #[test]
    fn test_config_with_domain_is_valid() {
        let cfg = test_config_with_domain("custom-domain-v2");
        assert_eq!(cfg.fiat_shamir.domain_separator, "custom-domain-v2");
    }

    // --- deterministic RNG ------------------------------------------------

    #[test]
    fn deterministic_rng_same_seed_same_output() {
        let mut rng_a = DeterministicRng::new(12345);
        let mut rng_b = DeterministicRng::new(12345);

        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];

        rng_a.fill_bytes(&mut buf_a);
        rng_b.fill_bytes(&mut buf_b);

        assert_eq!(buf_a, buf_b, "same seed must produce identical bytes");
    }

    #[test]
    fn deterministic_rng_different_seed_different_output() {
        let mut rng_a = DeterministicRng::new(1);
        let mut rng_b = DeterministicRng::new(2);

        let mut buf_a = [0u8; 32];
        let mut buf_b = [0u8; 32];

        rng_a.fill_bytes(&mut buf_a);
        rng_b.fill_bytes(&mut buf_b);

        assert_ne!(buf_a, buf_b, "different seeds must diverge");
    }

    #[test]
    fn deterministic_rng_next_u64_advances_state() {
        let mut rng = DeterministicRng::new(0);
        let a = rng.next_u64();
        let b = rng.next_u64();
        assert_ne!(a, b, "successive u64s must differ");
    }

    #[test]
    fn deterministic_rng_next_u32_matches_upper_bits() {
        // Reconstruct what next_u32 should return from a fresh next_u64.
        let mut rng_64 = DeterministicRng::new(99);
        let full = rng_64.next_u64();
        let expected_u32 = (full >> 32) as u32;

        let mut rng_32 = DeterministicRng::new(99);
        let got_u32 = rng_32.next_u32();

        assert_eq!(got_u32, expected_u32);
    }

    #[test]
    fn deterministic_rng_partial_tail_fill() {
        // Fill a buffer whose length is NOT a multiple of 8 to exercise
        // the tail-copy branch.
        let mut rng = DeterministicRng::new(7);
        let mut buf = [0u8; 13]; // 8 + 5 remainder
        rng.fill_bytes(&mut buf);

        // Re-run with a fresh rng at the same seed — must match.
        let mut rng2 = DeterministicRng::new(7);
        let mut buf2 = [0u8; 13];
        rng2.fill_bytes(&mut buf2);

        assert_eq!(buf, buf2);
    }

    // --- weak RNG ---------------------------------------------------------

    #[test]
    fn weak_rng_zeros_fills_all_zeros() {
        let mut rng = WeakRng::zeros();
        let mut buf = [0xFFu8; 32]; // start with 0xFF so change is visible
        rng.fill_bytes(&mut buf);
        assert!(buf.iter().all(|&b| b == 0x00));
    }

    #[test]
    fn weak_rng_custom_byte_fills_correctly() {
        let mut rng = WeakRng::new(0xAB);
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        assert!(buf.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn weak_rng_next_u64_is_constant() {
        let mut rng = WeakRng::new(0x01);
        let expected = u64::from_le_bytes([0x01; 8]);
        assert_eq!(rng.next_u64(), expected);
        assert_eq!(rng.next_u64(), expected); // same every call
    }

    #[test]
    fn weak_rng_next_u32_is_constant() {
        let mut rng = WeakRng::new(0x02);
        let expected = u32::from_le_bytes([0x02; 4]);
        assert_eq!(rng.next_u32(), expected);
        assert_eq!(rng.next_u32(), expected);
    }

    // --- constants sanity -------------------------------------------------

    #[test]
    fn dummy_usernames_are_distinct() {
        assert_ne!(DUMMY_USERNAME, DUMMY_USERNAME_2);
    }

    #[test]
    fn test_domain_differs_from_production_default() {
        let prod = ZkAuthConfig::default();
        assert_ne!(prod.fiat_shamir.domain_separator, TEST_DOMAIN);
    }
}