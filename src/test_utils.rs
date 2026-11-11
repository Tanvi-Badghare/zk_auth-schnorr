//! Shared test helpers for the zk-auth crate.

use rand::RngCore;
use crate::config::ZkAuthConfig;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const DUMMY_USERNAME: &str = "alice";
pub const DUMMY_USERNAME_2: &str = "bob";

/// Domain separator used in tests to avoid cross-use with production proofs.
pub const TEST_DOMAIN: &str = "zk-auth-test-v0.1";

// ---------------------------------------------------------------------------
// Config factories
// ---------------------------------------------------------------------------

pub fn test_config() -> ZkAuthConfig {
    let cfg = ZkAuthConfig::with_domain(TEST_DOMAIN);
    cfg.validate().expect("test_config must be valid");
    cfg
}

pub fn test_config_with_domain(domain: &str) -> ZkAuthConfig {
    let cfg = ZkAuthConfig::with_domain(domain);
    cfg.validate().expect("test_config_with_domain must be valid");
    cfg
}

// ---------------------------------------------------------------------------
// Deterministic RNG (LCG)
// ---------------------------------------------------------------------------

pub struct DeterministicRng {
    state: u64,
}

const LCG_A: u64 = 6_364_136_223_846_793_005;
const LCG_C: u64 = 1_442_695_040_888_963_407;

impl DeterministicRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_state(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(LCG_A).wrapping_add(LCG_C);
        self.state
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        (self.next_state() >> 32) as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.next_state()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;

        while i + 8 <= dest.len() {
            dest[i..i + 8].copy_from_slice(&self.next_state().to_le_bytes());
            i += 8;
        }

        if i < dest.len() {
            let tail = self.next_state().to_le_bytes();
            let remaining = dest.len() - i;
            dest[i..].copy_from_slice(&tail[..remaining]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Weak RNG
// ---------------------------------------------------------------------------

pub struct WeakRng {
    pub byte: u8,
}

impl WeakRng {
    pub fn new(byte: u8) -> Self {
        Self { byte }
    }

    pub fn zeros() -> Self {
        Self::new(0x00)
    }
}

impl RngCore for WeakRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([self.byte; 4])
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([self.byte; 8])
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(self.byte);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn deterministic_rng_same_seed_same_output() {
        let mut a = DeterministicRng::new(12345);
        let mut b = DeterministicRng::new(12345);

        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];

        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);

        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn deterministic_rng_different_seed_different_output() {
        let mut a = DeterministicRng::new(1);
        let mut b = DeterministicRng::new(2);

        let mut buf_a = [0u8; 32];
        let mut buf_b = [0u8; 32];

        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);

        assert_ne!(buf_a, buf_b);
    }

    #[test]
    fn weak_rng_zeros_fills_zeros() {
        let mut rng = WeakRng::zeros();
        let mut buf = [0xFFu8; 32];
        rng.fill_bytes(&mut buf);

        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn dummy_usernames_distinct() {
        assert_ne!(DUMMY_USERNAME, DUMMY_USERNAME_2);
    }

    #[test]
    fn test_domain_differs_from_default() {
        let prod = ZkAuthConfig::default();
        assert_ne!(prod.fiat_shamir.domain_separator, TEST_DOMAIN);
    }
}
