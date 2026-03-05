//! Test utilities — only compiled under #[cfg(test)].
//!
//! ⚠️ DeterministicRng is NOT cryptographically secure.
//! Never use it outside test code.

use rand::{CryptoRng, RngCore};

/// Seeded deterministic RNG for reproducible tests.
/// Uses a 64-bit LCG with Knuth's constants.
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    #[inline]
    fn next_u64_inner(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }
}

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

// Satisfies R: RngCore + CryptoRng bounds on Schnorr::prove / Keypair::generate.
// This is intentional for tests — see module doc warning above.
impl CryptoRng for DeterministicRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_output() {
        let mut r1 = DeterministicRng::new(42);
        let mut r2 = DeterministicRng::new(42);
        let mut b1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        r1.fill_bytes(&mut b1);
        r2.fill_bytes(&mut b2);
        assert_eq!(b1, b2);
    }

    #[test]
    fn different_seeds_different_output() {
        let mut r1 = DeterministicRng::new(1);
        let mut r2 = DeterministicRng::new(2);
        let mut b1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        r1.fill_bytes(&mut b1);
        r2.fill_bytes(&mut b2);
        assert_ne!(b1, b2);
    }
}
