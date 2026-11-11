//! System-wide configuration for zk-auth.
//!
//! All tuneable parameters live here.  Nothing is scattered across modules as
//! a magic number.  The top-level struct is [`ZkAuthConfig`]; construct one
//! with [`ZkAuthConfig::default()`] and override only the fields you need, or
//! deserialise from JSON with `serde_json`.
//!
//! ## Example
//! ```rust
//! use zk_auth::config::ZkAuthConfig;
//!
//! let config = ZkAuthConfig::default();
//! config.validate().expect("default config must be valid");
//! ```

use serde::{Deserialize, Serialize};
use crate::errors::{self, Result};

// ---------------------------------------------------------------------------
// Crypto-layer constants
// ---------------------------------------------------------------------------

/// Byte-length of a Ristretto scalar (curve25519-dalek).
/// This is a compile-time fact, but exposing it here avoids magic `32`s in
/// crypto/ modules.
pub const SCALAR_BYTE_LEN: usize = 32;

/// Byte-length of a compressed Ristretto point.
/// Same reasoning as [`SCALAR_BYTE_LEN`].
pub const POINT_BYTE_LEN: usize = 32;

/// Byte-length of a SHA-256 digest.
pub const HASH_BYTE_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Sub-configs
// ---------------------------------------------------------------------------

/// Parameters that govern the cryptographic primitives layer.
///
/// Currently curve25519 (Ristretto) + SHA-256 are the only supported
/// primitives; these fields document the sizes so that the rest of the
/// code does not hard-code them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CryptoConfig {
    /// Byte-length of a scalar.  Must equal [`SCALAR_BYTE_LEN`].
    pub scalar_byte_len: usize,

    /// Byte-length of a compressed curve point.  Must equal [`POINT_BYTE_LEN`].
    pub point_byte_len: usize,

    /// Byte-length of a hash digest.  Must equal [`HASH_BYTE_LEN`].
    pub hash_byte_len: usize,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            scalar_byte_len: SCALAR_BYTE_LEN,
            point_byte_len:  POINT_BYTE_LEN,
            hash_byte_len:   HASH_BYTE_LEN,
        }
    }
}

// ---------------------------------------------------------------------------

/// Parameters that govern the Fiat–Shamir transform.
///
/// The **domain separator** is the single most security-critical config value.
/// It is prepended to every transcript hash so that a proof generated for
/// *registration* cannot be replayed against the *authentication* verifier
/// (and vice-versa).  It should be versioned so that a protocol upgrade
/// automatically invalidates old proofs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FiatShamirConfig {
    /// ASCII domain tag prepended to Fiat–Shamir transcript hashes.
    /// Must be non-empty.  Convention: `"<project>-<purpose>-v<version>"`.
    pub domain_separator: String,
}

impl Default for FiatShamirConfig {
    fn default() -> Self {
        Self {
            domain_separator: "zk-auth-v0.1".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------

/// Parameters that govern the registration and authentication protocols.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolConfig {
    /// Maximum allowed byte-length for a username / identifier.
    /// Inputs longer than this are rejected before any crypto runs.
    pub max_username_len: usize,

    /// Byte-length of the random nonce used in authentication challenges.
    /// 32 bytes (256 bits) is the minimum for 128-bit security.
    pub nonce_byte_len: usize,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            max_username_len: 64,
            nonce_byte_len:   32,
        }
    }
}

// ---------------------------------------------------------------------------

/// Security-policy knobs (rate-limiting, lockout …).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityConfig {
    /// Number of consecutive failed authentication attempts after which
    /// the account is considered locked.  Set to `0` to disable lockout.
    pub max_auth_attempts: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_auth_attempts: 5,
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// Root configuration object for the entire zk-auth library.
///
/// Construct with [`Default::default()`] for sane out-of-the-box values,
/// then override individual fields as needed.  Call [`validate()`][Self::validate]
/// before passing the config into any protocol function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZkAuthConfig {
    /// Cryptographic primitive sizes.
    pub crypto: CryptoConfig,

    /// Fiat–Shamir transform parameters.
    pub fiat_shamir: FiatShamirConfig,

    /// Protocol-level constraints.
    pub protocol: ProtocolConfig,

    /// Security-policy constraints.
    pub security: SecurityConfig,
}

impl Default for ZkAuthConfig {
    fn default() -> Self {
        Self {
            crypto:       CryptoConfig::default(),
            fiat_shamir:  FiatShamirConfig::default(),
            protocol:     ProtocolConfig::default(),
            security:     SecurityConfig::default(),
        }
    }
}

impl ZkAuthConfig {
    // -----------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------

    /// Check every field for obviously-wrong values.
    ///
    /// Returns `Ok(())` if the config is usable, or
    /// `Err(ZkAuthError::InvalidConfig(_))` with a human-readable
    /// description of the first problem found.
    pub fn validate(&self) -> Result<()> {
        // --- crypto sizes must match the actual primitives ------------
        if self.crypto.scalar_byte_len != SCALAR_BYTE_LEN {
            return Err(errors::ZkAuthError::InvalidConfig(format!(
                "scalar_byte_len must be {}, got {}",
                SCALAR_BYTE_LEN, self.crypto.scalar_byte_len
            )));
        }
        if self.crypto.point_byte_len != POINT_BYTE_LEN {
            return Err(errors::ZkAuthError::InvalidConfig(format!(
                "point_byte_len must be {}, got {}",
                POINT_BYTE_LEN, self.crypto.point_byte_len
            )));
        }
        if self.crypto.hash_byte_len != HASH_BYTE_LEN {
            return Err(errors::ZkAuthError::InvalidConfig(format!(
                "hash_byte_len must be {}, got {}",
                HASH_BYTE_LEN, self.crypto.hash_byte_len
            )));
        }

        // --- domain separator must not be empty ------------------------
        if self.fiat_shamir.domain_separator.is_empty() {
            return Err(errors::ZkAuthError::InvalidConfig(
                "fiat_shamir.domain_separator must not be empty".to_string(),
            ));
        }

        // --- username length must be reasonable ------------------------
        if self.protocol.max_username_len == 0 {
            return Err(errors::ZkAuthError::InvalidConfig(
                "protocol.max_username_len must be > 0".to_string(),
            ));
        }

        // --- nonce must give at least 128-bit security (16 bytes) -----
        if self.protocol.nonce_byte_len < 16 {
            return Err(errors::ZkAuthError::InvalidConfig(format!(
                "protocol.nonce_byte_len must be >= 16, got {}",
                self.protocol.nonce_byte_len
            )));
        }

        Ok(())
    }

    // -----------------------------------------------------------------
    // Convenience constructors
    // -----------------------------------------------------------------

    /// Return a config identical to [`Default`] but with a custom domain
    /// separator.  Useful when you are running registration and
    /// authentication as separate services that must not share a domain.
    pub fn with_domain(domain: &str) -> Self {
        Self {
            fiat_shamir: FiatShamirConfig {
                domain_separator: domain.to_string(),
            },
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        ZkAuthConfig::default()
            .validate()
            .expect("default config must pass validation");
    }

    #[test]
    fn empty_domain_separator_is_rejected() {
        let mut cfg = ZkAuthConfig::default();
        cfg.fiat_shamir.domain_separator = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_max_username_len_is_rejected() {
        let mut cfg = ZkAuthConfig::default();
        cfg.protocol.max_username_len = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn tiny_nonce_is_rejected() {
        let mut cfg = ZkAuthConfig::default();
        cfg.protocol.nonce_byte_len = 8; // only 64 bits — insecure
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn with_domain_sets_separator() {
        let cfg = ZkAuthConfig::with_domain("my-service-v1");
        assert_eq!(cfg.fiat_shamir.domain_separator, "my-service-v1");
        // everything else is still the default
        assert_eq!(cfg.crypto, CryptoConfig::default());
        assert_eq!(cfg.protocol, ProtocolConfig::default());
        assert_eq!(cfg.security, SecurityConfig::default());
    }

    #[test]
    fn round_trips_through_json() {
        let original = ZkAuthConfig::default();
        let json     = serde_json::to_string(&original).unwrap();
        let decoded: ZkAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }
}