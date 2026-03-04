//! System-wide configuration for zk-auth.

use serde::{Deserialize, Serialize};
use crate::errors::{Result, ZkAuthError};

// ---------------------------------------------------------------------------
// Crypto-layer constants
// ---------------------------------------------------------------------------

pub const SCALAR_BYTE_LEN: usize = 32;
pub const POINT_BYTE_LEN: usize = 32;
pub const HASH_BYTE_LEN: usize = 32;

// ---------------------------------------------------------------------------
// CryptoConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CryptoConfig {
    pub scalar_byte_len: usize,
    pub point_byte_len: usize,
    pub hash_byte_len: usize,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            scalar_byte_len: SCALAR_BYTE_LEN,
            point_byte_len: POINT_BYTE_LEN,
            hash_byte_len: HASH_BYTE_LEN,
        }
    }
}

// ---------------------------------------------------------------------------
// FiatShamirConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FiatShamirConfig {
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
// ProtocolConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolConfig {
    pub max_username_len: usize,
    pub nonce_byte_len: usize,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            max_username_len: 64,
            nonce_byte_len: 32,
        }
    }
}

// ---------------------------------------------------------------------------
// SecurityConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityConfig {
    pub max_auth_attempts: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self { max_auth_attempts: 5 }
    }
}

// ---------------------------------------------------------------------------
// ZkAuthConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZkAuthConfig {
    pub crypto: CryptoConfig,
    pub fiat_shamir: FiatShamirConfig,
    pub protocol: ProtocolConfig,
    pub security: SecurityConfig,
}

impl Default for ZkAuthConfig {
    fn default() -> Self {
        Self {
            crypto: CryptoConfig::default(),
            fiat_shamir: FiatShamirConfig::default(),
            protocol: ProtocolConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

impl ZkAuthConfig {
    pub fn validate(&self) -> Result<()> {
        // FIX: InvalidConfig takes &'static str — cannot use format!() which
        // produces String. All messages are now bare string literals.
        // The constant values (32, 16) are embedded in the static strings
        // directly since they are compile-time constants that never change.

        if self.crypto.scalar_byte_len != SCALAR_BYTE_LEN {
            return Err(ZkAuthError::InvalidConfig("scalar_byte_len must be 32"));
        }

        if self.crypto.point_byte_len != POINT_BYTE_LEN {
            return Err(ZkAuthError::InvalidConfig("point_byte_len must be 32"));
        }

        if self.crypto.hash_byte_len != HASH_BYTE_LEN {
            return Err(ZkAuthError::InvalidConfig("hash_byte_len must be 32"));
        }

        if self.fiat_shamir.domain_separator.is_empty() {
            return Err(ZkAuthError::InvalidConfig(
                "fiat_shamir.domain_separator must not be empty",
            ));
        }

        if self.protocol.max_username_len == 0 {
            return Err(ZkAuthError::InvalidConfig(
                "protocol.max_username_len must be > 0",
            ));
        }

        if self.protocol.nonce_byte_len < 16 {
            return Err(ZkAuthError::InvalidConfig(
                "protocol.nonce_byte_len must be >= 16",
            ));
        }

        Ok(())
    }

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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        ZkAuthConfig::default().validate().unwrap();
    }

    #[test]
    fn empty_domain_separator_rejected() {
        let mut cfg = ZkAuthConfig::default();
        cfg.fiat_shamir.domain_separator.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_username_len_rejected() {
        let mut cfg = ZkAuthConfig::default();
        cfg.protocol.max_username_len = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn small_nonce_rejected() {
        let mut cfg = ZkAuthConfig::default();
        cfg.protocol.nonce_byte_len = 8;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn with_domain_sets_value() {
        let cfg = ZkAuthConfig::with_domain("my-service-v1");
        assert_eq!(cfg.fiat_shamir.domain_separator, "my-service-v1");
    }

    #[test]
    fn json_roundtrip() {
        let original = ZkAuthConfig::default();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ZkAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }
}