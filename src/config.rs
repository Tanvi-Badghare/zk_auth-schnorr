//! System-wide configuration for zk-auth.

use crate::errors::{Result, ZkAuthError};
use serde::{Deserialize, Serialize};

pub const SCALAR_BYTE_LEN: usize = 32;
pub const POINT_BYTE_LEN: usize = 32;
pub const HASH_BYTE_LEN: usize = 32;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FiatShamirConfig {
    pub domain_separator: String,
}

impl Default for FiatShamirConfig {
    fn default() -> Self {
        Self { domain_separator: "zk-auth-v0.1".to_string() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolConfig {
    pub max_username_len: usize,
    pub nonce_byte_len: usize,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self { max_username_len: 64, nonce_byte_len: 32 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityConfig {
    pub max_auth_attempts: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self { max_auth_attempts: 5 }
    }
}

// FIX: clippy::derivable_impls — the manual Default just calls ::default()
// on every field. Replace with #[derive(Default)].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ZkAuthConfig {
    pub crypto: CryptoConfig,
    pub fiat_shamir: FiatShamirConfig,
    pub protocol: ProtocolConfig,
    pub security: SecurityConfig,
}

impl ZkAuthConfig {
    pub fn validate(&self) -> Result<()> {
        if self.crypto.scalar_byte_len != SCALAR_BYTE_LEN {
            return Err(ZkAuthError::InvalidConfig(format!(
                "scalar_byte_len must be {}, got {}",
                SCALAR_BYTE_LEN, self.crypto.scalar_byte_len
            )));
        }
        if self.crypto.point_byte_len != POINT_BYTE_LEN {
            return Err(ZkAuthError::InvalidConfig(format!(
                "point_byte_len must be {}, got {}",
                POINT_BYTE_LEN, self.crypto.point_byte_len
            )));
        }
        if self.crypto.hash_byte_len != HASH_BYTE_LEN {
            return Err(ZkAuthError::InvalidConfig(format!(
                "hash_byte_len must be {}, got {}",
                HASH_BYTE_LEN, self.crypto.hash_byte_len
            )));
        }
        if self.fiat_shamir.domain_separator.is_empty() {
            return Err(ZkAuthError::InvalidConfig(
                "fiat_shamir.domain_separator must not be empty".to_string(),
            ));
        }
        if self.protocol.max_username_len == 0 {
            return Err(ZkAuthError::InvalidConfig(
                "protocol.max_username_len must be > 0".to_string(),
            ));
        }
        if self.protocol.nonce_byte_len < 16 {
            return Err(ZkAuthError::InvalidConfig(format!(
                "protocol.nonce_byte_len must be >= 16, got {}",
                self.protocol.nonce_byte_len
            )));
        }
        Ok(())
    }

    pub fn with_domain(domain: &str) -> Self {
        Self {
            fiat_shamir: FiatShamirConfig { domain_separator: domain.to_string() },
            ..Self::default()
        }
    }
}

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