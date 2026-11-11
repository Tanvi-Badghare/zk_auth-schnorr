//! Centralised error and Result types for zk-auth.
//!
//! Every public function in the library returns [`Result<T>`],
//! which aliases `std::result::Result<T, ZkAuthError>`.
//!
//! Security Note:
//! -------------
//! Verification and authentication errors are intentionally collapsed
//! to avoid leaking oracle information to potential attackers.

use thiserror::Error;

// ---------------------------------------------------------------------------
// Result alias
// ---------------------------------------------------------------------------

/// Library-wide Result type.
pub type Result<T> = std::result::Result<T, ZkAuthError>;

// ---------------------------------------------------------------------------
// Error enum
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum ZkAuthError {
    // =====================================================================
    // Crypto-layer errors
    // =====================================================================
    #[error("Invalid scalar value")]
    InvalidScalar,

    #[error("Invalid elliptic curve point")]
    InvalidPoint,

    #[error("Randomness generation failure")]
    RngFailure,

    // =====================================================================
    // Protocol-layer errors
    // =====================================================================
    #[error("Verification failed")]
    VerificationFailed,

    #[error("Transcript error")]
    TranscriptError,

    // =====================================================================
    // Registration / Authentication
    // =====================================================================
    #[error("User already registered: {0}")]
    UserAlreadyExists(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    // =====================================================================
    // Serialization
    // FIX: removed bincode::Error (unmaintained). The library uses serde_json
    // for all serialization — serde_json::Error covers both directions.
    // =====================================================================
    // =====================================================================
    // Serialization
    // =====================================================================
    #[error("Serialization error")]
    Serde(#[from] serde_json::Error),

    // =====================================================================
    // Configuration
    // =====================================================================
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}
