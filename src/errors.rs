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

/// All failure modes that can occur inside zk-auth.
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

    /// Collapsed verification failure to avoid side-channel leakage.
    #[error("Verification failed")]
    VerificationFailed,

    /// Transcript construction or domain separation failure.
    #[error("Transcript error")]
    TranscriptError,

    // =====================================================================
    // Registration / Authentication
    // =====================================================================

    #[error("User already registered")]
    UserAlreadyExists,

    #[error("User not found")]
    UserNotFound,

    /// Collapsed authentication failure.
    #[error("Authentication failed")]
    AuthenticationFailed,

    // =====================================================================
    // Serialization
    // =====================================================================

    #[error("Serialization failure")]
    Serialization(#[from] serde_json::Error),

    #[error("Deserialization failure")]
    Deserialization(#[from] bincode::Error),

    // =====================================================================
    // Configuration
    // =====================================================================

    // FIX: was &'static str — only accepts compile-time string literals.
    // config.rs validate() uses format!() to include the actual bad value,
    // which produces a runtime String. Changing to String accepts both
    // format!() output and plain string literals (via .to_string() or .into()).
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}