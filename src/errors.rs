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
///
/// Errors are grouped by architectural layer:
/// - Crypto layer
/// - Protocol layer
/// - Registration / Authentication
/// - Serialization
/// - Configuration
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

    #[error("Invalid configuration: {0}")]
    InvalidConfig(&'static str),
}