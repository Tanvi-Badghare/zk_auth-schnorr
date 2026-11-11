/// Centralised error and Result types for zk-auth.
///
/// Every public function in the library returns [`Result<T>`],
/// which aliases `std::result::Result<T, ZkAuthError>`.
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

    #[error("Hashing failure")]
    HashError,

    #[error("Randomness generation failure")]
    RngFailure,

    // =====================================================================
    // Protocol-layer errors
    // =====================================================================

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Verification failed")]
    VerificationFailed,

    #[error("Challenge mismatch")]
    ChallengeMismatch,

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
    // =====================================================================

    #[error("Serialization failure: {0}")]
    SerializationError(String),

    #[error("Deserialization failure: {0}")]
    DeserializationError(String),

    // =====================================================================
    // Configuration
    // =====================================================================

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    // =====================================================================
    // Catch-all
    // =====================================================================

    #[error("Internal error: {0}")]
    Internal(String),
}
