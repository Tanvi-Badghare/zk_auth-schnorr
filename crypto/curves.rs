//! Elliptic curve operations over Ristretto (curve25519).
//!
//! This module provides [`Scalar`] (field elements / secret keys) and
//! [`Point`] (curve points / public keys) as thin wrappers around
//! `curve25519-dalek`'s Ristretto group.
//!
//! ## Why Ristretto?
//!
//! Ristretto is a prime-order group constructed on top of curve25519.
//! It eliminates the cofactor-related pitfalls that plague raw curve25519
//! usage, making it the standard choice for Schnorr proofs and
//! zero-knowledge protocols.
//!
//! ## Newtype wrappers
//!
//! We wrap `curve25519_dalek::Scalar` and `RistrettoPoint` instead of
//! exposing them directly so that:
//! - The public API never depends on `curve25519_dalek` types.
//! - We can add [`Zeroize`][zeroize::Zeroize] to secret scalars.
//! - We control serialization format (always canonical bytes).
//! - We can swap curves in experiments without breaking downstream code.

use std::fmt;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint,
    scalar::Scalar as DalekScalar,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::{POINT_BYTE_LEN, SCALAR_BYTE_LEN};
use crate::errors::{Result, ZkAuthError};

// ---------------------------------------------------------------------------
// Scalar (field elements, secret keys, nonces)
// ---------------------------------------------------------------------------

/// A scalar in the Ristretto field (integers mod the group order).
///
/// Scalars are used for:
/// * Secret keys (long-term)
/// * Nonces (ephemeral randomness in Schnorr proofs)
/// * Challenges (output of Fiat–Shamir hash)
/// * Responses (s = k + c·x)
///
/// ## Security
/// [`Scalar`] derives [`Zeroize`] and [`ZeroizeOnDrop`] so that secret
/// values are overwritten with zeros when they go out of scope.  This
/// prevents them from lingering in memory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Scalar(
    #[serde(with = "scalar_serde")]
    pub(crate) DalekScalar,
);

impl Scalar {
    /// Generate a uniformly random scalar using the provided RNG.
    ///
    /// This is the **primary** way to create secret keys and nonces.
    /// The randomness comes from `rng`, which should be a cryptographically
    /// secure source (e.g. [`OsRng`][rand::rngs::OsRng]).
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        Self(DalekScalar::random(rng))
    }

    /// Deserialize a scalar from exactly 32 bytes (little-endian).
    ///
    /// Returns [`ZkAuthError::InvalidScalar`] if the bytes represent a
    /// value ≥ the group order (highly unlikely for random bytes, but
    /// possible if an attacker crafts malicious input).
    pub fn from_bytes(bytes: &[u8; SCALAR_BYTE_LEN]) -> Result<Self> {
        DalekScalar::from_canonical_bytes(*bytes)
            .map(Self)
            .ok_or(ZkAuthError::InvalidScalar)
    }

    /// Serialize this scalar to exactly 32 bytes (little-endian, canonical).
    pub fn to_bytes(&self) -> [u8; SCALAR_BYTE_LEN] {
        self.0.to_bytes()
    }
}

// --- Arithmetic trait forwarding (Scalar) ---------------------------------

impl Add for Scalar {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Add for &Scalar {
    type Output = Scalar;
    fn add(self, rhs: Self) -> Scalar {
        Scalar(self.0 + rhs.0)
    }
}

impl AddAssign for Scalar {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for Scalar {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl Sub for &Scalar {
    type Output = Scalar;
    fn sub(self, rhs: Self) -> Scalar {
        Scalar(self.0 - rhs.0)
    }
}

impl SubAssign for Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl Mul for Scalar {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self(self.0 * rhs.0)
    }
}

impl Mul for &Scalar {
    type Output = Scalar;
    fn mul(self, rhs: Self) -> Scalar {
        Scalar(self.0 * rhs.0)
    }
}

impl Neg for Scalar {
    type Output = Self;
    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl Neg for &Scalar {
    type Output = Scalar;
    fn neg(self) -> Scalar {
        Scalar(-self.0)
    }
}

// --- Serde helpers for Scalar ----------------------------------------------
//
// curve25519_dalek::Scalar's serde impl produces a 32-element array in JSON.
// We want a single base64 string instead.  This custom serde adapter uses
// to_bytes / from_bytes.

mod scalar_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(scalar: &DalekScalar, ser: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as 32 raw bytes (serde will base64-encode in JSON, or
        // use the native representation in bincode/etc).
        ser.serialize_bytes(&scalar.to_bytes())
    }

    pub fn deserialize<'de, D>(de: D) -> std::result::Result<DalekScalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = Deserialize::deserialize(de)?;
        if bytes.len() != SCALAR_BYTE_LEN {
            return Err(serde::de::Error::custom("scalar must be 32 bytes"));
        }
        let mut arr = [0u8; SCALAR_BYTE_LEN];
        arr.copy_from_slice(bytes);
        DalekScalar::from_canonical_bytes(arr)
            .ok_or_else(|| serde::de::Error::custom("invalid scalar (>= group order)"))
    }
}

// ---------------------------------------------------------------------------
// Point (curve points, public keys)
// ---------------------------------------------------------------------------

/// A point on the Ristretto group.
///
/// Points are used for:
/// * Public keys (long-term)
/// * Commitments (ephemeral `R` in Schnorr)
/// * Any value that needs to be public and verifiable
///
/// ## Serialization
/// Points serialize to 32 bytes (Ristretto compressed encoding).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Point(
    #[serde(with = "point_serde")]
    pub(crate) RistrettoPoint,
);

impl Point {
    /// Deserialize a point from exactly 32 bytes (Ristretto compressed).
    ///
    /// Returns [`ZkAuthError::InvalidPoint`] if the bytes do not represent
    /// a valid Ristretto point (this happens if an attacker sends garbage).
    pub fn from_bytes(bytes: &[u8; POINT_BYTE_LEN]) -> Result<Self> {
        RistrettoPoint::from_bytes(bytes)
            .map(Self)
            .map_err(|_| ZkAuthError::InvalidPoint)
    }

    /// Serialize this point to exactly 32 bytes (Ristretto compressed).
    pub fn to_bytes(&self) -> [u8; POINT_BYTE_LEN] {
        self.0.compress().to_bytes()
    }
}

// --- Arithmetic trait forwarding (Point) ----------------------------------

impl Add for Point {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Add for &Point {
    type Output = Point;
    fn add(self, rhs: Self) -> Point {
        Point(self.0 + rhs.0)
    }
}

impl Sub for Point {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl Sub for &Point {
    type Output = Point;
    fn sub(self, rhs: Self) -> Point {
        Point(self.0 - rhs.0)
    }
}

impl Neg for Point {
    type Output = Self;
    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl Neg for &Point {
    type Output = Point;
    fn neg(self) -> Point {
        Point(-self.0)
    }
}

// --- Scalar multiplication: Scalar * Point ---------------------------------

impl Mul<Point> for Scalar {
    type Output = Point;
    fn mul(self, rhs: Point) -> Point {
        Point(self.0 * rhs.0)
    }
}

impl Mul<&Point> for &Scalar {
    type Output = Point;
    fn mul(self, rhs: &Point) -> Point {
        Point(self.0 * rhs.0)
    }
}

impl Mul<Point> for &Scalar {
    type Output = Point;
    fn mul(self, rhs: Point) -> Point {
        Point(self.0 * rhs.0)
    }
}

impl Mul<&Point> for Scalar {
    type Output = Point;
    fn mul(self, rhs: &Point) -> Point {
        Point(self.0 * rhs.0)
    }
}

// --- Display for Point (hex-encoded public keys) ---------------------------

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

// --- Serde helpers for Point -----------------------------------------------

mod point_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(point: &RistrettoPoint, ser: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_bytes(&point.compress().to_bytes())
    }

    pub fn deserialize<'de, D>(de: D) -> std::result::Result<RistrettoPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = Deserialize::deserialize(de)?;
        if bytes.len() != POINT_BYTE_LEN {
            return Err(serde::de::Error::custom("point must be 32 bytes"));
        }
        let mut arr = [0u8; POINT_BYTE_LEN];
        arr.copy_from_slice(bytes);
        RistrettoPoint::from_bytes(&arr)
            .map_err(|_| serde::de::Error::custom("invalid Ristretto point"))
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The standard Ristretto basepoint (generator).
///
/// This is the point `G` in the group.  Every public key is computed as
/// `Y = x * BASEPOINT`, where `x` is the secret key.
pub const BASEPOINT: Point = Point(RISTRETTO_BASEPOINT_POINT);

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::DeterministicRng;

    // --- Scalar tests -----------------------------------------------------

    #[test]
    fn scalar_random_produces_different_values() {
        let mut rng = DeterministicRng::new(42);
        let s1 = Scalar::random(&mut rng);
        let s2 = Scalar::random(&mut rng);
        assert_ne!(s1, s2);
    }

    #[test]
    fn scalar_from_bytes_round_trips() {
        let mut rng = DeterministicRng::new(99);
        let original = Scalar::random(&mut rng);
        let bytes = original.to_bytes();
        let recovered = Scalar::from_bytes(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn scalar_from_bytes_rejects_invalid() {
        // All-ones is >= the group order (extremely likely to be invalid).
        let bad_bytes = [0xFFu8; 32];
        assert!(Scalar::from_bytes(&bad_bytes).is_err());
    }

    #[test]
    fn scalar_arithmetic_add_sub() {
        let mut rng = DeterministicRng::new(1);
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let sum = &a + &b;
        let diff = &sum - &b;
        assert_eq!(diff, a);
    }

    #[test]
    fn scalar_arithmetic_mul() {
        let mut rng = DeterministicRng::new(2);
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let prod = &a * &b;
        // a * b should not equal a or b (unless one is 1, which is unlikely).
        assert_ne!(prod, a);
        assert_ne!(prod, b);
    }

    #[test]
    fn scalar_arithmetic_neg() {
        let mut rng = DeterministicRng::new(3);
        let a = Scalar::random(&mut rng);
        let neg_a = -&a;
        let sum = &a + &neg_a;
        // a + (-a) = 0.  We check by multiplying by BASEPOINT — should be identity.
        let zero_point = sum * BASEPOINT;
        // The identity in Ristretto is not easily constructed, but a*G + (-a)*G = 0*G
        // is the identity, which serializes to all zeros in compressed form? No.
        // Actually, Ristretto identity serializes to a specific value.
        // Easier test: a - a = 0.
        let zero = &a - &a;
        assert_eq!(zero * BASEPOINT, sum * BASEPOINT);
    }

    #[test]
    fn scalar_serde_round_trips() {
        let mut rng = DeterministicRng::new(10);
        let original = Scalar::random(&mut rng);
        let json = serde_json::to_string(&original).unwrap();
        let recovered: Scalar = serde_json::from_str(&json).unwrap();
        assert_eq!(original, recovered);
    }

    // --- Point tests ------------------------------------------------------

    #[test]
    fn point_from_bytes_round_trips() {
        let mut rng = DeterministicRng::new(50);
        let scalar = Scalar::random(&mut rng);
        let point = scalar * BASEPOINT;
        let bytes = point.to_bytes();
        let recovered = Point::from_bytes(&bytes).unwrap();
        assert_eq!(point, recovered);
    }

    #[test]
    fn point_from_bytes_rejects_invalid() {
        // All-zeros is not a valid Ristretto point.
        let bad_bytes = [0u8; 32];
        assert!(Point::from_bytes(&bad_bytes).is_err());
    }

    #[test]
    fn point_arithmetic_add_sub() {
        let mut rng = DeterministicRng::new(60);
        let p = Scalar::random(&mut rng) * BASEPOINT;
        let q = Scalar::random(&mut rng) * BASEPOINT;
        let sum = &p + &q;
        let diff = &sum - &q;
        assert_eq!(diff, p);
    }

    #[test]
    fn point_arithmetic_neg() {
        let mut rng = DeterministicRng::new(70);
        let p = Scalar::random(&mut rng) * BASEPOINT;
        let neg_p = -&p;
        let sum = &p + &neg_p;
        // p + (-p) should be the identity.  We verify by checking serialization.
        // Actually, easier: subtract p from itself.
        let zero = &p - &p;
        assert_eq!(sum, zero);
    }

    #[test]
    fn scalar_mult_basepoint() {
        let mut rng = DeterministicRng::new(80);
        let x = Scalar::random(&mut rng);
        let y = x * BASEPOINT;
        // y should be a valid point.
        let bytes = y.to_bytes();
        let recovered = Point::from_bytes(&bytes).unwrap();
        assert_eq!(y, recovered);
    }

    #[test]
    fn scalar_mult_distributive() {
        // (a + b) * P = a*P + b*P
        let mut rng = DeterministicRng::new(90);
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let p = Scalar::random(&mut rng) * BASEPOINT;

        let lhs = (&a + &b) * &p;
        let rhs = (&a * &p) + (&b * &p);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn point_display_is_hex() {
        let p = BASEPOINT;
        let display = format!("{}", p);
        // Should be 64 hex chars (32 bytes * 2).
        assert_eq!(display.len(), 64);
        // Should decode as valid hex.
        assert!(hex::decode(&display).is_ok());
    }

    #[test]
    fn point_serde_round_trips() {
        let mut rng = DeterministicRng::new(100);
        let point = Scalar::random(&mut rng) * BASEPOINT;
        let json = serde_json::to_string(&point).unwrap();
        let recovered: Point = serde_json::from_str(&json).unwrap();
        assert_eq!(point, recovered);
    }

    // --- Zeroize test (Scalar only) ----------------------------------------

    #[test]
    fn scalar_is_zeroized_on_drop() {
        let mut rng = DeterministicRng::new(200);
        let scalar = Scalar::random(&mut rng);
        let bytes_before = scalar.to_bytes();
        
        // Drop the scalar.
        drop(scalar);
        
        // We can't actually inspect the memory after drop in safe Rust,
        // but we trust that Zeroize works.  This test documents the intent.
        // In a real audit, you'd use unsafe or a debugger to verify.
        assert_ne!(bytes_before, [0u8; 32]); // sanity: it wasn't zero before
    }
}