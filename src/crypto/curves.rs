//! Elliptic curve operations over Ristretto (curve25519).

use std::fmt;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as DalekScalar,
    traits::{Identity, IsIdentity},
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::{POINT_BYTE_LEN, SCALAR_BYTE_LEN};
use crate::errors::{Result, ZkAuthError};

//
// ---------------------------------------------------------------------------
// Scalar
// ---------------------------------------------------------------------------
//

/// A scalar modulo the Ristretto255 group order.
///
/// `Debug` is implemented manually so secret scalars are never printed.
/// Equality is constant-time (provided by dalek).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Scalar(#[serde(with = "scalar_serde")] pub(crate) DalekScalar);

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Scalar(<redacted>)")
    }
}

impl Scalar {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(DalekScalar::random(rng))
    }

    /// Decode a canonical (fully reduced) 32-byte scalar.
    pub fn from_bytes(bytes: &[u8; SCALAR_BYTE_LEN]) -> Result<Self> {
        DalekScalar::from_canonical_bytes(*bytes)
            .into_option()
            .map(Self)
            .ok_or(ZkAuthError::InvalidScalar)
    }

    pub fn to_bytes(&self) -> [u8; SCALAR_BYTE_LEN] {
        self.0.to_bytes()
    }

    /// Additive identity.
    pub fn zero() -> Self {
        Self(DalekScalar::ZERO)
    }

    /// Modular inverse.
    pub fn invert(&self) -> Self {
        Self(self.0.invert())
    }

    /// Access underlying dalek scalar.
    #[allow(dead_code)]
    pub fn inner(&self) -> &DalekScalar {
        &self.0
    }

    /// Construct a scalar from 32 bytes reduced mod q.
    ///
    /// Reducing only 256 bits introduces a small modular bias, so prefer
    /// [`Scalar::from_wide_bytes`] for hash-derived values.
    #[allow(dead_code)]
    pub(crate) fn from_hash_bytes(bytes: [u8; 32]) -> Self {
        Self(DalekScalar::from_bytes_mod_order(bytes))
    }

    /// Construct a scalar from 64 uniform bytes (wide reduction mod q).
    ///
    /// Use this for hash-derived challenges: it removes the modular bias of
    /// reducing only 256 bits.
    pub(crate) fn from_wide_bytes(bytes: [u8; 64]) -> Self {
        Self(DalekScalar::from_bytes_mod_order_wide(&bytes))
    }

    /// Construct directly from a dalek scalar.
    pub(crate) fn from_dalek(s: DalekScalar) -> Self {
        Self(s)
    }
}

//
// --- Scalar arithmetic
//

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

impl Mul for &Scalar {
    type Output = Scalar;
    fn mul(self, rhs: Self) -> Scalar {
        Scalar(self.0 * rhs.0)
    }
}

impl Neg for &Scalar {
    type Output = Scalar;
    fn neg(self) -> Scalar {
        Scalar(-self.0)
    }
}

//
// --- Scalar serde helper (hex strings, canonical encodings only)
//

mod scalar_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(scalar: &DalekScalar, ser: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str(&hex::encode(scalar.to_bytes()))
    }

    pub fn deserialize<'de, D>(de: D) -> std::result::Result<DalekScalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(de)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != SCALAR_BYTE_LEN {
            return Err(serde::de::Error::custom("scalar must be 32 bytes"));
        }
        let mut arr = [0u8; SCALAR_BYTE_LEN];
        arr.copy_from_slice(&bytes);
        DalekScalar::from_canonical_bytes(arr)
            .into_option()
            .ok_or_else(|| serde::de::Error::custom("invalid canonical scalar"))
    }
}

//
// ---------------------------------------------------------------------------
// Point
// ---------------------------------------------------------------------------
//

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Point(#[serde(with = "point_serde")] pub(crate) RistrettoPoint);

impl Point {
    /// Decode a compressed Ristretto point, rejecting invalid encodings.
    pub fn from_bytes(bytes: &[u8; POINT_BYTE_LEN]) -> Result<Self> {
        CompressedRistretto(*bytes)
            .decompress()
            .map(Self)
            .ok_or(ZkAuthError::InvalidPoint)
    }

    pub fn to_bytes(&self) -> [u8; POINT_BYTE_LEN] {
        self.0.compress().to_bytes()
    }

    /// Identity point.
    pub fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }

    /// True if this is the group identity.
    ///
    /// The identity has discrete log 0, so it must never be accepted as a
    /// public key: anyone can "prove" knowledge of it.
    pub fn is_identity(&self) -> bool {
        self.0.is_identity()
    }

    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &RistrettoPoint {
        &self.0
    }
}

//
// --- Point arithmetic
//

impl Add for &Point {
    type Output = Point;
    fn add(self, rhs: Self) -> Point {
        Point(self.0 + rhs.0)
    }
}

impl Sub for &Point {
    type Output = Point;
    fn sub(self, rhs: Self) -> Point {
        Point(self.0 - rhs.0)
    }
}

impl Neg for &Point {
    type Output = Point;
    fn neg(self) -> Point {
        Point(-self.0)
    }
}

impl Mul<&Point> for &Scalar {
    type Output = Point;
    fn mul(self, rhs: &Point) -> Point {
        Point(self.0 * rhs.0)
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

//
// --- Point serde helper (hex strings, validated decompression)
//

mod point_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(point: &RistrettoPoint, ser: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str(&hex::encode(point.compress().to_bytes()))
    }

    pub fn deserialize<'de, D>(de: D) -> std::result::Result<RistrettoPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(de)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != POINT_BYTE_LEN {
            return Err(serde::de::Error::custom("point must be 32 bytes"));
        }
        let mut arr = [0u8; POINT_BYTE_LEN];
        arr.copy_from_slice(&bytes);
        CompressedRistretto(arr)
            .decompress()
            .ok_or_else(|| serde::de::Error::custom("invalid Ristretto point encoding"))
    }
}

//
// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
//

pub const BASEPOINT: Point = Point(RISTRETTO_BASEPOINT_POINT);

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn debug_redacts_scalar() {
        let s = Scalar::random(&mut OsRng);
        let shown = format!("{:?}", s);
        assert!(shown.contains("redacted"));
        assert!(!shown.contains(&hex::encode(s.to_bytes())));
    }

    #[test]
    fn non_canonical_scalar_rejected() {
        assert!(Scalar::from_bytes(&[0xff; SCALAR_BYTE_LEN]).is_err());
    }

    #[test]
    fn invalid_point_encoding_rejected() {
        assert!(Point::from_bytes(&[0xff; POINT_BYTE_LEN]).is_err());
    }

    #[test]
    fn identity_is_detected() {
        assert!(Point::identity().is_identity());
        assert!(!BASEPOINT.is_identity());
    }

    #[test]
    fn wide_reduction_is_deterministic() {
        let a = Scalar::from_wide_bytes([7u8; 64]);
        let b = Scalar::from_wide_bytes([7u8; 64]);
        assert_eq!(a, b);
    }

    #[test]
    fn point_bytes_round_trip() {
        let s = Scalar::random(&mut OsRng);
        let p = &s * &BASEPOINT;
        assert_eq!(Point::from_bytes(&p.to_bytes()).unwrap(), p);
    }
}
