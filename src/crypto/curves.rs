//! Elliptic curve operations over Ristretto (curve25519).

use std::fmt;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as DalekScalar,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Scalar(#[serde(with = "scalar_serde")] pub(crate) DalekScalar);

impl Scalar {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(DalekScalar::random(rng))
    }

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

    /// Construct scalar from hash output.
    pub(crate) fn from_hash_bytes(bytes: [u8; 32]) -> Self {
        Self(DalekScalar::from_bytes_mod_order(bytes))
    }

    /// Construct directly from DalekScalar.
    pub(crate) fn from_dalek(s: DalekScalar) -> Self {
        Self(s)
    }
}

//
// --- Scalar arithmetic
//

impl Add for &Scalar {
    type Output = Scalar;
    fn add(self, rhs: Self) -> Scalar { Scalar(self.0 + rhs.0) }
}

impl AddAssign for Scalar {
    fn add_assign(&mut self, rhs: Self) { self.0 += rhs.0; }
}

impl Sub for &Scalar {
    type Output = Scalar;
    fn sub(self, rhs: Self) -> Scalar { Scalar(self.0 - rhs.0) }
}

impl SubAssign for Scalar {
    fn sub_assign(&mut self, rhs: Self) { self.0 -= rhs.0; }
}

impl Mul for &Scalar {
    type Output = Scalar;
    fn mul(self, rhs: Self) -> Scalar { Scalar(self.0 * rhs.0) }
}

impl Neg for &Scalar {
    type Output = Scalar;
    fn neg(self) -> Scalar { Scalar(-self.0) }
}

//
// --- Scalar serde helper
// FIX: serialize_bytes produces a JSON integer array that cannot be
// deserialized back as &[u8]. Use hex strings instead — they round-trip
// correctly with serde_json and all other formats.
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
        use curve25519_dalek::traits::Identity;
        Self(RistrettoPoint::identity())
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
    fn add(self, rhs: Self) -> Point { Point(self.0 + rhs.0) }
}

impl Sub for &Point {
    type Output = Point;
    fn sub(self, rhs: Self) -> Point { Point(self.0 - rhs.0) }
}

impl Neg for &Point {
    type Output = Point;
    fn neg(self) -> Point { Point(-self.0) }
}

impl Mul<&Point> for &Scalar {
    type Output = Point;
    fn mul(self, rhs: &Point) -> Point { Point(self.0 * rhs.0) }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

//
// ---------------------------------------------------------------------------
// point_serde
// FIX: same as scalar_serde — use hex strings for JSON compatibility.
// ---------------------------------------------------------------------------
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