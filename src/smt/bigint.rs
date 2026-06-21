//! Big-integer helpers for sparse-Merkle-tree path routing.
//!
//! The plain and sum trees route by interpreting keys and step paths as
//! arbitrary-precision unsigned integers, exactly mirroring the reference SDKs'
//! `BitString` and `BigintConverter`. Two conventions are load-bearing for
//! binary compatibility and must be reproduced precisely:
//!
//! * **`BigintConverter`** is big-endian and *minimal*: the integer `0` encodes
//!   to the **empty** byte string, not a single `0x00`. [`bytes_to_path`] /
//!   [`path_to_bytes`] implement this.
//! * **`BitString`** prepends a sentinel `0x01` byte before interpreting the key
//!   bytes big-endian, so leading zero bits survive the round-trip. The routing
//!   path of a key is therefore `0x01 ‖ key` read big-endian ([`key_to_path`]).

use alloc::vec::Vec;

use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::error::{CborError, Error};

/// Decode a `BigintConverter`-encoded big-endian byte string into a [`BigUint`].
/// The empty string decodes to zero.
pub fn bytes_to_path(bytes: &[u8]) -> Result<BigUint, Error> {
    if bytes.first() == Some(&0) {
        return Err(CborError::NonCanonicalEncoding.into());
    }
    Ok(BigUint::from_bytes_be(bytes))
}

/// Encode a [`BigUint`] as a `BigintConverter` big-endian byte string. Zero
/// encodes to the empty string (matching the reference, which strips leading
/// zero bytes entirely).
pub fn path_to_bytes(value: &BigUint) -> Vec<u8> {
    if value.is_zero() {
        Vec::new()
    } else {
        value.to_bytes_be()
    }
}

/// The sparse-Merkle routing path of a key: `0x01 ‖ key` interpreted big-endian
/// (the reference `BitString.fromBytes(key).toBigInt()`).
pub fn key_to_path(key: &[u8]) -> BigUint {
    let mut buf = Vec::with_capacity(key.len() + 1);
    buf.push(0x01);
    buf.extend_from_slice(key);
    BigUint::from_bytes_be(&buf)
}

/// The number of significant bits in `value` (`0` for zero), matching noble's
/// `bitLen`.
pub fn bit_len(value: &BigUint) -> u64 {
    value.bits()
}

/// The longest common prefix path of two routing paths, returned as
/// `(length, path)` exactly like the reference `calculateCommonPath`.
///
/// Walks bit positions from the least-significant end while the two paths agree
/// and neither has been fully consumed; `path` accumulates the shared bits with
/// the same sentinel-bit convention used throughout tree routing.
pub fn calculate_common_path(path1: &BigUint, path2: &BigUint) -> (BigUint, BigUint) {
    let one = BigUint::one();
    let mut path = one.clone();
    let mut mask = one.clone();
    let mut length = BigUint::zero();

    // (path1 & mask) == (path2 & mask) && path < path1 && path < path2
    while (path1 & &mask) == (path2 & &mask) && path < *path1 && path < *path2 {
        mask <<= 1u32;
        length += &one;
        // path = mask | ((mask - 1) & path1)
        path = &mask | (&(&mask - &one) & path1);
    }

    (length, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{CborError, Error};

    #[test]
    fn bigint_encoding_is_minimal() {
        assert_eq!(bytes_to_path(&[]).unwrap(), BigUint::ZERO);
        assert_eq!(bytes_to_path(&[1]).unwrap(), BigUint::one());
        assert_eq!(
            bytes_to_path(&[0, 1]),
            Err(Error::Cbor(CborError::NonCanonicalEncoding))
        );
    }
}
