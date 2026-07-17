//! Radix Sparse Merkle Sum Tree (RSMST).
//!
//! An RSMST is the radix sparse Merkle tree (a leaf-anchored, path-compressed
//! binary trie over a 256-bit key space, MSB-first) decorated with a positive
//! amount at every leaf and an accumulated sum at every internal node. It backs
//! the per-asset split-allocation roots of the token-splitting protocol
//! (yellowpaper Appendix "Radix Sparse Merkle Sum Trees"): one tree per asset
//! maps each output token id to the amount that output receives, and a single
//! leaf-to-root inclusion proof simultaneously proves a leaf's amount *and* that
//! the committed total equals the burned source amount.
//!
//! The structure deliberately mirrors the plain radix SMT used for transaction
//! inclusion ([`InclusionCertificate`](crate::api::InclusionCertificate)) — same
//! key space, same bit order (the single shared [`crate::radix::bit_at`]
//! convention), same canonical bifurcation depths — but is domain-separated from
//! it (`0x10`/`0x11` vs `0x00`/`0x01`) and additionally commits the per-subtree
//! sum next to every child hash.
//!
//! Hash inputs are fixed binary concatenations, **not** CBOR tuples:
//!
//! ```text
//! leaf:  SHA-256( 0x10 || key[32] || data[32] || u256(value) )
//! node:  SHA-256( 0x11 || depth[1] || hL[32] || u256(sumL) || hR[32] || u256(sumR) )
//! ```
//!
//! where `u256(x)` is the 32-byte big-endian encoding of `x` and `depth` is the
//! absolute bifurcation bit position. A node sum is `sumL + sumR` with checked
//! 256-bit addition: any overflow makes the node (and hence the proof) invalid.
//!
//! Proof *verification* ([`RsmstInclusionProof::verify`]) is part of the `no_std`
//! core; the mutable [`build::Rsmst`] builder is gated behind the `client`
//! feature.

mod proof;

#[cfg(any(feature = "client", test))]
pub mod build;

pub use proof::{RsmstInclusionProof, RsmstProofStep};

use alloc::vec::Vec;

use num_bigint::BigUint;

use crate::crypto::hash::sha256;
use crate::error::{CborError, Error};

/// Domain-separation prefix for an RSMST leaf hash.
pub const RSMST_LEAF: u8 = 0x10;
/// Domain-separation prefix for an RSMST internal-node hash.
pub const RSMST_NODE: u8 = 0x11;

/// Maximum byte length of a 256-bit amount or subtree sum (`v < 2^256`).
pub const AMOUNT_MAX_BYTES: usize = 32;

/// Maximum number of sibling entries in one inclusion proof (one per key bit).
pub const MAX_PROOF_STEPS: usize = 256;

/// Encode a non-negative amount as a minimal big-endian byte string.
///
/// Zero encodes to the empty string; a positive value to its big-endian bytes
/// with no leading `0x00`. This is the wire form of split amounts and sibling
/// sums (the latter are always positive).
pub fn encode_amount(value: &BigUint) -> Vec<u8> {
    if *value == BigUint::ZERO {
        Vec::new()
    } else {
        value.to_bytes_be()
    }
}

/// Decode a strictly positive, minimally encoded big-endian amount.
///
/// Rejects the empty string (zero is not a valid amount or sibling sum), a
/// leading `0x00` (non-minimal), and anything wider than 256 bits.
pub fn decode_positive_amount(bytes: &[u8]) -> Result<BigUint, Error> {
    if bytes.is_empty() {
        return Err(Error::OutOfRange("amount must be positive"));
    }
    if bytes.len() > AMOUNT_MAX_BYTES {
        return Err(Error::OutOfRange("amount exceeds 256 bits"));
    }
    if bytes[0] == 0 {
        return Err(CborError::NonCanonicalEncoding.into());
    }
    Ok(BigUint::from_bytes_be(bytes))
}

/// `true` when `value` fits the protocol amount domain `1 <= v < 2^256`.
pub fn is_valid_amount(value: &BigUint) -> bool {
    *value != BigUint::ZERO && value.bits() <= 256
}

/// The fixed 32-byte big-endian encoding of `value`, or `None` if `value` does
/// not fit in 256 bits.
fn u256_be(value: &BigUint) -> Option<[u8; 32]> {
    let bytes = value.to_bytes_be();
    if bytes.len() > AMOUNT_MAX_BYTES {
        return None;
    }
    let mut out = [0u8; 32];
    out[AMOUNT_MAX_BYTES - bytes.len()..].copy_from_slice(&bytes);
    Some(out)
}

/// SHA-256 of the concatenation of `parts`, returned as the raw 32-byte digest.
fn sha256_raw(parts: &[&[u8]]) -> [u8; 32] {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    let mut buf = Vec::with_capacity(len);
    for part in parts {
        buf.extend_from_slice(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(sha256(&buf).data());
    out
}

/// `rsmst_leaf_hash(k, d, v)` — `SHA-256(0x10 || k || d || u256(v))`.
///
/// Returns `None` if `v` does not fit in 256 bits (callers reject the leaf).
pub fn leaf_hash(key: &[u8; 32], data: &[u8; 32], value: &BigUint) -> Option<[u8; 32]> {
    let value = u256_be(value)?;
    Some(sha256_raw(&[&[RSMST_LEAF], key, data, &value]))
}

/// `rsmst_node_hash(δ, (hL, vL), (hR, vR))` with checked 256-bit sum.
///
/// Returns `(hash, sum)` where `sum = vL + vR`, or `None` if that sum overflows
/// 256 bits (in which case the node, and any proof using it, is invalid).
pub fn node_hash(
    depth: u8,
    left: (&[u8; 32], &BigUint),
    right: (&[u8; 32], &BigUint),
) -> Option<([u8; 32], BigUint)> {
    let sum = left.1 + right.1;
    if sum.bits() > 256 {
        return None;
    }
    let left_sum = u256_be(left.1)?;
    let right_sum = u256_be(right.1)?;
    let hash = sha256_raw(&[
        &[RSMST_NODE],
        &[depth],
        left.0,
        &left_sum,
        right.0,
        &right_sum,
    ]);
    Some((hash, sum))
}

/// Bit `index` of a 256-bit key, using the SDK's one shared radix bit order
/// ([`crate::radix::bit_at`]). The builder and the verifier go through this
/// same helper, so they share exactly one key/depth convention with the
/// transaction inclusion certificate.
fn key_bit(key: &[u8; 32], index: u8) -> bool {
    crate::radix::bit_at(key, index as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_bit_matches_shared_radix_convention() {
        // Bit i is the (i % 8)-th most-significant bit of byte i / 8.
        let mut key = [0u8; 32];
        key[0] = 0b1010_0000; // bits 0 and 2 set
        key[1] = 0b0100_0000; // bit 9 set
        key[31] = 0b0000_0001; // bit 255 set
        assert!(key_bit(&key, 0));
        assert!(!key_bit(&key, 1));
        assert!(key_bit(&key, 2));
        assert!(key_bit(&key, 9));
        assert!(key_bit(&key, 255));
        assert!(!key_bit(&key, 254));
        // Agrees with the helper the inclusion certificate uses.
        assert_eq!(key_bit(&key, 9), crate::radix::bit_at(&key, 9));
    }

    #[test]
    fn u256_is_left_padded_big_endian() {
        assert_eq!(u256_be(&BigUint::ZERO), Some([0u8; 32]));
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(u256_be(&BigUint::from(1u8)), Some(expected));
        // 2^256 does not fit.
        assert_eq!(u256_be(&(BigUint::from(1u8) << 256)), None);
    }

    #[test]
    fn node_hash_rejects_sum_overflow() {
        let max = (BigUint::from(1u8) << 256) - BigUint::from(1u8);
        let h = [0u8; 32];
        assert!(node_hash(0, (&h, &max), (&h, &BigUint::from(1u8))).is_none());
        assert!(node_hash(0, (&h, &max), (&h, &BigUint::ZERO)).is_some());
    }

    #[test]
    fn decode_positive_amount_enforces_minimality() {
        assert!(decode_positive_amount(&[]).is_err());
        assert!(decode_positive_amount(&[0x00, 0x01]).is_err());
        assert!(decode_positive_amount(&[0u8; 33]).is_err());
        assert_eq!(decode_positive_amount(&[0x01]).unwrap(), BigUint::from(1u8));
    }
}
