//! Shared bit addressing for the protocol's radix sparse Merkle trees.
//!
//! Both the transaction inclusion certificate
//! ([`InclusionCertificate`](crate::api::InclusionCertificate)) and the
//! token-split sum tree ([`rsmst`](crate::rsmst)) address keys (and the
//! certificate bitmap) in the same order, so they share this single helper —
//! there is exactly one key/depth convention in the SDK.
//!
//! Bit `i` is bit `i % 8` of byte `i / 8`: least significant bit first within
//! each byte, byte 0 first.

/// LSB-first bit `index` of a byte string: bit `index % 8` of byte `index / 8`.
pub(crate) fn bit_at(data: &[u8], index: usize) -> bool {
    (data[index / 8] >> (index % 8)) & 1 == 1
}
