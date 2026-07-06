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

pub(crate) const KEY_BITS: usize = 256;
pub(crate) const MAX_DEPTH: usize = KEY_BITS - 1;

/// LSB-first bit `index` of a byte string: bit `index % 8` of byte `index / 8`.
pub(crate) fn bit_at(data: &[u8], index: usize) -> bool {
    assert!(index < data.len() * 8, "bit index out of range");
    (data[index / 8] >> (index % 8)) & 1 == 1
}

/// Canonical radix region for an internal node at `depth`.
///
/// The SDK's radix order is LSB-first within each byte, byte 0 first. The
/// region therefore keeps key bits `0..depth` and clears the split bit and all
/// later bits. For example, `depth == 0` is the empty prefix, and
/// `depth == 255` keeps bits `0..254` while clearing bit 255.
pub(crate) fn prefix_region(key: &[u8; 32], depth: usize) -> [u8; 32] {
    assert!(depth <= MAX_DEPTH, "depth cannot exceed MAX_DEPTH");

    let mut region = [0u8; 32];
    let full_bytes = depth / 8;
    let partial_bits = depth % 8;

    region[..full_bytes].copy_from_slice(&key[..full_bytes]);
    if partial_bits != 0 {
        let mask = (1u8 << partial_bits) - 1;
        region[full_bytes] = key[full_bytes] & mask;
    }

    region
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_region_uses_shared_lsb_first_radix_order() {
        let key = [
            0b1010_1101,
            0b1100_0011,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0b1000_0000,
        ];

        assert_eq!(prefix_region(&key, 0), [0u8; 32]);

        let mut depth_3 = [0u8; 32];
        depth_3[0] = 0b0000_0101;
        assert_eq!(prefix_region(&key, 3), depth_3);

        let mut depth_9 = [0u8; 32];
        depth_9[0] = key[0];
        depth_9[1] = 0b0000_0001;
        assert_eq!(prefix_region(&key, 9), depth_9);

        let mut depth_255 = key;
        depth_255[31] = 0;
        assert_eq!(prefix_region(&key, 255), depth_255);
    }

    #[test]
    #[should_panic(expected = "depth cannot exceed MAX_DEPTH")]
    fn prefix_region_rejects_leaf_depth() {
        let key = [0u8; 32];
        let _ = prefix_region(&key, KEY_BITS);
    }

    #[test]
    #[should_panic(expected = "bit index out of range")]
    fn bit_at_rejects_out_of_range_index() {
        let key = [0u8; 32];
        let _ = bit_at(&key, KEY_BITS);
    }
}
