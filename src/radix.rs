//! Shared bit addressing for the protocol's radix sparse Merkle trees.
//!
//! Both the transaction inclusion certificate
//! ([`InclusionCertificate`](crate::api::InclusionCertificate)) and the
//! token-split sum tree ([`rsmst`](crate::rsmst)) address keys (and the
//! certificate bitmap) in the same order, so they share this single helper —
//! there is exactly one key/depth convention in the SDK.
//!
//! Bit `i` is the `(i % 8)`-th most-significant bit of byte `i / 8`.

use crate::crypto::hash::{DataHash, DataHasher, HashAlgorithm};

pub(crate) const KEY_BITS: usize = 256;
pub(crate) const MAX_DEPTH: usize = KEY_BITS - 1;

/// MSB-first bit `index` of `data`: the `(index % 8)`-th most-significant bit
/// of byte `index / 8`.
#[inline]
pub(crate) fn bit_at(data: &[u8], index: usize) -> bool {
    assert!(index < data.len() * 8, "bit index out of range");
    let byte_index = index / 8;
    let bit_in_byte = index % 8;
    data[byte_index] & (0x80 >> bit_in_byte) != 0
}

/// Canonical radix region for an internal node at `depth`.
///
/// The SDK's radix order is MSB-first within each byte, byte 0 first. The
/// region therefore keeps key bits `0..depth` and clears the split bit and all
/// later bits. For example, `depth == 0` is the empty prefix, and
/// `depth == 255` keeps bits `0..254` while clearing bit 255.
pub(crate) fn prefix_region(key: &[u8; 32], depth: usize) -> [u8; 32] {
    assert!(depth <= MAX_DEPTH, "depth cannot exceed MAX_DEPTH");

    let mut region = [0u8; 32];
    let full_bytes = depth / 8;
    let prefix_bits = depth % 8;

    region[..full_bytes].copy_from_slice(&key[..full_bytes]);
    if prefix_bits != 0 {
        let mask = 0xffu8 << (8 - prefix_bits);
        region[full_bytes] = key[full_bytes] & mask;
    }

    region
}

/// Fold one authenticated radix path from its terminal leaf to the root.
///
/// `target_key` controls key-directed descent; `terminal_key` controls the leaf
/// hash, node regions, and child orientation.  Requiring both keys to choose
/// the same side at every actual junction is essential for non-inclusion
/// soundness.  Inclusion passes the same key for both arguments.
pub(crate) fn fold_certificate_path(
    bitmap: &[u8; 32],
    siblings: &[[u8; 32]],
    target_key: &[u8; 32],
    terminal_key: &[u8; 32],
    terminal_value: &[u8],
) -> Option<DataHash> {
    let mut hash = DataHasher::new(HashAlgorithm::Sha256)
        .expect("sha256")
        .update(&[0x00])
        .update(terminal_key)
        .update(terminal_value)
        .finalize();

    let mut position = siblings.len();
    for depth in (0..=MAX_DEPTH).rev() {
        if !bit_at(bitmap, depth) {
            continue;
        }
        if position == 0 || bit_at(target_key, depth) != bit_at(terminal_key, depth) {
            return None;
        }
        position -= 1;
        let sibling = &siblings[position];
        let region = prefix_region(terminal_key, depth);
        let node = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(&[0x01, depth as u8])
            .update(&region);
        hash = if bit_at(terminal_key, depth) {
            node.update(sibling).update(hash.data())
        } else {
            node.update(hash.data()).update(sibling)
        }
        .finalize();
    }

    (position == 0).then_some(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_at_uses_msb_first_radix_order() {
        let key = [
            0b1000_0001,
            0b1000_0000,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0b0000_0001,
        ];

        assert!(bit_at(&key, 0));
        assert!(!bit_at(&key, 1));
        assert!(!bit_at(&key, 6));
        assert!(bit_at(&key, 7));
        assert!(bit_at(&key, 8));
        assert!(bit_at(&key, 255));
    }

    #[test]
    fn prefix_region_uses_shared_msb_first_radix_order() {
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
            0b1000_0001,
        ];

        assert_eq!(prefix_region(&key, 0), [0u8; 32]);

        let mut depth_3 = [0u8; 32];
        depth_3[0] = 0b1010_0000;
        assert_eq!(prefix_region(&key, 3), depth_3);

        let mut depth_9 = [0u8; 32];
        depth_9[0] = key[0];
        depth_9[1] = 0b1000_0000;
        assert_eq!(prefix_region(&key, 9), depth_9);

        let mut depth_255 = key;
        depth_255[31] &= 0xfe;
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
