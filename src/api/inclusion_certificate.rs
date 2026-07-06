//! Inclusion certificate: a radix sparse-Merkle-tree path proving that a
//! `(stateId -> transactionHash)` leaf is committed under a block's state root.
//!
//! Wire form (not CBOR-tagged): a 32-byte bitmap followed by the sibling hashes
//! (32 bytes each). The bitmap's set bits — one per tree depth, LSB-first —
//! select which depths contribute a sibling; their count must equal the number
//! of sibling hashes.

use alloc::vec::Vec;

use crate::api::state_id::StateId;
use crate::crypto::hash::{DataHash, DataHasher, HashAlgorithm};
use crate::error::Error;

const BITMAP_SIZE: usize = 32;
const HASH_SIZE: usize = 32;
const MAX_DEPTH: usize = 255;

use crate::radix::{bit_at, prefix_region};

/// A sparse-Merkle-tree inclusion path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionCertificate {
    bitmap: [u8; BITMAP_SIZE],
    siblings: Vec<[u8; HASH_SIZE]>,
}

impl InclusionCertificate {
    /// Decode from the raw byte form, validating bitmap/sibling alignment and
    /// that the sibling count matches the bitmap population count.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < BITMAP_SIZE {
            return Err(Error::InvalidLength {
                what: "InclusionCertificate bitmap",
                expected: BITMAP_SIZE,
                actual: bytes.len(),
            });
        }
        let sibling_bytes = bytes.len() - BITMAP_SIZE;
        if sibling_bytes % HASH_SIZE != 0 {
            return Err(Error::UnexpectedValue("inclusion siblings misaligned"));
        }
        let mut bitmap = [0u8; BITMAP_SIZE];
        bitmap.copy_from_slice(&bytes[..BITMAP_SIZE]);
        let popcount: u32 = bitmap.iter().map(|b| b.count_ones()).sum();
        let count = sibling_bytes / HASH_SIZE;
        if popcount as usize != count {
            return Err(Error::UnexpectedValue(
                "inclusion sibling count does not match bitmap",
            ));
        }
        let mut siblings = Vec::with_capacity(count);
        for chunk in bytes[BITMAP_SIZE..].chunks_exact(HASH_SIZE) {
            let mut h = [0u8; HASH_SIZE];
            h.copy_from_slice(chunk);
            siblings.push(h);
        }
        Ok(InclusionCertificate { bitmap, siblings })
    }

    /// Encode to the raw byte form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BITMAP_SIZE + self.siblings.len() * HASH_SIZE);
        out.extend_from_slice(&self.bitmap);
        for s in &self.siblings {
            out.extend_from_slice(s);
        }
        out
    }

    /// Verify the path: fold the leaf `H(0x00 || key || value)` up using the
    /// siblings and check the result equals `expected_root`.
    pub fn verify(
        &self,
        leaf_key: &StateId,
        leaf_value: &DataHash,
        expected_root: &DataHash,
    ) -> bool {
        let key = leaf_key.bytes();
        let mut hash = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(&[0x00])
            .update(key)
            .update(leaf_value.data())
            .finalize();

        let mut position = self.siblings.len();
        for depth in (0..=MAX_DEPTH).rev() {
            if !bit_at(&self.bitmap, depth) {
                continue;
            }
            if position == 0 {
                return false;
            }
            position -= 1;
            let sibling = &self.siblings[position];
            let region = prefix_region(key, depth);

            let h = DataHasher::new(HashAlgorithm::Sha256)
                .expect("sha256")
                .update(&[0x01, depth as u8])
                .update(&region);
            hash = if bit_at(key, depth) {
                h.update(sibling).update(hash.data())
            } else {
                h.update(hash.data()).update(sibling)
            }
            .finalize();
        }

        position == 0 && &hash == expected_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{encode_byte_string, Decoder};

    fn data_hash(bytes: [u8; 32]) -> DataHash {
        DataHash::new(HashAlgorithm::Sha256, bytes).unwrap()
    }

    fn state_id(bytes: [u8; 32]) -> StateId {
        StateId::from_cbor(Decoder::new(&encode_byte_string(&bytes))).unwrap()
    }

    fn leaf_hash(key: &[u8; 32], value: &[u8; 32]) -> DataHash {
        DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(&[0x00])
            .update(key)
            .update(value)
            .finalize()
    }

    fn old_3o_node_hash(depth: usize, left: &DataHash, right: &DataHash) -> DataHash {
        DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(&[0x01, depth as u8])
            .update(left.data())
            .update(right.data())
            .finalize()
    }

    fn v6a_node_hash(key: &[u8; 32], depth: usize, left: &DataHash, right: &DataHash) -> DataHash {
        let region = prefix_region(key, depth);
        DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(&[0x01, depth as u8])
            .update(&region)
            .update(left.data())
            .update(right.data())
            .finalize()
    }

    #[test]
    fn two_leaf_inclusion_uses_v6a_region_commitment() {
        let left_key = [0u8; 32];
        let mut right_key = [0u8; 32];
        right_key[0] = 0b0000_0001; // diverges at depth 0 in LSB-first order

        let left_value = [0x11u8; 32];
        let right_value = [0x22u8; 32];
        let left_leaf = leaf_hash(&left_key, &left_value);
        let right_leaf = leaf_hash(&right_key, &right_value);

        let root = v6a_node_hash(&left_key, 0, &left_leaf, &right_leaf);
        let old_root = old_3o_node_hash(0, &left_leaf, &right_leaf);

        let mut encoded = [0u8; BITMAP_SIZE + HASH_SIZE];
        encoded[0] = 0b0000_0001; // sibling at depth 0
        encoded[BITMAP_SIZE..].copy_from_slice(right_leaf.data());
        let proof = InclusionCertificate::decode(&encoded).unwrap();

        assert!(proof.verify(&state_id(left_key), &data_hash(left_value), &root));
        assert!(!proof.verify(&state_id(left_key), &data_hash(left_value), &old_root));
    }

    #[test]
    fn deep_split_region_is_derived_from_key_prefix() {
        let mut left_key = [0u8; 32];
        left_key[0] = 0b1010_1101;
        left_key[1] = 0b0000_0011;

        let mut right_key = left_key;
        right_key[1] ^= 0b0000_0100; // diverges at depth 10

        let left_value = [0x33u8; 32];
        let right_value = [0x44u8; 32];
        let left_leaf = leaf_hash(&left_key, &left_value);
        let right_leaf = leaf_hash(&right_key, &right_value);

        let root = v6a_node_hash(&left_key, 10, &left_leaf, &right_leaf);
        let old_root = old_3o_node_hash(10, &left_leaf, &right_leaf);

        let mut encoded = [0u8; BITMAP_SIZE + HASH_SIZE];
        encoded[1] = 0b0000_0100; // sibling at depth 10
        encoded[BITMAP_SIZE..].copy_from_slice(right_leaf.data());
        let proof = InclusionCertificate::decode(&encoded).unwrap();

        assert!(proof.verify(&state_id(left_key), &data_hash(left_value), &root));
        assert!(!proof.verify(&state_id(left_key), &data_hash(left_value), &old_root));
    }
}
