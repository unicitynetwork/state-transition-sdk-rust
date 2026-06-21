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

/// A sparse-Merkle-tree inclusion path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionCertificate {
    bitmap: [u8; BITMAP_SIZE],
    siblings: Vec<[u8; HASH_SIZE]>,
}

/// LSB-first bit at `depth` of `data`.
fn bit_at(data: &[u8], depth: usize) -> u8 {
    (data[depth / 8] >> (depth % 8)) & 1
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
            if bit_at(&self.bitmap, depth) == 0 {
                continue;
            }
            if position == 0 {
                return false;
            }
            position -= 1;
            let sibling = &self.siblings[position];

            let h = DataHasher::new(HashAlgorithm::Sha256)
                .expect("sha256")
                .update(&[0x01, depth as u8]);
            hash = if bit_at(key, depth) == 1 {
                h.update(sibling).update(hash.data())
            } else {
                h.update(hash.data()).update(sibling)
            }
            .finalize();
        }

        position == 0 && &hash == expected_root
    }
}
