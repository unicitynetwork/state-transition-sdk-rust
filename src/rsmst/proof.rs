//! Explicit-depth RSMST inclusion proof: the wire type and its verifier.
//!
//! A proof is a leaf-to-root sequence of sibling entries `(δ, s, w)` — the
//! sibling's parent bifurcation depth, the sibling subtree hash, and the sibling
//! subtree sum. Unlike the plain RSMT inclusion certificate, no bitmap is
//! carried: the explicit depth in each entry fully identifies the branch step,
//! and depths are strictly decreasing from the leaf toward the root.
//!
//! The leaf key, leaf data, leaf amount and root hash are **not** part of the
//! encoded proof; the verifier supplies them from the output token id, the
//! output commitment, the output payload and the split manifest respectively
//! (yellowpaper "Split Allocation Inclusion Proof").

use alloc::vec::Vec;

use num_bigint::BigUint;

use super::{
    decode_positive_amount, encode_amount, is_valid_amount, key_bit, leaf_hash, node_hash,
    MAX_PROOF_STEPS,
};
use crate::cbor::{encode_array, encode_byte_string, encode_uint, Decoder};
use crate::error::Error;

/// One sibling entry on the leaf-to-root path: the sibling's parent bifurcation
/// `depth`, the sibling subtree `hash`, and the positive sibling subtree `sum`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsmstProofStep {
    depth: u8,
    hash: [u8; 32],
    sum: BigUint,
}

impl RsmstProofStep {
    /// Construct a step. `sum` must be a positive 256-bit amount.
    pub fn new(depth: u8, hash: [u8; 32], sum: BigUint) -> Self {
        RsmstProofStep { depth, hash, sum }
    }

    /// The sibling's parent bifurcation depth (`0..=255`).
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// The sibling subtree hash.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// The sibling subtree sum.
    pub fn sum(&self) -> &BigUint {
        &self.sum
    }

    /// Decode from CBOR: `[uint(depth), bstr(hash[32]), bstr(sum)]`.
    fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(Some(3))?;
        let depth = u8::try_from(items[0].uint()?)
            .map_err(|_| Error::OutOfRange("RSMST proof depth exceeds 255"))?;
        let hash: [u8; 32] = items[1]
            .bytes_value()?
            .try_into()
            .map_err(|_| Error::InvalidLength {
                what: "RSMST sibling hash",
                expected: 32,
                actual: 0,
            })?;
        let sum = decode_positive_amount(items[2].bytes_value()?)?;
        Ok(RsmstProofStep { depth, hash, sum })
    }

    /// Encode to CBOR: `[uint(depth), bstr(hash[32]), bstr(sum)]`.
    fn to_cbor(&self) -> Vec<u8> {
        encode_array(&[
            &encode_uint(self.depth as u64),
            &encode_byte_string(&self.hash),
            &encode_byte_string(&encode_amount(&self.sum)),
        ])
    }
}

/// A complete leaf-to-root RSMST inclusion proof (a vector of sibling entries).
///
/// An empty proof is valid only for a single-leaf tree, where the leaf hash is
/// the root hash and the leaf amount is the root sum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsmstInclusionProof {
    steps: Vec<RsmstProofStep>,
}

impl RsmstInclusionProof {
    /// Construct from leaf-to-root sibling entries.
    pub fn new(steps: Vec<RsmstProofStep>) -> Self {
        RsmstInclusionProof { steps }
    }

    /// The sibling entries, leaf first.
    pub fn steps(&self) -> &[RsmstProofStep] {
        &self.steps
    }

    /// Decode from CBOR: an array of `0..=256` sibling entries.
    ///
    /// Rejects more than 256 entries, depths outside `0..=255`, non-decreasing
    /// depths, sibling hashes that are not 32 bytes, and zero / non-minimal /
    /// overlong sibling sums.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let encoded = d.array(None)?;
        if encoded.len() > MAX_PROOF_STEPS {
            return Err(Error::OutOfRange("RSMST proof has too many steps"));
        }
        let mut steps = Vec::with_capacity(encoded.len());
        let mut prev_depth: Option<u8> = None;
        for entry in encoded {
            let step = RsmstProofStep::from_cbor(entry)?;
            if let Some(previous) = prev_depth {
                if step.depth >= previous {
                    return Err(Error::UnexpectedValue(
                        "RSMST proof depths are not strictly decreasing",
                    ));
                }
            }
            prev_depth = Some(step.depth);
            steps.push(step);
        }
        Ok(RsmstInclusionProof { steps })
    }

    /// Encode to CBOR: an array of sibling entries.
    pub fn to_cbor(&self) -> Vec<u8> {
        let parts: Vec<Vec<u8>> = self.steps.iter().map(RsmstProofStep::to_cbor).collect();
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        encode_array(&refs)
    }

    /// `rsmst_verify_inclusion(k, d, v, C, r)`.
    ///
    /// Reconstructs the root hash from the leaf `(key, data, value)` upward,
    /// folding in each sibling at its committed depth, and returns the
    /// reconstructed root **sum** iff the reconstruction equals `root`. The
    /// caller compares that sum to the authenticated source amount for value
    /// conservation — the root hash alone is not sufficient, because sibling
    /// sums are committed by every internal node hash.
    ///
    /// Returns `None` on any failure: an out-of-domain amount, an over-long
    /// proof, non-decreasing or out-of-range depths, a non-positive sibling sum,
    /// a 256-bit sum overflow, or a root-hash mismatch.
    pub fn verify(
        &self,
        key: &[u8; 32],
        data: &[u8; 32],
        value: &BigUint,
        root: &[u8; 32],
    ) -> Option<BigUint> {
        if !is_valid_amount(value) || self.steps.len() > MAX_PROOF_STEPS {
            return None;
        }
        let mut hash = leaf_hash(key, data, value)?;
        let mut sum = value.clone();
        // Sentinel above the maximum depth so the first step (any depth 0..=255)
        // satisfies the strictly-decreasing requirement.
        let mut prev_depth: u16 = 256;

        for step in &self.steps {
            if u16::from(step.depth) >= prev_depth || !is_valid_amount(&step.sum) {
                return None;
            }
            let (next_hash, next_sum) = if key_bit(key, step.depth) {
                // The leaf side is the right child at this depth.
                node_hash(step.depth, (&step.hash, &step.sum), (&hash, &sum))?
            } else {
                node_hash(step.depth, (&hash, &sum), (&step.hash, &step.sum))?
            };
            hash = next_hash;
            sum = next_sum;
            prev_depth = u16::from(step.depth);
        }

        (hash == *root).then_some(sum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Decoder;

    fn step(depth: u8, sum: u32) -> RsmstProofStep {
        RsmstProofStep::new(depth, [depth; 32], BigUint::from(sum))
    }

    #[test]
    fn cbor_roundtrip() {
        let proof = RsmstInclusionProof::new(alloc::vec![step(9, 7), step(3, 11), step(1, 5)]);
        let bytes = proof.to_cbor();
        let decoded = RsmstInclusionProof::from_cbor(Decoder::new(&bytes)).unwrap();
        assert_eq!(decoded, proof);
        assert_eq!(decoded.to_cbor(), bytes);
    }

    #[test]
    fn decode_rejects_non_decreasing_depths() {
        let proof = RsmstInclusionProof::new(alloc::vec![step(3, 1), step(3, 1)]);
        let bytes = proof.to_cbor();
        assert!(RsmstInclusionProof::from_cbor(Decoder::new(&bytes)).is_err());
    }

    #[test]
    fn decode_rejects_zero_sibling_sum() {
        let bytes = RsmstInclusionProof::new(alloc::vec![step(3, 0)]).to_cbor();
        assert!(RsmstInclusionProof::from_cbor(Decoder::new(&bytes)).is_err());
    }
}
