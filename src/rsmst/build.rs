//! Mutable RSMST builder (`client` feature).
//!
//! Collects positive-valued leaves keyed by 256-bit token ids, then builds the
//! canonical path-compressed radix tree, from which the root `(hash, sum)` and
//! per-key leaf-to-root inclusion proofs are extracted. The bifurcation depth of
//! every internal node is the lowest key-bit position at which its descendant
//! keys disagree, so the structure — and therefore the root hash — is uniquely
//! determined by the key set, independent of insertion order.

use alloc::boxed::Box;
use alloc::vec::Vec;

use num_bigint::BigUint;

use super::{is_valid_amount, key_bit, leaf_hash, node_hash, RsmstInclusionProof, RsmstProofStep};
use crate::error::Error;

struct Leaf {
    key: [u8; 32],
    value: BigUint,
    hash: [u8; 32],
}

enum Node {
    Leaf(Leaf),
    Branch {
        depth: u8,
        left: Box<Node>,
        right: Box<Node>,
        hash: [u8; 32],
        sum: BigUint,
    },
}

impl Node {
    fn hash(&self) -> &[u8; 32] {
        match self {
            Node::Leaf(l) => &l.hash,
            Node::Branch { hash, .. } => hash,
        }
    }

    fn sum(&self) -> &BigUint {
        match self {
            Node::Leaf(l) => &l.value,
            Node::Branch { sum, .. } => sum,
        }
    }
}

/// A mutable radix sparse Merkle sum tree under construction.
#[derive(Default)]
pub struct Rsmst {
    leaves: Vec<Leaf>,
}

impl core::fmt::Debug for Rsmst {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rsmst")
            .field("leaves", &self.leaves.len())
            .finish()
    }
}

impl Rsmst {
    /// Create an empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a leaf `(key, data, value)`. Rejects a duplicate key, a zero or
    /// over-256-bit `value`, and (defensively) any value that does not hash.
    pub fn insert(&mut self, key: [u8; 32], data: [u8; 32], value: BigUint) -> Result<(), Error> {
        if !is_valid_amount(&value) {
            return Err(Error::OutOfRange("RSMST leaf amount must be in 1..2^256"));
        }
        if self.leaves.iter().any(|l| l.key == key) {
            return Err(Error::UnexpectedValue("duplicate RSMST leaf key"));
        }
        let hash = leaf_hash(&key, &data, &value).ok_or(Error::OutOfRange("RSMST leaf amount"))?;
        self.leaves.push(Leaf { key, value, hash });
        Ok(())
    }

    /// The number of leaves inserted so far.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether no leaves have been inserted.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Finalize the tree. Errors if empty or if any internal sum overflows.
    pub fn build(self) -> Result<BuiltRsmst, Error> {
        if self.leaves.is_empty() {
            return Err(Error::UnexpectedValue("RSMST must have at least one leaf"));
        }
        let root = build_subtree(self.leaves, 0)?;
        Ok(BuiltRsmst { root })
    }
}

/// Build the canonical subtree for a set of distinct leaves whose keys agree on
/// every bit below `start_bit`.
fn build_subtree(mut leaves: Vec<Leaf>, start_bit: u16) -> Result<Node, Error> {
    if leaves.len() == 1 {
        return Ok(Node::Leaf(leaves.pop().expect("len == 1")));
    }

    // Lowest bit position at or above start_bit where the keys disagree.
    let mut depth = start_bit;
    let bifurcation = loop {
        if depth > 255 {
            // Distinct keys must disagree on some bit; reaching here means two
            // leaves share all 256 bits (a duplicate that slipped through).
            return Err(Error::UnexpectedValue("duplicate RSMST leaf key"));
        }
        let position = depth as u8;
        let first = key_bit(&leaves[0].key, position);
        if leaves.iter().any(|l| key_bit(&l.key, position) != first) {
            break position;
        }
        depth += 1;
    };

    let mut left = Vec::new();
    let mut right = Vec::new();
    for leaf in leaves {
        if key_bit(&leaf.key, bifurcation) {
            right.push(leaf);
        } else {
            left.push(leaf);
        }
    }

    let next_bit = u16::from(bifurcation) + 1;
    let left = build_subtree(left, next_bit)?;
    let right = build_subtree(right, next_bit)?;
    let (hash, sum) = node_hash(
        bifurcation,
        (left.hash(), left.sum()),
        (right.hash(), right.sum()),
    )
    .ok_or(Error::OutOfRange("RSMST internal sum exceeds 256 bits"))?;
    Ok(Node::Branch {
        depth: bifurcation,
        left: Box::new(left),
        right: Box::new(right),
        hash,
        sum,
    })
}

/// A finalized RSMST: its root commitment and a proof extractor.
pub struct BuiltRsmst {
    root: Node,
}

impl core::fmt::Debug for BuiltRsmst {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BuiltRsmst")
            .field("root_hash", &hex::encode(self.root.hash()))
            .field("root_sum", self.root.sum())
            .finish()
    }
}

impl BuiltRsmst {
    /// The root hash (raw 32-byte SHA-256 digest).
    pub fn root_hash(&self) -> [u8; 32] {
        *self.root.hash()
    }

    /// The root sum (total of all leaf amounts).
    pub fn root_sum(&self) -> &BigUint {
        self.root.sum()
    }

    /// Extract the leaf-to-root inclusion proof for `key`, or `None` if `key` is
    /// not a leaf of this tree.
    pub fn proof(&self, key: &[u8; 32]) -> Option<RsmstInclusionProof> {
        let mut steps = Vec::new();
        let mut node = &self.root;
        loop {
            match node {
                Node::Leaf(leaf) => {
                    return (leaf.key == *key).then(|| {
                        steps.reverse();
                        RsmstInclusionProof::new(steps)
                    });
                }
                Node::Branch {
                    depth,
                    left,
                    right,
                    ..
                } => {
                    let (sibling, next): (&Node, &Node) = if key_bit(key, *depth) {
                        (left, right)
                    } else {
                        (right, left)
                    };
                    steps.push(RsmstProofStep::new(*depth, *sibling.hash(), sibling.sum().clone()));
                    node = next;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(bytes: &[(usize, u8)]) -> [u8; 32] {
        let mut k = [0u8; 32];
        for &(i, b) in bytes {
            k[i] = b;
        }
        k
    }

    #[test]
    fn single_leaf_root_is_leaf_hash_and_empty_proof() {
        let mut tree = Rsmst::new();
        let k = key(&[(31, 1)]);
        let d = [0xAB; 32];
        tree.insert(k, d, BigUint::from(42u32)).unwrap();
        let built = tree.build().unwrap();
        assert_eq!(*built.root_sum(), BigUint::from(42u32));
        assert_eq!(built.root_hash(), leaf_hash(&k, &d, &BigUint::from(42u32)).unwrap());
        let proof = built.proof(&k).unwrap();
        assert!(proof.steps().is_empty());
        assert_eq!(
            proof.verify(&k, &d, &BigUint::from(42u32), &built.root_hash()),
            Some(BigUint::from(42u32))
        );
    }

    #[test]
    fn multi_leaf_proofs_verify_and_sum() {
        let leaves: [([u8; 32], [u8; 32], u32); 5] = [
            (key(&[(31, 1)]), [0x01; 32], 10),
            (key(&[(31, 2)]), [0x02; 32], 20),
            (key(&[(31, 3)]), [0x03; 32], 5),
            (key(&[(0, 0x80)]), [0x04; 32], 7),
            (key(&[(15, 0x40)]), [0x05; 32], 3),
        ];
        let mut tree = Rsmst::new();
        for (k, d, v) in &leaves {
            tree.insert(*k, *d, BigUint::from(*v)).unwrap();
        }
        let built = tree.build().unwrap();
        assert_eq!(*built.root_sum(), BigUint::from(45u32));
        let root = built.root_hash();

        for (k, d, v) in &leaves {
            let proof = built.proof(k).unwrap();
            // Strictly decreasing depths.
            for w in proof.steps().windows(2) {
                assert!(w[0].depth() > w[1].depth());
            }
            assert_eq!(
                proof.verify(k, d, &BigUint::from(*v), &root),
                Some(BigUint::from(45u32)),
                "leaf {k:?} should verify and reconstruct the total"
            );
            // Wrong amount must not verify.
            assert_eq!(proof.verify(k, d, &BigUint::from(*v + 1), &root), None);
        }
    }

    #[test]
    fn rejects_duplicate_key_and_zero_value() {
        let mut tree = Rsmst::new();
        let k = key(&[(31, 1)]);
        tree.insert(k, [0; 32], BigUint::from(1u32)).unwrap();
        assert!(tree.insert(k, [1; 32], BigUint::from(2u32)).is_err());
        assert!(tree.insert(key(&[(31, 2)]), [0; 32], BigUint::ZERO).is_err());
    }

    /// Golden cross-implementation vector. The digests below were computed
    /// independently from the yellowpaper hash definitions
    /// (`SHA-256(0x10 || k || d || u256(v))` for leaves,
    /// `SHA-256(0x11 || depth || hL || u256(vL) || hR || u256(vR))` for nodes).
    /// Two keys `...01` and `...00` differ at bit 0, so the root bifurcates at
    /// depth 0 with `...00` (bit 0 = 0) on the left.
    #[test]
    fn golden_two_leaf_root() {
        use hex_literal::hex;
        let key_a = key(&[(31, 0x01)]);
        let key_b = key(&[]); // all zero
        let data_a = [0xAA; 32];
        let data_b = [0xBB; 32];

        assert_eq!(
            leaf_hash(&key_a, &data_a, &BigUint::from(10u32)).unwrap(),
            hex!("d2eeb3078ac5565fadc748863de7ea50affc0c13bf94b079c7abe971ec2a6213")
        );
        assert_eq!(
            leaf_hash(&key_b, &data_b, &BigUint::from(20u32)).unwrap(),
            hex!("51f25c331b15d0051422df960c80bdc5456be7422c2046b7a73a541cea81e6aa")
        );

        let mut tree = Rsmst::new();
        tree.insert(key_a, data_a, BigUint::from(10u32)).unwrap();
        tree.insert(key_b, data_b, BigUint::from(20u32)).unwrap();
        let built = tree.build().unwrap();
        assert_eq!(
            built.root_hash(),
            hex!("5aa8ce35ddea4792808b631b70b95e1406bf1a137f5c512f4adf1e36c1999c51")
        );
        assert_eq!(*built.root_sum(), BigUint::from(30u32));

        // The single-step proof for key_a folds in sibling key_b at depth 0.
        let proof = built.proof(&key_a).unwrap();
        assert_eq!(proof.steps().len(), 1);
        assert_eq!(proof.steps()[0].depth(), 0);
        assert_eq!(
            proof.verify(&key_a, &data_a, &BigUint::from(10u32), &built.root_hash()),
            Some(BigUint::from(30u32))
        );
    }

    #[test]
    fn proof_for_absent_key_is_none() {
        let mut tree = Rsmst::new();
        tree.insert(key(&[(31, 1)]), [0; 32], BigUint::from(1u32))
            .unwrap();
        tree.insert(key(&[(31, 2)]), [0; 32], BigUint::from(1u32))
            .unwrap();
        let built = tree.build().unwrap();
        assert!(built.proof(&key(&[(31, 9)])).is_none());
    }
}
