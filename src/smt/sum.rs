//! Sparse Merkle *sum* tree: path type + verification (core) and the mutable
//! builder (`client`). Each node carries the sum of its subtree's leaf values,
//! so a single path proves both inclusion and the committed amount. Used as the
//! per-asset tree mapping a new token's id to the amount it receives in a split.

use alloc::vec::Vec;

use num_bigint::BigUint;
use num_traits::One;

use super::bigint::{bit_len, bytes_to_path, path_to_bytes};
use super::{
    SumPathVerificationResult, MAX_SMT_DATA_BYTES, MAX_SMT_PATH_BYTES, MAX_SMT_PATH_STEPS,
};
use crate::cbor::{encode_array, encode_byte_string, encode_nullable, Decoder};
use crate::crypto::hash::{DataHash, DataHasher, HashAlgorithm};
use crate::error::Error;

const MAX_SMT_VALUE_BYTES: usize = 32;

/// A single step along a sum-tree path: routing `path`, sibling/leaf `data`, and
/// the subtree `value` hashed at that level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMerkleSumTreePathStep {
    path: BigUint,
    data: Option<Vec<u8>>,
    value: BigUint,
}

impl SparseMerkleSumTreePathStep {
    /// Construct a step from its routing path, optional data, and value.
    pub fn new(path: BigUint, data: Option<Vec<u8>>, value: BigUint) -> Self {
        SparseMerkleSumTreePathStep { path, data, value }
    }

    /// The routing path of this step.
    pub fn path(&self) -> &BigUint {
        &self.path
    }

    /// The data hashed at this level, if any.
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// The subtree value at this level.
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Decode from CBOR: `[bstr(path), nullable bstr(data), bstr(value)]`.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(Some(3))?;
        let path_bytes = items[0].bytes_value()?;
        if path_bytes.len() > MAX_SMT_PATH_BYTES {
            return Err(Error::OutOfRange("SMT path exceeds protocol limit"));
        }
        let path = bytes_to_path(path_bytes)?;
        let data =
            items[1].nullable(|d| d.bytes_value().map(<[u8]>::to_vec).map_err(Into::into))?;
        if data
            .as_ref()
            .is_some_and(|value| value.len() > MAX_SMT_DATA_BYTES)
        {
            return Err(Error::OutOfRange("SMT data exceeds protocol limit"));
        }
        let value_bytes = items[2].bytes_value()?;
        if value_bytes.len() > MAX_SMT_VALUE_BYTES {
            return Err(Error::OutOfRange("SMT value exceeds 256 bits"));
        }
        let value = bytes_to_path(value_bytes)?;
        Ok(SparseMerkleSumTreePathStep { path, data, value })
    }

    /// Encode to CBOR: `[bstr(path), nullable bstr(data), bstr(value)]`.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_array(&[
            &encode_byte_string(&path_to_bytes(&self.path)),
            &encode_nullable(self.data.as_ref(), |v| encode_byte_string(v)),
            &encode_byte_string(&path_to_bytes(&self.value)),
        ])
    }
}

/// A leaf-to-root path through a sparse Merkle sum tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMerkleSumTreePath {
    root: DataHash,
    steps: Vec<SparseMerkleSumTreePathStep>,
}

impl SparseMerkleSumTreePath {
    /// Construct from a committed root and its steps.
    pub fn new(root: DataHash, steps: Vec<SparseMerkleSumTreePathStep>) -> Self {
        SparseMerkleSumTreePath { root, steps }
    }

    /// The committed root hash.
    pub fn root(&self) -> &DataHash {
        &self.root
    }

    /// The path steps, leaf first.
    pub fn steps(&self) -> &[SparseMerkleSumTreePathStep] {
        &self.steps
    }

    /// Decode from CBOR: `[bstr(root.imprint), [steps...]]`.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(Some(2))?;
        let root = DataHash::from_imprint(items[0].bytes_value()?)?;
        let encoded_steps = items[1].array(None)?;
        if encoded_steps.len() > MAX_SMT_PATH_STEPS {
            return Err(Error::OutOfRange("SMT proof has too many steps"));
        }
        let mut steps = Vec::new();
        for step in encoded_steps {
            steps.push(SparseMerkleSumTreePathStep::from_cbor(step)?);
        }
        Ok(SparseMerkleSumTreePath { root, steps })
    }

    /// Encode to CBOR: `[bstr(root.imprint), [steps...]]`.
    pub fn to_cbor(&self) -> Vec<u8> {
        let step_bytes: Vec<Vec<u8>> = self.steps.iter().map(|s| s.to_cbor()).collect();
        let step_refs: Vec<&[u8]> = step_bytes.iter().map(Vec::as_slice).collect();
        encode_array(&[
            &encode_byte_string(&self.root.imprint()),
            &encode_array(&step_refs),
        ])
    }

    /// Verify the path against its committed root and the routing path of the
    /// queried key.
    pub fn verify(&self, key_path: &BigUint) -> SumPathVerificationResult {
        if self.steps.len() > MAX_SMT_PATH_STEPS
            || key_path.to_bytes_be().len() > MAX_SMT_PATH_BYTES
            || self.steps.iter().any(|step| {
                step.path.to_bytes_be().len() > MAX_SMT_PATH_BYTES
                    || step.value.to_bytes_be().len() > MAX_SMT_VALUE_BYTES
                    || step
                        .data
                        .as_ref()
                        .is_some_and(|value| value.len() > MAX_SMT_DATA_BYTES)
            })
        {
            return SumPathVerificationResult::invalid();
        }
        let Some(first) = self.steps.first() else {
            return SumPathVerificationResult::invalid();
        };
        let algorithm = self.root.algorithm();
        let one = BigUint::one();
        let zero = BigUint::ZERO;

        let mut current_path = first.path.clone();
        let mut current_sum = first.value.clone();
        let mut current_data: Option<Vec<u8>>;
        if first.path > zero {
            let preimage = encode_array(&[
                &encode_byte_string(&path_to_bytes(&first.path)),
                &encode_nullable(first.data.as_ref(), |v| encode_byte_string(v)),
                &encode_byte_string(&path_to_bytes(&first.value)),
            ]);
            current_data = match hash(algorithm, &preimage) {
                Some(d) => Some(d),
                None => return SumPathVerificationResult::invalid(),
            };
        } else {
            current_path = one.clone();
            current_data = first.data.clone();
        }

        for i in 1..self.steps.len() {
            let step = &self.steps[i];
            let is_right = self.steps[i - 1].path.bit(0);
            let (left_data, left_value, right_data, right_value) = if is_right {
                (
                    step.data.as_deref(),
                    &step.value,
                    current_data.as_deref(),
                    &current_sum,
                )
            } else {
                (
                    current_data.as_deref(),
                    &current_sum,
                    step.data.as_deref(),
                    &step.value,
                )
            };
            let preimage = encode_array(&[
                &encode_byte_string(&path_to_bytes(&step.path)),
                &encode_nullable(left_data, encode_byte_string),
                &encode_byte_string(&path_to_bytes(left_value)),
                &encode_nullable(right_data, encode_byte_string),
                &encode_byte_string(&path_to_bytes(right_value)),
            ]);
            current_data = match hash(algorithm, &preimage) {
                Some(d) => Some(d),
                None => return SumPathVerificationResult::invalid(),
            };

            let bits = bit_len(&step.path);
            if bits == 0 {
                return SumPathVerificationResult::invalid();
            }
            let length = bits - 1;
            current_path = (current_path << length) | (&step.path & ((&one << length) - &one));
            current_sum += &step.value;
        }

        let path_valid = current_data
            .as_deref()
            .is_some_and(|d| d == self.root.data());
        let path_included = key_path == &current_path;
        SumPathVerificationResult::new(path_valid, path_included, current_sum)
    }
}

fn hash(algorithm: HashAlgorithm, preimage: &[u8]) -> Option<Vec<u8>> {
    Some(
        DataHasher::new(algorithm)
            .ok()?
            .update(preimage)
            .finalize()
            .data()
            .to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Decoder;
    use crate::smt::bigint::key_to_path;

    #[test]
    fn build_get_path_verify_roundtrip_and_sum() {
        let leaves: [([u8; 32], u32); 4] = [
            (key32(1), 10),
            (key32(2), 20),
            (key32(0xff), 5),
            (key32(0x80), 7),
        ];
        let mut tree = SparseMerkleSumTree::new();
        for (k, v) in leaves {
            tree.add_leaf(key_to_path(&k), k.to_vec(), BigUint::from(v))
                .unwrap();
        }
        let root = tree.calculate_root();
        assert_eq!(*root.value(), BigUint::from(42u32));

        for (k, v) in leaves {
            let path = root.get_path(&key_to_path(&k));
            let result = path.verify(&key_to_path(&k));
            assert!(result.is_successful(), "key {k:?} should verify");
            assert_eq!(result.root_sum(), Some(&BigUint::from(42u32)));
            // The leaf step carries the committed amount.
            assert_eq!(path.steps().first().unwrap().value(), &BigUint::from(v));

            let bytes = path.to_cbor();
            let decoded = SparseMerkleSumTreePath::from_cbor(Decoder::new(&bytes)).unwrap();
            assert_eq!(decoded, path);
            assert_eq!(decoded.to_cbor(), bytes);
        }
    }

    fn key32(last: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[31] = last;
        k
    }
}

#[cfg(any(feature = "client", test))]
pub use build::{SparseMerkleSumTree, SparseMerkleSumTreeRootNode};

#[cfg(any(feature = "client", test))]
mod build {
    //! Mutable sum SMT builder.

    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;

    use num_bigint::BigUint;
    use num_traits::One;

    use super::{SparseMerkleSumTreePath, SparseMerkleSumTreePathStep};
    use crate::cbor::{encode_array, encode_byte_string, encode_nullable};
    use crate::crypto::hash::{DataHash, DataHasher, HashAlgorithm};
    use crate::error::Error;
    use crate::smt::bigint::{calculate_common_path, path_to_bytes};

    enum Pending {
        Leaf {
            path: BigUint,
            data: Vec<u8>,
            value: BigUint,
        },
        Node {
            path: BigUint,
            left: Box<Pending>,
            right: Box<Pending>,
        },
    }

    enum Finalized {
        Leaf {
            path: BigUint,
            data: Vec<u8>,
            value: BigUint,
            hash: DataHash,
        },
        Node {
            path: BigUint,
            left: Box<Finalized>,
            right: Box<Finalized>,
            value: BigUint,
            hash: DataHash,
        },
    }

    impl Finalized {
        fn hash(&self) -> &DataHash {
            match self {
                Finalized::Leaf { hash, .. } | Finalized::Node { hash, .. } => hash,
            }
        }
        fn value(&self) -> &BigUint {
            match self {
                Finalized::Leaf { value, .. } | Finalized::Node { value, .. } => value,
            }
        }
    }

    fn digest(algorithm: HashAlgorithm, preimage: &[u8]) -> DataHash {
        DataHasher::new(algorithm)
            .expect("split SMT uses SHA-256")
            .update(preimage)
            .finalize()
    }

    impl Pending {
        fn path(&self) -> &BigUint {
            match self {
                Pending::Leaf { path, .. } | Pending::Node { path, .. } => path,
            }
        }

        fn finalize(self, algorithm: HashAlgorithm) -> Finalized {
            match self {
                Pending::Leaf { path, data, value } => {
                    let preimage = encode_array(&[
                        &encode_byte_string(&path_to_bytes(&path)),
                        &encode_byte_string(&data),
                        &encode_byte_string(&path_to_bytes(&value)),
                    ]);
                    let hash = digest(algorithm, &preimage);
                    Finalized::Leaf {
                        path,
                        data,
                        value,
                        hash,
                    }
                }
                Pending::Node { path, left, right } => {
                    let left = left.finalize(algorithm);
                    let right = right.finalize(algorithm);
                    let preimage = encode_array(&[
                        &encode_byte_string(&path_to_bytes(&path)),
                        &encode_byte_string(left.hash().data()),
                        &encode_byte_string(&path_to_bytes(left.value())),
                        &encode_byte_string(right.hash().data()),
                        &encode_byte_string(&path_to_bytes(right.value())),
                    ]);
                    let hash = digest(algorithm, &preimage);
                    let value = left.value() + right.value();
                    Finalized::Node {
                        path,
                        left: Box::new(left),
                        right: Box::new(right),
                        value,
                        hash,
                    }
                }
            }
        }
    }

    /// A mutable sparse Merkle sum tree.
    #[derive(Default)]
    pub struct SparseMerkleSumTree {
        left: Option<Pending>,
        right: Option<Pending>,
    }

    impl core::fmt::Debug for SparseMerkleSumTree {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SparseMerkleSumTree")
                .finish_non_exhaustive()
        }
    }

    impl SparseMerkleSumTree {
        /// Create an empty tree.
        pub fn new() -> Self {
            Self::default()
        }

        /// Insert a leaf at routing `path` (`>= 1`) with `value`.
        pub fn add_leaf(
            &mut self,
            path: BigUint,
            data: Vec<u8>,
            value: BigUint,
        ) -> Result<(), Error> {
            if path < BigUint::one() {
                return Err(Error::OutOfRange("SMT leaf path must be >= 1"));
            }
            let is_right = path.bit(0);
            let slot = if is_right {
                &mut self.right
            } else {
                &mut self.left
            };
            let new = match slot.take() {
                Some(branch) => build_tree(branch, path, data, value)?,
                None => Pending::Leaf { path, data, value },
            };
            *slot = Some(new);
            Ok(())
        }

        /// Finalize all hashes and return the root node.
        pub fn calculate_root(self) -> SparseMerkleSumTreeRootNode {
            let algorithm = HashAlgorithm::Sha256;
            let zero = BigUint::ZERO;
            let left = self.left.map(|b| b.finalize(algorithm));
            let right = self.right.map(|b| b.finalize(algorithm));
            let left_value = left.as_ref().map_or(zero.clone(), |b| b.value().clone());
            let right_value = right.as_ref().map_or(zero.clone(), |b| b.value().clone());
            let preimage = encode_array(&[
                &encode_byte_string(&path_to_bytes(&BigUint::one())),
                &encode_nullable(left.as_ref(), |b| encode_byte_string(b.hash().data())),
                &encode_byte_string(&path_to_bytes(&left_value)),
                &encode_nullable(right.as_ref(), |b| encode_byte_string(b.hash().data())),
                &encode_byte_string(&path_to_bytes(&right_value)),
            ]);
            let hash = digest(algorithm, &preimage);
            let value = left_value + right_value;
            SparseMerkleSumTreeRootNode {
                left,
                right,
                value,
                hash,
            }
        }
    }

    fn build_tree(
        branch: Pending,
        remaining_path: BigUint,
        data: Vec<u8>,
        value: BigUint,
    ) -> Result<Pending, Error> {
        let (length, common) = calculate_common_path(&remaining_path, branch.path());
        let len = length_to_u64(&length);
        let shifted = &remaining_path >> len;
        let is_right = shifted.bit(0);

        if common == remaining_path {
            return Err(Error::UnexpectedValue(
                "SMT leaf is inside an existing branch",
            ));
        }

        match branch {
            Pending::Leaf {
                path: bpath,
                data: bdata,
                value: bvalue,
            } => {
                if common == bpath {
                    return Err(Error::UnexpectedValue("SMT leaf out of bounds"));
                }
                let old = Pending::Leaf {
                    path: &bpath >> len,
                    data: bdata,
                    value: bvalue,
                };
                let new = Pending::Leaf {
                    path: shifted,
                    data,
                    value,
                };
                Ok(node(common, is_right, old, new))
            }
            Pending::Node {
                path: bpath,
                left,
                right,
            } => {
                if common < bpath {
                    let new = Pending::Leaf {
                        path: shifted,
                        data,
                        value,
                    };
                    let old = Pending::Node {
                        path: &bpath >> len,
                        left,
                        right,
                    };
                    return Ok(node(common, is_right, old, new));
                }
                if is_right {
                    Ok(Pending::Node {
                        path: bpath,
                        left,
                        right: Box::new(build_tree(*right, shifted, data, value)?),
                    })
                } else {
                    Ok(Pending::Node {
                        path: bpath,
                        left: Box::new(build_tree(*left, shifted, data, value)?),
                        right,
                    })
                }
            }
        }
    }

    fn node(path: BigUint, is_right: bool, old: Pending, new: Pending) -> Pending {
        let (left, right) = if is_right { (old, new) } else { (new, old) };
        Pending::Node {
            path,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    fn length_to_u64(length: &BigUint) -> u64 {
        length.try_into().expect("common-path length fits in u64")
    }

    /// The finalized root of a sparse Merkle sum tree.
    pub struct SparseMerkleSumTreeRootNode {
        left: Option<Finalized>,
        right: Option<Finalized>,
        value: BigUint,
        hash: DataHash,
    }

    impl core::fmt::Debug for SparseMerkleSumTreeRootNode {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SparseMerkleSumTreeRootNode")
                .field("value", &self.value)
                .field("hash", &self.hash)
                .finish_non_exhaustive()
        }
    }

    impl SparseMerkleSumTreeRootNode {
        /// The root hash.
        pub fn hash(&self) -> &DataHash {
            &self.hash
        }

        /// The total of all leaf values in the tree.
        pub fn value(&self) -> &BigUint {
            &self.value
        }

        /// Extract the inclusion path for routing `path`.
        pub fn get_path(&self, path: &BigUint) -> SparseMerkleSumTreePath {
            let steps = generate_path_inner(
                path,
                &BigUint::one(),
                self.left.as_ref(),
                self.right.as_ref(),
            );
            SparseMerkleSumTreePath::new(self.hash.clone(), steps)
        }
    }

    fn data_of(branch: Option<&Finalized>) -> Option<Vec<u8>> {
        branch.map(|b| b.hash().data().to_vec())
    }

    fn value_of(branch: Option<&Finalized>) -> BigUint {
        branch.map_or(BigUint::ZERO, |b| b.value().clone())
    }

    fn generate_path_branch(
        path: &BigUint,
        parent: &Finalized,
    ) -> Vec<SparseMerkleSumTreePathStep> {
        match parent {
            Finalized::Leaf {
                path: p,
                data,
                value,
                ..
            } => {
                vec![SparseMerkleSumTreePathStep::new(
                    p.clone(),
                    Some(data.clone()),
                    value.clone(),
                )]
            }
            Finalized::Node {
                path: p,
                left,
                right,
                ..
            } => generate_path_inner(path, p, Some(left), Some(right)),
        }
    }

    fn generate_path_inner(
        path: &BigUint,
        parent_path: &BigUint,
        left: Option<&Finalized>,
        right: Option<&Finalized>,
    ) -> Vec<SparseMerkleSumTreePathStep> {
        let one = BigUint::one();
        let (length, common) = calculate_common_path(path, parent_path);
        let remaining = path >> length_to_u64(&length);

        if &common != parent_path || remaining == one {
            return vec![
                SparseMerkleSumTreePathStep::new(BigUint::ZERO, data_of(left), value_of(left)),
                SparseMerkleSumTreePathStep::new(
                    parent_path.clone(),
                    data_of(right),
                    value_of(right),
                ),
            ];
        }

        let is_right = remaining.bit(0);
        let (branch, sibling) = if is_right {
            (right, left)
        } else {
            (left, right)
        };
        let step = SparseMerkleSumTreePathStep::new(
            parent_path.clone(),
            data_of(sibling),
            value_of(sibling),
        );

        match branch {
            None => {
                let bit = if is_right { one } else { BigUint::ZERO };
                vec![
                    SparseMerkleSumTreePathStep::new(bit, None, BigUint::ZERO),
                    step,
                ]
            }
            Some(b) => {
                let mut steps = generate_path_branch(&remaining, b);
                steps.push(step);
                steps
            }
        }
    }
}
