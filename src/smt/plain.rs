//! Plain sparse Merkle tree: path type + verification (core) and the mutable
//! builder (`client`). Used as the split *aggregation tree* over asset roots.

use alloc::vec::Vec;

use num_bigint::BigUint;
use num_traits::One;

use super::bigint::{bit_len, bytes_to_path, path_to_bytes};
use super::{PathVerificationResult, MAX_SMT_DATA_BYTES, MAX_SMT_PATH_BYTES, MAX_SMT_PATH_STEPS};
use crate::cbor::{encode_array, encode_byte_string, encode_nullable, Decoder};
use crate::crypto::hash::{DataHash, DataHasher, HashAlgorithm};
use crate::error::Error;

/// A single step along a plain SMT path: the routing `path` of the node and the
/// sibling/leaf `data` hashed at that level (`null` for an empty child).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMerkleTreePathStep {
    path: BigUint,
    data: Option<Vec<u8>>,
}

impl SparseMerkleTreePathStep {
    /// Construct a step from its routing path and optional data.
    pub fn new(path: BigUint, data: Option<Vec<u8>>) -> Self {
        SparseMerkleTreePathStep { path, data }
    }

    /// The routing path of this step.
    pub fn path(&self) -> &BigUint {
        &self.path
    }

    /// The data hashed at this level, if any.
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// Decode from CBOR: `[bstr(path), nullable bstr(data)]`.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(Some(2))?;
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
        Ok(SparseMerkleTreePathStep { path, data })
    }

    /// Encode to CBOR: `[bstr(path), nullable bstr(data)]`.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_array(&[
            &encode_byte_string(&path_to_bytes(&self.path)),
            &encode_nullable(self.data.as_ref(), |v| encode_byte_string(v)),
        ])
    }
}

/// A leaf-to-root path through a plain sparse Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMerkleTreePath {
    root: DataHash,
    steps: Vec<SparseMerkleTreePathStep>,
}

impl SparseMerkleTreePath {
    /// Construct from a committed root and its steps.
    pub fn new(root: DataHash, steps: Vec<SparseMerkleTreePathStep>) -> Self {
        SparseMerkleTreePath { root, steps }
    }

    /// The committed root hash.
    pub fn root(&self) -> &DataHash {
        &self.root
    }

    /// The path steps, leaf first.
    pub fn steps(&self) -> &[SparseMerkleTreePathStep] {
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
            steps.push(SparseMerkleTreePathStep::from_cbor(step)?);
        }
        Ok(SparseMerkleTreePath { root, steps })
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
    /// queried key. Returns whether the path recomputes the root and whether it
    /// routes to `key_path`.
    pub fn verify(&self, key_path: &BigUint) -> PathVerificationResult {
        if self.steps.len() > MAX_SMT_PATH_STEPS
            || key_path.to_bytes_be().len() > MAX_SMT_PATH_BYTES
            || self.steps.iter().any(|step| {
                step.path.to_bytes_be().len() > MAX_SMT_PATH_BYTES
                    || step
                        .data
                        .as_ref()
                        .is_some_and(|value| value.len() > MAX_SMT_DATA_BYTES)
            })
        {
            return PathVerificationResult::new(false, false);
        }
        let Some(first) = self.steps.first() else {
            return PathVerificationResult::new(false, false);
        };
        let algorithm = self.root.algorithm();
        let one = BigUint::one();

        let mut current_path = first.path.clone();
        let mut current_data: Option<Vec<u8>>;
        if first.path > one {
            let preimage = encode_array(&[
                &encode_byte_string(&path_to_bytes(&first.path)),
                &encode_nullable(first.data.as_ref(), |v| encode_byte_string(v)),
            ]);
            current_data = match hash(algorithm, &preimage) {
                Some(d) => Some(d),
                None => return PathVerificationResult::new(false, false),
            };
        } else {
            current_path = one.clone();
            current_data = first.data.clone();
        }

        for i in 1..self.steps.len() {
            let step = &self.steps[i];
            let is_right = self.steps[i - 1].path.bit(0);
            let (left, right) = if is_right {
                (step.data.as_deref(), current_data.as_deref())
            } else {
                (current_data.as_deref(), step.data.as_deref())
            };
            let preimage = encode_array(&[
                &encode_byte_string(&path_to_bytes(&step.path)),
                &encode_nullable(left, encode_byte_string),
                &encode_nullable(right, encode_byte_string),
            ]);
            current_data = match hash(algorithm, &preimage) {
                Some(d) => Some(d),
                None => return PathVerificationResult::new(false, false),
            };

            let bits = bit_len(&step.path);
            if bits == 0 {
                return PathVerificationResult::new(false, false);
            }
            let length = bits - 1;
            // current_path = (current_path << length) | (step.path & ((1 << length) - 1))
            current_path = (current_path << length) | (&step.path & ((&one << length) - &one));
        }

        let path_valid = current_data
            .as_deref()
            .is_some_and(|d| d == self.root.data());
        let path_included = key_path == &current_path;
        PathVerificationResult::new(path_valid, path_included)
    }
}

/// Hash a CBOR preimage with `algorithm`, returning the raw digest bytes, or
/// `None` if the algorithm has no streaming hasher (e.g. RIPEMD-160).
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
    fn build_get_path_verify_roundtrip() {
        // Fixed-length (32-byte) keys, as in real usage (asset/token ids).
        let keys: [[u8; 32]; 4] = [key32(1), key32(2), key32(0xff), key32(0x80)];
        let mut tree = SparseMerkleTree::new();
        for (i, k) in keys.iter().enumerate() {
            tree.add_leaf(key_to_path(k), alloc::vec![i as u8; 8])
                .unwrap();
        }
        let root = tree.calculate_root();

        for k in keys {
            let path = root.get_path(&key_to_path(&k));
            let result = path.verify(&key_to_path(&k));
            assert!(result.is_successful(), "key {k:?} should verify");

            // CBOR round-trips byte-for-byte.
            let bytes = path.to_cbor();
            let decoded = SparseMerkleTreePath::from_cbor(Decoder::new(&bytes)).unwrap();
            assert_eq!(decoded, path);
            assert_eq!(decoded.to_cbor(), bytes);

            // A path proves inclusion only for its own key.
            assert!(!path.verify(&key_to_path(&key32(0x55))).is_path_included);
        }
    }

    fn key32(last: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[31] = last;
        k
    }
}

#[cfg(any(feature = "client", test))]
pub use build::{SparseMerkleTree, SparseMerkleTreeRootNode};

#[cfg(any(feature = "client", test))]
mod build {
    //! Mutable plain SMT builder (insert leaves, finalize, extract paths).

    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;

    use num_bigint::BigUint;
    use num_traits::One;

    use super::{SparseMerkleTreePath, SparseMerkleTreePathStep};
    use crate::cbor::{encode_array, encode_byte_string, encode_nullable};
    use crate::crypto::hash::{DataHash, DataHasher, HashAlgorithm};
    use crate::error::Error;
    use crate::smt::bigint::{calculate_common_path, path_to_bytes};

    enum Pending {
        Leaf {
            path: BigUint,
            data: Vec<u8>,
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
            hash: DataHash,
        },
        Node {
            path: BigUint,
            left: Box<Finalized>,
            right: Box<Finalized>,
            hash: DataHash,
        },
    }

    impl Finalized {
        fn hash(&self) -> &DataHash {
            match self {
                Finalized::Leaf { hash, .. } | Finalized::Node { hash, .. } => hash,
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
                Pending::Leaf { path, data } => {
                    let preimage = encode_array(&[
                        &encode_byte_string(&path_to_bytes(&path)),
                        &encode_byte_string(&data),
                    ]);
                    let hash = digest(algorithm, &preimage);
                    Finalized::Leaf { path, data, hash }
                }
                Pending::Node { path, left, right } => {
                    let left = left.finalize(algorithm);
                    let right = right.finalize(algorithm);
                    let preimage = encode_array(&[
                        &encode_byte_string(&path_to_bytes(&path)),
                        &encode_byte_string(left.hash().data()),
                        &encode_byte_string(right.hash().data()),
                    ]);
                    let hash = digest(algorithm, &preimage);
                    Finalized::Node {
                        path,
                        left: Box::new(left),
                        right: Box::new(right),
                        hash,
                    }
                }
            }
        }
    }

    /// A mutable plain sparse Merkle tree. Insert leaves with
    /// [`add_leaf`](Self::add_leaf), then [`calculate_root`](Self::calculate_root).
    #[derive(Default)]
    pub struct SparseMerkleTree {
        left: Option<Pending>,
        right: Option<Pending>,
    }

    impl core::fmt::Debug for SparseMerkleTree {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SparseMerkleTree").finish_non_exhaustive()
        }
    }

    impl SparseMerkleTree {
        /// Create an empty tree.
        pub fn new() -> Self {
            Self::default()
        }

        /// Insert a leaf at routing `path` (which must be `>= 1`).
        pub fn add_leaf(&mut self, path: BigUint, data: Vec<u8>) -> Result<(), Error> {
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
                Some(branch) => build_tree(branch, path, data)?,
                None => Pending::Leaf { path, data },
            };
            *slot = Some(new);
            Ok(())
        }

        /// Finalize all hashes and return the root node.
        pub fn calculate_root(self) -> SparseMerkleTreeRootNode {
            let algorithm = HashAlgorithm::Sha256;
            let left = self.left.map(|b| b.finalize(algorithm));
            let right = self.right.map(|b| b.finalize(algorithm));
            let preimage = encode_array(&[
                &encode_byte_string(&path_to_bytes(&BigUint::one())),
                &encode_nullable(left.as_ref(), |b| encode_byte_string(b.hash().data())),
                &encode_nullable(right.as_ref(), |b| encode_byte_string(b.hash().data())),
            ]);
            let hash = digest(algorithm, &preimage);
            SparseMerkleTreeRootNode { left, right, hash }
        }
    }

    fn build_tree(
        branch: Pending,
        remaining_path: BigUint,
        data: Vec<u8>,
    ) -> Result<Pending, Error> {
        let (length, common) = calculate_common_path(&remaining_path, branch.path());
        let shifted = &remaining_path >> length_to_u64(&length);
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
            } => {
                if common == bpath {
                    return Err(Error::UnexpectedValue("SMT leaf out of bounds"));
                }
                let old = Pending::Leaf {
                    path: &bpath >> length_to_u64(&length),
                    data: bdata,
                };
                let new = Pending::Leaf {
                    path: shifted,
                    data,
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
                    };
                    let old = Pending::Node {
                        path: &bpath >> length_to_u64(&length),
                        left,
                        right,
                    };
                    return Ok(node(common, is_right, old, new));
                }
                if is_right {
                    Ok(Pending::Node {
                        path: bpath,
                        left,
                        right: Box::new(build_tree(*right, shifted, data)?),
                    })
                } else {
                    Ok(Pending::Node {
                        path: bpath,
                        left: Box::new(build_tree(*left, shifted, data)?),
                        right,
                    })
                }
            }
        }
    }

    /// Place `old`/`new` under a fresh node at `path`, ordering by `is_right`.
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

    /// The finalized root of a plain sparse Merkle tree.
    pub struct SparseMerkleTreeRootNode {
        left: Option<Finalized>,
        right: Option<Finalized>,
        hash: DataHash,
    }

    impl core::fmt::Debug for SparseMerkleTreeRootNode {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SparseMerkleTreeRootNode")
                .field("hash", &self.hash)
                .finish_non_exhaustive()
        }
    }

    impl SparseMerkleTreeRootNode {
        /// The root hash.
        pub fn hash(&self) -> &DataHash {
            &self.hash
        }

        /// Extract the inclusion path for routing `path`.
        pub fn get_path(&self, path: &BigUint) -> SparseMerkleTreePath {
            let steps = generate_path_root(path, self);
            SparseMerkleTreePath::new(self.hash.clone(), steps)
        }
    }

    fn data_of(branch: Option<&Finalized>) -> Option<Vec<u8>> {
        branch.map(|b| b.hash().data().to_vec())
    }

    fn generate_path_root(
        path: &BigUint,
        root: &SparseMerkleTreeRootNode,
    ) -> Vec<SparseMerkleTreePathStep> {
        generate_path_inner(
            path,
            &BigUint::one(),
            root.left.as_ref(),
            root.right.as_ref(),
        )
    }

    fn generate_path_branch(path: &BigUint, parent: &Finalized) -> Vec<SparseMerkleTreePathStep> {
        match parent {
            Finalized::Leaf { path: p, data, .. } => {
                vec![SparseMerkleTreePathStep::new(p.clone(), Some(data.clone()))]
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
    ) -> Vec<SparseMerkleTreePathStep> {
        let one = BigUint::one();
        let (length, common) = calculate_common_path(path, parent_path);
        let remaining = path >> length_to_u64(&length);

        if &common != parent_path || remaining == one {
            return vec![
                SparseMerkleTreePathStep::new(BigUint::ZERO, data_of(left)),
                SparseMerkleTreePathStep::new(parent_path.clone(), data_of(right)),
            ];
        }

        let is_right = remaining.bit(0);
        let (branch, sibling) = if is_right {
            (right, left)
        } else {
            (left, right)
        };
        let step = SparseMerkleTreePathStep::new(parent_path.clone(), data_of(sibling));

        match branch {
            None => {
                let bit = if is_right { one } else { BigUint::ZERO };
                vec![SparseMerkleTreePathStep::new(bit, None), step]
            }
            Some(b) => {
                let mut steps = generate_path_branch(&remaining, b);
                steps.push(step);
                steps
            }
        }
    }
}
