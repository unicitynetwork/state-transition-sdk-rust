//! Sparse Merkle trees used by the token-split payment subsystem.
//!
//! These are the **bigint-routed** plain and sum trees from the reference SDKs
//! (`smt/plain`, `smt/sum`), distinct from the radix SMT in
//! [`InclusionCertificate`](crate::api::InclusionCertificate) that proves a
//! transaction's inclusion under a block root. A split commits its outputs in
//! two layers:
//!
//! * a **sum tree** per asset, mapping each new token's id to the amount it
//!   receives (the node sums let a verifier check value conservation), and
//! * a **plain aggregation tree** over all asset trees, mapping each asset id to
//!   its sum-tree root.
//!
//! The aggregation root is the burn predicate's reason, binding the burned
//! source token to exactly this set of outputs.
//!
//! Path *verification* ([`plain::SparseMerkleTreePath::verify`],
//! [`sum::SparseMerkleSumTreePath::verify`]) is part of the `no_std` core; the
//! mutable tree *builders* are gated behind the `client` feature.

pub mod bigint;
pub mod plain;
pub mod sum;

/// Maximum routing-path width accepted by the payment SMT protocol.
pub const MAX_SMT_PATH_BYTES: usize = 129;
/// Maximum number of compressed nodes in one payment SMT proof.
pub const MAX_SMT_PATH_STEPS: usize = 1025;
/// Maximum opaque leaf/sibling data length accepted in a payment SMT proof.
pub const MAX_SMT_DATA_BYTES: usize = 128;

/// Outcome of verifying a sparse-Merkle-tree path.
///
/// A path is only trustworthy when it is both well-formed (recomputes the
/// committed root) *and* proves inclusion of the queried key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathVerificationResult {
    /// The path recomputed the committed root hash.
    pub is_path_valid: bool,
    /// The path routes to the queried key.
    pub is_path_included: bool,
}

/// Outcome of verifying a sparse-Merkle sum-tree path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumPathVerificationResult {
    path: PathVerificationResult,
    root_sum: Option<num_bigint::BigUint>,
}

impl SumPathVerificationResult {
    pub(crate) fn invalid() -> Self {
        Self {
            path: PathVerificationResult::new(false, false),
            root_sum: None,
        }
    }

    pub(crate) fn new(
        is_path_valid: bool,
        is_path_included: bool,
        root_sum: num_bigint::BigUint,
    ) -> Self {
        let path = PathVerificationResult::new(is_path_valid, is_path_included);
        let root_sum = path.is_successful().then_some(root_sum);
        Self { path, root_sum }
    }

    /// `true` only when the path recomputes the root and proves inclusion.
    pub fn is_successful(&self) -> bool {
        self.path.is_successful()
    }

    /// Sum committed by the verified root, available only for a successful path.
    pub fn root_sum(&self) -> Option<&num_bigint::BigUint> {
        self.root_sum.as_ref()
    }
}

impl PathVerificationResult {
    /// Construct a result; [`is_successful`](Self::is_successful) is their `&&`.
    pub fn new(is_path_valid: bool, is_path_included: bool) -> Self {
        PathVerificationResult {
            is_path_valid,
            is_path_included,
        }
    }

    /// `true` only when the path is both valid and proves inclusion.
    pub fn is_successful(&self) -> bool {
        self.is_path_valid && self.is_path_included
    }
}
