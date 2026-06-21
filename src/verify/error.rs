//! Verification failure reasons.

use alloc::boxed::Box;
use core::fmt;

use crate::Error;

/// Why a token (or one of its transactions) failed verification.
///
/// Distinct variants make it possible to test that each rule rejects the
/// forgery it is meant to catch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationError {
    /// The supplied root trust base is structurally unsafe.
    InvalidTrustBase(Error),
    /// The genesis network id does not match the trust base.
    NetworkMismatch,
    /// The genesis lock script is not the deterministic minter key for the token id.
    InvalidMintLockScript,
    /// A mint justification was present but no verifier supports it.
    UnsupportedMintJustification,
    /// Token application data required validation but no verifier was registered.
    UnsupportedTokenData,
    /// A registered token-data verifier rejected malformed application data.
    MalformedTokenData,
    /// Application policy did not authorize this payment issuance.
    PaymentIssuanceRejected,
    /// A cumulative verification resource limit was exceeded.
    VerificationLimitExceeded(&'static str),
    /// A mint justification (or its embedded payment data) failed to decode.
    MalformedMintJustification,
    /// A split-minted token's genesis carried no payment (asset) data.
    PaymentDataMissing,
    /// A split mint is on a different network than its burned source token.
    SplitNetworkMismatch,
    /// The burned source token in a split justification failed verification.
    BurnTokenVerificationFailed(Box<VerificationError>),
    /// The payment asset count does not match the number of split proofs.
    SplitAssetCountMismatch,
    /// The burned source token carried no decodable payment data.
    SplitSourcePaymentDataMissing,
    /// An output asset did not exist in the burned source token.
    SplitSourceAssetMissing,
    /// The split sum-tree total did not equal the burned source amount.
    SplitSourceAmountMismatch,
    /// Two split proofs claim the same asset id.
    DuplicateSplitProof,
    /// A split proof's aggregation-tree path did not verify for its asset id.
    SplitAggregationPathInvalid,
    /// A split proof's asset-tree path did not verify for the minted token id.
    SplitAssetTreePathInvalid,
    /// Split proofs are not all derived from the same aggregation tree.
    SplitProofRootMismatch,
    /// A proof's asset-tree root does not match its aggregation-path leaf.
    SplitAssetTreeRootMismatch,
    /// A proof's asset id is absent from the genesis payment data.
    SplitAssetNotInPayment,
    /// A proof's certified amount does not match the payment data amount.
    SplitAssetAmountMismatch,
    /// The burned token was not locked to the split's aggregation-root burn predicate.
    SplitBurnPredicateMismatch,
    /// Fewer validated proofs than payment assets — some proofs are missing.
    SplitProofsIncomplete,
    /// The inclusion proof had no inclusion certificate.
    InclusionCertificateMissing,
    /// The inclusion proof had no certification data.
    CertificationDataMissing,
    /// Certification fields do not match the reconstructed transaction state.
    CertificationDataMismatch,
    /// The certified transaction hash does not match the recomputed one.
    TransactionHashMismatch,
    /// The sparse-Merkle-tree path did not reproduce the expected root.
    PathInvalid,
    /// The certified shard does not contain the state id.
    ShardMismatch,
    /// The unicity seal's network id does not match the trust base.
    SealNetworkMismatch,
    /// The recomputed unicity-tree root does not match the signed seal hash.
    SealRootMismatch,
    /// Fewer than `quorumThreshold` distinct root-node signatures were valid.
    QuorumNotMet,
    /// The unlock script does not satisfy the lock script.
    NotAuthenticated,
    /// The genesis failed verification (wraps the underlying cause).
    Genesis(Box<VerificationError>),
    /// Transfer at `index` failed verification (wraps the underlying cause).
    Transfer {
        /// Position in the transfer history.
        index: usize,
        /// The underlying failure.
        source: Box<VerificationError>,
    },
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::InvalidTrustBase(e) => write!(f, "{e}"),
            VerificationError::NetworkMismatch => write!(f, "network id does not match trust base"),
            VerificationError::InvalidMintLockScript => {
                write!(
                    f,
                    "genesis lock script is not the minter key for the token id"
                )
            }
            VerificationError::UnsupportedMintJustification => {
                write!(f, "unsupported mint justification")
            }
            VerificationError::UnsupportedTokenData => {
                write!(f, "token data has no registered verifier")
            }
            VerificationError::MalformedTokenData => write!(f, "malformed token data"),
            VerificationError::PaymentIssuanceRejected => {
                write!(f, "payment issuance rejected by application policy")
            }
            VerificationError::VerificationLimitExceeded(resource) => {
                write!(f, "verification resource limit exceeded: {resource}")
            }
            VerificationError::MalformedMintJustification => {
                write!(f, "malformed mint justification")
            }
            VerificationError::PaymentDataMissing => write!(f, "payment data missing"),
            VerificationError::SplitNetworkMismatch => {
                write!(f, "split mint network does not match source token")
            }
            VerificationError::BurnTokenVerificationFailed(e) => {
                write!(f, "burned source token verification failed: {e}")
            }
            VerificationError::SplitAssetCountMismatch => {
                write!(f, "asset count does not match split proof count")
            }
            VerificationError::SplitSourcePaymentDataMissing => {
                write!(f, "burned source token has no valid payment data")
            }
            VerificationError::SplitSourceAssetMissing => {
                write!(f, "split asset is absent from burned source token")
            }
            VerificationError::SplitSourceAmountMismatch => {
                write!(
                    f,
                    "split sum-tree total does not match burned source amount"
                )
            }
            VerificationError::DuplicateSplitProof => write!(f, "duplicate split proof for asset"),
            VerificationError::SplitAggregationPathInvalid => {
                write!(f, "split aggregation path invalid")
            }
            VerificationError::SplitAssetTreePathInvalid => {
                write!(f, "split asset tree path invalid")
            }
            VerificationError::SplitProofRootMismatch => {
                write!(f, "split proofs derive from different aggregation trees")
            }
            VerificationError::SplitAssetTreeRootMismatch => {
                write!(f, "asset tree root does not match aggregation path leaf")
            }
            VerificationError::SplitAssetNotInPayment => {
                write!(f, "split proof asset id not present in payment data")
            }
            VerificationError::SplitAssetAmountMismatch => {
                write!(f, "split proof amount does not match payment data")
            }
            VerificationError::SplitBurnPredicateMismatch => {
                write!(
                    f,
                    "burned token not locked to split aggregation-root burn predicate"
                )
            }
            VerificationError::SplitProofsIncomplete => {
                write!(f, "some split proofs are missing from the token")
            }
            VerificationError::InclusionCertificateMissing => {
                write!(f, "inclusion certificate missing")
            }
            VerificationError::CertificationDataMissing => write!(f, "certification data missing"),
            VerificationError::CertificationDataMismatch => {
                write!(f, "certification data does not match transaction state")
            }
            VerificationError::TransactionHashMismatch => write!(f, "transaction hash mismatch"),
            VerificationError::PathInvalid => write!(f, "inclusion path invalid"),
            VerificationError::ShardMismatch => write!(f, "shard does not contain state id"),
            VerificationError::SealNetworkMismatch => {
                write!(f, "unicity seal network does not match trust base")
            }
            VerificationError::SealRootMismatch => {
                write!(f, "unicity tree root does not match seal hash")
            }
            VerificationError::QuorumNotMet => write!(f, "quorum of root-node signatures not met"),
            VerificationError::NotAuthenticated => {
                write!(f, "unlock script does not satisfy lock script")
            }
            VerificationError::Genesis(e) => write!(f, "genesis verification failed: {e}"),
            VerificationError::Transfer { index, source } => {
                write!(f, "transfer[{index}] verification failed: {source}")
            }
        }
    }
}

impl core::error::Error for VerificationError {}
