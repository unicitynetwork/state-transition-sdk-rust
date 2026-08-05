//! Aggregator-facing API types: identifiers, certification data, proofs, and
//! the BFT trust structures.

pub mod bft;
pub mod certification;
pub mod certification_request;
pub mod inclusion_certificate;
pub mod inclusion_proof;
pub mod network_id;
pub mod non_inclusion_certificate;
pub mod non_inclusion_proof;
pub mod state_id;

/// Leaf-value width in the Unicity aggregation profile.
///
/// The generic RSMT certificate format permits arbitrary byte-string values;
/// Unicity restricts each value to one raw SHA-256 transaction hash.
pub const AGGREGATION_TREE_VALUE_SIZE: usize = 32;

pub use certification::CertificationData;
pub use certification_request::CertificationRequest;
pub use inclusion_certificate::InclusionCertificate;
pub use inclusion_proof::InclusionProof;
pub use network_id::NetworkId;
pub use non_inclusion_certificate::NonInclusionCertificate;
pub use non_inclusion_proof::NonInclusionProof;
pub use state_id::StateId;
