//! Aggregator-facing API types: identifiers, certification data, proofs, and
//! the BFT trust structures.

pub mod bft;
pub mod certification;
pub mod certification_request;
pub mod inclusion_certificate;
pub mod inclusion_proof;
pub mod network_id;
pub mod state_id;

pub use certification::CertificationData;
pub use certification_request::CertificationRequest;
pub use inclusion_certificate::InclusionCertificate;
pub use inclusion_proof::InclusionProof;
pub use network_id::NetworkId;
pub use state_id::StateId;
