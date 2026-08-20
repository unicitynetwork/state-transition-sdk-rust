//! Inclusion proof (CBOR tag 39033): the aggregator's response binding a
//! transaction to a unique, BFT-certified position in the state tree.

use alloc::vec::Vec;

use super::bft::{RootTrustBase, UnicityCertificate};
use super::certification::CertificationData;
use super::inclusion_certificate::InclusionCertificate;
use super::StateId;
use crate::cbor::{
    encode_array, encode_byte_string, encode_nullable, encode_tag, encode_uint, Decoder,
};
use crate::error::Error;
use crate::verify::{self, VerificationError};

/// CBOR tag for [`InclusionProof`].
pub const INCLUSION_PROOF_TAG: u64 = 39033;
const VERSION: u64 = 1;

/// A proof of inclusion in the sparse Merkle tree, plus the unicity certificate
/// that anchors the tree root to the BFT consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// What was certified (present for an inclusion proof).
    pub certification_data: Option<CertificationData>,
    /// Reference time of the round the certified leaf was created in (present
    /// for an inclusion proof).
    ///
    /// It cannot be recovered from the certificate chain: an aggregator serves
    /// proofs against the current certified root, whose input record time is
    /// that of the latest round rather than the one the leaf was created under.
    pub reference_time: Option<u64>,
    /// The SMT path (present for an inclusion proof).
    pub inclusion_certificate: Option<InclusionCertificate>,
    /// The BFT unicity certificate.
    pub unicity_certificate: UnicityCertificate,
}

impl InclusionProof {
    /// Decode from CBOR (tagged).
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(INCLUSION_PROOF_TAG)?;
        let items = inner.array(Some(5))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue("unsupported InclusionProof version"));
        }
        let certification_data = items[1].nullable(CertificationData::from_cbor)?;
        let reference_time = items[2].nullable(|x| x.uint().map_err(Into::into))?;
        let inclusion_certificate =
            items[3].nullable(|x| InclusionCertificate::decode(x.bytes_value()?))?;

        // A proof either establishes a leaf or reports that there is none yet. A
        // partially present proof is neither, and would let a caller reach a leaf
        // check with a reference time nothing certified.
        let present = certification_data.is_some() as u8
            + reference_time.is_some() as u8
            + inclusion_certificate.is_some() as u8;
        if present != 0 && present != 3 {
            return Err(Error::UnexpectedValue(
                "InclusionProof must carry certification data, reference time and inclusion certificate together, or none of them",
            ));
        }

        Ok(InclusionProof {
            certification_data,
            reference_time,
            inclusion_certificate,
            unicity_certificate: UnicityCertificate::from_cbor(items[4])?,
        })
    }

    /// Encode to CBOR (tagged).
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_tag(
            INCLUSION_PROOF_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_nullable(self.certification_data.as_ref(), |c| c.to_cbor()),
                &encode_nullable(self.reference_time.as_ref(), |t| encode_uint(*t)),
                &encode_nullable(self.inclusion_certificate.as_ref(), |c| {
                    encode_byte_string(&c.encode())
                }),
                &self.unicity_certificate.to_cbor(),
            ]),
        )
    }

    /// Verify that this proof includes `state_id` at its certified root.
    ///
    /// This verifies the state relation, certification data, shard, quorum UC,
    /// and unlock witness. Transaction/token verification may impose additional
    /// application-level constraints.
    ///
    /// `reference_time` is the value the leaf was built from; it is taken from
    /// the caller rather than from this proof's certificate, because the tree
    /// is append-only and a proof may be issued against a later root.
    pub fn verify_for(
        &self,
        state_id: &StateId,
        reference_time: u64,
        trust_base: &RootTrustBase,
    ) -> Result<(), VerificationError> {
        verify::verify_inclusion_proof_for(trust_base, self, state_id, reference_time)
    }
}
