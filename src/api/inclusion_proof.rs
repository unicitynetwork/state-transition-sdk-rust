//! Inclusion proof (CBOR tag 39033): the aggregator's response binding a
//! transaction to a unique, BFT-certified position in the state tree.

use alloc::vec::Vec;

use super::bft::UnicityCertificate;
use super::certification::CertificationData;
use super::inclusion_certificate::InclusionCertificate;
use crate::cbor::{
    encode_array, encode_byte_string, encode_nullable, encode_tag, encode_uint, Decoder,
};
use crate::error::Error;

/// CBOR tag for [`InclusionProof`].
pub const INCLUSION_PROOF_TAG: u64 = 39033;
const VERSION: u64 = 1;

/// A proof of (non-)inclusion in the sparse Merkle tree, plus the unicity
/// certificate that anchors the tree root to the BFT consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// What was certified (present for an inclusion proof).
    pub certification_data: Option<CertificationData>,
    /// The SMT path (present for an inclusion proof).
    pub inclusion_certificate: Option<InclusionCertificate>,
    /// The BFT unicity certificate.
    pub unicity_certificate: UnicityCertificate,
}

impl InclusionProof {
    /// Decode from CBOR (tagged).
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(INCLUSION_PROOF_TAG)?;
        let items = inner.array(Some(4))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue("unsupported InclusionProof version"));
        }
        let certification_data = items[1].nullable(CertificationData::from_cbor)?;
        let inclusion_certificate =
            items[2].nullable(|x| InclusionCertificate::decode(x.bytes_value()?))?;
        Ok(InclusionProof {
            certification_data,
            inclusion_certificate,
            unicity_certificate: UnicityCertificate::from_cbor(items[3])?,
        })
    }

    /// Encode to CBOR (tagged).
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_tag(
            INCLUSION_PROOF_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_nullable(self.certification_data.as_ref(), |c| c.to_cbor()),
                &encode_nullable(self.inclusion_certificate.as_ref(), |c| {
                    encode_byte_string(&c.encode())
                }),
                &self.unicity_certificate.to_cbor(),
            ]),
        )
    }
}
