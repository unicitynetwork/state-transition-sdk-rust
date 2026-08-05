//! Non-inclusion proof (CBOR tag 39034): an absence certificate plus the BFT
//! certificate authenticating the SMT root at one certified point in time.

use alloc::vec::Vec;

use super::bft::{RootTrustBase, UnicityCertificate};
use super::{NonInclusionCertificate, StateId};
use crate::cbor::{encode_array, encode_byte_string, encode_tag, encode_uint, Decoder};
use crate::error::Error;
use crate::verify::{self, VerificationError};

/// CBOR tag for [`NonInclusionProof`].
pub const NON_INCLUSION_PROOF_TAG: u64 = 39034;
const VERSION: u64 = 1;

/// Proof that a state id was absent at the root authenticated by a Unicity
/// Certificate.
///
/// This is a snapshot statement.  Verification does not assert that the state
/// remains absent at a later root; callers with freshness requirements must
/// apply their own certified-round or timestamp policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonInclusionProof {
    certificate: NonInclusionCertificate,
    unicity_certificate: UnicityCertificate,
}

impl NonInclusionProof {
    /// Construct a proof using the canonical version-1 certificate profile.
    pub fn new(
        certificate: NonInclusionCertificate,
        unicity_certificate: UnicityCertificate,
    ) -> Self {
        Self {
            certificate,
            unicity_certificate,
        }
    }

    /// Decode a tagged proof in the canonical version-1 certificate profile.
    pub fn from_cbor(decoder: Decoder<'_>) -> Result<Self, Error> {
        let items = decoder
            .expect_tag(NON_INCLUSION_PROOF_TAG)?
            .array(Some(3))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue(
                "unsupported NonInclusionProof version",
            ));
        }
        let certificate = NonInclusionCertificate::decode(items[1].bytes_value()?)?;
        let unicity_certificate = UnicityCertificate::from_cbor(items[2])?;
        Ok(Self {
            certificate,
            unicity_certificate,
        })
    }

    /// Encode using the canonical version-1 certificate profile.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_tag(
            NON_INCLUSION_PROOF_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_byte_string(&self.certificate.encode()),
                &self.unicity_certificate.to_cbor(),
            ]),
        )
    }

    /// The relation-specific SMT certificate.
    pub fn certificate(&self) -> &NonInclusionCertificate {
        &self.certificate
    }

    /// The BFT certificate anchoring this proof's SMT root.
    pub fn unicity_certificate(&self) -> &UnicityCertificate {
        &self.unicity_certificate
    }

    /// Verify the complete proof for `target` against `trust_base`.
    pub fn verify(
        &self,
        target: &StateId,
        trust_base: &RootTrustBase,
    ) -> Result<(), VerificationError> {
        verify::verify_non_inclusion_proof(trust_base, self, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_rejects_wrong_tag_version_and_shape() {
        let wrong_tag = encode_tag(
            NON_INCLUSION_PROOF_TAG + 1,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_byte_string(&[]),
                &encode_uint(0),
            ]),
        );
        assert!(NonInclusionProof::from_cbor(Decoder::new(&wrong_tag)).is_err());

        let wrong_version = encode_tag(
            NON_INCLUSION_PROOF_TAG,
            &encode_array(&[
                &encode_uint(VERSION + 1),
                &encode_byte_string(&[]),
                &encode_uint(0),
            ]),
        );
        assert!(NonInclusionProof::from_cbor(Decoder::new(&wrong_version)).is_err());

        let wrong_shape = encode_tag(
            NON_INCLUSION_PROOF_TAG,
            &encode_array(&[&encode_uint(VERSION), &encode_byte_string(&[])]),
        );
        assert!(NonInclusionProof::from_cbor(Decoder::new(&wrong_shape)).is_err());
    }

    #[test]
    fn decoder_rejects_legacy_unicity_certificate_profile() {
        let legacy_uc = encode_tag(1007, &encode_array(&[]));
        let proof = encode_tag(
            NON_INCLUSION_PROOF_TAG,
            &encode_array(&[&encode_uint(VERSION), &encode_byte_string(&[]), &legacy_uc]),
        );

        assert!(NonInclusionProof::from_cbor(Decoder::new(&proof)).is_err());
    }
}
