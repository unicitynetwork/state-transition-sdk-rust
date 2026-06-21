//! [`SplitMintJustification`] (CBOR tag 39044): the mint justification proving a
//! token was minted as an output of splitting a (now burned) source token.

use alloc::vec::Vec;

use super::asset::MAX_PAYMENT_ASSETS;
use super::proof::SplitAssetProof;
use crate::cbor::{encode_array, encode_tag, DecodeLimits, Decoder};
use crate::error::Error;
use crate::transaction::Token;

/// CBOR tag for [`SplitMintJustification`].
pub const SPLIT_MINT_JUSTIFICATION_TAG: u64 = 39044;

/// Justification carried by a split-minted token's genesis: the burned source
/// token plus one [`SplitAssetProof`] per asset the new token receives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitMintJustification {
    token: Token,
    proofs: Vec<SplitAssetProof>,
    encoded_token_len: usize,
}

impl SplitMintJustification {
    /// Construct from the burned source token and its asset proofs. `proofs`
    /// must be non-empty.
    pub fn create(token: Token, proofs: Vec<SplitAssetProof>) -> Result<Self, Error> {
        if proofs.is_empty() {
            return Err(Error::UnexpectedValue(
                "split mint justification needs at least one proof",
            ));
        }
        if proofs.len() > MAX_PAYMENT_ASSETS {
            return Err(Error::OutOfRange(
                "split proof count exceeds protocol limit",
            ));
        }
        let encoded_token_len = token.to_cbor().len();
        Ok(SplitMintJustification {
            token,
            proofs,
            encoded_token_len,
        })
    }

    /// The burned source token.
    pub fn token(&self) -> &Token {
        &self.token
    }

    /// The per-asset proofs.
    pub fn proofs(&self) -> &[SplitAssetProof] {
        &self.proofs
    }

    pub(crate) fn encoded_token_len(&self) -> usize {
        self.encoded_token_len
    }

    /// Decode from CBOR (tag 39044): `[token, [proofs...]]`.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_cbor_with_limits(bytes, DecodeLimits::DEFAULT)
    }

    /// Decode with explicit limits, including the embedded source token.
    pub fn from_cbor_with_limits(bytes: &[u8], limits: DecodeLimits) -> Result<Self, Error> {
        let inner = Decoder::with_limits(bytes, limits).expect_tag(SPLIT_MINT_JUSTIFICATION_TAG)?;
        let items = inner.array(Some(2))?;
        let encoded_token_len = items[0].bytes().len();
        let token = Token::from_cbor_with_limits(items[0].bytes(), limits)?;
        let mut proofs = Vec::new();
        for proof in items[1].array(None)? {
            proofs.push(SplitAssetProof::from_cbor(proof)?);
        }
        let mut justification = SplitMintJustification::create(token, proofs)?;
        justification.encoded_token_len = encoded_token_len;
        Ok(justification)
    }

    /// Encode to CBOR (tag 39044): `[token, [proofs...]]`.
    pub fn to_cbor(&self) -> Vec<u8> {
        let proof_bytes: Vec<Vec<u8>> = self.proofs.iter().map(SplitAssetProof::to_cbor).collect();
        let proof_refs: Vec<&[u8]> = proof_bytes.iter().map(Vec::as_slice).collect();
        encode_tag(
            SPLIT_MINT_JUSTIFICATION_TAG,
            &encode_array(&[&self.token.to_cbor(), &encode_array(&proof_refs)]),
        )
    }
}
