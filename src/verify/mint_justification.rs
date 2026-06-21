//! Pluggable mint-justification verification.
//!
//! A mint may carry an optional *justification* explaining why minting it is
//! legitimate (e.g. it is an output of a token split). The justification is an
//! opaque CBOR item identified by its tag; a [`MintJustificationVerifier`]
//! claims one tag and decides whether the justification holds.
//!
//! [`MintJustificationRegistry`] dispatches by tag and is threaded recursively
//! through [`verify_token_with`](crate::verify::verify_token_with): a verifier
//! whose justification embeds another token (such as the split verifier) can
//! re-enter verification with the same registry. An empty registry rejects any
//! present justification (fail closed), preserving the core's default of
//! trusting no justification it cannot check.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;

use super::{VerificationContext, VerificationError};
use crate::cbor::Decoder;
use crate::error::Error;
use crate::transaction::ids::TokenType;
use crate::transaction::CertifiedMintTransaction;

/// Verifier for a single mint-justification CBOR tag.
pub trait MintJustificationVerifier {
    /// The CBOR tag this verifier handles.
    fn tag(&self) -> u64;

    /// Verify the justification embedded in `genesis`. The `registry` is
    /// provided for recursive verification of any nested token.
    fn verify(
        &self,
        genesis: &CertifiedMintTransaction,
        context: &mut VerificationContext<'_>,
    ) -> Result<(), VerificationError>;
}

/// Verifier for application data carried by one token type.
///
/// Registering a verifier is an application trust decision. Payment consumers
/// should use a verifier that checks both payload structure and their issuance
/// policy; cryptographic certification alone does not authorize an asset issuer.
pub trait TokenDataVerifier {
    /// Token type whose application data this verifier handles.
    fn token_type(&self) -> &TokenType;

    /// Validate the genesis application data and any application-level policy.
    fn verify(
        &self,
        genesis: &CertifiedMintTransaction,
        context: &mut VerificationContext<'_>,
    ) -> Result<(), VerificationError>;
}

/// Registry of [`MintJustificationVerifier`]s keyed by tag.
#[derive(Default)]
pub struct MintJustificationRegistry {
    verifiers: BTreeMap<u64, Box<dyn MintJustificationVerifier>>,
    data_verifiers: BTreeMap<alloc::vec::Vec<u8>, Box<dyn TokenDataVerifier>>,
}

impl core::fmt::Debug for MintJustificationRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MintJustificationRegistry")
            .field("tags", &self.verifiers.keys())
            .field("token_data_types", &self.data_verifiers.keys())
            .finish()
    }
}

impl MintJustificationRegistry {
    /// An empty registry (rejects any present justification).
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `verifier` for its declared tag. Errors if the tag is taken.
    pub fn register(
        &mut self,
        verifier: Box<dyn MintJustificationVerifier>,
    ) -> Result<&mut Self, Error> {
        let tag = verifier.tag();
        if self.verifiers.contains_key(&tag) {
            return Err(Error::UnexpectedValue(
                "duplicate mint justification verifier tag",
            ));
        }
        self.verifiers.insert(tag, verifier);
        Ok(self)
    }

    /// Register an application-data verifier for one token type.
    pub fn register_token_data(
        &mut self,
        verifier: Box<dyn TokenDataVerifier>,
    ) -> Result<&mut Self, Error> {
        let token_type = verifier.token_type().bytes().to_vec();
        if self.data_verifiers.contains_key(&token_type) {
            return Err(Error::UnexpectedValue(
                "duplicate token data verifier for token type",
            ));
        }
        self.data_verifiers.insert(token_type, verifier);
        Ok(self)
    }

    /// Verify the genesis's mint justification (if any). A genesis with no
    /// justification is accepted; one with a justification whose tag has no
    /// registered verifier is rejected as unsupported.
    pub(crate) fn verify_genesis(
        &self,
        genesis: &CertifiedMintTransaction,
        context: &mut VerificationContext<'_>,
    ) -> Result<(), VerificationError> {
        let Some(bytes) = genesis.transaction().justification() else {
            return Ok(());
        };
        // Read just the tag; the verifier re-decodes the body it understands.
        let (tag, _) = Decoder::with_limits(bytes, context.policy().limits.decode)
            .tag()
            .map_err(|_| VerificationError::UnsupportedMintJustification)?;
        let verifier = self
            .verifiers
            .get(&tag)
            .ok_or(VerificationError::UnsupportedMintJustification)?;
        verifier.verify(genesis, context)
    }

    pub(crate) fn verify_token_data(
        &self,
        genesis: &CertifiedMintTransaction,
        context: &mut VerificationContext<'_>,
    ) -> Result<(), VerificationError> {
        let Some(data) = genesis.transaction().data() else {
            return Ok(());
        };
        if data.len() > context.policy().limits.decode.max_input_bytes {
            return Err(VerificationError::VerificationLimitExceeded(
                "token data bytes",
            ));
        }
        let verifier = self
            .data_verifiers
            .get(genesis.transaction().token_type().bytes());
        match verifier {
            Some(verifier) => verifier.verify(genesis, context),
            None if context.policy().require_token_data_verifier => {
                Err(VerificationError::UnsupportedTokenData)
            }
            None => Ok(()),
        }
    }
}
