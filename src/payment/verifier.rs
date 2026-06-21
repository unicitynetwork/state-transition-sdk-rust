//! [`SplitMintJustificationVerifier`]: the security-critical check that a
//! split-minted token is a legitimate output of burning a real source token.
//!
//! Faithful port of the reference `SplitMintJustificationVerifier`. The chain of
//! evidence it enforces:
//!
//! 1. the burned **source token fully verifies** against the trust base (so its
//!    value was real and is now provably destroyed);
//! 2. the source token's final state is a **burn predicate whose reason is the
//!    aggregation-tree root** — binding the burn to *exactly* this set of
//!    outputs and no other;
//! 3. for every asset, an **aggregation path** (asset id → asset-tree root) and
//!    an **asset-tree path** (this minted token's id → amount) both verify, all
//!    proofs share one aggregation root, and the certified amounts match the
//!    minted token's declared payment data.
//!
//! Any deviation rejects the mint, so a forged or over-issued split cannot pass.

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::asset::PaymentAssetCollection;
use super::justification::{SplitMintJustification, SPLIT_MINT_JUSTIFICATION_TAG};
use crate::error::Error;
use crate::predicate::builtin::BurnPredicate;
use crate::predicate::EncodedPredicate;
use crate::smt::bigint::key_to_path;
use crate::transaction::ids::TokenType;
use crate::transaction::{CertifiedMintTransaction, Token};
use crate::verify::{
    verify_token_with_policy, MintJustificationRegistry, MintJustificationVerifier,
    TokenDataVerifier, VerificationContext, VerificationPolicy,
};
use crate::VerificationError;

/// Decoder from a token's mint `data` bytes to its [`PaymentAssetCollection`].
///
/// The default ([`PaymentAssetCollection::from_cbor_bytes`]) treats the mint
/// `data` as exactly the encoded collection; supply a custom decoder if the
/// payment data is wrapped in an application envelope.
pub type PaymentDataDecoder = fn(&[u8]) -> Result<PaymentAssetCollection, Error>;

/// Application policy authorizing issuance of a payment payload.
pub type PaymentIssuancePolicy =
    fn(&CertifiedMintTransaction, &PaymentAssetCollection) -> Result<(), VerificationError>;

/// Verifier for [`SplitMintJustification`] mint justifications.
#[derive(Debug, Clone)]
pub struct SplitMintJustificationVerifier {
    decode_payment_data: PaymentDataDecoder,
}

impl SplitMintJustificationVerifier {
    /// Create a verifier using the default payment-data decoder.
    pub fn new() -> Self {
        SplitMintJustificationVerifier {
            decode_payment_data: PaymentAssetCollection::from_cbor_bytes,
        }
    }

    /// Create a verifier with a custom payment-data decoder.
    pub fn with_payment_decoder(decoder: PaymentDataDecoder) -> Self {
        SplitMintJustificationVerifier {
            decode_payment_data: decoder,
        }
    }
}

impl Default for SplitMintJustificationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Payment-data and mandatory issuance-policy verifier for one token type.
#[derive(Debug, Clone)]
pub struct PaymentDataVerifier {
    token_type: TokenType,
    decode_payment_data: PaymentDataDecoder,
    authorize_issuance: PaymentIssuancePolicy,
}

impl PaymentDataVerifier {
    /// Validate bare [`PaymentAssetCollection`] data and invoke the issuance
    /// policy for `token_type`.
    pub fn new(token_type: TokenType, authorize_issuance: PaymentIssuancePolicy) -> Self {
        Self {
            token_type,
            decode_payment_data: PaymentAssetCollection::from_cbor_bytes,
            authorize_issuance,
        }
    }

    /// Validate custom payment-data envelopes and invoke the issuance policy.
    pub fn with_payment_decoder(
        token_type: TokenType,
        decoder: PaymentDataDecoder,
        authorize_issuance: PaymentIssuancePolicy,
    ) -> Self {
        Self {
            token_type,
            decode_payment_data: decoder,
            authorize_issuance,
        }
    }
}

impl TokenDataVerifier for PaymentDataVerifier {
    fn token_type(&self) -> &TokenType {
        &self.token_type
    }

    fn verify(
        &self,
        genesis: &CertifiedMintTransaction,
        _context: &mut VerificationContext<'_>,
    ) -> Result<(), VerificationError> {
        let bytes = genesis
            .transaction()
            .data()
            .ok_or(VerificationError::MalformedTokenData)?;
        let assets =
            (self.decode_payment_data)(bytes).map_err(|_| VerificationError::MalformedTokenData)?;
        (self.authorize_issuance)(genesis, &assets)
    }
}

/// Verify cryptographic history, all registered payloads, and return the
/// validated payment carried by `token`.
pub fn verify_payment_token(
    token: &Token,
    trust_base: &crate::api::bft::RootTrustBase,
    registry: &MintJustificationRegistry,
    decode_payment_data: PaymentDataDecoder,
) -> Result<PaymentAssetCollection, VerificationError> {
    let policy = VerificationPolicy {
        require_token_data_verifier: true,
        ..VerificationPolicy::default()
    };
    verify_token_with_policy(token, trust_base, registry, policy)?;
    let bytes = token
        .genesis()
        .transaction()
        .data()
        .ok_or(VerificationError::PaymentDataMissing)?;
    decode_payment_data(bytes).map_err(|_| VerificationError::MalformedTokenData)
}

impl MintJustificationVerifier for SplitMintJustificationVerifier {
    fn tag(&self) -> u64 {
        SPLIT_MINT_JUSTIFICATION_TAG
    }

    fn verify(
        &self,
        genesis: &CertifiedMintTransaction,
        context: &mut VerificationContext<'_>,
    ) -> Result<(), VerificationError> {
        let mint = genesis.transaction();

        let justification_bytes = mint
            .justification()
            .ok_or(VerificationError::MalformedMintJustification)?;
        let justification = SplitMintJustification::from_cbor_with_limits(
            justification_bytes,
            context.policy().limits.decode,
        )
        .map_err(|_| VerificationError::MalformedMintJustification)?;

        // The minted token must declare the payment (assets) it received.
        let payment_bytes = mint.data().ok_or(VerificationError::PaymentDataMissing)?;
        if payment_bytes.len() > context.policy().limits.decode.max_input_bytes {
            return Err(VerificationError::VerificationLimitExceeded(
                "payment data bytes",
            ));
        }
        let assets = (self.decode_payment_data)(payment_bytes)
            .map_err(|_| VerificationError::MalformedTokenData)?;

        // Mint and source token must live on the same network.
        if mint.network_id() != justification.token().genesis().transaction().network_id() {
            return Err(VerificationError::SplitNetworkMismatch);
        }

        // The burned source token must itself fully verify (recursively, so a
        // split of a split is checked end to end).
        context
            .verify_embedded_token(justification.token(), justification.encoded_token_len())
            .map_err(|e| VerificationError::BurnTokenVerificationFailed(Box::new(e)))?;

        let source_payment_bytes = justification
            .token()
            .genesis()
            .transaction()
            .data()
            .ok_or(VerificationError::SplitSourcePaymentDataMissing)?;
        if source_payment_bytes.len() > context.policy().limits.decode.max_input_bytes {
            return Err(VerificationError::VerificationLimitExceeded(
                "source payment data bytes",
            ));
        }
        let source_assets = (self.decode_payment_data)(source_payment_bytes)
            .map_err(|_| VerificationError::SplitSourcePaymentDataMissing)?;

        if assets.len() != justification.proofs().len() {
            return Err(VerificationError::SplitAssetCountMismatch);
        }

        let token_id_path = key_to_path(mint.token_id().bytes());
        let aggregation_root = justification
            .proofs()
            .first()
            .map(|p| p.aggregation_path().root());
        let last_recipient = justification
            .token()
            .transactions()
            .last()
            .map(|t| t.recipient());

        let mut validated: BTreeSet<Vec<u8>> = BTreeSet::new();
        for proof in justification.proofs() {
            let asset_key = proof.asset_id().bytes().to_vec();
            if validated.contains(&asset_key) {
                return Err(VerificationError::DuplicateSplitProof);
            }

            // Asset id is committed in the aggregation tree.
            if !proof
                .aggregation_path()
                .verify(&proof.asset_id().to_path())
                .is_successful()
            {
                return Err(VerificationError::SplitAggregationPathInvalid);
            }

            // This minted token's id is committed in the asset's sum tree.
            let asset_path_result = proof.asset_tree_path().verify(&token_id_path);
            if !asset_path_result.is_successful() {
                return Err(VerificationError::SplitAssetTreePathInvalid);
            }

            // All proofs must share one aggregation tree.
            if Some(proof.aggregation_path().root()) != aggregation_root {
                return Err(VerificationError::SplitProofRootMismatch);
            }

            // The asset-tree root must be the leaf committed in the aggregation
            // path (binding the two layers together).
            if Some(proof.asset_tree_path().root().imprint().as_slice())
                != proof
                    .aggregation_path()
                    .steps()
                    .first()
                    .and_then(|s| s.data())
            {
                return Err(VerificationError::SplitAssetTreeRootMismatch);
            }

            // The certified amount must match the declared payment amount.
            let amount = assets
                .get(proof.asset_id())
                .map(|a| a.value())
                .ok_or(VerificationError::SplitAssetNotInPayment)?;
            if proof.asset_tree_path().steps().first().map(|s| s.value()) != Some(amount) {
                return Err(VerificationError::SplitAssetAmountMismatch);
            }

            // The sum committed by this asset tree must equal the amount that
            // existed in the burned source. This is the verifier-side value
            // conservation check; client-side split construction is untrusted.
            let source_amount = source_assets
                .get(proof.asset_id())
                .map(|asset| asset.value())
                .ok_or(VerificationError::SplitSourceAssetMissing)?;
            if asset_path_result.root_sum() != Some(source_amount) {
                return Err(VerificationError::SplitSourceAmountMismatch);
            }

            // The source token must have been burned to this aggregation root.
            let expected_recipient = EncodedPredicate::from_predicate(&BurnPredicate::new(
                proof.aggregation_path().root().imprint(),
            ));
            if last_recipient != Some(&expected_recipient) {
                return Err(VerificationError::SplitBurnPredicateMismatch);
            }

            validated.insert(asset_key);
        }

        if validated.len() != assets.len() {
            return Err(VerificationError::SplitProofsIncomplete);
        }

        Ok(())
    }
}
