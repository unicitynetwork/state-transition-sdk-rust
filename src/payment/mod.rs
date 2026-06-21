//! Payment / asset / token-split subsystem.
//!
//! A token can carry a [`PaymentAssetCollection`] in its mint `data`: a set of
//! fungible [`Asset`]s. `TokenSplit` (client only) burns
//! such a token and produces several new ones whose combined assets equal the
//! original, each accompanied by [`SplitAssetProof`]s. A split-minted token's
//! genesis carries a [`SplitMintJustification`] (tag 39044), which
//! [`SplitMintJustificationVerifier`] checks during
//! [`Token::verify_with`](crate::transaction::Token::verify_with).
//!
//! The proofs ride on the bigint-routed [`smt`](crate::smt) plain and sum trees.

pub mod asset;
pub mod justification;
pub mod proof;
pub mod verifier;

#[cfg(any(feature = "client", test))]
pub mod split;

#[cfg(test)]
mod tests;

pub use asset::{Asset, AssetId, PaymentAssetCollection};
pub use justification::{SplitMintJustification, SPLIT_MINT_JUSTIFICATION_TAG};
pub use proof::SplitAssetProof;
pub use verifier::{
    verify_payment_token, PaymentDataDecoder, PaymentDataVerifier, PaymentIssuancePolicy,
    SplitMintJustificationVerifier,
};

#[cfg(any(feature = "client", test))]
pub use split::{Split, SplitBurn, SplitToken, SplitTokenRequest, TokenSplit};
