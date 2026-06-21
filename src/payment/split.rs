//! Client-side token splitting (`client` feature).
//!
//! [`TokenSplit::split`] burns a payment-carrying token and produces the data
//! needed to mint several new tokens whose assets sum to the original. It builds
//! a sum tree per asset (token id → amount) and a plain aggregation tree over
//! the asset-tree roots; the aggregation root becomes the burn predicate's
//! reason, and each output carries [`SplitAssetProof`]s extracted from those
//! trees. The result is exactly what [`SplitMintJustificationVerifier`] checks.
//!
//! [`SplitMintJustificationVerifier`]: super::verifier::SplitMintJustificationVerifier

use alloc::vec::Vec;

use super::asset::{AssetId, PaymentAssetCollection};
use super::proof::SplitAssetProof;
use crate::api::network_id::NetworkId;
use crate::error::Error;
use crate::predicate::builtin::BurnPredicate;
use crate::predicate::EncodedPredicate;
use crate::smt::bigint::key_to_path;
use crate::smt::plain::SparseMerkleTree;
use crate::smt::sum::SparseMerkleSumTree;
use crate::transaction::ids::{TokenId, TokenSalt, TokenType};
use crate::transaction::{Token, TransferTransaction};

/// A request to mint one new token as part of a split.
#[derive(Debug, Clone)]
pub struct SplitTokenRequest {
    recipient: EncodedPredicate,
    token_type: TokenType,
    assets: PaymentAssetCollection,
    salt: TokenSalt,
}

impl SplitTokenRequest {
    /// Create a request: `recipient` locks the new token, which receives
    /// `assets` and is identified by `token_type` and `salt`.
    pub fn create(
        recipient: EncodedPredicate,
        assets: PaymentAssetCollection,
        token_type: TokenType,
        salt: TokenSalt,
    ) -> Self {
        SplitTokenRequest {
            recipient,
            token_type,
            assets,
            salt,
        }
    }
}

/// A realized split output: everything needed to mint the new token.
#[derive(Debug, Clone)]
pub struct SplitToken {
    /// Network of the new token (inherited from the source token).
    pub network_id: NetworkId,
    /// Predicate that will lock the new token.
    pub recipient: EncodedPredicate,
    /// Token type of the new token.
    pub token_type: TokenType,
    /// Salt of the new token.
    pub salt: TokenSalt,
    /// Assets the new token receives.
    pub assets: PaymentAssetCollection,
    /// Inclusion proofs binding these assets to the burned source token.
    pub proofs: Vec<SplitAssetProof>,
}

/// The burn side of a split: the predicate and transfer that destroy the source.
#[derive(Debug, Clone)]
pub struct SplitBurn {
    /// The burn predicate (reason = aggregation-tree root imprint).
    pub owner_predicate: BurnPredicate,
    /// The transfer that burns the source token.
    pub transaction: TransferTransaction,
}

/// The result of [`TokenSplit::split`].
#[derive(Debug, Clone)]
pub struct Split {
    /// The burn of the source token.
    pub burn: SplitBurn,
    /// The new tokens to mint.
    pub tokens: Vec<SplitToken>,
}

/// Token splitting.
#[derive(Debug)]
pub struct TokenSplit;

impl TokenSplit {
    /// Split `token` into the outputs described by `requests`.
    ///
    /// `decode_payment_data` extracts the source token's [`PaymentAssetCollection`]
    /// from its mint `data`. `burn_state_mask` sets the burn transfer's state
    /// mask; pass `None` for a random mask (requires the `std` RNG) or a fixed
    /// value for a reproducible, crash-resumable burn.
    pub fn split(
        token: &Token,
        decode_payment_data: fn(&[u8]) -> Result<PaymentAssetCollection, Error>,
        requests: Vec<SplitTokenRequest>,
        burn_state_mask: Option<[u8; 32]>,
    ) -> Result<Split, Error> {
        let network_id = token.genesis().transaction().network_id();

        // Derive each output's token id and reject duplicates.
        let mut entries: Vec<(SplitTokenRequest, TokenId, num_bigint::BigUint)> = Vec::new();
        for request in requests {
            let token_id = TokenId::derive(network_id, &request.salt);
            let token_id_path = key_to_path(token_id.bytes());
            if entries.iter().any(|(_, _, p)| p == &token_id_path) {
                return Err(Error::UnexpectedValue("duplicate split token id"));
            }
            entries.push((request, token_id, token_id_path));
        }

        // One sum tree per asset, mapping each output token id to its amount.
        let mut trees: Vec<(AssetId, SparseMerkleSumTree)> = Vec::new();
        for (request, _, token_id_path) in &entries {
            for asset in request.assets.as_slice() {
                let tree = match trees.iter_mut().find(|(id, _)| id == asset.id()) {
                    Some((_, tree)) => tree,
                    None => {
                        trees.push((asset.id().clone(), SparseMerkleSumTree::new()));
                        &mut trees.last_mut().expect("just pushed").1
                    }
                };
                tree.add_leaf(
                    token_id_path.clone(),
                    asset.id().bytes().to_vec(),
                    asset.value().clone(),
                )?;
            }
        }

        // The source token's declared payment must match the requested assets.
        let payment_bytes = token
            .genesis()
            .transaction()
            .data()
            .ok_or(Error::UnexpectedValue("source token has no payment data"))?;
        let assets = decode_payment_data(payment_bytes)?;
        if trees.len() != assets.len() {
            return Err(Error::UnexpectedValue(
                "asset count does not match source payment",
            ));
        }

        // Finalize each asset tree, checking value conservation, and aggregate
        // the roots into a plain tree keyed by asset id.
        let mut aggregation_tree = SparseMerkleTree::new();
        let mut asset_tree_roots: Vec<(AssetId, crate::smt::sum::SparseMerkleSumTreeRootNode)> =
            Vec::new();
        for (asset_id, tree) in trees {
            let token_asset = assets
                .get(&asset_id)
                .ok_or(Error::UnexpectedValue("source payment missing an asset"))?;
            let root = tree.calculate_root();
            if root.value() != token_asset.value() {
                return Err(Error::UnexpectedValue(
                    "split asset total does not match source amount",
                ));
            }
            aggregation_tree.add_leaf(key_to_path(asset_id.bytes()), root.hash().imprint())?;
            asset_tree_roots.push((asset_id, root));
        }

        let aggregation_root = aggregation_tree.calculate_root();
        let burn_predicate = BurnPredicate::new(aggregation_root.hash().imprint());

        let mask = match burn_state_mask {
            Some(m) => m,
            None => random_mask()?,
        };
        let (source_state_hash, lock_script) = token.latest_state();
        let burn_transaction = TransferTransaction::new(
            source_state_hash,
            lock_script,
            burn_predicate.to_encoded(),
            mask.to_vec(),
            None,
        );

        // Build each output with its per-asset proofs.
        let mut tokens = Vec::new();
        for (request, _token_id, token_id_path) in entries {
            let mut proofs = Vec::new();
            for asset in request.assets.as_slice() {
                let (_, asset_root) = asset_tree_roots
                    .iter()
                    .find(|(id, _)| id == asset.id())
                    .expect("asset tree built for every requested asset");
                proofs.push(SplitAssetProof::new(
                    asset.id().clone(),
                    aggregation_root.get_path(&key_to_path(asset.id().bytes())),
                    asset_root.get_path(&token_id_path),
                ));
            }
            tokens.push(SplitToken {
                network_id,
                recipient: request.recipient,
                token_type: request.token_type,
                salt: request.salt,
                assets: request.assets,
                proofs,
            });
        }

        Ok(Split {
            burn: SplitBurn {
                owner_predicate: burn_predicate,
                transaction: burn_transaction,
            },
            tokens,
        })
    }
}

#[cfg(feature = "std")]
fn random_mask() -> Result<[u8; 32], Error> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Crypto("RNG failure"))?;
    Ok(bytes)
}

#[cfg(not(feature = "std"))]
fn random_mask() -> Result<[u8; 32], Error> {
    Err(Error::Crypto(
        "burn_state_mask must be supplied without the std RNG",
    ))
}
