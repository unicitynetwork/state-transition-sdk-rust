//! [`SplitAssetProof`]: proves one asset's contribution to a split, by an
//! aggregation-tree path (asset id → asset-tree root) and an asset-tree path
//! (new token id → amount).

use alloc::vec::Vec;

use super::asset::AssetId;
use crate::cbor::{encode_array, Decoder};
use crate::error::Error;
use crate::smt::plain::SparseMerkleTreePath;
use crate::smt::sum::SparseMerkleSumTreePath;

/// Inclusion proof for a single asset within a split payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitAssetProof {
    asset_id: AssetId,
    aggregation_path: SparseMerkleTreePath,
    asset_tree_path: SparseMerkleSumTreePath,
}

impl SplitAssetProof {
    /// Construct from its parts.
    pub fn new(
        asset_id: AssetId,
        aggregation_path: SparseMerkleTreePath,
        asset_tree_path: SparseMerkleSumTreePath,
    ) -> Self {
        SplitAssetProof {
            asset_id,
            aggregation_path,
            asset_tree_path,
        }
    }

    /// The asset id this proof is for.
    pub fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    /// Path through the aggregation tree (asset id → asset-tree root).
    pub fn aggregation_path(&self) -> &SparseMerkleTreePath {
        &self.aggregation_path
    }

    /// Path through this asset's sum tree (new token id → amount).
    pub fn asset_tree_path(&self) -> &SparseMerkleSumTreePath {
        &self.asset_tree_path
    }

    /// Decode from CBOR: `[bstr(assetId), aggregationPath, assetTreePath]`.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(Some(3))?;
        Ok(SplitAssetProof {
            asset_id: AssetId::from_cbor(items[0])?,
            aggregation_path: SparseMerkleTreePath::from_cbor(items[1])?,
            asset_tree_path: SparseMerkleSumTreePath::from_cbor(items[2])?,
        })
    }

    /// Encode to CBOR: `[bstr(assetId), aggregationPath, assetTreePath]`.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_array(&[
            &self.asset_id.to_cbor(),
            &self.aggregation_path.to_cbor(),
            &self.asset_tree_path.to_cbor(),
        ])
    }
}
