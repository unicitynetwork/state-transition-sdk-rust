//! Assets: a fungible value tagged with an [`AssetId`], and the payment
//! collection a token carries. Mirrors `payment/asset/*` in the reference SDKs.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use num_bigint::BigUint;

use crate::cbor::{encode_array, encode_byte_string, Decoder};
use crate::error::Error;
use crate::smt::bigint::{bytes_to_path, key_to_path, path_to_bytes};

/// Maximum encoded asset identifier length accepted by the payment protocol.
pub const MAX_ASSET_ID_BYTES: usize = 128;
/// Maximum encoded asset amount length (256 bits).
pub const MAX_ASSET_VALUE_BYTES: usize = 32;
/// Maximum number of distinct assets carried by one token.
pub const MAX_PAYMENT_ASSETS: usize = 256;

/// Identifier of an asset class. Arbitrary-length opaque bytes; routes a sum
/// tree in the aggregation tree of a split.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AssetId(Vec<u8>);

impl AssetId {
    /// Wrap raw bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        AssetId(bytes.into())
    }

    /// The raw id bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// The sparse-Merkle routing path of this id (`0x01 ‖ bytes` big-endian).
    pub fn to_path(&self) -> BigUint {
        key_to_path(&self.0)
    }

    /// CBOR byte string.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_byte_string(&self.0)
    }

    /// Decode from a CBOR byte string.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let bytes = d.bytes_value()?;
        if bytes.len() > MAX_ASSET_ID_BYTES {
            return Err(Error::OutOfRange("asset id exceeds protocol limit"));
        }
        Ok(AssetId(bytes.to_vec()))
    }
}

impl core::fmt::Debug for AssetId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AssetId({})", hex::encode(&self.0))
    }
}

/// An [`AssetId`] paired with a non-negative value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    id: AssetId,
    value: BigUint,
}

impl Asset {
    /// Construct an asset.
    pub fn new(id: AssetId, value: BigUint) -> Self {
        Asset { id, value }
    }

    /// The asset id.
    pub fn id(&self) -> &AssetId {
        &self.id
    }

    /// The value held.
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Decode from CBOR: `[bstr(id), bstr(value)]`.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(Some(2))?;
        let id = AssetId::from_cbor(items[0])?;
        let value_bytes = items[1].bytes_value()?;
        if value_bytes.len() > MAX_ASSET_VALUE_BYTES {
            return Err(Error::OutOfRange("asset value exceeds 256 bits"));
        }
        let value = bytes_to_path(value_bytes)?;
        Ok(Asset { id, value })
    }

    /// Encode to CBOR: `[bstr(id), bstr(value)]`.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_array(&[
            &self.id.to_cbor(),
            &encode_byte_string(&path_to_bytes(&self.value)),
        ])
    }
}

/// An id-keyed collection of [`Asset`]s, preserving insertion order. Duplicate
/// asset ids are rejected at construction.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PaymentAssetCollection {
    assets: Vec<Asset>,
}

impl PaymentAssetCollection {
    /// Build a collection, rejecting duplicate asset ids.
    pub fn create(assets: impl IntoIterator<Item = Asset>) -> Result<Self, Error> {
        let mut out: Vec<Asset> = Vec::new();
        let mut ids = BTreeSet::new();
        for asset in assets {
            if out.len() == MAX_PAYMENT_ASSETS {
                return Err(Error::OutOfRange(
                    "payment asset count exceeds protocol limit",
                ));
            }
            if asset.id.bytes().len() > MAX_ASSET_ID_BYTES {
                return Err(Error::OutOfRange("asset id exceeds protocol limit"));
            }
            if asset.value.to_bytes_be().len() > MAX_ASSET_VALUE_BYTES {
                return Err(Error::OutOfRange("asset value exceeds 256 bits"));
            }
            if !ids.insert(asset.id.bytes().to_vec()) {
                return Err(Error::UnexpectedValue(
                    "duplicate asset id in payment collection",
                ));
            }
            out.push(asset);
        }
        Ok(PaymentAssetCollection { assets: out })
    }

    /// Look up an asset by id.
    pub fn get(&self, id: &AssetId) -> Option<&Asset> {
        self.assets.iter().find(|a| &a.id == id)
    }

    /// The number of assets.
    pub fn len(&self) -> usize {
        self.assets.len()
    }

    /// Whether the collection contains no assets.
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    /// The assets in insertion order.
    pub fn as_slice(&self) -> &[Asset] {
        &self.assets
    }

    /// Decode from CBOR: `[asset...]`.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(None)?;
        if items.len() > MAX_PAYMENT_ASSETS {
            return Err(Error::OutOfRange(
                "payment asset count exceeds protocol limit",
            ));
        }
        let mut assets = Vec::new();
        for asset in items {
            assets.push(Asset::from_cbor(asset)?);
        }
        PaymentAssetCollection::create(assets)
    }

    /// Decode directly from CBOR bytes (the default payment-data form, where a
    /// token's mint `data` is exactly the encoded collection).
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_cbor(Decoder::new(bytes))
    }

    /// Encode to CBOR: `[asset...]`.
    pub fn to_cbor(&self) -> Vec<u8> {
        let parts: Vec<Vec<u8>> = self.assets.iter().map(Asset::to_cbor).collect();
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        encode_array(&refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{encode_array, encode_byte_string};
    use crate::error::{CborError, Error};

    #[test]
    fn payment_decoder_rejects_non_minimal_amount() {
        let asset = encode_array(&[&encode_byte_string(b"USD"), &encode_byte_string(&[0, 1])]);
        let payment = encode_array(&[&asset]);
        assert_eq!(
            PaymentAssetCollection::from_cbor_bytes(&payment),
            Err(Error::Cbor(CborError::NonCanonicalEncoding))
        );
    }

    #[test]
    fn payment_collection_enforces_semantic_limits() {
        let oversized_id = AssetId::new(alloc::vec![0; MAX_ASSET_ID_BYTES + 1]);
        assert!(PaymentAssetCollection::create([Asset::new(oversized_id, BigUint::ZERO)]).is_err());

        let oversized_value = BigUint::from(1u8) << (MAX_ASSET_VALUE_BYTES * 8);
        assert!(PaymentAssetCollection::create([Asset::new(
            AssetId::new(b"USD".to_vec()),
            oversized_value,
        )])
        .is_err());
    }
}
