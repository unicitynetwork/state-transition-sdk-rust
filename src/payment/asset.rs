//! The fungible payload a token carries: an [`Asset`] is an amount tagged with
//! an [`AssetId`], and a [`PaymentAssetCollection`] is the canonical set of them.
//!
//! This module implements the yellowpaper `Assets(ty, auxd')` function for the
//! default payload form (the mint `data` is exactly the encoded collection): the
//! decoded collection is non-empty, holds at most 256 distinct assets in strict
//! canonical asset-id order, with every amount in `1..2^256`. A payload with a
//! zero amount, a duplicate or out-of-order id, or an empty id is **rejected**,
//! never normalized — split verification associates proofs with assets purely by
//! this canonical order.

use alloc::vec::Vec;

use num_bigint::BigUint;

use crate::cbor::{encode_array, encode_byte_string, Decoder};
use crate::error::{CborError, Error};
use crate::rsmst::{decode_positive_amount, encode_amount, AMOUNT_MAX_BYTES};

/// Maximum encoded asset identifier length accepted by the payment protocol.
pub const MAX_ASSET_ID_BYTES: usize = 128;
/// Maximum encoded asset amount length (256 bits).
pub const MAX_ASSET_VALUE_BYTES: usize = AMOUNT_MAX_BYTES;
/// Maximum number of distinct assets carried by one token.
pub const MAX_PAYMENT_ASSETS: usize = 256;

/// Unsigned lexicographic comparison with a shorter byte string ordered first
/// when it is a prefix of another. This is the canonical asset-id ordering.
fn canonical_cmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let common = a.len().min(b.len());
    match a[..common].cmp(&b[..common]) {
        core::cmp::Ordering::Equal => a.len().cmp(&b.len()),
        other => other,
    }
}

/// Identifier of an asset class: 1..=128 opaque bytes.
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

    /// CBOR byte string.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_byte_string(&self.0)
    }

    /// Decode from a CBOR byte string, enforcing the non-empty / length bounds.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let bytes = d.bytes_value()?;
        if bytes.is_empty() {
            return Err(Error::OutOfRange("asset id must be non-empty"));
        }
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

/// An [`AssetId`] paired with a strictly positive amount (`1 <= v < 2^256`).
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

    /// The amount held.
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Decode from CBOR: `[bstr(id), bstr(value)]` with a positive minimal value.
    fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(Some(2))?;
        let id = AssetId::from_cbor(items[0])?;
        let value = decode_positive_amount(items[1].bytes_value()?)?;
        Ok(Asset { id, value })
    }

    /// Encode to CBOR: `[bstr(id), bstr(value)]`.
    fn to_cbor(&self) -> Vec<u8> {
        encode_array(&[&self.id.to_cbor(), &encode_byte_string(&encode_amount(&self.value))])
    }
}

/// A canonical, id-ordered collection of [`Asset`]s — the result of the
/// `Assets(ty, auxd')` function. Always non-empty, at most 256 assets, distinct
/// ids in strict canonical order, every amount positive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentAssetCollection {
    assets: Vec<Asset>,
}

impl PaymentAssetCollection {
    /// Build a collection from arbitrary-order assets, validating every field
    /// and canonicalizing the order. Rejects an empty input, a duplicate id, an
    /// over-long id, or a non-positive / over-256-bit amount.
    pub fn create(assets: impl IntoIterator<Item = Asset>) -> Result<Self, Error> {
        let mut out: Vec<Asset> = assets.into_iter().collect();
        if out.is_empty() {
            return Err(Error::OutOfRange("payment collection must be non-empty"));
        }
        if out.len() > MAX_PAYMENT_ASSETS {
            return Err(Error::OutOfRange(
                "payment asset count exceeds protocol limit",
            ));
        }
        for asset in &out {
            if asset.id.0.is_empty() {
                return Err(Error::OutOfRange("asset id must be non-empty"));
            }
            if asset.id.0.len() > MAX_ASSET_ID_BYTES {
                return Err(Error::OutOfRange("asset id exceeds protocol limit"));
            }
            if asset.value == BigUint::ZERO {
                return Err(Error::OutOfRange("asset amount must be positive"));
            }
            if asset.value.bits() > 256 {
                return Err(Error::OutOfRange("asset amount exceeds 256 bits"));
            }
        }
        out.sort_by(|a, b| canonical_cmp(a.id.bytes(), b.id.bytes()));
        if out.windows(2).any(|w| w[0].id == w[1].id) {
            return Err(Error::UnexpectedValue(
                "duplicate asset id in payment collection",
            ));
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

    /// Always `false` (a collection is never empty); present for lint parity.
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    /// The assets in canonical id order.
    pub fn as_slice(&self) -> &[Asset] {
        &self.assets
    }

    /// Decode the `Assets` function from CBOR: `[asset...]` in strict canonical
    /// order. Rejects an empty array, more than 256 assets, a non-canonical or
    /// duplicate id ordering, an empty id, or a non-positive amount.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(None)?;
        if items.is_empty() {
            return Err(Error::OutOfRange("payment collection must be non-empty"));
        }
        if items.len() > MAX_PAYMENT_ASSETS {
            return Err(Error::OutOfRange(
                "payment asset count exceeds protocol limit",
            ));
        }
        let mut assets: Vec<Asset> = Vec::with_capacity(items.len());
        for item in items {
            let asset = Asset::from_cbor(item)?;
            if let Some(previous) = assets.last() {
                match canonical_cmp(previous.id.bytes(), asset.id.bytes()) {
                    core::cmp::Ordering::Less => {}
                    core::cmp::Ordering::Equal => {
                        return Err(Error::UnexpectedValue("duplicate asset id"))
                    }
                    core::cmp::Ordering::Greater => {
                        return Err(CborError::NonCanonicalEncoding.into())
                    }
                }
            }
            assets.push(asset);
        }
        Ok(PaymentAssetCollection { assets })
    }

    /// Decode directly from CBOR bytes (the default payload form, where a token's
    /// mint `data` is exactly the encoded collection).
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let d = Decoder::new(bytes);
        d.finish()?;
        Self::from_cbor(d)
    }

    /// Encode to CBOR: `[asset...]` in canonical order.
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
    fn payment_decoder_rejects_zero_amount() {
        let asset = encode_array(&[&encode_byte_string(b"USD"), &encode_byte_string(&[])]);
        let payment = encode_array(&[&asset]);
        assert!(PaymentAssetCollection::from_cbor_bytes(&payment).is_err());
    }

    #[test]
    fn payment_decoder_rejects_non_canonical_order() {
        let a = encode_array(&[&encode_byte_string(b"USD"), &encode_byte_string(&[1])]);
        let b = encode_array(&[&encode_byte_string(b"EUR"), &encode_byte_string(&[1])]);
        // USD before EUR is not canonical.
        let payment = encode_array(&[&a, &b]);
        assert_eq!(
            PaymentAssetCollection::from_cbor_bytes(&payment),
            Err(Error::Cbor(CborError::NonCanonicalEncoding))
        );
    }

    #[test]
    fn create_canonicalizes_order_and_roundtrips() {
        let collection = PaymentAssetCollection::create([
            Asset::new(AssetId::new(b"USD".to_vec()), BigUint::from(2u32)),
            Asset::new(AssetId::new(b"EUR".to_vec()), BigUint::from(1u32)),
        ])
        .unwrap();
        assert_eq!(collection.as_slice()[0].id().bytes(), b"EUR");
        let bytes = collection.to_cbor();
        assert_eq!(
            PaymentAssetCollection::from_cbor_bytes(&bytes).unwrap(),
            collection
        );
    }

    #[test]
    fn create_enforces_semantic_limits() {
        let oversized_id = AssetId::new(alloc::vec![0; MAX_ASSET_ID_BYTES + 1]);
        assert!(
            PaymentAssetCollection::create([Asset::new(oversized_id, BigUint::from(1u8))]).is_err()
        );

        let oversized_value = BigUint::from(1u8) << (MAX_ASSET_VALUE_BYTES * 8);
        assert!(PaymentAssetCollection::create([Asset::new(
            AssetId::new(b"USD".to_vec()),
            oversized_value,
        )])
        .is_err());

        assert!(PaymentAssetCollection::create([Asset::new(
            AssetId::new(b"USD".to_vec()),
            BigUint::ZERO,
        )])
        .is_err());

        assert!(PaymentAssetCollection::create([]).is_err());
    }
}
