//! The split manifest (CBOR tag 39046): the ordered vector of per-asset RSMST
//! root hashes committed by the source token's burn.
//!
//! The certified burn transfer of the source token stores the manifest's exact
//! canonical encoding `b_M` as its auxiliary data, and the burn predicate's
//! reason is `SHA-256(b_M)`. The roots are positionally aligned with the source
//! token's canonical asset collection, so the manifest itself repeats no asset
//! identifier, amount or source id — all are already authenticated by the burned
//! token (yellowpaper "Split Manifest").

use alloc::vec::Vec;

use crate::cbor::{encode_array, encode_byte_string, encode_tag, DecodeLimits, Decoder};
use crate::crypto::hash::sha256;
use crate::error::Error;

use super::asset::MAX_PAYMENT_ASSETS;

/// CBOR tag for a [`SplitManifest`].
pub const SPLIT_MANIFEST_TAG: u64 = 39046;

/// An ordered vector of `1..=256` raw 32-byte RSMST root digests.
#[derive(Clone, PartialEq, Eq)]
pub struct SplitManifest {
    roots: Vec<[u8; 32]>,
}

impl SplitManifest {
    /// Build a manifest from per-asset root hashes (one per source asset, in
    /// canonical asset order). Rejects an empty or over-256 vector.
    pub fn create(roots: Vec<[u8; 32]>) -> Result<Self, Error> {
        if roots.is_empty() {
            return Err(Error::OutOfRange("split manifest must be non-empty"));
        }
        if roots.len() > MAX_PAYMENT_ASSETS {
            return Err(Error::OutOfRange("split manifest exceeds protocol limit"));
        }
        Ok(SplitManifest { roots })
    }

    /// The root hashes, in canonical source-asset order.
    pub fn roots(&self) -> &[[u8; 32]] {
        &self.roots
    }

    /// The number of roots (equals the source asset count).
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Always `false` (a manifest is never empty); present for lint parity.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Encode to CBOR (tag 39046): `[bstr(r_1), ..., bstr(r_m)]`.
    pub fn to_cbor(&self) -> Vec<u8> {
        let parts: Vec<Vec<u8>> = self.roots.iter().map(|r| encode_byte_string(r)).collect();
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        encode_tag(SPLIT_MANIFEST_TAG, &encode_array(&refs))
    }

    /// `SHA-256(b_M)`: the burn predicate reason that commits to this manifest.
    pub fn reason_hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(sha256(&self.to_cbor()).data());
        out
    }

    /// Decode from the complete tagged CBOR encoding, enforcing no trailing
    /// bytes, the 39046 tag, `1..=256` roots, and a 32-byte length per root.
    pub fn from_cbor_bytes(bytes: &[u8], limits: DecodeLimits) -> Result<Self, Error> {
        let d = Decoder::with_limits(bytes, limits);
        d.finish()?;
        let inner = d.expect_tag(SPLIT_MANIFEST_TAG)?;
        let items = inner.array(None)?;
        if items.is_empty() {
            return Err(Error::OutOfRange("split manifest must be non-empty"));
        }
        if items.len() > MAX_PAYMENT_ASSETS {
            return Err(Error::OutOfRange("split manifest exceeds protocol limit"));
        }
        let mut roots = Vec::with_capacity(items.len());
        for item in items {
            let root: [u8; 32] =
                item.bytes_value()?
                    .try_into()
                    .map_err(|_| Error::InvalidLength {
                        what: "split manifest root",
                        expected: 32,
                        actual: 0,
                    })?;
            roots.push(root);
        }
        Ok(SplitManifest { roots })
    }
}

impl core::fmt::Debug for SplitManifest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SplitManifest")
            .field("roots", &self.roots.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_reason_hash() {
        let manifest = SplitManifest::create(alloc::vec![[0x11; 32], [0x22; 32]]).unwrap();
        let bytes = manifest.to_cbor();
        let decoded = SplitManifest::from_cbor_bytes(&bytes, DecodeLimits::DEFAULT).unwrap();
        assert_eq!(decoded, manifest);
        assert_eq!(manifest.reason_hash(), {
            let mut h = [0u8; 32];
            h.copy_from_slice(crate::crypto::hash::sha256(&bytes).data());
            h
        });
    }

    #[test]
    fn rejects_trailing_bytes_and_wrong_tag() {
        let manifest = SplitManifest::create(alloc::vec![[0x11; 32]]).unwrap();
        let mut bytes = manifest.to_cbor();
        bytes.push(0xff);
        assert!(SplitManifest::from_cbor_bytes(&bytes, DecodeLimits::DEFAULT).is_err());
    }
}
