//! Unicity tree certificate (CBOR tag 39004) and its hash steps.

use alloc::vec::Vec;

use crate::cbor::{encode_array, encode_byte_string, encode_tag, encode_uint, Decoder};
use crate::error::Error;

/// CBOR tag for [`UnicityTreeCertificate`].
pub const UNICITY_TREE_CERTIFICATE_TAG: u64 = 39004;
const VERSION: u64 = 1;

/// A single step on the path from the partition leaf to the unicity-tree root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashStep {
    /// The sibling node's key.
    pub key: u32,
    /// The sibling node's hash.
    pub hash: Vec<u8>,
}

impl HashStep {
    fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let items = d.array(Some(2))?;
        Ok(HashStep {
            key: u32::try_from(items[0].uint()?)
                .map_err(|_| Error::OutOfRange("unicity tree step key exceeds 32 bits"))?,
            hash: items[1].bytes_value()?.to_vec(),
        })
    }

    fn to_cbor(&self) -> Vec<u8> {
        encode_array(&[
            &encode_uint(self.key as u64),
            &encode_byte_string(&self.hash),
        ])
    }
}

/// Proof folding the shard-tree root up to the unicity-tree root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicityTreeCertificate {
    /// Partition identifier (the leaf key).
    pub partition_identifier: u32,
    /// Steps up to the root.
    pub steps: Vec<HashStep>,
}

impl UnicityTreeCertificate {
    /// Decode from CBOR (tagged).
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(UNICITY_TREE_CERTIFICATE_TAG)?;
        let items = inner.array(Some(3))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue(
                "unsupported UnicityTreeCertificate version",
            ));
        }
        let partition_identifier = u32::try_from(items[1].uint()?)
            .map_err(|_| Error::OutOfRange("partition identifier exceeds 32 bits"))?;
        let mut steps = Vec::new();
        for s in items[2].array(None)? {
            steps.push(HashStep::from_cbor(s)?);
        }
        Ok(UnicityTreeCertificate {
            partition_identifier,
            steps,
        })
    }

    /// Encode to CBOR (tagged).
    pub fn to_cbor(&self) -> Vec<u8> {
        let steps: Vec<Vec<u8>> = self.steps.iter().map(|s| s.to_cbor()).collect();
        let step_refs: Vec<&[u8]> = steps.iter().map(|v| v.as_slice()).collect();
        encode_tag(
            UNICITY_TREE_CERTIFICATE_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_uint(self.partition_identifier as u64),
                &encode_array(&step_refs),
            ]),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_partition_and_step_keys_above_u32() {
        let oversized = encode_uint(u32::MAX as u64 + 1);
        let certificate = encode_tag(
            UNICITY_TREE_CERTIFICATE_TAG,
            &encode_array(&[&encode_uint(VERSION), &oversized, &encode_array(&[])]),
        );
        assert!(UnicityTreeCertificate::from_cbor(Decoder::new(&certificate)).is_err());

        let step = encode_array(&[&oversized, &encode_byte_string(&[0u8; 32])]);
        let certificate = encode_tag(
            UNICITY_TREE_CERTIFICATE_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_uint(1),
                &encode_array(&[&step]),
            ]),
        );
        assert!(UnicityTreeCertificate::from_cbor(Decoder::new(&certificate)).is_err());
    }
}
