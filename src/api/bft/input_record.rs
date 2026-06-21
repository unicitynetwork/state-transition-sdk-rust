//! Input record (CBOR tag 39002) — the per-block commitment whose `hash` is the
//! SMT root an inclusion certificate proves against.

use alloc::vec::Vec;

use crate::cbor::{
    encode_array, encode_byte_string, encode_nullable, encode_tag, encode_uint, Decoder,
};
use crate::error::Error;

/// CBOR tag for [`InputRecord`].
pub const INPUT_RECORD_TAG: u64 = 39002;
const VERSION: u64 = 1;

/// Input record carried inside a [`UnicityCertificate`](super::UnicityCertificate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRecord {
    /// Round number.
    pub round_number: u64,
    /// Epoch number.
    pub epoch: u64,
    /// Previous block hash.
    pub previous_hash: Option<Vec<u8>>,
    /// This block's state-tree root hash (the inclusion-proof root).
    pub hash: Vec<u8>,
    /// Summary value.
    pub summary_value: Vec<u8>,
    /// Timestamp.
    pub timestamp: u64,
    /// Block hash.
    pub block_hash: Option<Vec<u8>>,
    /// Sum of earned fees.
    pub sum_of_earned_fees: u64,
    /// Executed transactions hash.
    pub executed_transactions_hash: Option<Vec<u8>>,
}

impl InputRecord {
    /// Decode from CBOR (tagged).
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(INPUT_RECORD_TAG)?;
        let items = inner.array(Some(10))?;
        if items[0].uint()? != VERSION {
            return Err(Error::UnexpectedValue("unsupported InputRecord version"));
        }
        let opt = |d: Decoder<'_>| {
            d.nullable(|x| x.bytes_value().map(|b| b.to_vec()).map_err(Into::into))
        };
        Ok(InputRecord {
            round_number: items[1].uint()?,
            epoch: items[2].uint()?,
            previous_hash: opt(items[3])?,
            hash: items[4].bytes_value()?.to_vec(),
            summary_value: items[5].bytes_value()?.to_vec(),
            timestamp: items[6].uint()?,
            block_hash: opt(items[7])?,
            sum_of_earned_fees: items[8].uint()?,
            executed_transactions_hash: opt(items[9])?,
        })
    }

    /// Encode to CBOR (tagged).
    pub fn to_cbor(&self) -> Vec<u8> {
        let bs = |v: &Vec<u8>| encode_byte_string(v);
        encode_tag(
            INPUT_RECORD_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_uint(self.round_number),
                &encode_uint(self.epoch),
                &encode_nullable(self.previous_hash.as_ref(), bs),
                &encode_byte_string(&self.hash),
                &encode_byte_string(&self.summary_value),
                &encode_uint(self.timestamp),
                &encode_nullable(self.block_hash.as_ref(), bs),
                &encode_uint(self.sum_of_earned_fees),
                &encode_nullable(self.executed_transactions_hash.as_ref(), bs),
            ]),
        )
    }
}
