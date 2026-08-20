//! Token transfer transaction.
//!
//! `sourceStateHash` and `lockScript` are **not** serialized — they are
//! reconstructed from the previous transaction's resulting state and recipient
//! when a [`Token`](super::token::Token) is decoded. Decoding therefore *binds*
//! every transfer to its predecessor, which the verification engine then checks
//! against the certified state id (invariants I1/I2/I3).

use alloc::vec::Vec;

use super::Transaction;
use crate::cbor::{
    encode_array, encode_byte_string, encode_nullable, encode_tag, encode_uint, Decoder,
};
use crate::crypto::hash::{sha256, DataHash};
use crate::error::Error;
use crate::predicate::EncodedPredicate;

/// CBOR tag for [`TransferTransaction`].
pub const TRANSFER_TRANSACTION_TAG: u64 = 39045;
/// The only accepted wire version. One version, one element count.
pub const TRANSFER_TRANSACTION_VERSION: u64 = 2;
const FIELD_COUNT: usize = 5;

/// A token transfer transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferTransaction {
    // Reconstructed from the previous state:
    source_state_hash: DataHash,
    lock_script: EncodedPredicate,
    // On the wire:
    recipient: EncodedPredicate,
    expires_at: Option<u64>,
    state_mask: Vec<u8>,
    data: Option<Vec<u8>>,
}

impl TransferTransaction {
    /// Construct a transfer from explicit parts. `source_state_hash` and
    /// `lock_script` come from the previous transaction's resulting state /
    /// recipient.
    ///
    /// `expires_at` is the exclusive request deadline in Unix seconds, or
    /// `None` to let the Unicity Service assign one, which requires no local
    /// clock. Either way it is committed by the transaction hash.
    pub fn new(
        source_state_hash: DataHash,
        lock_script: EncodedPredicate,
        recipient: EncodedPredicate,
        state_mask: Vec<u8>,
        data: Option<Vec<u8>>,
        expires_at: Option<u64>,
    ) -> Self {
        TransferTransaction {
            source_state_hash,
            lock_script,
            recipient,
            expires_at,
            state_mask,
            data,
        }
    }

    /// The state mask mixed into the resulting state hash.
    pub fn state_mask(&self) -> &[u8] {
        &self.state_mask
    }

    /// Optional application data.
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// Decode from CBOR, supplying the previous state's hash and lock script
    /// (the previous recipient) for the reconstructed fields.
    pub fn from_cbor(
        d: Decoder<'_>,
        source_state_hash: DataHash,
        lock_script: EncodedPredicate,
    ) -> Result<Self, Error> {
        let inner = d.expect_tag(TRANSFER_TRANSACTION_TAG)?;
        let items = inner.array(Some(FIELD_COUNT))?;
        if items[0].uint()? != TRANSFER_TRANSACTION_VERSION {
            return Err(Error::UnexpectedValue(
                "unsupported TransferTransaction version",
            ));
        }
        let recipient = EncodedPredicate::from_cbor(items[1])?;
        let state_mask = items[2].bytes_value()?.to_vec();
        let data =
            items[3].nullable(|d| d.bytes_value().map(|b| b.to_vec()).map_err(Into::into))?;
        let expires_at = items[4].nullable(|d| d.uint().map_err(Into::into))?;
        Ok(TransferTransaction::new(
            source_state_hash,
            lock_script,
            recipient,
            state_mask,
            data,
            expires_at,
        ))
    }
}

impl Transaction for TransferTransaction {
    fn lock_script(&self) -> &EncodedPredicate {
        &self.lock_script
    }

    fn recipient(&self) -> &EncodedPredicate {
        &self.recipient
    }

    fn source_state_hash(&self) -> &DataHash {
        &self.source_state_hash
    }

    fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }

    fn calculate_state_hash(&self) -> DataHash {
        sha256(&encode_array(&[
            &encode_byte_string(&self.source_state_hash.imprint()),
            &encode_byte_string(&self.state_mask),
        ]))
    }

    fn to_cbor(&self) -> Vec<u8> {
        let payload = encode_array(&[
            &encode_uint(TRANSFER_TRANSACTION_VERSION),
            &self.recipient.to_cbor(),
            &encode_byte_string(&self.state_mask),
            &encode_nullable(self.data.as_ref(), |v| encode_byte_string(v)),
            &encode_nullable(self.expires_at.as_ref(), |v| encode_uint(*v)),
        ]);
        encode_tag(TRANSFER_TRANSACTION_TAG, &payload)
    }
}
