//! Token mint (genesis) transaction.

use alloc::vec::Vec;

use super::ids::{MintTransactionState, TokenId, TokenSalt, TokenType};
use super::minter::Minter;
use super::Transaction;
use crate::api::network_id::NetworkId;
use crate::cbor::{
    encode_array, encode_byte_string, encode_nullable, encode_tag, encode_uint, Decoder,
};
use crate::crypto::hash::{sha256, DataHash};
use crate::error::Error;
use crate::predicate::builtin::SignaturePredicate;
use crate::predicate::EncodedPredicate;

/// CBOR tag for [`MintTransaction`].
pub const MINT_TRANSACTION_TAG: u64 = 39041;
const VERSION: u64 = 1;

/// A token mint transaction. The lock script, source (mint) state, and token id
/// are *derived* from the network id and salt — never taken from the wire — so
/// a forged genesis cannot claim someone else's token id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintTransaction {
    network_id: NetworkId,
    recipient: EncodedPredicate,
    salt: TokenSalt,
    token_type: TokenType,
    justification: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
    // Derived:
    token_id: TokenId,
    lock_script: EncodedPredicate,
    source_state: MintTransactionState,
}

impl MintTransaction {
    /// Build a mint transaction, deriving the token id, lock script, and mint
    /// state.
    pub fn create(
        network_id: NetworkId,
        recipient: EncodedPredicate,
        token_type: TokenType,
        salt: TokenSalt,
        data: Option<Vec<u8>>,
        justification: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        let token_id = TokenId::derive(network_id, &salt);
        let lock_script = SignaturePredicate::new(Minter::public_key(&token_id)?).to_encoded();
        let source_state = MintTransactionState::derive(&token_id);
        Ok(MintTransaction {
            network_id,
            recipient,
            salt,
            token_type,
            justification,
            data,
            token_id,
            lock_script,
            source_state,
        })
    }

    /// The network id.
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    /// The derived token id.
    pub fn token_id(&self) -> &TokenId {
        &self.token_id
    }
    /// The token type.
    pub fn token_type(&self) -> &TokenType {
        &self.token_type
    }
    /// The mint salt.
    pub fn salt(&self) -> &TokenSalt {
        &self.salt
    }
    /// Optional mint justification bytes.
    pub fn justification(&self) -> Option<&[u8]> {
        self.justification.as_deref()
    }
    /// Optional application data.
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// Decode from CBOR (tagged), re-deriving the lock script / mint state.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(MINT_TRANSACTION_TAG)?;
        let items = inner.array(Some(7))?;
        let version = items[0].uint()?;
        if version != VERSION {
            return Err(Error::UnexpectedValue(
                "unsupported MintTransaction version",
            ));
        }
        let network_id = NetworkId::new(
            u16::try_from(items[1].uint()?)
                .map_err(|_| Error::OutOfRange("network id exceeds 16 bits"))?,
        )?;
        let recipient = EncodedPredicate::from_cbor(items[2])?;
        let salt = TokenSalt::from_cbor(items[3])?;
        let token_type = TokenType::from_cbor(items[4])?;
        let justification =
            items[5].nullable(|d| d.bytes_value().map(|b| b.to_vec()).map_err(Into::into))?;
        let data =
            items[6].nullable(|d| d.bytes_value().map(|b| b.to_vec()).map_err(Into::into))?;
        MintTransaction::create(network_id, recipient, token_type, salt, data, justification)
    }
}

impl Transaction for MintTransaction {
    fn lock_script(&self) -> &EncodedPredicate {
        &self.lock_script
    }

    fn recipient(&self) -> &EncodedPredicate {
        &self.recipient
    }

    fn source_state_hash(&self) -> &DataHash {
        self.source_state.hash()
    }

    fn calculate_state_hash(&self) -> DataHash {
        // stateMask for a mint is the token id bytes.
        sha256(&encode_array(&[
            &encode_byte_string(&self.source_state.hash().imprint()),
            &encode_byte_string(self.token_id.bytes()),
        ]))
    }

    fn to_cbor(&self) -> Vec<u8> {
        encode_tag(
            MINT_TRANSACTION_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &encode_uint(self.network_id.id() as u64),
                &self.recipient.to_cbor(),
                &self.salt.to_cbor(),
                &self.token_type.to_cbor(),
                &encode_nullable(self.justification.as_ref(), |v| encode_byte_string(v)),
                &encode_nullable(self.data.as_ref(), |v| encode_byte_string(v)),
            ]),
        )
    }
}
