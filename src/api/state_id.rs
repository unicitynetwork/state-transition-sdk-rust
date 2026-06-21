//! State identifier: the SMT key under which a state's transaction is certified.

use alloc::vec::Vec;

use crate::cbor::{encode_array, encode_byte_string, Decoder};
use crate::crypto::hash::{sha256, DataHash};
use crate::error::Error;
use crate::predicate::EncodedPredicate;

/// Unique identifier of a token state:
/// `H(array[lockScript.toCBOR(), bstr(sourceStateHash.data)])`.
///
/// Note this hashes the source state hash's **raw 32-byte data**, not its
/// imprint — an intentional asymmetry with the state-hash preimage.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct StateId([u8; 32]);

impl StateId {
    /// Derive from a lock script and source state hash.
    pub fn derive(lock_script: &EncodedPredicate, source_state_hash: &DataHash) -> Self {
        let hash = sha256(&encode_array(&[
            &lock_script.to_cbor(),
            &encode_byte_string(source_state_hash.data()),
        ]));
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.data());
        StateId(out)
    }

    /// The 32 id bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// CBOR byte string of the id.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_byte_string(&self.0)
    }

    /// Decode from a CBOR byte string.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let bytes = d.bytes_value()?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidLength {
            what: "StateId",
            expected: 32,
            actual: bytes.len(),
        })?;
        Ok(StateId(arr))
    }
}

impl core::fmt::Debug for StateId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "StateId({})", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::network_id::NetworkId;
    use crate::predicate::builtin::SignaturePredicate;
    use crate::transaction::ids::{MintTransactionState, TokenId, TokenSalt};
    use crate::transaction::minter::Minter;
    use hex_literal::hex;

    // Golden vector from state-transition-sdk-js StateIdTest.ts:
    // a mint of network MAINNET, token type/salt = 32 zero bytes, recipient
    // SignaturePredicate(02ce9f...0026). StateId is taken from the *mint*
    // transaction (lock script = minter key, source state = mint state).
    #[test]
    fn state_id_golden_vector() {
        let salt = TokenSalt::from_bytes([0u8; 32]);
        let token_id = TokenId::derive(NetworkId::MAINNET, &salt);

        let lock_script =
            SignaturePredicate::new(Minter::public_key(&token_id).unwrap()).to_encoded();
        let source_state = MintTransactionState::derive(&token_id);

        let state_id = StateId::derive(&lock_script, source_state.hash());

        assert_eq!(
            state_id.to_cbor(),
            hex!("5820ffb36b55de9bfaf48b766d1f4e041a6c5d35ba23b402ea2a56a6c7692cb8f81a")
        );
    }
}
