//! Certification data: the payload an aggregator certifies for a state
//! transition, and what an [`InclusionProof`](super::inclusion_proof) carries
//! back to bind a proof to a specific transaction.

use alloc::vec::Vec;

use crate::cbor::{encode_array, encode_byte_string, encode_tag, encode_uint, Decoder};
use crate::crypto::hash::{DataHash, HashAlgorithm};
use crate::error::Error;
use crate::predicate::EncodedPredicate;
use crate::transaction::Transaction;

/// CBOR tag for [`CertificationData`].
pub const CERTIFICATION_DATA_TAG: u64 = 39031;
const VERSION: u64 = 1;

/// What the aggregator certified for one state transition.
///
/// Holds the lock script and source-state hash (so a proof can be tied back to
/// a transaction), the transaction hash (the certified value), and the unlock
/// script (the witness satisfying the lock script).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificationData {
    lock_script: EncodedPredicate,
    source_state_hash: DataHash,
    transaction_hash: DataHash,
    unlock_script: Vec<u8>,
}

impl CertificationData {
    /// Construct from parts.
    pub fn new(
        lock_script: EncodedPredicate,
        source_state_hash: DataHash,
        transaction_hash: DataHash,
        unlock_script: Vec<u8>,
    ) -> Self {
        CertificationData {
            lock_script,
            source_state_hash,
            transaction_hash,
            unlock_script,
        }
    }

    /// Build from a transaction and an unlock script, computing the
    /// transaction hash.
    pub fn from_transaction(transaction: &impl Transaction, unlock_script: Vec<u8>) -> Self {
        CertificationData {
            lock_script: transaction.lock_script().clone(),
            source_state_hash: transaction.source_state_hash().clone(),
            transaction_hash: transaction.calculate_transaction_hash(),
            unlock_script,
        }
    }

    /// The lock script the unlock script must satisfy.
    pub fn lock_script(&self) -> &EncodedPredicate {
        &self.lock_script
    }
    /// The source state hash.
    pub fn source_state_hash(&self) -> &DataHash {
        &self.source_state_hash
    }
    /// The certified transaction hash.
    pub fn transaction_hash(&self) -> &DataHash {
        &self.transaction_hash
    }
    /// The unlock script (witness).
    pub fn unlock_script(&self) -> &[u8] {
        &self.unlock_script
    }

    /// Encode to CBOR (tagged). Hashes are encoded as their raw 32-byte data.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_tag(
            CERTIFICATION_DATA_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &self.lock_script.to_cbor(),
                &encode_byte_string(self.source_state_hash.data()),
                &encode_byte_string(self.transaction_hash.data()),
                &encode_byte_string(&self.unlock_script),
            ]),
        )
    }

    /// Decode from CBOR. The reference SDKs always store SHA-256 hashes here.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(CERTIFICATION_DATA_TAG)?;
        let items = inner.array(Some(5))?;
        let version = items[0].uint()?;
        if version != VERSION {
            return Err(Error::UnexpectedValue(
                "unsupported CertificationData version",
            ));
        }
        Ok(CertificationData {
            lock_script: EncodedPredicate::from_cbor(items[1])?,
            source_state_hash: DataHash::new(HashAlgorithm::Sha256, items[2].bytes_value()?)?,
            transaction_hash: DataHash::new(HashAlgorithm::Sha256, items[3].bytes_value()?)?,
            unlock_script: items[4].bytes_value()?.to_vec(),
        })
    }
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use crate::api::network_id::NetworkId;
    use crate::crypto::signature::PublicKey;
    use crate::predicate::builtin::SignaturePredicate;
    use crate::predicate::unlock::sign_signature_unlock;
    use crate::transaction::ids::{TokenSalt, TokenType};
    use crate::transaction::{MintTransaction, Minter};
    use hex_literal::hex;

    // Golden vector from state-transition-sdk-js CertificationDataTest.ts.
    // Both SDKs use RFC 6979 deterministic ECDSA, so the unlock signature must
    // also match byte-for-byte.
    #[test]
    fn certification_data_golden_vector() {
        let recipient = SignaturePredicate::new(
            PublicKey::from_bytes(&hex!(
                "02ce9f22e51333c97a8fb1f807a229ece3a8765a16af5fc1a13e30834be3280026"
            ))
            .unwrap(),
        )
        .to_encoded();

        let mint = MintTransaction::create(
            NetworkId::MAINNET,
            recipient,
            TokenType::new([0u8; 32]),
            TokenSalt::from_bytes([0u8; 32]),
            None,
            None,
        )
        .unwrap();

        let signer = Minter::signer(mint.token_id()).unwrap();
        let tx_hash = mint.calculate_transaction_hash();
        let unlock = sign_signature_unlock(&signer, mint.source_state_hash(), &tx_hash);

        let cert = CertificationData::from_transaction(&mint, unlock);

        assert_eq!(
            cert.to_cbor(),
            hex!(
                "d998778501d9987883014101582103a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f9635075820e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e6152415820df524cffc08a1dc30579a8a51f440a97b30630988084f8d12a4d8bd741c7791258419efb637f14dbdaada6e293e2182932d82265b04b1abf4f28bc4c285b32b5e2325140fe7f94bc9b705c568b4fcb7f9ea90cf0fadcacc1b4504275f81558aad1e700"
            )
        );

        // Round-trips back to an equal structure.
        let encoded = cert.to_cbor();
        assert_eq!(
            CertificationData::from_cbor(Decoder::new(&encoded)).unwrap(),
            cert
        );
    }
}
