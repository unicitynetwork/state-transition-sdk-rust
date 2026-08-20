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
const LEGACY_VERSION: u64 = 1;
const TIMEOUT_VERSION: u64 = 2;

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
    timeout: Option<u64>,
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
            timeout: None,
            unlock_script,
        }
    }

    /// Construct certification data with an explicit exclusive request timeout.
    pub fn new_with_timeout(
        lock_script: EncodedPredicate,
        source_state_hash: DataHash,
        transaction_hash: DataHash,
        timeout: u64,
        unlock_script: Vec<u8>,
    ) -> Self {
        let mut data = Self::new(
            lock_script,
            source_state_hash,
            transaction_hash,
            unlock_script,
        );
        data.timeout = Some(timeout);
        data
    }

    /// Build from a transaction and an unlock script, computing the
    /// transaction hash.
    pub fn from_transaction(transaction: &impl Transaction, unlock_script: Vec<u8>) -> Self {
        CertificationData {
            lock_script: transaction.lock_script().clone(),
            source_state_hash: transaction.source_state_hash().clone(),
            transaction_hash: transaction.calculate_transaction_hash(),
            timeout: transaction.timeout(),
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
    /// The exclusive timeout of the certification request.
    pub fn timeout(&self) -> Option<u64> {
        self.timeout
    }
    /// The unlock script (witness).
    pub fn unlock_script(&self) -> &[u8] {
        &self.unlock_script
    }

    /// Encode to CBOR (tagged). Hashes are encoded as their raw 32-byte data.
    pub fn to_cbor(&self) -> Vec<u8> {
        let payload = if let Some(timeout) = self.timeout {
            encode_array(&[
                &encode_uint(TIMEOUT_VERSION),
                &self.lock_script.to_cbor(),
                &encode_byte_string(self.source_state_hash.data()),
                &encode_byte_string(self.transaction_hash.data()),
                &encode_uint(timeout),
                &encode_byte_string(&self.unlock_script),
            ])
        } else {
            encode_array(&[
                &encode_uint(LEGACY_VERSION),
                &self.lock_script.to_cbor(),
                &encode_byte_string(self.source_state_hash.data()),
                &encode_byte_string(self.transaction_hash.data()),
                &encode_byte_string(&self.unlock_script),
            ])
        };
        encode_tag(CERTIFICATION_DATA_TAG, &payload)
    }

    /// Decode from CBOR. The reference SDKs always store SHA-256 hashes here.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(CERTIFICATION_DATA_TAG)?;
        let items = inner.array(None)?;
        let version = items[0].uint()?;
        let has_timeout = version == TIMEOUT_VERSION;
        if (version != LEGACY_VERSION && version != TIMEOUT_VERSION)
            || items.len() != if has_timeout { 6 } else { 5 }
        {
            return Err(Error::UnexpectedValue(
                "unsupported CertificationData version",
            ));
        }
        Ok(CertificationData {
            lock_script: EncodedPredicate::from_cbor(items[1])?,
            source_state_hash: DataHash::new(HashAlgorithm::Sha256, items[2].bytes_value()?)?,
            transaction_hash: DataHash::new(HashAlgorithm::Sha256, items[3].bytes_value()?)?,
            timeout: if has_timeout {
                Some(items[4].uint()?)
            } else {
                None
            },
            unlock_script: items[if has_timeout { 5 } else { 4 }]
                .bytes_value()?
                .to_vec(),
        })
    }
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;

    /// Exclusive certification request timeout used by the golden vector.
    const TIMEOUT: u64 = 1755000000;
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

        let mint = MintTransaction::create_with_timeout(
            NetworkId::MAINNET,
            recipient,
            TIMEOUT,
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
                "d998778602d9987883014101582103a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f9635075820e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e6152415820ed275ff0a0694d1b61ec22f13914a431569220ba7f2f043d7940aac78d02c2f91a689b2cc0584111f0f7929d70e0e32db9159b7e23b6e0043502bc36609728e9dc0353251c241a7b1adb047c9234cd77ed519c409048a6c8bc247f0262c1f161b03d6fee49426e00"
            )
        );

        // Round-trips back to an equal structure.
        let encoded = cert.to_cbor();
        assert_eq!(
            CertificationData::from_cbor(Decoder::new(&encoded)).unwrap(),
            cert
        );
    }

    #[test]
    fn legacy_creation_preserves_v1_bytes_without_a_clock() {
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

        assert_eq!(mint.timeout(), None);
        assert_eq!(cert.timeout(), None);
        assert_eq!(cert.to_cbor(), hex!(
            "d998778501d9987883014101582103a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f9635075820e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e6152415820df524cffc08a1dc30579a8a51f440a97b30630988084f8d12a4d8bd741c7791258419efb637f14dbdaada6e293e2182932d82265b04b1abf4f28bc4c285b32b5e2325140fe7f94bc9b705c568b4fcb7f9ea90cf0fadcacc1b4504275f81558aad1e700"
        ));
    }

    /// Each version pairs with exactly one field count. A version 1 array with
    /// a timeout appended promises bytes the transaction hash does not commit
    /// to, so it is not a payload this decoder recognises.
    #[test]
    fn rejects_a_version_that_does_not_match_the_field_count() {
        let mut mismatched = hex!(
            "d998778602d9987883014101582103a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f9635075820e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e6152415820ed275ff0a0694d1b61ec22f13914a431569220ba7f2f043d7940aac78d02c2f91a689b2cc0584111f0f7929d70e0e32db9159b7e23b6e0043502bc36609728e9dc0353251c241a7b1adb047c9234cd77ed519c409048a6c8bc247f0262c1f161b03d6fee49426e00"
        )
        .to_vec();
        assert!(CertificationData::from_cbor(Decoder::new(&mismatched)).is_ok());

        mismatched[4] = 1;

        assert!(CertificationData::from_cbor(Decoder::new(&mismatched)).is_err());
    }
}
