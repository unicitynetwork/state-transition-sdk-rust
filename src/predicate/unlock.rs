//! Unlock scripts: the witness proving a predicate's spend condition is met.
//!
//! For a [`SignaturePredicate`](super::builtin::SignaturePredicate) the unlock
//! script is a 65-byte secp256k1 signature over
//! `H(array[bstr(sourceStateHash.data), bstr(transactionHash.data)])`. The
//! verification half is always available; producing one needs the `client`
//! feature.

use crate::cbor::{encode_array, encode_byte_string};
use crate::crypto::hash::{sha256, DataHash};
use crate::crypto::signature::{PublicKey, Signature};

/// The digest a signature unlock script signs over.
pub fn signature_unlock_message(
    source_state_hash: &DataHash,
    transaction_hash: &DataHash,
) -> DataHash {
    sha256(&encode_array(&[
        &encode_byte_string(source_state_hash.data()),
        &encode_byte_string(transaction_hash.data()),
    ]))
}

/// Verify a signature unlock script (`unlock_script`, 65 bytes) against
/// `public_key` for the given source-state and transaction hashes.
pub fn verify_signature_unlock(
    public_key: &PublicKey,
    source_state_hash: &DataHash,
    transaction_hash: &DataHash,
    unlock_script: &[u8],
) -> bool {
    let Ok(signature) = Signature::decode(unlock_script) else {
        return false;
    };
    let message = signature_unlock_message(source_state_hash, transaction_hash);
    signature.verify(message.data(), public_key)
}

/// Produce a signature unlock script: sign the unlock message and return the
/// 65-byte encoding.
#[cfg(any(feature = "client", test))]
pub fn sign_signature_unlock(
    signer: &impl crate::crypto::signer::Signer,
    source_state_hash: &DataHash,
    transaction_hash: &DataHash,
) -> alloc::vec::Vec<u8> {
    let message = signature_unlock_message(source_state_hash, transaction_hash);
    signer.sign(&message).encode().to_vec()
}
