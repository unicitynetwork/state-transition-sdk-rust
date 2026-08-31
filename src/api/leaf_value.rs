//! Sparse Merkle tree leaf value recorded by the Unicity Service for an
//! accepted certification request.
//!
//! The value binds the reference time the request was validated under, not the
//! transaction hash alone. The tree is append-only, so a leaf can be certified
//! afresh against any later root and a later inclusion proof carries a later
//! round's reference time. Binding the reference time into the leaf value fixes
//! the value the transition was validated under, for any proof of that leaf.

use crate::cbor::{encode_array, encode_byte_string, encode_uint};
use crate::crypto::hash::{sha256, DataHash};

/// Calculate the leaf value for a certified request:
/// `SHA-256(CBOR([transactionHash, referenceTime]))`.
pub fn calculate_leaf_value(transaction_hash: &DataHash, reference_time: u64) -> DataHash {
    sha256(&encode_array(&[
        &encode_byte_string(transaction_hash.data()),
        &encode_uint(reference_time),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::HashAlgorithm;
    use hex_literal::hex;

    // Shared across the Go, Java and TypeScript implementations.
    const TRANSACTION_HASH: [u8; 32] =
        hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const REFERENCE_TIME: u64 = 1755000000;
    const EXPECTED: [u8; 32] =
        hex!("0235bd52cfa10c9785dfa01942bc396f201fe715dbc3896ee117a97e895e1e36");

    #[test]
    fn matches_the_shared_test_vector() {
        let transaction_hash = DataHash::new(HashAlgorithm::Sha256, TRANSACTION_HASH).unwrap();

        assert_eq!(
            calculate_leaf_value(&transaction_hash, REFERENCE_TIME).data(),
            EXPECTED
        );
    }

    #[test]
    fn changes_with_the_reference_time() {
        let transaction_hash = DataHash::new(HashAlgorithm::Sha256, TRANSACTION_HASH).unwrap();

        assert_ne!(
            calculate_leaf_value(&transaction_hash, REFERENCE_TIME + 1).data(),
            EXPECTED
        );
    }
}
