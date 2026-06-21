//! Token identifiers and state values, plus their exact derivations.
//!
//! Every derivation here is SHA-256 over canonical CBOR and must reproduce the
//! reference SDKs byte-for-byte. Pay attention to which preimage uses a hash's
//! imprint (34 B) versus its raw data (32 B).

use alloc::vec::Vec;

use crate::api::network_id::NetworkId;
use crate::cbor::{encode_array, encode_byte_string, encode_uint, Decoder};
use crate::crypto::hash::{sha256, DataHash, DataHasher, HashAlgorithm};
use crate::error::Error;

/// Fixed 32-byte suffix used when deriving the mint initial state
/// (the SHA-256 of the ASCII string "TOKENID" in the reference SDKs).
pub const MINT_SUFFIX: [u8; 32] = [
    0x9e, 0x82, 0x00, 0x2c, 0x14, 0x4d, 0x7c, 0x57, 0x96, 0xc5, 0x0f, 0x6d, 0xb5, 0x0a, 0x0c, 0x7b,
    0xbd, 0x7f, 0x71, 0x7a, 0xe3, 0xaf, 0x6c, 0x6c, 0x71, 0xa3, 0xe9, 0xeb, 0xa3, 0x02, 0x27, 0x30,
];

/// Globally unique identifier of a token: `H(array[bstr(salt), uint(networkId)])`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TokenId([u8; 32]);

impl TokenId {
    /// Derive from a network id and mint salt.
    pub fn derive(network: NetworkId, salt: &TokenSalt) -> Self {
        let digest = DataHasher::new(HashAlgorithm::Sha256)
            .expect("sha256")
            .update(&encode_array(&[
                &salt.to_cbor(),
                &encode_uint(network.id() as u64),
            ]))
            .finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.data());
        TokenId(out)
    }

    /// The 32 identifier bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wrap raw bytes as a token id.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        TokenId(bytes)
    }

    /// CBOR byte string of the id.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_byte_string(&self.0)
    }

    /// Decode from a CBOR byte string.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let bytes = d.bytes_value()?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidLength {
            what: "TokenId",
            expected: 32,
            actual: bytes.len(),
        })?;
        Ok(TokenId(arr))
    }
}

impl core::fmt::Debug for TokenId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TokenId({})", hex::encode(self.0))
    }
}

/// Token type / class identifier. Arbitrary length (commonly 32 bytes).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TokenType(Vec<u8>);

impl TokenType {
    /// Wrap raw bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        TokenType(bytes.into())
    }

    /// Generate a random 32-byte token type using the platform RNG.
    #[cfg(feature = "std")]
    pub fn random() -> Result<Self, Error> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::Crypto("RNG failure"))?;
        Ok(TokenType(bytes.to_vec()))
    }

    /// The raw bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// CBOR byte string.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_byte_string(&self.0)
    }

    /// Decode from a CBOR byte string.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        Ok(TokenType(d.bytes_value()?.to_vec()))
    }
}

impl core::fmt::Debug for TokenType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TokenType({})", hex::encode(&self.0))
    }
}

/// Random 32-byte salt mixed into a token id at mint time.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TokenSalt([u8; 32]);

impl TokenSalt {
    /// Wrap raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        TokenSalt(bytes)
    }

    /// The raw bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Generate a random salt using the platform RNG.
    #[cfg(feature = "std")]
    pub fn random() -> Result<Self, Error> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::Crypto("RNG failure"))?;
        Ok(TokenSalt(bytes))
    }

    /// CBOR byte string.
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_byte_string(&self.0)
    }

    /// Decode from a CBOR byte string.
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let bytes = d.bytes_value()?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidLength {
            what: "TokenSalt",
            expected: 32,
            actual: bytes.len(),
        })?;
        Ok(TokenSalt(arr))
    }
}

impl core::fmt::Debug for TokenSalt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TokenSalt({})", hex::encode(self.0))
    }
}

/// 32-byte mask mixed into a transfer's resulting state hash.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct StateMask([u8; 32]);

impl StateMask {
    /// Wrap raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        StateMask(bytes)
    }

    /// Generate a random mask using the platform RNG.
    #[cfg(feature = "std")]
    pub fn random() -> Result<Self, Error> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::Crypto("RNG failure"))?;
        Ok(StateMask(bytes))
    }

    /// The raw bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for StateMask {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "StateMask({})", hex::encode(self.0))
    }
}

/// The initial (mint) state of a token:
/// `H(array[bstr(tokenId), bstr(MINT_SUFFIX)])`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MintTransactionState(DataHash);

impl MintTransactionState {
    /// Derive from a token id.
    pub fn derive(token_id: &TokenId) -> Self {
        let hash = sha256(&encode_array(&[
            &encode_byte_string(token_id.bytes()),
            &encode_byte_string(&MINT_SUFFIX),
        ]));
        MintTransactionState(hash)
    }

    /// The underlying hash.
    pub fn hash(&self) -> &DataHash {
        &self.0
    }
}
