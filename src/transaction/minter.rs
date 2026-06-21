//! Deterministic universal-minter key derivation.
//!
//! Every token's genesis is locked to a key derived solely from the token id
//! and a fixed public secret, so anyone can recompute the minter public key and
//! check a genesis lock script — but no one can mint a *different* history for
//! an existing token id. The public-key path is always available (verification
//! needs it); the signing path is `client`-only.

use k256::ecdsa::SigningKey;

use super::ids::TokenId;
use crate::cbor::{encode_array, encode_byte_string};
use crate::crypto::hash::{sha256, DataHash};
use crate::crypto::signature::PublicKey;
use crate::error::Error;

/// The fixed universal-minter secret: ASCII "I_AM_UNIVERSAL_MINTER_FOR_".
pub const MINTER_SECRET: &[u8] = b"I_AM_UNIVERSAL_MINTER_FOR_";

/// Deterministic minter key derivation for a token id.
#[derive(Debug)]
pub struct Minter;

impl Minter {
    /// `priv = H(array[bstr(MINTER_SECRET), tokenId.toCBOR()])`.
    pub fn derive_private_key(token_id: &TokenId) -> DataHash {
        sha256(&encode_array(&[
            &encode_byte_string(MINTER_SECRET),
            &token_id.to_cbor(),
        ]))
    }

    /// The minter public key for `token_id`.
    pub fn public_key(token_id: &TokenId) -> Result<PublicKey, Error> {
        let secret = Minter::derive_private_key(token_id);
        let key = SigningKey::from_slice(secret.data())
            .map_err(|_| Error::Crypto("invalid minter key"))?;
        let enc = key.verifying_key().to_encoded_point(true);
        PublicKey::from_bytes(enc.as_bytes())
    }

    /// A signer over the minter key (for constructing a genesis).
    #[cfg(any(feature = "client", test))]
    pub fn signer(token_id: &TokenId) -> Result<crate::crypto::signer::Secp256k1Signer, Error> {
        let secret = Minter::derive_private_key(token_id);
        crate::crypto::signer::Secp256k1Signer::from_bytes(secret.data())
    }
}
