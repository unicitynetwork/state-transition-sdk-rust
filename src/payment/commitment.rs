//! The split output commitment `d_j` (yellowpaper "Output Commitment").
//!
//! `d_j` binds a split allocation leaf to the complete output mint transaction
//! *except* its mint reason (excluded to avoid a circular commitment). Including
//! the output token type, recipient predicate, salt, resulting token id and the
//! exact auxiliary payload means a proof prepared for one recipient or token type
//! cannot authorize a mint to another, even though the universal minting key is
//! public.
//!
//! ```text
//! d_j = SHA-256(CBOR(
//!   SPLIT_OUTPUT, id_src, α, encpred(pred'_j), salt_j, id_j, ty_j, auxd'_j ))
//! ```
//!
//! Every term is a CBOR byte string except `α`, which is an unsigned integer.

use crate::api::network_id::NetworkId;
use crate::cbor::{encode_array, encode_byte_string, encode_uint};
use crate::crypto::hash::sha256;
use crate::error::Error;
use crate::predicate::EncodedPredicate;
use crate::transaction::ids::{TokenId, TokenSalt, TokenType};
use crate::transaction::{MintTransaction, Transaction};

/// The `SPLIT_OUTPUT` domain tag: the ASCII bytes `UNICITY_SPLIT_OUTPUT`.
pub const SPLIT_OUTPUT: &[u8] = b"UNICITY_SPLIT_OUTPUT";

/// Compute the split output commitment `d_j` from its constituent fields.
///
/// `aux_data` is the exact auxiliary-payload byte string stored in the output
/// mint transaction (not a decoded or re-encoded object).
#[allow(clippy::too_many_arguments)]
pub fn split_output_commitment(
    source_id: &TokenId,
    network_id: NetworkId,
    recipient: &EncodedPredicate,
    salt: &TokenSalt,
    output_id: &TokenId,
    token_type: &TokenType,
    aux_data: &[u8],
) -> [u8; 32] {
    let preimage = encode_array(&[
        &encode_byte_string(SPLIT_OUTPUT),
        &encode_byte_string(source_id.bytes()),
        &encode_uint(network_id.id() as u64),
        &encode_byte_string(&recipient.to_cbor()),
        &encode_byte_string(salt.bytes()),
        &encode_byte_string(output_id.bytes()),
        &encode_byte_string(token_type.bytes()),
        &encode_byte_string(aux_data),
    ]);
    let mut out = [0u8; 32];
    out.copy_from_slice(sha256(&preimage).data());
    out
}

/// Compute `d_j` for an output mint transaction, given the source token id.
///
/// Errors if the output carries no auxiliary payload (a split output must always
/// declare the non-empty canonical asset collection it receives).
pub fn commitment_for_mint(source_id: &TokenId, mint: &MintTransaction) -> Result<[u8; 32], Error> {
    let aux_data = mint
        .data()
        .ok_or(Error::UnexpectedValue("split output has no auxiliary payload"))?;
    Ok(split_output_commitment(
        source_id,
        mint.network_id(),
        mint.recipient(),
        mint.salt(),
        mint.token_id(),
        mint.token_type(),
        aux_data,
    ))
}
