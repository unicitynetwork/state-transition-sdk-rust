//! SP1 guest: verifies, from scratch and with a local seal session, either
//!
//! * mode 0 - a complete token (UC quorum signatures, inclusion paths, unlock-script
//!   signatures, SHA-256), or
//! * mode 1 - a native unicity certificate: tree path to the seal hash plus the
//!   strict seal authentication (network, epoch, quorum signatures).
//!
//! Signature verification is `Signature::verify`: the O3 strict rule (65 bytes, low-S, key
//! recovered with `v` equals the trusted key) implemented as one recover-and-compare from
//! k256 primitives (`AffinePoint::decompress`, `Scalar::invert`, one
//! `ProjectivePoint::lincomb`), all accelerated by the SP1 k256 patch; no
//! `recover_from_prehash` and no separate ECDSA verification.
//!
//! Public output (committed in this order): `ok`, `mode`, the authority identity
//! ([`SealSession::authority_identity`], a digest of the trust base history's network, genesis
//! entry and latest entry; here a one-entry history) and the SHA-256 of the payload. The trust base
//! and payload are private inputs, so a proof of this program is only meaningful together with
//! these values: the verifier of the proof must compare the identity with the authority it
//! trusts and the digest with the token or certificate it is about.
#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};
use unicity_token::api::bft::{
    TrustBaseEntry, TrustBaseHistory, TrustBaseMember, UnicityCertificate,
};
use unicity_token::api::NetworkId;
use unicity_token::cbor::Decoder;
use unicity_token::crypto::hash::sha256;
use unicity_token::crypto::signature::PublicKey;
use unicity_token::transaction::Token;
use unicity_token::verify::{SealAuthenticator, SealSession};

#[derive(Serialize, Deserialize)]
pub struct Input {
    pub mode: u8,
    /// Unused: the entry record version is fixed by the library. Kept so the host's input
    /// layout does not change.
    pub version: u64,
    pub network: u16,
    pub epoch: u64,
    pub epoch_start_round: u64,
    /// Must equal the entry's quorum threshold `floor(2W/3)+1` of the total weight `W`; the
    /// history derives it and a different value fails the proof.
    pub threshold: u64,
    /// (node id, 33-byte compressed key, weight)
    pub nodes: Vec<(String, Vec<u8>, u64)>,
    pub payload: Vec<u8>,
}

fn main() {
    let input = sp1_zkvm::io::read::<Input>();
    let members = input
        .nodes
        .iter()
        .map(|(id, key, weight)| {
            TrustBaseMember::new(
                id.clone(),
                PublicKey::from_bytes(key).expect("trust base key"),
                *weight,
            )
        })
        .collect();
    let genesis = TrustBaseEntry::genesis(
        NetworkId::new(input.network).expect("network"),
        input.epoch,
        input.epoch_start_round,
        members,
    );
    assert_eq!(
        genesis.quorum_threshold, input.threshold,
        "threshold is not floor(2W/3)+1"
    );
    // a one-entry history: this guest trusts exactly the committee it was given
    let trust_base = TrustBaseHistory::from_genesis(genesis, None).expect("trust base");

    let ok = match input.mode {
        0 => Token::from_cbor(&input.payload)
            .map(|token| token.verify(&trust_base).is_ok())
            .unwrap_or(false),
        1 => {
            let uc = UnicityCertificate::from_cbor(Decoder::new(&input.payload)).expect("uc");
            let mut session = SealSession::new(&trust_base);
            uc.computed_seal_hash()
                .is_ok_and(|h| h.data() == uc.unicity_seal.hash.as_slice())
                && session.authenticate_seal(&uc.unicity_seal).is_ok()
        }
        _ => false,
    };
    let authority: [u8; 32] = SealSession::new(&trust_base).authority_identity();
    let payload_digest: [u8; 32] = sha256(&input.payload)
        .data()
        .try_into()
        .expect("sha-256 is 32 bytes");
    sp1_zkvm::io::commit(&ok);
    sp1_zkvm::io::commit(&input.mode);
    sp1_zkvm::io::commit(&authority);
    sp1_zkvm::io::commit(&payload_digest);
}
