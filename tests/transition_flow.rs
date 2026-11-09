//! End-to-end cross-SDK verification test.
//!
//! `tests/vectors/transition_flow.json` is produced by the reference
//! TypeScript SDK (`tests/functional/TestAggregatorClient.ts` +
//! `tests/utils/TokenUtils.ts`): a token minted to Alice and transferred
//! Alice -> Bob -> Carol through an in-memory aggregator, with the JS SDK
//! asserting `verify == OK` after every step before export. This test
//! confirms the Rust SDK decodes those exact bytes, round-trips them
//! byte-for-byte, and reaches the same verification decisions (RSMT v6a,
//! big-endian bit order).
//!
//! The Alice/Bob/Carol tokens leave the request deadline to the service, so
//! their `expiresAt` is CBOR null and no client clock is involved.
//! `explicitTimeoutToken` carries a sender-chosen deadline. Both are the same
//! wire version with the same element count, so one vector covers the encoding
//! with and without a value in that slot.

use unicity_token::api::bft::TrustBaseHistory;
use unicity_token::api::{CertificationData, InclusionProofResponse, NetworkId};
use unicity_token::cbor::Decoder;
use unicity_token::crypto::hash::sha256;
use unicity_token::crypto::signature::PublicKey;
use unicity_token::transaction::{CertifiedTransferTransaction, Token, Transaction};
use unicity_token::verify::VerificationError;

mod common;
use common::history_of;

const FIXTURE: &str = include_str!("vectors/transition_flow.json");

fn field<'a>(json: &'a str, key: &str) -> &'a str {
    // Tiny extractor to avoid a serde dependency in the test: find "key": "value".
    let needle = alloc_format(key);
    let start = json.find(&needle).expect("key present") + needle.len();
    let rest = &json[start..];
    let q1 = rest.find('"').expect("open quote") + 1;
    let q2 = rest[q1..].find('"').expect("close quote") + q1;
    &rest[q1..q2]
}

fn alloc_format(key: &str) -> String {
    format!("\"{key}\"")
}

fn trust_base() -> TrustBaseHistory {
    let pk = PublicKey::from_bytes(&hex::decode(field(FIXTURE, "aggregatorPublicKey")).unwrap())
        .unwrap();
    history_of(NetworkId::LOCAL, 1, 0, vec![("NODE".into(), pk, 1)])
}

/// The cross-SDK fixtures (`tests/vectors`, shared and unchangeable here) were generated
/// with seals of epoch 0, which no trust base history can hold (epochs start at 1).
/// This re-issues every seal of a fixture token as epoch 1, signed by the fixture
/// aggregator key (the JS generator's private key 9, checked against the fixture's public
/// key). Nothing else changes: a seal's hash covers the unicity tree root and not the
/// epoch, so every proof, path and certificate stays valid, and the epoch and the
/// 65-byte signature keep their encoded length, so the splice is a same-length
/// replacement.
#[cfg(feature = "client")]
fn reissue_seals_as_epoch_1(json: &str, bytes: &[u8]) -> Vec<u8> {
    use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
    let mut secret = [0u8; 32];
    secret[31] = 9;
    let signer = Secp256k1Signer::from_bytes(&secret).unwrap();
    assert_eq!(
        hex::encode(signer.public_key().as_bytes()),
        field(json, "aggregatorPublicKey"),
        "fixture aggregator key"
    );
    let token = Token::from_cbor(bytes).expect("decode token");
    let mut seals = vec![token
        .genesis()
        .inclusion_proof()
        .unicity_certificate
        .unicity_seal
        .clone()];
    seals.extend(
        token
            .transactions()
            .iter()
            .map(|t| t.inclusion_proof().unicity_certificate.unicity_seal.clone()),
    );
    let mut out = bytes.to_vec();
    for old in seals {
        assert_eq!(old.epoch, 0, "fixture seals are epoch 0");
        let mut new = old.clone();
        new.epoch = 1;
        let signature = signer.sign(&new.calculate_hash()).encode().to_vec();
        for (_, sig) in new.signatures.iter_mut() {
            assert_eq!(sig.len(), signature.len());
            *sig = signature.clone();
        }
        let (old, new) = (old.to_cbor(), new.to_cbor());
        assert_eq!(old.len(), new.len());
        let mut at = 0;
        while let Some(i) = common::find_subslice(&out[at..], &old) {
            out[at + i..at + i + new.len()].copy_from_slice(&new);
            at += i + new.len();
        }
    }
    out
}

/// The re-issued tokens, `{fixture: {token name: hex}}`: stored, so that the verification core (no `client` feature, no signing) runs the
/// same tests; `epoch_1_fixtures_are_current` regenerates them with [`reissue_seals_as_epoch_1`] and compares (`EPOCH1_UPDATE=1` rewrites
/// the file).
const EPOCH_1: &str = include_str!("vectors/transition_flow_epoch1.json");
const OTHER_FIXTURE: &str = include_str!("vectors/transition_flow_partition0.json");
#[cfg(feature = "client")]
const TOKEN_NAMES: [&str; 4] = [
    "aliceToken",
    "bobToken",
    "carolToken",
    "explicitTimeoutToken",
];

/// A fixture token, its seals re-issued as epoch 1 (see [`reissue_seals_as_epoch_1`]).
fn token(name: &str) -> (Vec<u8>, Token) {
    token_of("transition_flow", name)
}

/// `fixture` is `transition_flow` or `transition_flow_partition0`.
fn token_of(fixture: &str, name: &str) -> (Vec<u8>, Token) {
    let stored: serde_json::Value = serde_json::from_str(EPOCH_1).unwrap();
    let hex_str = stored[fixture][name].as_str().expect("stored token");
    let bytes = hex::decode(hex_str).unwrap();
    let token = Token::from_cbor(&bytes).expect("decode token");
    (bytes, token)
}

#[cfg(feature = "client")]
#[test]
fn epoch_1_fixtures_are_current() {
    let mut all = serde_json::Map::new();
    for (fixture, json) in [
        ("transition_flow", FIXTURE),
        ("transition_flow_partition0", OTHER_FIXTURE),
    ] {
        let mut tokens = serde_json::Map::new();
        for name in TOKEN_NAMES {
            let raw = hex::decode(field(json, name)).unwrap();
            let bytes = reissue_seals_as_epoch_1(json, &raw);
            tokens.insert(name.into(), serde_json::Value::String(hex::encode(bytes)));
        }
        all.insert(fixture.into(), serde_json::Value::Object(tokens));
    }
    let fresh = serde_json::Value::Object(all);
    if std::env::var_os("EPOCH1_UPDATE").is_some() {
        let text = serde_json::to_string_pretty(&fresh).unwrap() + "\n";
        std::fs::write("tests/vectors/transition_flow_epoch1.json", text).unwrap();
        return;
    }
    assert_eq!(
        fresh,
        serde_json::from_str::<serde_json::Value>(EPOCH_1).unwrap(),
        "tests/vectors/transition_flow_epoch1.json is stale; EPOCH1_UPDATE=1 cargo test --test transition_flow regenerates it"
    );
}

#[test]
fn decodes_and_roundtrips_byte_for_byte() {
    for name in [
        "aliceToken",
        "bobToken",
        "carolToken",
        "explicitTimeoutToken",
    ] {
        // the unmodified bytes of the reference SDK, not the epoch-1 re-issue
        let bytes = hex::decode(field(FIXTURE, name)).unwrap();
        let token = Token::from_cbor(&bytes).expect("decode token");
        assert_eq!(token.to_cbor(), bytes, "{name} did not round-trip");
    }
}

/// Both cases cross the SDK boundary: the default flow carries no deadline,
/// and the explicit one carries a deadline the round's reference time
/// is below.
#[test]
fn covers_present_and_absent_deadlines() {
    let tb = trust_base();

    let (_, default_token) = token("aliceToken");
    assert_eq!(default_token.genesis().transaction().expires_at(), None);
    default_token.verify(&tb).expect("absent deadline verifies");

    let (_, explicit_token) = token("explicitTimeoutToken");
    let genesis = explicit_token.genesis();
    let timeout = genesis
        .transaction()
        .expires_at()
        .expect("explicit deadline is present");
    assert!(
        genesis.reference_time() < timeout,
        "certified reference time {} must precede the request deadline {timeout}",
        genesis.reference_time()
    );
    explicit_token
        .verify(&tb)
        .expect("explicit deadline verifies");
}

#[test]
fn verifies_against_trust_base() {
    let tb = trust_base();
    for name in [
        "aliceToken",
        "bobToken",
        "carolToken",
        "explicitTimeoutToken",
    ] {
        let (_, token) = token(name);
        token
            .verify(&tb)
            .unwrap_or_else(|e| panic!("{name} should verify: {e}"));
    }
}

/// The same flow certified under partition 0 by the same trusted key: every signature, seal
/// and path is valid, only the partition is not the aggregation partition.
#[test]
fn rejects_validly_signed_tokens_of_another_partition() {
    let pk =
        PublicKey::from_bytes(&hex::decode(field(OTHER_FIXTURE, "aggregatorPublicKey")).unwrap())
            .unwrap();
    let tb = history_of(NetworkId::LOCAL, 1, 0, vec![("NODE".into(), pk, 1)]);
    for name in [
        "aliceToken",
        "bobToken",
        "carolToken",
        "explicitTimeoutToken",
    ] {
        let (_, token) = token_of("transition_flow_partition0", name);
        // the wrapper names the failing transaction; the cause is the partition rule
        let err = token.verify(&tb).expect_err(name);
        assert!(
            format!("{err:?}").contains("PartitionMismatch"),
            "{name}: {err:?}"
        );
    }
}

#[test]
fn rejects_wrong_aggregator_key() {
    // A trust base with a different validator key must fail the quorum check:
    // the seal signature no longer verifies. (secp256k1 generator point as a
    // valid-but-wrong key.)
    let other = PublicKey::from_bytes(
        &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap(),
    )
    .unwrap();
    let tb = history_of(NetworkId::LOCAL, 1, 0, vec![("NODE".into(), other, 1)]);
    let (_, token) = token("carolToken");
    let err = token.verify(&tb).unwrap_err();
    assert!(
        matches!(
            err,
            VerificationError::QuorumNotMet
                | VerificationError::Genesis(_)
                | VerificationError::Transfer { .. }
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_wrong_network() {
    // Genesis network is LOCAL; a MAINNET trust base must be rejected up front.
    let tb_pk = PublicKey::from_bytes(&hex::decode(field(FIXTURE, "aggregatorPublicKey")).unwrap())
        .unwrap();
    let tb = history_of(NetworkId::MAINNET, 1, 0, vec![("NODE".into(), tb_pk, 1)]);
    let (_, token) = token("aliceToken");
    assert_eq!(token.verify(&tb), Err(VerificationError::NetworkMismatch));
}

#[test]
fn rejects_tampered_recipient() {
    // Flip a byte inside the Carol token and require that it no longer both
    // decodes-and-verifies. (Most single-byte flips break CBOR or a hash.)
    let (mut bytes, _) = token("carolToken");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    let verified = Token::from_cbor(&bytes)
        .map(|t| t.verify(&trust_base()).is_ok())
        .unwrap_or(false);
    assert!(!verified, "tampered token must not verify");
}

#[test]
fn rejects_trailing_and_non_minimal_token_encodings() {
    let (mut trailing, _) = token("aliceToken");
    trailing.push(0xff);
    assert!(Token::from_cbor(&trailing).is_err());

    let (canonical, _) = token("aliceToken");
    // The token tag is three bytes and the following array header is one byte;
    // replace the canonical version with its non-minimal two-byte form.
    assert_eq!(canonical[4], 0x02);
    let mut non_minimal = canonical[..4].to_vec();
    non_minimal.extend_from_slice(&[0x18, 0x02]);
    non_minimal.extend_from_slice(&canonical[5..]);
    assert!(Token::from_cbor(&non_minimal).is_err());
}

#[test]
fn rejects_mismatched_transfer_certification_state() {
    let (_, token) = token("bobToken");
    let certified = &token.transactions()[0];
    let mut proof = certified.inclusion_proof().clone();
    let data = proof.certification_data.clone();
    // Rebuild with the same fields, so only the substituted source state differs.
    proof.certification_data = CertificationData::new(
        data.lock_script().clone(),
        sha256(b"unrelated source state"),
        data.transaction_hash().clone(),
        data.unlock_script().to_vec(),
        data.expires_at(),
    );

    let forged = Token::new(
        token.genesis().clone(),
        vec![CertifiedTransferTransaction::new(
            certified.transaction().clone(),
            proof,
        )],
    );
    assert!(matches!(
        forged.verify(&trust_base()),
        Err(VerificationError::Transfer { source, .. })
            if matches!(*source, VerificationError::CertificationDataMismatch)
    ));
}

/// The aggregator's answer round-trips in both of the shapes the wire admits,
/// and only the certified one yields a proof.
#[test]
fn inclusion_proof_response_round_trips_both_shapes() {
    let (_, token) = token("carolToken");
    let proof = token.transactions()[0].inclusion_proof().clone();

    let certified = InclusionProofResponse::Certified {
        block_number: 7,
        proof: proof.clone(),
    };
    let bytes = certified.to_cbor();
    let decoded = InclusionProofResponse::from_cbor(Decoder::new(&bytes)).expect("certified");
    assert_eq!(decoded, certified);
    assert_eq!(decoded.block_number(), 7);
    assert_eq!(decoded.inclusion_proof(), Some(&proof));
    assert_eq!(decoded.unicity_certificate(), &proof.unicity_certificate);

    let not_certified = InclusionProofResponse::NotCertified {
        block_number: 9,
        unicity_certificate: proof.unicity_certificate.clone(),
    };
    let bytes = not_certified.to_cbor();
    let decoded = InclusionProofResponse::from_cbor(Decoder::new(&bytes)).expect("not certified");
    assert_eq!(decoded, not_certified);
    assert_eq!(decoded.block_number(), 9);
    assert_eq!(decoded.inclusion_proof(), None);
    assert_eq!(decoded.unicity_certificate(), &proof.unicity_certificate);

    // The uncertified body is not an InclusionProof, and says so rather than
    // decoding into one with empty fields.
    let items = Decoder::new(&bytes).array(Some(2)).unwrap();
    assert!(unicity_token::api::InclusionProof::from_cbor(items[1]).is_err());
}

/// Verification authenticates each distinct seal once per operation: the
/// number of quorum-signature checks equals the number of distinct complete
/// seals among the token's proofs, however many proofs share them.
#[test]
fn verification_checks_each_distinct_seal_once() {
    use std::collections::BTreeSet;
    use unicity_token::verify::{
        verify_token_with_seal_stats, MintJustificationRegistry, VerificationPolicy,
    };

    let tb = trust_base();
    for name in ["aliceToken", "bobToken", "carolToken"] {
        let (_, token) = token(name);
        let mut seals = vec![token
            .genesis()
            .inclusion_proof()
            .unicity_certificate
            .unicity_seal
            .to_cbor()];
        for t in token.transactions() {
            seals.push(
                t.inclusion_proof()
                    .unicity_certificate
                    .unicity_seal
                    .to_cbor(),
            );
        }
        let distinct: BTreeSet<_> = seals.iter().collect();

        let (result, stats) = verify_token_with_seal_stats(
            &token,
            &tb,
            &MintJustificationRegistry::new(),
            VerificationPolicy::default(),
        );
        result.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(stats.quorum_checks as usize, distinct.len(), "{name}");
        assert_eq!(
            (stats.quorum_checks + stats.memo_hits) as usize,
            seals.len(),
            "{name}"
        );
    }
}
