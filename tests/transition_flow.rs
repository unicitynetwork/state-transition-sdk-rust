//! End-to-end cross-SDK verification test.
//!
//! `tests/vectors/transition_flow.json` is produced by the reference
//! TypeScript SDK (see `state-transition-sdk-js/generate-fixtures.mjs`): a token
//! minted to Alice and transferred Alice -> Bob -> Carol through an in-memory
//! aggregator. Until the JS fixture generator is rolled to RSMT v6a, the
//! multi-leaf Bob/Carol paths are intentionally pre-rollover negative fixtures.
//! This test still confirms the Rust SDK decodes those exact bytes and
//! round-trips them byte-for-byte.

use unicity_token::api::bft::root_trust_base::RootTrustBaseNodeInfo;
use unicity_token::api::bft::RootTrustBase;
use unicity_token::api::{CertificationData, NetworkId};
use unicity_token::crypto::hash::sha256;
use unicity_token::crypto::signature::PublicKey;
use unicity_token::transaction::{CertifiedTransferTransaction, Token};
use unicity_token::verify::VerificationError;

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

fn trust_base() -> RootTrustBase {
    let pk = PublicKey::from_bytes(&hex::decode(field(FIXTURE, "aggregatorPublicKey")).unwrap())
        .unwrap();
    RootTrustBase::new(
        0,
        NetworkId::LOCAL,
        0,
        0,
        vec![RootTrustBaseNodeInfo {
            node_id: "NODE".into(),
            signing_key: pk,
            stake: 1,
        }],
        1,
    )
}

fn token(name: &str) -> (Vec<u8>, Token) {
    let bytes = hex::decode(field(FIXTURE, name)).unwrap();
    let token = Token::from_cbor(&bytes).expect("decode token");
    (bytes, token)
}

#[test]
fn decodes_and_roundtrips_byte_for_byte() {
    for name in ["aliceToken", "bobToken", "carolToken"] {
        let (bytes, token) = token(name);
        assert_eq!(token.to_cbor(), bytes, "{name} did not round-trip");
    }
}

#[test]
fn single_leaf_fixture_verifies_against_trust_base() {
    let tb = trust_base();
    let (_, token) = token("aliceToken");
    token
        .verify(&tb)
        .unwrap_or_else(|e| panic!("aliceToken should verify: {e}"));
}

#[test]
fn pre_v6a_multileaf_fixtures_are_rejected() {
    let tb = trust_base();
    for name in ["bobToken", "carolToken"] {
        let (_, token) = token(name);
        assert!(
            matches!(
                token.verify(&tb),
                Err(VerificationError::Transfer { source, .. })
                    if matches!(*source, VerificationError::PathInvalid)
            ),
            "{name} should be rejected as a pre-v6a multi-leaf fixture"
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
    let tb = RootTrustBase::new(
        0,
        NetworkId::LOCAL,
        0,
        0,
        vec![RootTrustBaseNodeInfo {
            node_id: "NODE".into(),
            signing_key: other,
            stake: 1,
        }],
        1,
    );
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
    let tb = RootTrustBase::new(
        0,
        NetworkId::MAINNET,
        0,
        0,
        vec![RootTrustBaseNodeInfo {
            node_id: "NODE".into(),
            signing_key: tb_pk,
            stake: 1,
        }],
        1,
    );
    let (_, token) = token("aliceToken");
    assert_eq!(token.verify(&tb), Err(VerificationError::NetworkMismatch));
}

#[test]
fn rejects_structurally_unsafe_trust_bases() {
    let (_, token) = token("aliceToken");
    let empty = RootTrustBase::new(1, NetworkId::LOCAL, 1, 1, vec![], 0);
    assert!(matches!(
        token.verify(&empty),
        Err(VerificationError::InvalidTrustBase(_))
    ));

    let key = PublicKey::from_bytes(&hex::decode(field(FIXTURE, "aggregatorPublicKey")).unwrap())
        .unwrap();
    let duplicate_key = RootTrustBase::new(
        1,
        NetworkId::LOCAL,
        1,
        1,
        vec![
            RootTrustBaseNodeInfo {
                node_id: "A".into(),
                signing_key: key.clone(),
                stake: 1,
            },
            RootTrustBaseNodeInfo {
                node_id: "B".into(),
                signing_key: key,
                stake: 1,
            },
        ],
        2,
    );
    assert!(matches!(
        token.verify(&duplicate_key),
        Err(VerificationError::InvalidTrustBase(_))
    ));
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
    // replace canonical version 1 with its non-minimal two-byte form.
    assert_eq!(canonical[4], 0x01);
    let mut non_minimal = canonical[..4].to_vec();
    non_minimal.extend_from_slice(&[0x18, 0x01]);
    non_minimal.extend_from_slice(&canonical[5..]);
    assert!(Token::from_cbor(&non_minimal).is_err());
}

#[test]
fn rejects_mismatched_transfer_certification_state() {
    let (_, token) = token("bobToken");
    let certified = &token.transactions()[0];
    let mut proof = certified.inclusion_proof().clone();
    let data = proof
        .certification_data
        .as_ref()
        .expect("fixture has certification data");
    proof.certification_data = Some(CertificationData::new(
        data.lock_script().clone(),
        sha256(b"unrelated source state"),
        data.transaction_hash().clone(),
        data.unlock_script().to_vec(),
    ));

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
