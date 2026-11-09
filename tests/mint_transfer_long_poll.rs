//! `client::mint` / `client::transfer` over `HttpAggregatorClient` wait for the proof with
//! long poll by default (JS parity): `waitMs` is sent and few requests are made; a server
//! that ignores `waitMs` is polled at the interval (bounded as before); `with_long_poll(false)`
//! sends no `waitMs`. Request counts and sent parameters are the checks, not timings.
//!
//! The mock serves a real fixture proof that belongs to another state, so the flow ends in
//! `ClientError::Verification`: reaching it shows the wait returned the served proof; the
//! assertions are on what the client sent before that.
#![cfg(feature = "http")]

mod common;

use std::time::Duration;

use common::*;
use unicity_token::api::bft::TrustBaseHistory;
use unicity_token::api::NetworkId;
use unicity_token::client::{self, ClientError, HttpAggregatorClient};
use unicity_token::crypto::signature::PublicKey;
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::transaction::ids::{StateMask, TokenSalt, TokenType};
use unicity_token::transaction::Token;

const FIXTURE: &str = include_str!("vectors/transition_flow.json");

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
        while let Some(i) = find_subslice(&out[at..], &old) {
            out[at + i..at + i + new.len()].copy_from_slice(&new);
            at += i + new.len();
        }
    }
    out
}

fn obj(proof: &str, status: &str, echo: Option<u64>) -> String {
    match echo {
        Some(e) => format!(r#"{{"proof":"{proof}","status":"{status}","waitedMs":{e}}}"#),
        None => format!(r#"{{"proof":"{proof}","status":"{status}"}}"#),
    }
}

/// Reply script: the submission, then `pending_polls` pending answers, then the proof.
/// `echo` makes the server long-poll aware.
fn script(pending_polls: usize, echo: bool) -> Scripted {
    let (proof, _) = fixture_proof_and_data();
    let (empty, full) = (empty_proof_response_hex(&proof), proof_response_hex(&proof));
    Scripted::start(move |i, seen| {
        if seen.method == "certification_request" {
            return Reply::result(r#"{"status":"SUCCESS"}"#);
        }
        let polls_before = i - 1;
        // a long-poll aware server echoes only a wait it was asked for
        let echo = echo && seen.params.get("waitMs").is_some();
        if polls_before < pending_polls {
            let r = Reply::result(obj(&empty, "pending", echo.then_some(100)));
            if echo {
                r.after(Duration::from_millis(100))
            } else {
                r
            }
        } else {
            Reply::result(obj(&full, "included", echo.then_some(10)))
        }
    })
}

fn polls(server: &Scripted) -> Vec<serde_json::Value> {
    (0..server.count())
        .map(|i| server.request(i))
        .filter(|r| r.method == "get_inclusion_proof.v2")
        .map(|r| r.params)
        .collect()
}

fn http(url: &str) -> HttpAggregatorClient {
    HttpAggregatorClient::new_insecure_http(url).with_polling(Duration::from_millis(100), 100)
}

fn do_mint(c: &HttpAggregatorClient) {
    let alice = Secp256k1Signer::generate().unwrap();
    let err = client::mint(
        c,
        &trust_base(),
        NetworkId::LOCAL,
        &SignaturePredicate::new(alice.public_key()),
        TokenType::random().unwrap(),
        TokenSalt::random().unwrap(),
        None,
        None,
        Some(4_000_000_000),
    )
    .unwrap_err();
    assert!(matches!(err, ClientError::Verification(_)), "{err:?}");
}

fn do_transfer(c: &HttpAggregatorClient) {
    let raw = hex::decode(field(FIXTURE, "aliceToken")).unwrap();
    let token = Token::from_cbor(&reissue_seals_as_epoch_1(FIXTURE, &raw)).unwrap();
    let bob = Secp256k1Signer::generate().unwrap();
    let alice = Secp256k1Signer::generate().unwrap();
    let err = client::transfer(
        c,
        &trust_base(),
        &token,
        &SignaturePredicate::new(bob.public_key()),
        &alice,
        StateMask::random().unwrap(),
        None,
        Some(4_000_000_000),
    )
    .unwrap_err();
    assert!(matches!(err, ClientError::Verification(_)), "{err:?}");
}

type Flow = fn(&HttpAggregatorClient);

#[test]
fn a_long_poll_server_sees_waitms_and_few_requests() {
    for flow in [do_mint as Flow, do_transfer as Flow] {
        let server = script(2, true);
        flow(&http(&server.url));
        let p = polls(&server);
        assert_eq!(p.len(), 3, "two held pendings, then the proof");
        assert!(p.iter().all(|x| x["waitMs"].as_u64().unwrap() > 0));
        assert!(p.iter().all(|x| x["includeStatus"] == true));
    }
}

#[test]
fn a_server_ignoring_waitms_is_polled_at_the_interval_with_waitms_dropped() {
    for flow in [do_mint as Flow, do_transfer as Flow] {
        let server = script(3, false);
        flow(&http(&server.url));
        let p = polls(&server);
        // one probe carried waitMs; the missing echo dropped it for the rest of the wait
        assert_eq!(p.len(), 4, "3 pendings + the proof, as the classic poller");
        assert!(p[0].get("waitMs").is_some());
        assert!(p[1..].iter().all(|x| x.get("waitMs").is_none()));
    }
}

#[test]
fn long_poll_off_sends_no_waitms() {
    for flow in [do_mint as Flow, do_transfer as Flow] {
        let server = script(2, true);
        flow(&http(&server.url).with_long_poll(false));
        let p = polls(&server);
        assert_eq!(p.len(), 3);
        assert!(p.iter().all(|x| x.get("waitMs").is_none()));
    }
}

// --- budget edge cases of the default `get_inclusion_proof` --------------------------

use unicity_token::client::{AggregatorClient, HttpError};

fn pending_then_proof(pending: usize) -> Scripted {
    let (proof, _) = fixture_proof_and_data();
    let (empty, full) = (empty_proof_response_hex(&proof), proof_response_hex(&proof));
    Scripted::start(move |i, _| {
        if i < pending {
            Reply::result(obj(&empty, "pending", None))
        } else {
            Reply::result(obj(&full, "included", None))
        }
    })
}

#[test]
fn a_zero_budget_makes_the_probes_of_the_classic_loop() {
    // zero interval: 4 immediate probes, then Timeout
    let server = pending_then_proof(usize::MAX);
    let c = HttpAggregatorClient::new_insecure_http(&server.url).with_polling(Duration::ZERO, 4);
    assert!(matches!(
        c.get_inclusion_proof(&state_id(7)),
        Err(HttpError::Timeout)
    ));
    assert_eq!(server.count(), 4);
    // ... and the proof is found when it arrives on the third
    let server = pending_then_proof(2);
    let c = HttpAggregatorClient::new_insecure_http(&server.url).with_polling(Duration::ZERO, 4);
    assert!(c.get_inclusion_proof(&state_id(7)).is_ok());
    assert_eq!(server.count(), 3);
    // zero attempts: no request at all, as before
    let server = pending_then_proof(0);
    let c = HttpAggregatorClient::new_insecure_http(&server.url)
        .with_polling(Duration::from_millis(10), 0);
    assert!(matches!(
        c.get_inclusion_proof(&state_id(7)),
        Err(HttpError::Timeout)
    ));
    assert_eq!(server.count(), 0);
}

#[test]
fn an_enormous_budget_does_not_overflow_the_clock() {
    let server = pending_then_proof(0);
    let c =
        HttpAggregatorClient::new_insecure_http(&server.url).with_polling(Duration::MAX, u32::MAX);
    assert!(c.get_inclusion_proof(&state_id(7)).is_ok());
    assert_eq!(server.count(), 1);
}

#[test]
fn a_small_budget_does_not_shrink_the_request_timeout() {
    let (proof, _) = fixture_proof_and_data();
    let full = proof_response_hex(&proof);
    // answers after 700 ms; the budget is 3 x 100 ms. The classic loop (30 s transport
    // timeout) gets the proof, so must the default.
    let server = Scripted::start(move |_, _| {
        Reply::result(obj(&full, "included", None)).after(Duration::from_millis(700))
    });
    let c = HttpAggregatorClient::new_insecure_http(&server.url)
        .with_polling(Duration::from_millis(100), 3);
    assert!(c.get_inclusion_proof(&state_id(7)).is_ok());
    assert_eq!(server.count(), 1);
}

#[test]
fn the_default_proof_wait_budget_is_fifteen_one_second_attempts() {
    // 1 s x 15 = 15 s in total, for the long-poll and the attempts-loop path alike
    for c in [
        HttpAggregatorClient::new("https://aggregator.invalid"),
        HttpAggregatorClient::new_insecure_http("http://127.0.0.1:1"),
    ] {
        let dbg = format!("{c:?}");
        assert!(dbg.contains("poll_attempts: 15"), "{dbg}");
        assert!(dbg.contains("poll_interval: 1s"), "{dbg}");
    }
}
