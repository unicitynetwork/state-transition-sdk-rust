//! Live end-to-end test against the testnet2 gateway.
//!
//! Reads connection parameters from `e2e/unicity-service` and the trust base
//! from `e2e/bft-trustbase.testnet2.json`, then mints and transfers a token
//! through the real aggregator and verifies the result.
//!
//! Ignored by default (it requires network access and live infra). Run with:
//!   cargo test --features http --test e2e -- --ignored --nocapture
#![cfg(feature = "http")]

use std::time::Duration;

use unicity_token::api::bft::RootTrustBase;
use unicity_token::client::{self, HttpAggregatorClient};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::transaction::ids::{StateMask, TokenSalt, TokenType};

/// Parse the `key: value` lines of `e2e/unicity-service`.
fn read_service() -> (String, Option<String>) {
    let text = std::fs::read_to_string("e2e/unicity-service").expect("e2e/unicity-service");
    let mut gateway = None;
    let mut api_key = None;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let value = v.trim().to_string();
            match k.trim() {
                "gateway" => gateway = Some(value),
                "api_key" => api_key = Some(value),
                _ => {}
            }
        }
    }
    (gateway.expect("gateway in e2e/unicity-service"), api_key)
}

#[test]
#[ignore = "hits the live testnet2 gateway"]
fn e2e_mint_transfer_verify() {
    let (gateway, api_key) = read_service();
    let trust_json =
        std::fs::read_to_string("e2e/bft-trustbase.testnet2.json").expect("trust base file");
    let trust_base = RootTrustBase::from_json(&trust_json).expect("parse trust base");

    let mut aggregator =
        HttpAggregatorClient::new(gateway).with_polling(Duration::from_secs(2), 90);
    if let Some(key) = api_key {
        aggregator = aggregator.with_api_key(key);
    }

    let alice = Secp256k1Signer::generate().unwrap();
    let bob = Secp256k1Signer::generate().unwrap();

    let token = client::mint(
        &aggregator,
        &trust_base,
        trust_base.network_id,
        &SignaturePredicate::new(alice.public_key()),
        TokenType::random().unwrap(),
        TokenSalt::random().unwrap(),
        None,
        None,
    )
    .expect("mint");
    token.verify(&trust_base).expect("verify minted token");

    let transferred = client::transfer(
        &aggregator,
        &trust_base,
        &token,
        &SignaturePredicate::new(bob.public_key()),
        &alice,
        StateMask::random().unwrap(),
        None,
    )
    .expect("transfer");
    transferred
        .verify(&trust_base)
        .expect("verify transferred token");

    println!(
        "transferred token CBOR: {}",
        hex::encode(transferred.to_cbor())
    );
}
