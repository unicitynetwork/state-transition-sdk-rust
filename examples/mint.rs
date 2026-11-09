//! Token minting against a live aggregator — the Rust equivalent of the
//! reference SDKs' `tests/examples/mint`.
//!
//! Connection parameters come from `e2e/.env` (see `e2e/.env.example`); the
//! example talks to the gateway via [`HttpAggregatorClient`] and prints the
//! minted token's CBOR, just like the model example.
//!
//! Run with:
//!   cargo run --example mint --features http

use std::time::Duration;

use unicity_token::api::bft::trust_base_cache::{MemoryStore, Session};
use unicity_token::cbor::encode_text_string;
use unicity_token::client::{self, HttpAggregatorClient};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::transaction::ids::{TokenSalt, TokenType};

#[path = "common/session.rs"]
mod session;

const DEFAULT_GATEWAY: &str = "https://gateway.testnet2.unicity.network/";

/// Build an aggregator client and the open trust base session (the release pin of the network, extended from the aggregator).
fn load() -> (HttpAggregatorClient, Session<MemoryStore>) {
    // Load e2e/.env (values already in the process environment win).
    dotenvy::from_path("e2e/.env").ok();

    let gateway = std::env::var("UNICITY_GATEWAY").unwrap_or_else(|_| DEFAULT_GATEWAY.to_string());

    let mut aggregator =
        HttpAggregatorClient::new(gateway).with_polling(Duration::from_secs(2), 90);
    if let Ok(key) = std::env::var("UNICITY_API_KEY") {
        aggregator = aggregator.with_api_key(key);
    }

    let mut session = session::open();
    session::refresh(&mut session, &aggregator);
    (aggregator, session)
}

fn main() {
    let (aggregator, session) = load();
    let trust_base = session.history().expect("trust base history");

    // A fresh in-memory owner wallet.
    let owner = Secp256k1Signer::generate().expect("generate owner key");
    let owner_predicate = SignaturePredicate::new(owner.public_key());

    // `client::mint` submits the certification request, waits for the inclusion
    // proof, assembles the token, and verifies it before returning.
    let token = client::mint(
        &aggregator,
        trust_base,
        trust_base.network_id(),
        &owner_predicate,
        TokenType::random().expect("token type"),
        TokenSalt::random().expect("salt"),
        Some(encode_text_string("My custom data")),
        None,
        /* expires_at */ None,
    )
    .expect("mint");

    println!("{}", hex::encode(token.to_cbor()));
}
