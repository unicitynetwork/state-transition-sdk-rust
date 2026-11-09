//! Live end-to-end test against the testnet2 gateway.
//!
//! Reads connection parameters from `e2e/.env` (see `e2e/.env.example`), the
//! same source the examples and the `e2e/` demo crate use, then mints and
//! transfers a token through the real aggregator and verifies the result.
//!
//! Ignored by default (it requires network access and live infra). Run with:
//!   cargo test --features http --test e2e -- --ignored --nocapture
#![cfg(feature = "http")]

use std::env;
use std::time::Duration;

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use unicity_token::api::bft::trust_base_cache::{
    Authority, MemoryStore, PinSpec, Session, SessionOptions,
};
use unicity_token::api::bft::trust_base_update::UpdateOptions;
use unicity_token::api::NetworkId;
use unicity_token::client::{self, HttpAggregatorClient};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::transaction::ids::{StateMask, TokenSalt, TokenType};

const DEFAULT_GATEWAY: &str = "https://gateway.testnet2.unicity.network/";

/// Read connection parameters from `e2e/.env`, matching the examples and the
/// `e2e/` demo crate. Values already in the process environment take
/// precedence, so CI can supply the key without writing a file.
fn read_service() -> (String, Option<String>) {
    dotenvy::from_path("e2e/.env").ok();

    let gateway = std::env::var("UNICITY_GATEWAY").unwrap_or_else(|_| DEFAULT_GATEWAY.to_string());
    let api_key = std::env::var("UNICITY_API_KEY")
        .ok()
        .filter(|k| !k.is_empty());
    (gateway, api_key)
}

/// Drive a future to completion on this thread (the SDK chooses no executor; the in-memory store never waits on I/O).
fn block_on<F: Future>(f: F) -> F::Output {
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&waker);
    let mut f = pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}

/// Open the trust base session of the network: the SDK's release pin (testnet2 by default, `UNICITY_NETWORK=mainnet` for mainnet), or the
/// complete bundle of a local deployment in `UNICITY_LOCAL_BUNDLE`; then extend it from the aggregator (untrusted source, every entry
/// verified from the held tip).
fn open_session(aggregator: &HttpAggregatorClient) -> Session<MemoryStore> {
    let (network, authority) = match env::var("UNICITY_LOCAL_BUNDLE") {
        Ok(path) => {
            let bundle = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            let pin = PinSpec::from_bundle(&bundle).expect("a complete trust base bundle");
            (
                pin.network_id,
                Authority::local(&bundle).expect("local authority"),
            )
        }
        Err(_) => (
            match env::var("UNICITY_NETWORK").as_deref() {
                Ok("mainnet") => NetworkId::MAINNET,
                _ => NetworkId::TESTNET2,
            },
            Authority::Release,
        ),
    };
    let (mut session, _diagnostics) = block_on(Session::open(
        network,
        authority,
        MemoryStore::new(),
        SessionOptions::default(),
    ))
    .expect("open the trust base session");
    block_on(session.refresh(&[aggregator], &UpdateOptions::default()))
        .expect("refresh the trust base history from the aggregator");
    session
}

#[test]
#[ignore = "hits the live testnet2 gateway"]
fn e2e_mint_transfer_verify() {
    let timeout = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
        + 3600;
    let (gateway, api_key) = read_service();

    let mut aggregator =
        HttpAggregatorClient::new(gateway).with_polling(Duration::from_secs(2), 90);
    if let Some(key) = api_key {
        aggregator = aggregator.with_api_key(key);
    }
    let session = open_session(&aggregator);
    let trust_base = session.history().expect("trust base history");

    let alice = Secp256k1Signer::generate().unwrap();
    let bob = Secp256k1Signer::generate().unwrap();

    let token = client::mint(
        &aggregator,
        trust_base,
        trust_base.network_id(),
        &SignaturePredicate::new(alice.public_key()),
        TokenType::random().unwrap(),
        TokenSalt::random().unwrap(),
        None,
        None,
        Some(timeout),
    )
    .expect("mint");
    token.verify(trust_base).expect("verify minted token");

    let transferred = client::transfer(
        &aggregator,
        trust_base,
        &token,
        &SignaturePredicate::new(bob.public_key()),
        &alice,
        StateMask::random().unwrap(),
        None,
        Some(timeout),
    )
    .expect("transfer");
    transferred
        .verify(trust_base)
        .expect("verify transferred token");

    println!(
        "transferred token CBOR: {}",
        hex::encode(transferred.to_cbor())
    );
}
