use std::env;
use std::error::Error;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use unicity_token::api::bft::trust_base_cache::{
    Authority, MemoryStore, PinSpec, Session, SessionOptions,
};
use unicity_token::api::bft::trust_base_update::UpdateOptions;
use unicity_token::api::bft::TrustBaseHistory;
use unicity_token::api::NetworkId;
use unicity_token::cbor::encode_text_string;
use unicity_token::client::{self, HttpAggregatorClient};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::transaction::ids::{StateMask, TokenSalt, TokenType};
use unicity_token::transaction::Token;

const DEFAULT_GATEWAY: &str = "https://gateway.testnet2.unicity.network/";
const DEFAULT_OUTPUT_DIR: &str = "artifacts";

fn request_timeout() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600)
}

fn main() -> Result<(), Box<dyn Error>> {
    // Load local development configuration without overriding variables that
    // were explicitly supplied by the process environment.
    let _ = dotenvy::dotenv();
    let config = Config::load()?;
    let gateway = HttpAggregatorClient::new(&config.gateway)
        .with_api_key(config.api_key)
        .with_polling(Duration::from_secs(1), 120);
    let session = open_session(&gateway);
    let trust_base = session.history()?;

    fs::create_dir_all(&config.output_dir)?;

    // These signers are the two local wallets. Private keys remain in memory;
    // only the corresponding public keys are displayed.
    let alice = Secp256k1Signer::generate()?;
    let bob = Secp256k1Signer::generate()?;
    let alice_lock = SignaturePredicate::new(alice.public_key());
    let bob_lock = SignaturePredicate::new(bob.public_key());

    println!("Gateway: {}", config.gateway);
    println!("Network ID: {}", trust_base.network_id().id());
    println!(
        "Alice public key: {}",
        hex::encode(alice.public_key().as_bytes())
    );
    println!(
        "Bob public key:   {}",
        hex::encode(bob.public_key().as_bytes())
    );

    println!("\nMinting token to Alice...");
    let minted = client::mint(
        &gateway,
        trust_base,
        trust_base.network_id(),
        &alice_lock,
        TokenType::random()?,
        TokenSalt::random()?,
        Some(encode_text_string("Rust SDK live e2e mint")),
        None,
        Some(request_timeout()?),
    )?;

    let minted_path = config.output_dir.join("token-minted.cbor");
    save_token(&minted_path, &minted)?;
    let minted = load_and_verify(&minted_path, trust_base)?;
    println!("Minted token ID: {}", hex::encode(minted.id().bytes()));
    println!("Saved and verified: {}", minted_path.display());

    println!("\nTransferring token from Alice to Bob...");
    let transferred = client::transfer(
        &gateway,
        trust_base,
        &minted,
        &bob_lock,
        &alice,
        StateMask::random()?,
        Some(encode_text_string("Rust SDK live e2e transfer")),
        Some(request_timeout()?),
    )?;

    let transferred_path = config.output_dir.join("token-transferred.cbor");
    save_token(&transferred_path, &transferred)?;
    let transferred = load_and_verify(&transferred_path, trust_base)?;

    let (_, current_lock) = transferred.latest_state();
    if current_lock != bob_lock.to_encoded() {
        return Err("transferred token is not locked to Bob".into());
    }
    if transferred.transactions().len() != 1 {
        return Err("transferred token does not contain exactly one transfer".into());
    }

    println!("Saved and verified: {}", transferred_path.display());
    println!("\nEnd-to-end flow completed; Bob owns the verified token.");
    Ok(())
}

struct Config {
    gateway: String,
    api_key: String,
    output_dir: PathBuf,
}

impl Config {
    fn load() -> Result<Self, Box<dyn Error>> {
        let gateway = env::var("UNICITY_GATEWAY")
            .ok()
            .unwrap_or_else(|| DEFAULT_GATEWAY.to_owned());
        let api_key = env::var("UNICITY_API_KEY")
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or("set UNICITY_API_KEY in .env or the process environment")?;

        Ok(Self {
            gateway,
            api_key,
            output_dir: env::var_os("UNICITY_OUTPUT_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_DIR)),
        })
    }
}

/// Drive a future to completion on this thread (the SDK chooses no executor; the in-memory store never waits on I/O).
fn block_on<F: Future>(f: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
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

fn save_token(path: &Path, token: &Token) -> Result<(), Box<dyn Error>> {
    fs::write(path, token.to_cbor())?;
    Ok(())
}

fn load_and_verify(path: &Path, trust_base: &TrustBaseHistory) -> Result<Token, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let token = Token::from_cbor(&bytes)?;
    token.verify(trust_base)?;
    Ok(token)
}
