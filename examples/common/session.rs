//! The trust base session of the live examples (shared by `mint`, `transfer`, `split` and the consolidation examples).
//!
//! Verification is anchored in a trust-base *history* pinned to a known genesis. `open` opens a session for the network:
//!
//! | Variable | Meaning |
//! |---|---|
//! | `UNICITY_NETWORK` | `testnet2` (default) or `mainnet`: the history is the release pin embedded in the SDK |
//! | `UNICITY_LOCAL_BUNDLE` | path of a complete trust base bundle (`GET /api/v1/trustbases` from genesis to tip) of a local or private deployment, obtained through a channel you trust; it overrides `UNICITY_NETWORK` |
//!
//! After opening, `refresh` fetches the entries the release pin does not have yet from the aggregator (an untrusted source; every entry is verified
//! from the held tip). Pass `session.history()` to the verification APIs.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use unicity_token::api::bft::trust_base_cache::{
    Authority, MemoryStore, PinSpec, Session, SessionOptions,
};
use unicity_token::api::bft::trust_base_update::{TrustBaseSource, UpdateOptions};
use unicity_token::api::NetworkId;

struct Noop;
impl Wake for Noop {
    fn wake(self: Arc<Self>) {}
}

/// Drive a future to completion on this thread (the SDK chooses no executor; the in-memory store never waits on I/O).
pub fn block_on<F: Future>(f: F) -> F::Output {
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

/// Open the session for the configured network.
pub fn open() -> Session<MemoryStore> {
    let (network, authority) = match std::env::var("UNICITY_LOCAL_BUNDLE") {
        Ok(path) => {
            let bundle = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            let pin = PinSpec::from_bundle(&bundle).expect("a complete trust base bundle");
            (
                pin.network_id,
                Authority::local(&bundle).expect("local authority"),
            )
        }
        Err(_) => {
            let network = match std::env::var("UNICITY_NETWORK").as_deref() {
                Ok("mainnet") => NetworkId::MAINNET,
                Ok("testnet2") | Err(_) => NetworkId::TESTNET2,
                Ok(other) => panic!("UNICITY_NETWORK must be testnet2 or mainnet, not {other}"),
            };
            (network, Authority::Release)
        }
    };
    let (session, diagnostics) = block_on(Session::open(
        network,
        authority,
        MemoryStore::new(),
        SessionOptions::default(),
    ))
    .expect("open the trust base session");
    for d in diagnostics {
        eprintln!("trust base cache: {d:?}");
    }
    session
}

/// Fetch the entries after the held tip from `source` and keep them in the session. A failed refresh is reported and the entries held so far
/// are used: verification then fails with `UnknownTrustEpoch` only for a seal of an epoch that is still missing.
pub fn refresh(session: &mut Session<MemoryStore>, source: &dyn TrustBaseSource) {
    match block_on(session.refresh(&[source], &UpdateOptions::default())) {
        Ok(r) => eprintln!("trust base refresh: {} new entries", r.appended),
        Err(e) => eprintln!("trust base refresh failed: {e}"),
    }
}
