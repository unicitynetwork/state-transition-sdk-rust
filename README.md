# Unicity State Transition SDK -- Rust

A Rust SDK for the Unicity token state-transition protocol.

The crate is `no_std`-first: the verification core has no C dependencies
(RustCrypto `sha2` + `k256`), is allocation-light, and runs inside a **zkVM
guest** (SP1 / RISC0) or on `wasm32`. The default build adds the necessary
client for minting and transferring tokens.

```toml
[dependencies]
unicity-token = "0.1"
```

## Security model

Decoding a token proves its structural integrity only. Trust is established only by
`Token::verify`, which walks an unbroken chain of cryptographic checks from a
caller-supplied root of trust down to every state in the token's history.

`Token::verify` treats application `data` and any mint *justification* as
**opaque** and rejects a token that carries either — unless you explicitly
register a verifier for it. There is no implicit trust in the API.

The root of trust is the Unicity Trust Base json. An authentic trust base must
be bundled with the application or left user-configurable.

## Verify a token (`no_std` core, no features needed)

```rust
use unicity_token::Token;
use unicity_token::api::bft::RootTrustBase;

// Root of trust (validator set + quorum), supplied out-of-band.
let trust_base = RootTrustBase::from_json(trust_base_json)?; // ::new(..) in no_std

let token = Token::from_cbor(&token_bytes)?; // decoding confers NO trust
token.verify(&trust_base)?;                  // verifies the cryptographic history
```

## Mint & transfer against a live aggregator (`http` feature)

```rust
use std::time::Duration;
use unicity_token::api::bft::RootTrustBase;
use unicity_token::client::{self, HttpAggregatorClient};

let trust_base = RootTrustBase::from_json(&std::fs::read_to_string("trust-base.json")?)?;
let aggregator = HttpAggregatorClient::new("https://gateway.testnet2.unicity.network/")
    .with_api_key("sk_…")
    .with_polling(Duration::from_secs(2), 90);

let token = client::mint(&aggregator, &trust_base, trust_base.network_id,
    &recipient, token_type, salt, /* data */ None, /* justification */ None)?;
```

The SDK is generic over the `AggregatorClient` trait, so you can plug in any
transport (or an in-memory one for tests); `HttpAggregatorClient` is the
batteries-included blocking JSON-RPC implementation.

## Payment tokens & splits

A token can carry a fungible **payment payload** (a canonical set of asset id →
amount entries) in its mint `data`, and can be **split** into new tokens whose
per-asset allocations sum to the original. Splitting burns the source and proves
each output's share with a radix sparse Merkle sum tree (RSMST) inclusion proof.

Payment verification is **fail-closed and policy-gated** — cryptographic
validity never authorizes an asset issuer on its own. You register the verifiers
and issuance policy you trust, then call `payment::verify_payment_token` instead
of bare `Token::verify`:

```rust
use unicity_token::payment::{
    verify_payment_token, PaymentAssetCollection, PaymentDataVerifier,
    SplitMintJustificationVerifier,
};
use unicity_token::verify::MintJustificationRegistry;

// `authorize` is your closure: given the genesis + decoded assets, decide
// whether this issuance is allowed (issuer key, supply caps, …).
let mut registry = MintJustificationRegistry::new();
registry
    .register(Box::new(SplitMintJustificationVerifier::new()))?         // accept split outputs
    .register_token_data(Box::new(PaymentDataVerifier::new(            // validate the payload…
        my_token_type, authorize)))?;                                  // …then run *your* policy

let assets = verify_payment_token(
    &token, &trust_base, &registry, PaymentAssetCollection::from_cbor_bytes,
)?; // returns the validated assets; fails closed if anything is off
```

Constructing a split is a `client`-feature operation
(`payment::TokenSplit::split`) that verifies the source token fully before
building the irreversible burn. See `src/payment/tests.rs` for the end-to-end
split → verify flow.

## Feature flags

| Flag | Default | Purpose |
|------|:-------:|---------|
| `alloc` | (transitive) | Required by the core (`Vec`/`BTreeMap` for CBOR + structures). |
| `std` | y | std error integration, host RNG, JSON trust-base parsing. |
| `client` | y | Transaction construction, signing, mint/transfer flow, split construction. |
| `http` | | Blocking JSON-RPC `HttpAggregatorClient` (host only; pulls in a TLS stack). |

Payment/asset **verification** is provided by `no_std` core and needs no feature.
The zkVM/WASM guest build is `--no-default-features --features alloc`.

## Building & testing

```sh
cargo test                                         # full suite (host)
cargo test --no-default-features --features alloc  # verification core only
cargo build --no-default-features --features alloc --target wasm32-unknown-unknown
```

Live end-to-end test against an aggregator (config in `e2e/`):

```sh
cargo test --features http --test e2e -- --ignored --nocapture
```

## Examples

Runnable flows in [`examples/`](./examples), talking to a live aggregator via
`HttpAggregatorClient` (config from `e2e/.env`):

```sh
cargo run --example mint     --features http   # mint a token, print its CBOR
cargo run --example transfer --features http   # mint then transfer
cargo run --example split    --features http   # mint a coin, split it, verify outputs
```

A self-contained demo application is provided under [`e2e/`](./e2e).

## Regenerating cross-SDK fixtures

```sh
cd ../state-transition-sdk-js && npm install && npm run build
node generate-fixtures.mjs > tests/vectors/transition_flow.json
```

## License

MIT OR Apache-2.0.
