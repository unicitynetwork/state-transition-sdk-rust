# Unicity State Transition SDK - Rust

A Rust SDK for the Unicity token state-transition protocol.

The crate is ready to **cryptographically verify token histories inside a
zkVM guest** (SP1 / RISC0) or `wasm32`, so the core is `no_std`, allocation-light,
and free of C dependencies (RustCrypto `sha2` + `k256`).

Token creation expects `client` and `http` features. Async `AggregatorClient`
has to be provided by the user.

## Usage

```rust
use unicity_token::Token;
use unicity_token::api::bft::RootTrustBase;

// The root of trust (validator set + quorum), supplied out-of-band.
let trust_base = RootTrustBase::from_json(trust_base_json)?; // host; or ::new(..) in no_std

let token = Token::from_cbor(&token_bytes)?;   // decoding confers NO trust
token.verify(&trust_base)?;                     // verifies cryptographic history
```

`Token::verify` establishes the cryptographic chain of custody but deliberately
treats application `data` (and any mint *justification*) as opaque — a mint that
carries either is rejected unless you opt in to a verifier for it.

## Payment, assets & token split

A token can carry a fungible **payment payload** — a `PaymentAssetCollection`
(asset id → amount) — in its mint `data`, and a token can be **split** into
several new tokens whose assets sum to the original. The source token is burned
to an aggregation-tree root, and each output's genesis carries a
`SplitMintJustification` (CBOR tag 39044) proving its share.

Verifying payment tokens is **fail-closed and policy-gated**: cryptographic
certification alone never authorizes an asset issuer, so you must register the
verifiers you trust and call `payment::verify_payment_token` (not bare
`Token::verify`):

```rust
use unicity_token::payment::{
    verify_payment_token, PaymentAssetCollection, PaymentDataVerifier,
    SplitMintJustificationVerifier,
};
use unicity_token::verify::{MintJustificationRegistry, VerificationError};
use unicity_token::transaction::CertifiedMintTransaction;

// Your application's issuance policy: is this genesis allowed to mint this
// payload? (Cryptographic validity is necessary but not sufficient.)
fn authorize(genesis: &CertifiedMintTransaction, assets: &PaymentAssetCollection)
    -> Result<(), VerificationError> { /* check issuer key, supply, … */ Ok(()) }

let mut registry = MintJustificationRegistry::new();
registry
    // accept tokens minted as outputs of a split:
    .register(Box::new(SplitMintJustificationVerifier::new()))?
    // validate the fungible payload for your token type + run your policy:
    .register_token_data(Box::new(PaymentDataVerifier::new(my_token_type, authorize)))?;

// Returns the validated assets; errors fail-closed if anything is off.
let assets = verify_payment_token(
    &token, &trust_base, &registry, PaymentAssetCollection::from_cbor_bytes,
)?;
```

Constructing a split (mint → split → mint outputs) is a `client`-feature
operation via `payment::TokenSplit::split`. The verifier independently re-checks
value conservation, so client-side construction is untrusted. The split proofs
ride on bigint-routed sparse Merkle trees in the `smt` module; their decoding is
bounded by the `MAX_SMT_*` limits and the cumulative `VerificationPolicy` /
`VerificationLimits` (embedded-token depth and byte budgets) to stay safe on
attacker-controlled input. See `src/payment/tests.rs` for an end-to-end example.

## Feature Flags

- `std` *(default)* — std error integration, host RNG, JSON trust-base parsing.
- `client` *(default)* — transaction construction, signing, the mint/transfer
  flow over a caller-supplied [`AggregatorClient`] transport, and token-split
  construction (`payment::TokenSplit`). Payment/asset *verification* is in the
  `no_std` core and needs no feature.
- `http` — a blocking JSON-RPC [`HttpAggregatorClient`] for talking to a live
  aggregator/gateway (pulls in a TLS HTTP stack; host only).
- `alloc` — required by the core; enabled transitively.

### Connecting to a live aggregator

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

A live end-to-end test is in `tests/e2e.rs` (reads `e2e/`):

```sh
cargo test --features http --test e2e -- --ignored --nocapture
```

Independent demo application is under `./e2e/`.

The zkVM/WASM guest build is `--no-default-features --features alloc`: pure
`no_std` decode + verify.

## Building

```sh
cargo test                                         # full suite (host)
cargo test --no-default-features --features alloc  # verification core
cargo build --no-default-features --features alloc --target wasm32-unknown-unknown
```

## Examples

Runnable example flows (see [`examples/`](./examples)):

```sh
cargo run --example mint  --features http   # mint a token, print its CBOR
cargo run --example transfer --features http # mint then transfer, print the CBOR
cargo run --example split --features http     # mint a coin, split it, verify outputs
```

The `mint`/`transfer`/`split` examples talk to a live aggregator via
[`HttpAggregatorClient`] (config from `e2e/.env`). For a transport-agnostic
in-memory flow, the SDK is generic over the `AggregatorClient` trait. The
[Payment, assets & token split](#payment-assets--token-split) section and
`src/payment/tests.rs` cover the split → verify flow end-to-end.

There is a self-contained application under `e2e/`.

## Regenerating cross-SDK fixtures

```sh
cd ../state-transition-sdk-js && npm install && npm run build
node generate-fixtures.mjs > tests/vectors/transition_flow.json
```

## License

MIT OR Apache-2.0.
