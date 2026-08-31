# Unicity State Transition SDK -- Rust

A Rust SDK for the Unicity token state-transition protocol.

The crate is `no_std`-first: the verification core has no C dependencies
(RustCrypto `sha2` + `k256`), is allocation-light, and runs inside a **zkVM
guest** (SP1 / RISC0) or on `wasm32`. The default build adds the necessary
client for minting and transferring tokens.

```toml
[dependencies]
unicity-token = "3.0"
```

The version line is shared with the TypeScript and Java SDKs: a 3.0.1 client
interoperates with `state-transition-sdk-js` 3.0.1 and
`state-transition-sdk-java` 3.0.1, and with an aggregator at
`ghcr.io/unicitynetwork/aggregator-go:sha-ae08165` or later.

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
    &recipient, token_type, salt, /* data */ None, /* justification */ None,
    /* expires_at */ None)?;
```

`expires_at` is the exclusive request deadline in Unix seconds. Use `None` to let the Unicity
Service assign a default one from consensus time, or explicitly `Some(deadline)`.

The SDK is generic over the `AggregatorClient` trait, so you can plug in any
transport (or an in-memory one for tests); `HttpAggregatorClient` is the
batteries-included blocking JSON-RPC implementation.
Inclusion polling accepts either way a server reports a leaf that is not
certified yet: an explicit `-32021` pending status, or a successful response
whose leaf fields are absent. `get_inclusion_proof.v2` never answers with a
non-inclusion proof, so the empty response is unambiguous. Only the explicit
status lets the client tell "not yet" apart from "no such state": against a
server that reports it, an unknown StateID fails immediately as
`HttpError::StateNotFound` rather than consuming the polling budget; against one
that does not, it polls to the attempt limit.

## Prove that a state is absent

```rust
use unicity_token::client::NonInclusionAggregatorClient;

let proof = aggregator.get_non_inclusion_proof(&state_id)?;
proof.verify(&trust_base)?; // verifies the StateId bound by the client
```

Verification authenticates the terminal leaf and every branch choice against
the quorum-signed SMT root, then checks that the terminal key differs from the
requested state id. A proof is a snapshot statement at its embedded certified
root; a caller that needs “still absent now” must separately enforce an
acceptable certified round or timestamp. The HTTP client distinguishes an
already-included state (`HttpError::StateIncluded`) from the absence of any
certified root (`HttpError::CertifiedStateUnavailable`).

If the caller does not know which relation holds, the HTTP client hides the
endpoint selection:

```rust
use unicity_token::client::MembershipStatus;

match aggregator.membership_status(&state_id)? {
    MembershipStatus::Included(proof) => proof.verify_for(&state_id, &trust_base)?,
    MembershipStatus::Absent(proof) => proof.verify(&trust_base)?,
}
```

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
cargo test                                         # default features
cargo test --all-features                          # adds the http transport tests
cargo test --no-default-features --features alloc  # verification core only
cargo build --no-default-features --features alloc --target wasm32-unknown-unknown
```

The cross-SDK fixture under [`tests/vectors/`](./tests/vectors) is generated by
the TypeScript SDK; see the README there before changing anything on the wire.

Live end-to-end test against an aggregator. It reads `e2e/.env` (copy
`e2e/.env.example` and set `UNICITY_API_KEY`), the same configuration the
examples and the `e2e/` demo crate use:

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

## Upgrading to 3.0

Tokens minted by earlier versions of this crate cannot be loaded, and this
release is the first that interoperates with the shipped TypeScript and Java
SDKs. Both changes are on the wire, so there is no migration path for tokens
already in circulation: they have to be re-minted.

### The certified leaf value binds the reference time

```
v = SHA-256( CBOR([ transactionHash, referenceTime ]) )
```

rather than the transaction hash alone, where `referenceTime` is the timestamp of
the consensus seal for the round the request was validated in. A 3.0 client
cannot verify proofs from an older service, and an older client cannot verify
proofs from a current one.

### Four wire versions move

| Structure | earlier | 3.0 |
|---|---|---|
| `Token` | 1 | **2** |
| `MintTransaction` | 1 | **2** |
| `TransferTransaction` | 1 | **2** |
| `CertificationData` | 1 | **2** |
| `InclusionProof` | 1 | 1 (unchanged) |

`Token` at version 2 and the two-element certified transaction below are
corrections: earlier builds of this crate encoded a version-1 token whose
certified transactions carried a third element, and neither shape was ever
readable by the TypeScript or Java SDKs. Anything this crate produced before 3.0
has to be re-minted regardless of which aggregator it was certified against.

### A certified transaction is two elements

`CertifiedMintTransaction` and `CertifiedTransferTransaction` encode
`[transaction, inclusionProof]`. The separate `referenceTime` slot is gone;
`reference_time()` reads it off the inclusion proof, which is the only copy
consensus certified.

### Requests can carry a deadline

`expires_at` is an exclusive request deadline in Unix seconds, taken as a
trailing `Option<u64>` by `client::mint`, `client::transfer`, `TokenSplit::split`
and the transaction constructors. The service admits a request only to a round
whose reference time is strictly below it, and answers a late one with
`REQUEST_EXPIRED`.

Pass `None` and the service assigns a deadline from consensus time instead. That
branch is for a caller with no trustworthy clock: the assigned value governs
admission but never enters the leaf, never alters the transaction hash, and is
never re-checked by a later verifier. An explicit deadline is the opposite: the
transaction hash commits to it, so it travels with the token and every verifier
checks it.

Both the deadline and a round's reference time are wall-clock Unix seconds, not
round numbers, and both are consensus time rather than any caller's clock. Leave
margin for the difference; hour-scale deadlines are unaffected, second-scale ones
are not.

There are no `*_with_timeout` constructors. Rust has no overloading and no
default arguments, and `Option` is how it spells optional, so the deadline is a
trailing parameter on the one constructor.

### What a deadline does not guarantee

Admission is enforced by the aggregator when it accepts the request. A later
verifier confirms that the leaf's recorded reference time is internally
consistent and precedes the deadline, but cannot establish *when* the leaf was
created: that value is chosen by the aggregator, and the inclusion proof
authenticates the value it chose rather than the moment it chose it. An
aggregator that accepted a request after its deadline and recorded an earlier
reference time produces a proof that verifies.

So `expires_at` is an instruction to an honest service, and the guarantee that a
late request is dropped rests on the same consensus that secures the aggregator.
Verification does reject a leaf claiming to postdate the round that certified it,
which is an impossible pairing, but that bound is one-sided and does not cover
back-dating. Tracked as unicitynetwork/aggregator-go#186.

### An inclusion proof describes a certified leaf, and nothing else

`InclusionProof` requires every field: `certification_data`, `reference_time` and
`inclusion_certificate` are no longer `Option`. The aggregator's answer for a
state it has not certified yet is not a proof at all, and
[`InclusionProofResponse`] carries that case:

```rust
pub enum InclusionProofResponse {
    Certified { block_number: u64, proof: InclusionProof },
    NotCertified { block_number: u64, unicity_certificate: UnicityCertificate },
}
```

The response owns the wire's two shapes: it decodes the tagged structure, decides
certified from not, rejects a partially present proof, and builds the
`InclusionProof` from the parts. `VerificationError::InclusionCertificateMissing`
and `VerificationError::CertificationDataMissing` are gone, because neither can
occur.

`AggregatorClient::get_inclusion_proof` still returns an `InclusionProof` rather
than the response: the polling contract already guarantees a certified leaf, and
an implementor signals "not yet" through its own error type. Decode an
aggregator's raw answer with `InclusionProofResponse::from_cbor`.

[`InclusionProofResponse`]: https://docs.rs/unicity-token/latest/unicity_token/api/inclusion_proof_response/enum.InclusionProofResponse.html

## License

MIT OR Apache-2.0.
