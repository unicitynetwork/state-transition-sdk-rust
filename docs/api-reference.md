# Unicity State Transition SDK for Rust: API Reference

This document describes SDK behaviour that the README only summarizes. The rustdoc comments in the source are authoritative.

## 1. Waiting for Inclusion Proofs

### Status hints

`HttpAggregatorClient` asks the aggregator for a status hint (`includeStatus` on `get_inclusion_proof.v2`). While waiting for a proof:

- `pending`: polling continues at the configured interval.
- `expired`: the wait stops at once with `HttpError::StateExpired`. The same signed request may be resubmitted.
- `unknown`: the wait stops with `HttpError::StateUnknown` after a grace period (`with_unknown_grace`, default two answers). Right after a submission, another aggregator instance may not have seen the request yet.

`lookup_inclusion_proof` returns the hint together with the response, without waiting. Servers without the feature answer with a plain string and the client behaves as before; the same applies to status values this version does not know.

The hint is unauthenticated and is used only for control flow and user feedback. `unknown` does not show that a state was never certified or is unspent, and `expired` does not show that it is unspent. An `included` hint has no value without a proof that verifies. A certified proof is returned regardless of the hint, and no token, proof or certificate verification depends on it.

With several aggregator instances behind a load balancer, an instance that did not admit the request may answer `unknown`. After a restart, the in-memory status is empty, so queued requests answer `unknown` until a round picks them up.

### Long polling

`client::mint` and `client::transfer` wait for the proof through `HttpAggregatorClient::get_inclusion_proof`, which by default asks the aggregator to hold each request while the state is pending (`waitMs`). This reduces the number of requests and returns the proof soon after certification. With long polling on, `with_polling(interval, attempts)` sets the polling interval and a total time budget of `interval * attempts` (default 1 s × 15 = 15 s, for both the long-poll and the attempts-loop path). `HttpAggregatorClient::with_long_poll(false)` restores the attempt-based loop, which sends no `waitMs`. The same wait is available directly as `wait_for_inclusion_proof(&state_id, &WaitOptions::new(total))`, with these options:

- The wait never exceeds `total`. Each request asks for at most the preferred wait (`with_preferred_wait`, default 20 s) and leaves a response margin (`with_margin`, default 2 s) within the remaining time and the per-call limit (`with_max_request_timeout`, default 30 s).
- `WaitOptions::with_long_poll(false)` sends no `waitMs` and polls at the interval (`with_poll_interval`, default the client's interval).
- An answer without the `waitedMs` echo to a request that asked for a wait means the server does not support long polling; the rest of that call polls at the interval. Nothing is remembered across calls.
- The echo is unauthenticated and never extends the deadline. The returned proof is unverified, as with `get_inclusion_proof`.
- `with_unknown_grace` overrides the client's `unknown` grace for this wait. `with_cancel` is checked before every call and during pauses; a call already in flight ends at its own timeout, because a blocking transport cannot be interrupted.
- A transport-level failure of a proof read inside a wait (refused or reset connection, stale pooled connection, one call timing out inside the budget, truncated response, an interrupted 502/503/504 body) is inconclusive too: plain reads at the interval within the original budget (a pause that does not fit the time left ends the wait as `HttpError::Timeout`, like JS `waitInclusionProof`; `OverloadTimeout` is only for an overload answer, never for an unreachable aggregator); TLS certificate/hostname failures, invalid URLs and cancellation stay terminal, submissions are never replayed and one-shot calls surface the error. HTTP 502 and 504 inside a wait are inconclusive like an overload (plain reads for the rest of the wait, original budget, no resubmission); the status counts even when the body is not JSON or exceeds the error-body limit, and one-shot calls still return the error. `Retry-After` accepts delay-seconds and HTTP-date, capped at 60 s. A gateway's HTTP 400 for a batch spanning shards keeps its `-32602` classification (not the retry-without-`waitMs` case).
- An overload answer (HTTP 503 or 429, JSON-RPC `-32006`, or `data.retryable: true`) is not a failure: the wait pauses the larger of the interval and `Retry-After` (at most 60 s) and then sends plain reads without `waitMs`, or fails at once with `HttpError::OverloadTimeout` (the overload as `source`) when that pause does not fit the time left. The same holds for the attempts loop.
- `waitedMs` is accepted only in the answer to a request that sent `waitMs`; an echo to any other request in a result is a protocol error (`HttpError::Decode` / `BatchFailure::Decode`), malformed or not. An unsolicited `error.data.waitedMs` is ignored, even if malformed, and the error keeps its classification (a `-32006` stays a retryable busy answer). Both as in JS. A pending answer, including a legacy `-32021` error, resets the `unknown` grace count. With a zero poll interval the 10 ms pause floor still applies after a positive echo. `MasterLongPoll::max_request_ms` bounds the call: a waiting batch call times out at `min(remaining, wait + margin)`.
- `wait_for_inclusion_proof_with_stats` also returns request counts (`WaitStats`).

For batches, `BatchAggregatorClient::get_inclusion_proofs_with_wait(&request, &options, &WaitRequest::new(wait_ms))` applies the wait to a latest-root request; it is never sent for an exact root. `get_latest_negotiating_wait` repeats the request once without `waitMs` when a server rejects the unknown field as `malformed_params`. Consolidation waits only when enabled with `ProofClient::with_master_long_poll(MasterLongPoll::default())`, and then only on the master's latest request.

### Resubmission

A certification request is signed and deterministic, so sending it again is the same request; the aggregator never creates a second leaf for it.

`resubmit_certification_request` is the idempotent form of submission. It returns `SubmitOutcome::AlreadySubmitted` instead of an error when the aggregator already holds a record for the state ID. The server reports this in two ways:

- A MongoDB-backed queue rejects a copy of a still-pending request with an internal error (code `-32603`) whose data names a duplicate key. The client recognizes it by that text, since the server has no dedicated code for it. A Redis-backed queue accepts and drops the copy.
- `STATE_ID_EXISTS` when the state is already certified.

Both reports are by state ID only, so a different request for the same state, such as a conflicting spend, is reported the same way. Every other rejection, such as `REQUEST_EXPIRED`, remains an error. The plain `submit_certification_request` reports both duplicate responses as errors.

`submit_and_wait(data, max_resubmits)` combines submission, waiting, and at most `max_resubmits` resubmissions after `StateUnknown` or `StateExpired`. It requires the proof to certify exactly the submitted data. If the state ID was certified with another request, it fails with `HttpError::ProofOfOtherData` (based on unauthenticated data; no resubmission) instead of returning the other transaction's proof. `submit_and_wait_verified(data, max_resubmits, &trust_base)` authenticates that proof first and reports `HttpError::StateCertifiedWithOtherData` only if it verifies.

## 2. Aggregation Partition

All Unicity networks use one aggregation partition, exported as `unicity_token::AGGREGATION_PARTITION_ID` (`u32`, value `7`; also `unicity_token::api::AGGREGATION_PARTITION_ID`). It is a protocol constant: there is no environment, constructor or per-network override, and a proof never selects its own expected partition. Network authentication remains mandatory; the trust base fixes the network, authority and epoch.

Every application verification path requires the authenticated unicity certificate to be of this partition and otherwise fails with `VerificationError::PartitionMismatch`. This covers inclusion verification, token verification (genesis, transfers and nested source tokens), non-inclusion verification, and consolidation (input proofs, partition views, enclosing certificates and the unsharded direct target). The check runs before the seal memo is consulted, so a cached seal cannot carry a certificate of another partition. Generic codecs (`UnicityTreeCertificate`, `PartitionView::from_cbor`) are partition-agnostic and do not by themselves establish validity.

## 3. Partition Views and Seal Reuse

`unicity_token::consolidation` (`no_std + alloc`, no network access) decodes a `PartitionViewV1`, the complete shard-leaf vector of a partition under one unicity seal, as an untrusted candidate. `PartitionView::authenticate`:

1. validates its structure;
2. rebuilds the shard tree;
3. follows the enclosing certificate's partition path to the seal hash and matches the enclosing leaf exactly;
4. authenticates the complete seal under the caller's `TrustAnchor` (a session history for epoch-aware verification) (network, exact epoch, round at or after the epoch start, quorum).

Only then does it return an immutable `AuthenticatedView`, the only input accepted by `certificates()`, which yields ordinary unicity certificates for every shard, all carrying the same seal. No peer configuration list is needed, because the seal commits to every leaf's configuration hash. Independently pinned shard configuration hashes (`Some(&PartitionTopology)`) are an optional stricter policy and are part of `AuthenticatedView::identity()`. The authority is never taken from a response.

Token verification authenticates each distinct seal once per operation (`verify::SealSession`, a bounded memo of successful quorum checks bound to one trust base). Only the quorum signature check is reused; paths, reference times, predicates and application rules are checked for every proof. `verify::verify_token_with_seal_stats` reports the signature work performed. Seal reuse does not change token size or format, and nested proofs that carry other seals still need their own check.

## 4. Proof Consolidation

With the `client` feature, `client::ProofClient::consolidate(&token, &options)` returns a new, fully verified token whose replaceable outer-history proofs share one unicity seal. This reduces verification cost where a verifier reuses a successful quorum check, for example in a smart contract or a zkVM guest.

Properties:

- It is only called explicitly. Mint, transfer, receive, import, serialization and `Token::verify` do not call it.
- It needs no signing key and never submits or resubmits a transaction.
- Token format and size do not change. Proofs nested in signed mint justifications or split and burn dependencies stay byte-identical and may still need their own seals; the summary reports outer-history and whole-verification quorum checks separately.

An attempt asks the master shard (the one with the newest authenticated evidence) for its latest batch and partition view, authenticates it under the caller's trust base and configured topology, then fetches the exact roots named by the authenticated view from the other participating shards (in bounded parallel on a host). All requests run under one deadline and one `CancelToken`. The batch call is the optional `client::BatchAggregatorClient` capability (`get_inclusion_proofs.v1`), implemented by `HttpAggregatorClient`; it is never emulated with single-proof calls.

Results:

- `Consolidated` with the new token.
- `Unavailable { reason, retryable }` for a missing capability, a view that is not retained or not yet published, or a busy service. The original token is unchanged.
- An error for integrity failures, transport and server failures, timeouts and cancellation.

Status details from the shards map to `UnavailableReason::StatePending` (retryable), `StateExpired`, `StateUnknown` and `StateNotInRoot` (not retryable).

Examples: `examples/consolidate_for_bridge.rs` and `examples/consolidate_for_zkvm.rs`. Planning and checked reconstruction (`consolidation::{ShardRouter, outer_proofs, rebuild_token, ..}`) are `no_std + alloc`.

## 5. Non-inclusion Proofs

> Non-inclusion proves absence only at the authenticated snapshot returned by verification. It does not prove absence now, continuous absence, or that a token can be spent. Compare the snapshot’s network and root round (or its certified seal timestamp under your application’s time policy) with an independently trusted requirement. The seal timestamp is a consensus-certified time, not proof of real-time freshness. Do not use unverified response metadata for this check.

`AggregatorClient::get_non_inclusion_proof(&state_id)` fetches a proof; it is unverified.

`NonInclusionProof::verify_at_snapshot(&trust_base, &context)` (also `verify_for_at_snapshot` for a directly decoded proof, and `verify::verify_non_inclusion_at_snapshot` / `verify_non_inclusion_in` for explicit sessions) authenticates the unicity certificate before it returns anything: shape, trusted network, authority and epoch interval, quorum, the aggregation partition, the shard and partition commitments together with the optional pins of the `NonInclusionContext`, the query binding and the full state-tree relation. The result is:

- `Ok(NonInclusionOutcome::AbsentAtSnapshot { state_id, snapshot })`: the path proves the key absent.
- `Ok(NonInclusionOutcome::IncludedAtSnapshot { state_id, snapshot })`: the path proves that exact key present.
- `Err(VerificationError)`: rejected; no snapshot metadata.

`NonInclusionSnapshot` exposes `network_id`, `partition_id`, `shard_id`, `root_round`, `seal_timestamp_seconds` (Unix seconds), `root_epoch`, `shard_round`, `shard_epoch` and `state_root` (`None` for the certified empty tree). All values are read from the authenticated certificate, not from the RPC block number or the time of receipt. The snapshot owns copies of its data.

There is no freshness option. Freshness is the application's decision on the returned snapshot, against a checkpoint obtained independently of the proof and the server response:

```rust
// `checkpoint` is obtained independently of the proof and of the server response.
let outcome = proof.verify_at_snapshot(&trust_base, &NonInclusionContext::new())?;
let NonInclusionOutcome::AbsentAtSnapshot { snapshot, .. } = outcome else {
    return Err("no verified absence".into());
};
if snapshot.network_id().id() != checkpoint.network_id
    || snapshot.root_round() < checkpoint.required_root_round
{
    return Err("snapshot does not meet application policy".into());
}
// Absence at `snapshot` only; any spend or finality decision needs its own policy.
```

`NonInclusionContext::new()` expects the unsharded partition, where the certificate's shard is the empty shard; this matches the Go verifier with an empty `Shard`. For a sharded partition, pin the served shard with `NonInclusionContext::new().with_shard(shard)`. The certificate's shard ID and complete shard path must then be that shard's, and the query and terminal must belong to it. Because the certificate is authenticated first, a rejection reflects the certificate before the path is examined.

`NonInclusionProof::for_state` only records which state ID a proof was requested for. It is request bookkeeping, not evidence.

`HttpError::StateIncluded` reports the server's claim that the state is included. The claim is unauthenticated; request an inclusion proof and verify it.

## 6. Trust-base Sessions

The `api::bft` modules provide V2 trust-base entries and an append-only history. Token verification accepts a `TrustAnchor`; pass the history of an open session so each seal is checked against its own epoch's committee and round interval. Opening verifies the release pin and cached history locally; it makes no HTTP request.

### Public and local setup

The following runs inside an application's async function; the SDK does not choose an executor:

```rust
use unicity_token::api::NetworkId;
use unicity_token::api::bft::trust_base_cache::{Authority, MemoryStore, Session, SessionOptions};

let (mut session, diagnostics) = Session::open(
    NetworkId::TESTNET2, // NetworkId::MAINNET for mainnet.
    Authority::Release,
    MemoryStore::new(),
    SessionOptions::default(),
).await?;
// Pass session.history()? to Token::verify and other verification APIs.
```

For a local/private deployment, obtain a complete bundle through authenticated operator configuration, then use:

```rust
use unicity_token::api::bft::trust_base_cache::PinSpec;

// deployment_bundle: &[u8], authenticated independently of an untrusted server response.
let pin = PinSpec::from_bundle(deployment_bundle)?;
let (local, diagnostics) = Session::open(
    pin.network_id, Authority::local(deployment_bundle)?,
    MemoryStore::new(), SessionOptions::default(),
).await?;
```

`Authority::local` derives the pins from the supplied bundle and uses namespace `local`. It deliberately chooses that deployment as the authority, without public release-lineage checks; never use an arbitrary downloaded bundle this way to authenticate mainnet. For an explicit private namespace/pin use `Authority::Custom { namespace, pin }`; the namespace must be 1–64 bytes, contain no `/`, and differ from `public`. Chain and signature checks still apply.

`RELEASE_PINS` embeds mainnet (1) and testnet2 (4) genesis-to-release-tip bundles with genesis/checkpoint EntryIDs, epochs and bundle SHA-256. `Authority::ReleaseOverride(pin)` must extend the built-in checkpoint. `Session::open_in` with another table is for tests/release tooling. An unknown public network or invalid release pin is fatal, never rescued by a cache. Release assets and `release-pins/manifest.json` are checked against the generated table by `tests/release_pins.rs`.

### Refresh and verification failures

With the `http` feature, `HttpAggregatorClient` implements `trust_base_update::TrustBaseSource`, reading bounded CBOR from `GET /api/v1/trustbases` on the gateway origin. The source is untrusted transport. Given the client from the README:

```rust
use unicity_token::api::bft::trust_base_update::UpdateOptions;
let refreshed = session.refresh(&[&aggregator], &UpdateOptions::default()).await?;
// Inspect refreshed.flush: a successful fetch can still leave a pending cache save.
```

The HTTP source is blocking even though session storage is async; run it off an async runtime's event-loop thread. `UpdateOptions` controls passes (default 2), backoff (200 ms), page limits and cancellation. The caller supplies `pause` to implement backoff; the default `None` retries immediately. Pagination freezes the first response's end epoch/EntryID, echoes it on later pages, and continues the same cursor across sources. Every accepted entry extends the held history cryptographically. A source saying `NotYetAvailable`, or a zero-entry update, does not authenticate freshness.

`VerificationError::UnknownTrustEpoch` is the typed missing-future-entry failure; a seal before genesis, outside its epoch interval, of another network or with bad signatures is not repaired by fetching a new authority. Plain verification never fetches. `trust_base_update::verify_with_update` offers one update/retry for a mutable history; it has no store. For sessions, refresh on the typed failure and verify again against `session.history()?` before accepting. `refresh` attempts to save even a valid prefix followed by a failed page; `RefreshError::Update` carries both the update error and flush result.

### Store, merge and conflicts

`trust_base_cache::TrustBaseStore` has async `read(key, max_bytes)` and `compare_and_swap(key, expected, bytes)`. Read returns `StoreRead::Absent` or a coherent `Present` snapshot with bytes and revision. Enforce bounds before allocation; CAS must atomically compare and replace across all sharing writers, returning `StoreCas::Written` or `Changed`. Revisions are not authentication. The key is `utb/v1/<network>/<genesis EntryID hex>/<namespace>`; the application chooses user scope, location and refresh policy.

`MemoryStore` is volatile and single-threaded. With `file-cache`, `trust_base_file_store::FileStore::new(directory)` supplies the optional host adapter; the core remains `no_std + alloc`. It uses a lock directory and a synced temporary file with atomic rename. Busy locks fail immediately and are never stolen, including after a crash; the operator must establish that no writer owns a stale lock before removing it.

All cache entries are re-verified from genesis. A compatible longer cache extends the release history; a newer pin extends a shorter cache. Damage/unreadability falls back to embedded history with diagnostics. Oversize or authenticated checkpoint-conflicting caches are not overwritten. `flush().await` re-reads and validates, imports a longer compatible suffix, and saves the whole bundle with at most four CAS attempts. `Flush::Pending` leaves verified memory usable and unsaved progress dirty. A clean flush does not rescan the store; reopen to discover another writer's changes.

`Session::append`/`merge_bundle` never replace a held entry. An authenticated fork after the pinned checkpoint latches the session (`SessionError::Conflict`, then `SessionError::HistoryConflicted`); `history()` stops being usable for verification. Invalid offers do not latch it, and the pin settles discrepancies within its prefix. `conflict()` and `export_bundle()` expose evidence. The latch is process-local: recording/reporting it is the application's responsibility, not a promise of an untrusted cache surviving deletion.

### Codec, history and resource budgets

`TrustBaseEntry::from_cbor`/`to_cbor` handles deterministic tag 39000, version 2. `entry_id()` hashes unsigned bytes, independent of the witness signatures. `TrustBaseHistory::from_bundle(bytes, Some(genesis_id))` authenticates a complete tag-39015 bundle; `parse_bundle` only decodes it and does not authenticate signatures. A complete bundle starts at genesis, has no gaps and no continuation, and ends at its stated tip. `to_bundle()` exports the entire history. `append` checks network, consecutive epoch, previous EntryID, increasing start round and the predecessor's weighted quorum. All supplied entry signatures must be valid known-member 65-byte low-S recoverable signatures; invalid extras reject the entry. This is separate from seal verification rules.

| Resource | Limit |
| --- | --- |
| Members / supplied entry signatures | 256 / 256 |
| Node ID / encoded entry | 128 UTF-8 bytes / 128 KiB |
| `trust_base_range::PAGE_LIMITS` | 64 entries / 1 MiB |
| `BundleLimits::default()` | 4,096 entries / 16 MiB / 128 KiB per entry |

`SessionOptions.limits` can change bundle budgets; exceeding them never prunes old epochs. Keep old entries for old tokens. `TrustBaseError`, `HistoryError`, `RangeError`, `CacheError` and `SessionError` distinguish decoding, chain, page, pin/storage and session failures. `RootTrustBase` remains a single-authority API; the repository's existing JSON-based examples do not establish cross-epoch verification.
