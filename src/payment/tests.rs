//! End-to-end token-split tests: build a payment-carrying token, split it,
//! mint each output with a [`SplitMintJustification`], and verify the outputs
//! against the trust base through the registered split verifier. Negative cases
//! confirm each split rule rejects its forgery.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use num_bigint::BigUint;

use super::{
    verify_payment_token, Asset, AssetId, PaymentAssetCollection, PaymentDataVerifier,
    SplitAssetProof, SplitMintJustification, SplitMintJustificationVerifier, SplitTokenRequest,
    TokenSplit,
};
use crate::api::bft::{
    InputRecord, RootTrustBase, RootTrustBaseNodeInfo, ShardId, ShardTreeCertificate,
    UnicityCertificate, UnicitySeal, UnicityTreeCertificate,
};
use crate::api::inclusion_proof::InclusionProof;
use crate::api::{CertificationData, InclusionCertificate, NetworkId, StateId};
use crate::crypto::hash::{sha256, DataHash};
use crate::crypto::signer::{Secp256k1Signer, Signer};
use crate::predicate::builtin::{BurnPredicate, SignaturePredicate};
use crate::predicate::unlock::sign_signature_unlock;
use crate::predicate::EncodedPredicate;
use crate::smt::bigint::key_to_path;
use crate::smt::plain::SparseMerkleTree;
use crate::smt::sum::SparseMerkleSumTree;
use crate::transaction::ids::{TokenSalt, TokenType};
use crate::transaction::{
    CertifiedMintTransaction, CertifiedTransferTransaction, MintTransaction, Minter, Token,
    Transaction, TransferTransaction,
};
use crate::verify::{
    verify_token_with_policy, MintJustificationRegistry, VerificationError, VerificationLimits,
    VerificationPolicy,
};

// --- proof construction (mirrors the verify-engine test harness) -----------

fn signer(b: u8) -> Secp256k1Signer {
    Secp256k1Signer::from_bytes(&[b; 32]).unwrap()
}

fn sig_pred(s: &Secp256k1Signer) -> EncodedPredicate {
    SignaturePredicate::new(s.public_key()).to_encoded()
}

fn node_info(s: &Secp256k1Signer, id: &str) -> RootTrustBaseNodeInfo {
    RootTrustBaseNodeInfo {
        node_id: id.to_string(),
        signing_key: s.public_key(),
        stake: 1,
    }
}

fn trust_base(node: &Secp256k1Signer) -> RootTrustBase {
    RootTrustBase::new(0, NetworkId::LOCAL, 0, 0, vec![node_info(node, "NODE")], 1)
}

fn empty_shard() -> ShardId {
    ShardId::decode(&[0b1000_0000]).unwrap()
}

fn mk_seal(hash: Vec<u8>, signatures: Vec<(String, Vec<u8>)>) -> UnicitySeal {
    UnicitySeal {
        network_id: NetworkId::LOCAL,
        root_chain_round_number: 0,
        epoch: 0,
        timestamp: 0,
        previous_hash: None,
        hash,
        signatures,
    }
}

fn leaf_root(state_id: &StateId, tx_hash: &DataHash) -> [u8; 32] {
    let mut preimage = vec![0x00u8];
    preimage.extend_from_slice(state_id.bytes());
    preimage.extend_from_slice(tx_hash.data());
    let mut root = [0u8; 32];
    root.copy_from_slice(sha256(&preimage).data());
    root
}

fn signed_uc(node: &Secp256k1Signer, root: [u8; 32]) -> UnicityCertificate {
    let input_record = InputRecord {
        round_number: 0,
        epoch: 0,
        previous_hash: None,
        hash: root.to_vec(),
        summary_value: Vec::new(),
        timestamp: 0,
        block_hash: None,
        sum_of_earned_fees: 0,
        executed_transactions_hash: None,
    };
    let mut uc = UnicityCertificate {
        input_record,
        technical_record_hash: None,
        shard_configuration_hash: vec![0u8; 32],
        shard_tree_certificate: ShardTreeCertificate {
            shard: empty_shard(),
            sibling_hash_list: Vec::new(),
        },
        unicity_tree_certificate: UnicityTreeCertificate {
            partition_identifier: 0,
            steps: Vec::new(),
        },
        unicity_seal: mk_seal(vec![0u8; 32], Vec::new()),
    };
    let seal_hash = uc.computed_seal_hash().unwrap().data().to_vec();
    let signature = node
        .sign(&mk_seal(seal_hash.clone(), Vec::new()).calculate_hash())
        .encode()
        .to_vec();
    uc.unicity_seal = mk_seal(seal_hash, vec![("NODE".to_string(), signature)]);
    uc
}

fn valid_proof(
    transaction: &impl Transaction,
    owner: &Secp256k1Signer,
    node: &Secp256k1Signer,
) -> InclusionProof {
    let tx_hash = transaction.calculate_transaction_hash();
    let state_id = StateId::derive(transaction.lock_script(), transaction.source_state_hash());
    let root = leaf_root(&state_id, &tx_hash);
    let unlock = sign_signature_unlock(owner, transaction.source_state_hash(), &tx_hash);
    let certification_data = CertificationData::new(
        transaction.lock_script().clone(),
        transaction.source_state_hash().clone(),
        tx_hash,
        unlock,
    );
    InclusionProof {
        certification_data: Some(certification_data),
        inclusion_certificate: Some(InclusionCertificate::decode(&[0u8; 32]).unwrap()),
        unicity_certificate: signed_uc(node, root),
    }
}

// --- scenario builders ------------------------------------------------------

fn asset_a() -> AssetId {
    AssetId::new(vec![0xAA; 32])
}
fn asset_b() -> AssetId {
    AssetId::new(vec![0xBB; 32])
}

/// Mint a source token to `owner` carrying `payment`, fully certified.
fn source_token(node: &Secp256k1Signer, owner: &Secp256k1Signer) -> Token {
    let payment = PaymentAssetCollection::create([
        Asset::new(asset_a(), BigUint::from(100u32)),
        Asset::new(asset_b(), BigUint::from(50u32)),
    ])
    .unwrap();
    let mint = MintTransaction::create(
        NetworkId::LOCAL,
        sig_pred(owner),
        TokenType::new(vec![0xC0; 32]),
        TokenSalt::from_bytes([0x01; 32]),
        Some(payment.to_cbor()),
        None,
    )
    .unwrap();
    let minter = Minter::signer(mint.token_id()).unwrap();
    let proof = valid_proof(&mint, &minter, node);
    Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new())
}

/// Wrap a burn transfer into a certified, burned source token.
fn burned_token(
    source: &Token,
    burn_tx: TransferTransaction,
    owner: &Secp256k1Signer,
    node: &Secp256k1Signer,
) -> Token {
    let proof = valid_proof(&burn_tx, owner, node);
    Token::new(
        source.genesis().clone(),
        vec![CertifiedTransferTransaction::new(burn_tx, proof)],
    )
}

/// Mint a split output token, certified, carrying its split justification.
fn mint_output(
    network: NetworkId,
    recipient: EncodedPredicate,
    token_type: TokenType,
    salt: TokenSalt,
    assets: &PaymentAssetCollection,
    justification: &SplitMintJustification,
    node: &Secp256k1Signer,
) -> Token {
    let mint = MintTransaction::create(
        network,
        recipient,
        token_type,
        salt,
        Some(assets.to_cbor()),
        Some(justification.to_cbor()),
    )
    .unwrap();
    let minter = Minter::signer(mint.token_id()).unwrap();
    let proof = valid_proof(&mint, &minter, node);
    Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new())
}

fn registry(_tb: &RootTrustBase) -> MintJustificationRegistry {
    let mut r = MintJustificationRegistry::new();
    r.register(Box::new(SplitMintJustificationVerifier::new()))
        .unwrap();
    for byte in [0xC0, 0xC1, 0xC2] {
        r.register_token_data(Box::new(PaymentDataVerifier::new(
            TokenType::new(vec![byte; 32]),
            authorize_test_payment,
        )))
        .unwrap();
    }
    r
}

fn authorize_test_payment(
    _genesis: &CertifiedMintTransaction,
    _assets: &PaymentAssetCollection,
) -> Result<(), VerificationError> {
    Ok(())
}

/// Build the full positive scenario, returning everything needed by the tests.
struct Scenario {
    tb: RootTrustBase,
    node: Secp256k1Signer,
    source: Token,
    alice: Secp256k1Signer,
    requests: Vec<SplitTokenRequest>,
}

fn scenario() -> Scenario {
    let node = signer(0x11);
    let alice = signer(0x22);
    let bob = signer(0x33);
    let carol = signer(0x44);
    let source = source_token(&node, &alice);

    let req1 = SplitTokenRequest::create(
        sig_pred(&bob),
        PaymentAssetCollection::create([
            Asset::new(asset_a(), BigUint::from(60u32)),
            Asset::new(asset_b(), BigUint::from(50u32)),
        ])
        .unwrap(),
        TokenType::new(vec![0xC1; 32]),
        TokenSalt::from_bytes([0x10; 32]),
    );
    let req2 = SplitTokenRequest::create(
        sig_pred(&carol),
        PaymentAssetCollection::create([Asset::new(asset_a(), BigUint::from(40u32))]).unwrap(),
        TokenType::new(vec![0xC2; 32]),
        TokenSalt::from_bytes([0x20; 32]),
    );

    Scenario {
        tb: trust_base(&node),
        node,
        source,
        alice,
        requests: vec![req1, req2],
    }
}

fn forged_single_asset_output(s: &Scenario, asset_id: AssetId, amount: u32) -> Token {
    let recipient = signer(0x55);
    let salt = TokenSalt::from_bytes([0x31; 32]);
    let token_type = TokenType::new(vec![0xC1; 32]);
    let token_id = crate::transaction::ids::TokenId::derive(NetworkId::LOCAL, &salt);
    let token_id_path = key_to_path(token_id.bytes());

    let mut asset_tree = SparseMerkleSumTree::new();
    asset_tree
        .add_leaf(
            token_id_path.clone(),
            asset_id.bytes().to_vec(),
            BigUint::from(amount),
        )
        .unwrap();
    let asset_root = asset_tree.calculate_root();
    let mut aggregation_tree = SparseMerkleTree::new();
    aggregation_tree
        .add_leaf(asset_id.to_path(), asset_root.hash().imprint())
        .unwrap();
    let aggregation_root = aggregation_tree.calculate_root();

    let (source_state_hash, lock_script) = s.source.latest_state();
    let burn = TransferTransaction::new(
        source_state_hash,
        lock_script,
        BurnPredicate::new(aggregation_root.hash().imprint()).to_encoded(),
        vec![9u8; 32],
        None,
    );
    let burned = burned_token(&s.source, burn, &s.alice, &s.node);
    let proof = SplitAssetProof::new(
        asset_id.clone(),
        aggregation_root.get_path(&asset_id.to_path()),
        asset_root.get_path(&token_id_path),
    );
    let justification = SplitMintJustification::create(burned, vec![proof]).unwrap();
    let assets =
        PaymentAssetCollection::create([Asset::new(asset_id, BigUint::from(amount))]).unwrap();
    mint_output(
        NetworkId::LOCAL,
        sig_pred(&recipient),
        token_type,
        salt,
        &assets,
        &justification,
        &s.node,
    )
}

// --- tests ------------------------------------------------------------------

#[test]
fn split_outputs_verify_end_to_end() {
    let s = scenario();
    assert_eq!(s.source.verify(&s.tb), Ok(()), "source token should verify");
    let registry = registry(&s.tb);
    assert_eq!(
        verify_payment_token(
            &s.source,
            &s.tb,
            &registry,
            PaymentAssetCollection::from_cbor_bytes,
        )
        .unwrap()
        .len(),
        2
    );

    let split = TokenSplit::split(
        &s.source,
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
    )
    .unwrap();

    let burned = burned_token(&s.source, split.burn.transaction.clone(), &s.alice, &s.node);
    assert_eq!(burned.verify(&s.tb), Ok(()), "burned token should verify");

    for out in &split.tokens {
        let just = SplitMintJustification::create(burned.clone(), out.proofs.clone()).unwrap();
        // Justification round-trips byte-for-byte.
        assert_eq!(
            SplitMintJustification::from_cbor(&just.to_cbor())
                .unwrap()
                .to_cbor(),
            just.to_cbor()
        );
        let token = mint_output(
            out.network_id,
            out.recipient.clone(),
            out.token_type.clone(),
            out.salt.clone(),
            &out.assets,
            &just,
            &s.node,
        );
        assert_eq!(
            token.verify_with(&s.tb, &registry),
            Ok(()),
            "split output should verify"
        );
        // Without the split verifier registered it is fail-closed.
        assert_eq!(
            token.verify(&s.tb),
            Err(VerificationError::UnsupportedMintJustification)
        );
    }
}

#[test]
fn payment_verification_requires_registered_payload_validator() {
    let s = scenario();
    assert_eq!(
        verify_payment_token(
            &s.source,
            &s.tb,
            &MintJustificationRegistry::new(),
            PaymentAssetCollection::from_cbor_bytes,
        ),
        Err(VerificationError::UnsupportedTokenData)
    );
}

#[test]
fn payment_verification_enforces_issuance_policy() {
    fn reject(
        _genesis: &CertifiedMintTransaction,
        _assets: &PaymentAssetCollection,
    ) -> Result<(), VerificationError> {
        Err(VerificationError::PaymentIssuanceRejected)
    }

    let s = scenario();
    let mut registry = MintJustificationRegistry::new();
    registry
        .register_token_data(Box::new(PaymentDataVerifier::new(
            TokenType::new(vec![0xC0; 32]),
            reject,
        )))
        .unwrap();
    assert_eq!(
        verify_payment_token(
            &s.source,
            &s.tb,
            &registry,
            PaymentAssetCollection::from_cbor_bytes,
        ),
        Err(VerificationError::PaymentIssuanceRejected)
    );
}

#[test]
fn recursive_split_verification_honors_shared_depth_limit() {
    let s = scenario();
    let split = TokenSplit::split(
        &s.source,
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
    )
    .unwrap();
    let burned = burned_token(&s.source, split.burn.transaction.clone(), &s.alice, &s.node);
    let out = &split.tokens[0];
    let justification = SplitMintJustification::create(burned, out.proofs.clone()).unwrap();
    let token = mint_output(
        out.network_id,
        out.recipient.clone(),
        out.token_type.clone(),
        out.salt.clone(),
        &out.assets,
        &justification,
        &s.node,
    );
    let policy = VerificationPolicy {
        limits: VerificationLimits {
            max_embedded_token_depth: 0,
            ..VerificationLimits::default()
        },
        require_token_data_verifier: false,
    };

    assert_eq!(
        verify_token_with_policy(&token, &s.tb, &registry(&s.tb), policy),
        Err(VerificationError::BurnTokenVerificationFailed(Box::new(
            VerificationError::VerificationLimitExceeded("embedded token depth")
        )))
    );
}

#[test]
fn rejects_inflated_sum_tree_built_without_split_builder() {
    let s = scenario();
    // Forge a tree claiming 1,000 units although the source owns only 100.
    let token = forged_single_asset_output(&s, asset_a(), 1_000);

    assert_eq!(
        token.verify_with(&s.tb, &registry(&s.tb)),
        Err(VerificationError::SplitSourceAmountMismatch)
    );
}

#[test]
fn rejects_asset_absent_from_burned_source() {
    let s = scenario();
    let token = forged_single_asset_output(&s, AssetId::new(vec![0xCC; 32]), 10);

    assert_eq!(
        token.verify_with(&s.tb, &registry(&s.tb)),
        Err(VerificationError::SplitSourceAssetMissing)
    );
}

#[test]
fn rejects_tampered_output_amount() {
    let s = scenario();
    let split = TokenSplit::split(
        &s.source,
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
    )
    .unwrap();
    let burned = burned_token(&s.source, split.burn.transaction.clone(), &s.alice, &s.node);
    let registry = registry(&s.tb);

    let out = &split.tokens[0];
    let just = SplitMintJustification::create(burned, out.proofs.clone()).unwrap();
    // Declare more of asset A than the proofs certify.
    let inflated = PaymentAssetCollection::create([
        Asset::new(asset_a(), BigUint::from(61u32)),
        Asset::new(asset_b(), BigUint::from(50u32)),
    ])
    .unwrap();
    let token = mint_output(
        out.network_id,
        out.recipient.clone(),
        out.token_type.clone(),
        out.salt.clone(),
        &inflated,
        &just,
        &s.node,
    );
    assert_eq!(
        token.verify_with(&s.tb, &registry),
        Err(VerificationError::SplitAssetAmountMismatch)
    );
}

#[test]
fn rejects_dropped_proof() {
    let s = scenario();
    let split = TokenSplit::split(
        &s.source,
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
    )
    .unwrap();
    let burned = burned_token(&s.source, split.burn.transaction.clone(), &s.alice, &s.node);
    let registry = registry(&s.tb);

    let out = &split.tokens[0]; // has two assets / two proofs
    let mut proofs = out.proofs.clone();
    proofs.pop(); // drop one proof while payment still declares two assets
    let just = SplitMintJustification::create(burned, proofs).unwrap();
    let token = mint_output(
        out.network_id,
        out.recipient.clone(),
        out.token_type.clone(),
        out.salt.clone(),
        &out.assets,
        &just,
        &s.node,
    );
    assert_eq!(
        token.verify_with(&s.tb, &registry),
        Err(VerificationError::SplitAssetCountMismatch)
    );
}

#[test]
fn rejects_wrong_burn_predicate() {
    let s = scenario();
    let split = TokenSplit::split(
        &s.source,
        PaymentAssetCollection::from_cbor_bytes,
        s.requests,
        Some([7u8; 32]),
    )
    .unwrap();
    let registry = registry(&s.tb);

    // Burn the source to an unrelated burn predicate (not the aggregation root).
    let (source_state_hash, lock_script) = s.source.latest_state();
    let wrong_burn = TransferTransaction::new(
        source_state_hash,
        lock_script,
        BurnPredicate::new(b"not-the-aggregation-root".to_vec()).to_encoded(),
        vec![7u8; 32],
        None,
    );
    let burned = burned_token(&s.source, wrong_burn, &s.alice, &s.node);
    assert_eq!(
        burned.verify(&s.tb),
        Ok(()),
        "the wrong burn still verifies on its own"
    );

    let out = &split.tokens[0];
    let just = SplitMintJustification::create(burned, out.proofs.clone()).unwrap();
    let token = mint_output(
        out.network_id,
        out.recipient.clone(),
        out.token_type.clone(),
        out.salt.clone(),
        &out.assets,
        &just,
        &s.node,
    );
    assert_eq!(
        token.verify_with(&s.tb, &registry),
        Err(VerificationError::SplitBurnPredicateMismatch)
    );
}

#[test]
fn rejects_unbalanced_split_at_build_time() {
    let s = scenario();
    let bob = signer(0x33);
    // Asset A totals 99, not the source's 100 -> value conservation fails.
    let bad = vec![SplitTokenRequest::create(
        sig_pred(&bob),
        PaymentAssetCollection::create([
            Asset::new(asset_a(), BigUint::from(99u32)),
            Asset::new(asset_b(), BigUint::from(50u32)),
        ])
        .unwrap(),
        TokenType::new(vec![0xC1; 32]),
        TokenSalt::from_bytes([0x10; 32]),
    )];
    assert!(TokenSplit::split(
        &s.source,
        PaymentAssetCollection::from_cbor_bytes,
        bad,
        Some([7u8; 32]),
    )
    .is_err());
}
