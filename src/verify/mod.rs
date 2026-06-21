//! The verification engine: establishes an unbroken chain of cryptographic
//! checks from the [`RootTrustBase`] down to every state in a token's history.
//!
//! ## Threat model
//!
//! The token is fully attacker-controlled bytes. An adversary wins if we accept
//! a forged genesis, a stolen/forged transfer, a double-spend, or a history
//! whose links don't actually connect. Each rule below closes one of those.
//!
//! ## Enforced invariants
//!
//! * **I1/I2 — chain linkage.** A transfer's source-state hash and lock script
//!   are *reconstructed* from its predecessor during [`Token::from_cbor`], not
//!   read from the wire. The inclusion proof is then verified against a
//!   `stateId` derived from those reconstructed values, so a transfer can only
//!   verify if it genuinely spends its predecessor's output state.
//! * **I3 — certification binding.** All certification state fields must equal
//!   the reconstructed transaction fields, the certified `transactionHash`
//!   must equal the recomputed transaction hash, and the spend signature is
//!   checked over the reconstructed source-state hash.
//! * **I4 — no structural-only trust.** Decoding never confers validity; only
//!   this module does.
//! * **I5 — signature canonicality.** Signatures must be exactly 65 bytes and
//!   low-`s` (enforced in [`Signature`](crate::crypto::signature::Signature)).
//! * **I6 — quorum honesty.** The trust base must have a positive, attainable
//!   threshold and unique validator ids/keys. Only distinct root-node signing
//!   identities count toward the threshold.
//!
//! [`RootTrustBase`]: crate::api::bft::RootTrustBase
//! [`Token::from_cbor`]: crate::transaction::Token::from_cbor

mod context;
mod error;
mod mint_justification;

pub use context::{VerificationContext, VerificationLimits, VerificationPolicy};
pub use error::VerificationError;
pub use mint_justification::{
    MintJustificationRegistry, MintJustificationVerifier, TokenDataVerifier,
};

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::api::bft::RootTrustBase;
use crate::api::inclusion_proof::InclusionProof;
use crate::api::StateId;
use crate::crypto::hash::{DataHash, HashAlgorithm};
use crate::predicate::builtin::SignaturePredicate;
use crate::predicate::unlock::verify_signature_unlock;
use crate::predicate::EncodedPredicate;
use crate::transaction::{Minter, Token, Transaction};

/// Verify a whole token: genesis first, then every transfer in order.
///
/// Any mint justification is rejected as unsupported (fail closed). To accept
/// justified mints (e.g. token splits), use [`verify_token_with`] with a
/// [`MintJustificationRegistry`] holding the relevant verifiers.
pub fn verify_token(token: &Token, trust_base: &RootTrustBase) -> Result<(), VerificationError> {
    verify_token_with(token, trust_base, &MintJustificationRegistry::new())
}

/// Verify a whole token, dispatching any mint justification through `registry`.
pub fn verify_token_with(
    token: &Token,
    trust_base: &RootTrustBase,
    registry: &MintJustificationRegistry,
) -> Result<(), VerificationError> {
    verify_token_with_policy(token, trust_base, registry, VerificationPolicy::default())
}

/// Verify a token with explicit cumulative limits and payload-validation policy.
pub fn verify_token_with_policy(
    token: &Token,
    trust_base: &RootTrustBase,
    registry: &MintJustificationRegistry,
    policy: VerificationPolicy,
) -> Result<(), VerificationError> {
    trust_base
        .validate()
        .map_err(VerificationError::InvalidTrustBase)?;
    let mut context = VerificationContext::new(trust_base, registry, policy);
    verify_token_in_context(token, &mut context)
}

pub(crate) fn verify_token_in_context(
    token: &Token,
    context: &mut VerificationContext<'_>,
) -> Result<(), VerificationError> {
    if token.transactions().len() > context.policy().limits.max_token_transfers {
        return Err(VerificationError::VerificationLimitExceeded(
            "token transfer count",
        ));
    }
    verify_genesis(token, context)?;

    for (i, transfer) in token.transactions().iter().enumerate() {
        verify_inclusion_proof(
            context.trust_base(),
            transfer.inclusion_proof(),
            transfer.transaction(),
        )
        .map_err(|e| VerificationError::Transfer {
            index: i,
            source: alloc::boxed::Box::new(e),
        })?;
    }
    Ok(())
}

fn verify_genesis(
    token: &Token,
    context: &mut VerificationContext<'_>,
) -> Result<(), VerificationError> {
    let genesis = token.genesis();
    let mint = genesis.transaction();
    let trust_base = context.trust_base();

    // Network must match the trust base.
    if mint.network_id() != trust_base.network_id {
        return Err(VerificationError::NetworkMismatch);
    }

    // The genesis must be locked to the deterministic universal-minter key for
    // this token id — proving no one minted a competing history for the id.
    let expected_lock = SignaturePredicate::new(
        Minter::public_key(mint.token_id())
            .map_err(|_| VerificationError::InvalidMintLockScript)?,
    )
    .to_encoded();

    let certified_lock = genesis
        .inclusion_proof()
        .certification_data
        .as_ref()
        .map(|c| c.lock_script());
    if certified_lock != Some(&expected_lock) {
        return Err(VerificationError::InvalidMintLockScript);
    }

    verify_inclusion_proof(trust_base, genesis.inclusion_proof(), mint)
        .map_err(|e| VerificationError::Genesis(alloc::boxed::Box::new(e)))?;

    // Mint justification: dispatch through the registry. An empty registry
    // rejects any present justification (fail closed); a registered verifier
    // (e.g. the split verifier) may recursively re-enter verification.
    let registry = context.registry();
    registry.verify_token_data(token.genesis(), context)?;
    registry.verify_genesis(token.genesis(), context)?;

    Ok(())
}

/// Verify a single inclusion proof for `transaction`.
fn verify_inclusion_proof(
    trust_base: &RootTrustBase,
    proof: &InclusionProof,
    transaction: &impl Transaction,
) -> Result<(), VerificationError> {
    let inclusion_certificate = proof
        .inclusion_certificate
        .as_ref()
        .ok_or(VerificationError::InclusionCertificateMissing)?;
    let certification_data = proof
        .certification_data
        .as_ref()
        .ok_or(VerificationError::CertificationDataMissing)?;

    if certification_data.lock_script() != transaction.lock_script()
        || certification_data.source_state_hash() != transaction.source_state_hash()
    {
        return Err(VerificationError::CertificationDataMismatch);
    }

    // The certified transaction hash must be this transaction's hash.
    let tx_hash = transaction.calculate_transaction_hash();
    if certification_data.transaction_hash() != &tx_hash {
        return Err(VerificationError::TransactionHashMismatch);
    }

    // Derive the state id from the transaction's *reconstructed* lock script and
    // source-state hash (I1/I2/I3), and check the SMT path proves it was
    // committed with this transaction hash, under the block's state root.
    let state_id = StateId::derive(transaction.lock_script(), transaction.source_state_hash());
    let expected_root = DataHash::new(
        HashAlgorithm::Sha256,
        proof.unicity_certificate.input_record.hash.clone(),
    )
    .map_err(|_| VerificationError::PathInvalid)?;
    if !inclusion_certificate.verify(
        &state_id,
        certification_data.transaction_hash(),
        &expected_root,
    ) {
        return Err(VerificationError::PathInvalid);
    }

    // The shard the proof claims must actually contain this state id.
    let shard = &proof.unicity_certificate.shard_tree_certificate.shard;
    if shard.length() != 0 && !shard.is_prefix_of(state_id.bytes()) {
        return Err(VerificationError::ShardMismatch);
    }

    // The unicity certificate must chain to a quorum-signed seal on our network.
    verify_unicity_certificate(trust_base, proof)?;

    // Finally, the unlock script must satisfy the (reconstructed) lock script.
    verify_predicate(
        transaction.lock_script(),
        transaction.source_state_hash(),
        certification_data.transaction_hash(),
        certification_data.unlock_script(),
    )?;

    Ok(())
}

fn verify_unicity_certificate(
    trust_base: &RootTrustBase,
    proof: &InclusionProof,
) -> Result<(), VerificationError> {
    let uc = &proof.unicity_certificate;
    let seal = &uc.unicity_seal;

    if seal.network_id != trust_base.network_id {
        return Err(VerificationError::SealNetworkMismatch);
    }

    // The recomputed unicity-tree root must equal the signed seal hash.
    let computed = uc
        .computed_seal_hash()
        .map_err(|_| VerificationError::SealRootMismatch)?;
    if computed.data() != seal.hash.as_slice() {
        return Err(VerificationError::SealRootMismatch);
    }

    // Count distinct, valid root-node signatures over the seal hash.
    let seal_hash = seal.calculate_hash();
    let mut counted: BTreeSet<&str> = BTreeSet::new();
    let mut counted_keys = Vec::new();
    for (node_id, signature) in &seal.signatures {
        if counted.contains(node_id.as_str()) {
            continue;
        }
        let Some(key) = trust_base.signing_key(node_id) else {
            continue;
        };
        if counted_keys.contains(&key) {
            continue;
        }
        let Ok(sig) = crate::crypto::signature::Signature::decode(signature) else {
            continue;
        };
        if sig.verify(seal_hash.data(), key) {
            counted.insert(node_id.as_str());
            counted_keys.push(key);
        }
    }

    if (counted.len() as u64) < trust_base.quorum_threshold {
        return Err(VerificationError::QuorumNotMet);
    }
    Ok(())
}

fn verify_predicate(
    lock_script: &EncodedPredicate,
    source_state_hash: &DataHash,
    transaction_hash: &DataHash,
    unlock_script: &[u8],
) -> Result<(), VerificationError> {
    // Spendable states are signature-locked; anything else cannot be unlocked.
    let predicate = SignaturePredicate::from_encoded(lock_script)
        .map_err(|_| VerificationError::NotAuthenticated)?;
    if verify_signature_unlock(
        predicate.public_key(),
        source_state_hash,
        transaction_hash,
        unlock_script,
    ) {
        Ok(())
    } else {
        Err(VerificationError::NotAuthenticated)
    }
}

/// Per-rule adversarial tests.
///
/// Each test builds a *fully valid* baseline (a single-leaf inclusion proof,
/// signed by a known root node) and then tampers with exactly one field, so that
/// only the rule under test can fire — proving every verification rule rejects
/// its precise adversarial case and returns its specific error.
#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;

    use alloc::string::{String, ToString};

    use crate::api::bft::{
        InputRecord, RootTrustBaseNodeInfo, ShardId, ShardTreeCertificate, UnicityCertificate,
        UnicitySeal, UnicityTreeCertificate,
    };
    use crate::api::{CertificationData, InclusionCertificate, NetworkId};
    use crate::crypto::hash::sha256;
    use crate::crypto::signer::{Secp256k1Signer, Signer};
    use crate::predicate::unlock::sign_signature_unlock;
    use crate::transaction::ids::{TokenSalt, TokenType};
    use crate::transaction::{
        CertifiedMintTransaction, CertifiedTransferTransaction, MintTransaction,
        TransferTransaction,
    };

    fn signer(byte: u8) -> Secp256k1Signer {
        Secp256k1Signer::from_bytes(&[byte; 32]).unwrap()
    }

    fn node_info(s: &Secp256k1Signer, id: &str) -> RootTrustBaseNodeInfo {
        RootTrustBaseNodeInfo {
            node_id: id.to_string(),
            signing_key: s.public_key(),
            stake: 1,
        }
    }

    fn trust_base(node: &Secp256k1Signer) -> RootTrustBase {
        RootTrustBase::new(
            0,
            NetworkId::LOCAL,
            0,
            0,
            alloc::vec![node_info(node, "NODE")],
            1,
        )
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

    /// The SMT root for a single `(state_id -> tx_hash)` leaf.
    fn leaf_root(state_id: &StateId, tx_hash: &DataHash) -> [u8; 32] {
        let mut preimage = alloc::vec![0x00u8];
        preimage.extend_from_slice(state_id.bytes());
        preimage.extend_from_slice(tx_hash.data());
        let mut root = [0u8; 32];
        root.copy_from_slice(sha256(&preimage).data());
        root
    }

    /// A unicity certificate committing to `root`, signed by `node`.
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
            shard_configuration_hash: alloc::vec![0u8; 32],
            shard_tree_certificate: ShardTreeCertificate {
                shard: empty_shard(),
                sibling_hash_list: Vec::new(),
            },
            unicity_tree_certificate: UnicityTreeCertificate {
                partition_identifier: 0,
                steps: Vec::new(),
            },
            unicity_seal: mk_seal(alloc::vec![0u8; 32], Vec::new()),
        };
        let seal_hash = uc.computed_seal_hash().unwrap().data().to_vec();
        let signature = node
            .sign(&mk_seal(seal_hash.clone(), Vec::new()).calculate_hash())
            .encode()
            .to_vec();
        uc.unicity_seal = mk_seal(seal_hash, alloc::vec![("NODE".to_string(), signature)]);
        uc
    }

    /// Build a valid single-leaf inclusion proof for `transaction`, with the
    /// unlock signed by `owner`.
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

    fn make_transfer(owner: &Secp256k1Signer, recipient: &Secp256k1Signer) -> TransferTransaction {
        TransferTransaction::new(
            sha256(b"source-state"),
            SignaturePredicate::new(owner.public_key()).to_encoded(),
            SignaturePredicate::new(recipient.public_key()).to_encoded(),
            alloc::vec![7u8; 32],
            None,
        )
    }

    /// A valid `(trust_base, node, owner, transfer, proof)` baseline.
    fn transfer_case() -> (
        RootTrustBase,
        Secp256k1Signer,
        Secp256k1Signer,
        TransferTransaction,
        InclusionProof,
    ) {
        let node = signer(0x11);
        let owner = signer(0x22);
        let recipient = signer(0x33);
        let transfer = make_transfer(&owner, &recipient);
        let proof = valid_proof(&transfer, &owner, &node);
        (trust_base(&node), node, owner, transfer, proof)
    }

    /// Re-sign `proof`'s unicity certificate after a field of it was changed so
    /// the seal root/signature stay self-consistent (isolates later rules).
    fn reseal(proof: &mut InclusionProof, node: &Secp256k1Signer) {
        let seal_hash = proof
            .unicity_certificate
            .computed_seal_hash()
            .unwrap()
            .data()
            .to_vec();
        let signature = node
            .sign(&mk_seal(seal_hash.clone(), Vec::new()).calculate_hash())
            .encode()
            .to_vec();
        proof.unicity_certificate.unicity_seal =
            mk_seal(seal_hash, alloc::vec![("NODE".to_string(), signature)]);
    }

    fn cert(proof: &InclusionProof) -> &CertificationData {
        proof.certification_data.as_ref().unwrap()
    }

    // --- baseline ----------------------------------------------------------

    #[test]
    fn baseline_transfer_proof_verifies() {
        let (tb, _node, _owner, transfer, proof) = transfer_case();
        assert_eq!(verify_inclusion_proof(&tb, &proof, &transfer), Ok(()));
    }

    // --- one test per inclusion-proof rule ---------------------------------

    #[test]
    fn rule_inclusion_certificate_missing() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        proof.inclusion_certificate = None;
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::InclusionCertificateMissing)
        );
    }

    #[test]
    fn rule_certification_data_missing() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        proof.certification_data = None;
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::CertificationDataMissing)
        );
    }

    #[test]
    fn rule_certification_data_mismatch_lock_script() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        let stranger = signer(0xAB);
        let c = cert(&proof);
        proof.certification_data = Some(CertificationData::new(
            SignaturePredicate::new(stranger.public_key()).to_encoded(), // wrong lock
            c.source_state_hash().clone(),
            c.transaction_hash().clone(),
            c.unlock_script().to_vec(),
        ));
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::CertificationDataMismatch)
        );
    }

    #[test]
    fn rule_certification_data_mismatch_source_state() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        let c = cert(&proof);
        proof.certification_data = Some(CertificationData::new(
            c.lock_script().clone(),
            sha256(b"a-different-source-state"), // wrong source
            c.transaction_hash().clone(),
            c.unlock_script().to_vec(),
        ));
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::CertificationDataMismatch)
        );
    }

    #[test]
    fn rule_transaction_hash_mismatch() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        let c = cert(&proof);
        proof.certification_data = Some(CertificationData::new(
            c.lock_script().clone(),
            c.source_state_hash().clone(),
            sha256(b"not-the-tx-hash"), // wrong tx hash
            c.unlock_script().to_vec(),
        ));
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::TransactionHashMismatch)
        );
    }

    #[test]
    fn rule_path_invalid() {
        let (tb, node, _o, transfer, mut proof) = transfer_case();
        // Point the inclusion proof at a different state-tree root.
        proof.unicity_certificate.input_record.hash = alloc::vec![0xCDu8; 32];
        reseal(&mut proof, &node); // keep the seal consistent so PATH fails first
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::PathInvalid)
        );
    }

    #[test]
    fn rule_shard_mismatch() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        // A 256-bit all-zero shard cannot be a prefix of a real state id.
        let mut encoded = alloc::vec![0u8; 32];
        encoded.push(0b1000_0000);
        proof.unicity_certificate.shard_tree_certificate.shard = ShardId::decode(&encoded).unwrap();
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::ShardMismatch)
        );
    }

    #[test]
    fn rule_seal_network_mismatch() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        proof.unicity_certificate.unicity_seal.network_id = NetworkId::MAINNET;
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::SealNetworkMismatch)
        );
    }

    #[test]
    fn rule_seal_root_mismatch() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        proof.unicity_certificate.unicity_seal.hash = alloc::vec![0u8; 32];
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::SealRootMismatch)
        );
    }

    #[test]
    fn rule_quorum_not_met_without_signatures() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        proof.unicity_certificate.unicity_seal.signatures = Vec::new();
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::QuorumNotMet)
        );
    }

    #[test]
    fn rule_quorum_not_met_with_untrusted_signer() {
        let (tb, _n, owner, transfer, _p) = transfer_case();
        // Seal signed by a key that is not in the trust base.
        let rogue = signer(0xEE);
        let proof = valid_proof(&transfer, &owner, &rogue);
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::QuorumNotMet)
        );
    }

    #[test]
    fn rule_not_authenticated_on_bad_unlock() {
        let (tb, _n, _o, transfer, mut proof) = transfer_case();
        let c = cert(&proof);
        let mut unlock = c.unlock_script().to_vec();
        unlock[0] ^= 0xff; // corrupt the signature (still 65 bytes)
        proof.certification_data = Some(CertificationData::new(
            c.lock_script().clone(),
            c.source_state_hash().clone(),
            c.transaction_hash().clone(),
            unlock,
        ));
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::NotAuthenticated)
        );
    }

    #[test]
    fn rule_not_authenticated_when_signed_by_non_owner() {
        let (tb, node, _owner, transfer, _p) = transfer_case();
        // A valid signature, but from a key that is not the lock-script owner.
        let thief = signer(0x44);
        let proof = valid_proof(&transfer, &thief, &node);
        assert_eq!(
            verify_inclusion_proof(&tb, &proof, &transfer),
            Err(VerificationError::NotAuthenticated)
        );
    }

    // --- genesis-only rules (full token) -----------------------------------

    /// Build a valid genesis-only token (and its trust base).
    fn genesis_token(
        node: &Secp256k1Signer,
        justification: Option<Vec<u8>>,
    ) -> (RootTrustBase, MintTransaction, InclusionProof) {
        let recipient = signer(0x55);
        let mint = MintTransaction::create(
            NetworkId::LOCAL,
            SignaturePredicate::new(recipient.public_key()).to_encoded(),
            TokenType::new(alloc::vec![0xAA; 32]),
            TokenSalt::from_bytes([0x66; 32]),
            None,
            justification,
        )
        .unwrap();
        let minter = Minter::signer(mint.token_id()).unwrap();
        let proof = valid_proof(&mint, &minter, node);
        (trust_base(node), mint, proof)
    }

    #[test]
    fn baseline_genesis_token_verifies() {
        let node = signer(0x11);
        let (tb, mint, proof) = genesis_token(&node, None);
        let token = Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new());
        assert_eq!(token.verify(&tb), Ok(()));
    }

    #[test]
    fn rule_network_mismatch() {
        let node = signer(0x11);
        let (_, mint, proof) = genesis_token(&node, None);
        let token = Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new());
        // Mint is on LOCAL; verify against a (valid) MAINNET trust base.
        let mainnet = RootTrustBase::new(
            0,
            NetworkId::MAINNET,
            0,
            0,
            alloc::vec![node_info(&node, "NODE")],
            1,
        );
        assert_eq!(
            token.verify(&mainnet),
            Err(VerificationError::NetworkMismatch)
        );
    }

    #[test]
    fn rule_invalid_mint_lock_script() {
        let node = signer(0x11);
        let (tb, mint, mut proof) = genesis_token(&node, None);
        // Replace the certified lock script with one that is not the minter key.
        let stranger = signer(0x77);
        let c = cert(&proof);
        proof.certification_data = Some(CertificationData::new(
            SignaturePredicate::new(stranger.public_key()).to_encoded(),
            c.source_state_hash().clone(),
            c.transaction_hash().clone(),
            c.unlock_script().to_vec(),
        ));
        let token = Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new());
        assert_eq!(
            token.verify(&tb),
            Err(VerificationError::InvalidMintLockScript)
        );
    }

    #[test]
    fn rule_unsupported_mint_justification() {
        let node = signer(0x11);
        // A justified mint whose proof is otherwise fully valid reaches — and
        // fails at — the justification rule (no verifier is registered).
        let (tb, mint, proof) = genesis_token(&node, Some(alloc::vec![0xde, 0xad]));
        let token = Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new());
        assert_eq!(
            token.verify(&tb),
            Err(VerificationError::UnsupportedMintJustification)
        );
    }

    // --- trust base rule ---------------------------------------------------

    #[test]
    fn rule_invalid_trust_base() {
        let node = signer(0x11);
        let (_, mint, proof) = genesis_token(&node, None);
        let token = Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new());

        // Threshold of zero would accept an unsigned seal.
        let zero_threshold = RootTrustBase::new(
            0,
            NetworkId::LOCAL,
            0,
            0,
            alloc::vec![node_info(&node, "NODE")],
            0,
        );
        assert!(matches!(
            token.verify(&zero_threshold),
            Err(VerificationError::InvalidTrustBase(_))
        ));

        // Threshold exceeding the validator count is unattainable.
        let unattainable = RootTrustBase::new(
            0,
            NetworkId::LOCAL,
            0,
            0,
            alloc::vec![node_info(&node, "NODE")],
            2,
        );
        assert!(matches!(
            token.verify(&unattainable),
            Err(VerificationError::InvalidTrustBase(_))
        ));

        // Duplicate signing keys would let one signer satisfy the quorum twice.
        let duplicate = RootTrustBase::new(
            0,
            NetworkId::LOCAL,
            0,
            0,
            alloc::vec![node_info(&node, "NODE-A"), node_info(&node, "NODE-B")],
            2,
        );
        assert!(matches!(
            token.verify(&duplicate),
            Err(VerificationError::InvalidTrustBase(_))
        ));
    }

    // --- error wrapping ----------------------------------------------------

    #[test]
    fn genesis_failures_are_wrapped() {
        let node = signer(0x11);
        let (tb, mint, mut proof) = genesis_token(&node, None);
        proof.unicity_certificate.unicity_seal.hash = alloc::vec![0u8; 32]; // break seal root
        let token = Token::new(CertifiedMintTransaction::new(mint, proof), Vec::new());
        assert_eq!(
            token.verify(&tb),
            Err(VerificationError::Genesis(alloc::boxed::Box::new(
                VerificationError::SealRootMismatch
            )))
        );
    }

    #[test]
    fn transfer_failures_are_wrapped_with_index() {
        // A valid genesis followed by a transfer that spends the genesis output,
        // each with its own single-leaf proof; then break the transfer's seal.
        let node = signer(0x11);
        let owner = signer(0x55); // genesis recipient == transfer owner
        let (tb, mint, genesis_proof) = genesis_token(&node, None);
        let genesis = CertifiedMintTransaction::new(mint, genesis_proof);

        let recipient = signer(0x88);
        let transfer = TransferTransaction::new(
            genesis.result_state_hash(),
            genesis.recipient().clone(),
            SignaturePredicate::new(recipient.public_key()).to_encoded(),
            alloc::vec![9u8; 32],
            None,
        );
        let mut transfer_proof = valid_proof(&transfer, &owner, &node);

        // Baseline: the whole chain verifies.
        let valid = Token::new(
            genesis.clone(),
            alloc::vec![CertifiedTransferTransaction::new(
                transfer.clone(),
                transfer_proof.clone()
            )],
        );
        assert_eq!(valid.verify(&tb), Ok(()));

        // Break the transfer's seal -> wrapped as Transfer { index: 0, .. }.
        transfer_proof.unicity_certificate.unicity_seal.hash = alloc::vec![0u8; 32];
        let tampered = Token::new(
            genesis,
            alloc::vec![CertifiedTransferTransaction::new(transfer, transfer_proof)],
        );
        assert_eq!(
            tampered.verify(&tb),
            Err(VerificationError::Transfer {
                index: 0,
                source: alloc::boxed::Box::new(VerificationError::SealRootMismatch),
            })
        );
    }

    // --- chain-of-custody (I1/I2): a swapped proof is rejected --------------

    #[test]
    fn transfer_with_foreign_proof_is_rejected() {
        // Give the transfer a proof certified for a *different* state (the
        // genesis state). On verification the state id is derived from the
        // transfer's own reconstructed fields, so the foreign proof no longer
        // matches and the transfer is rejected.
        let node = signer(0x11);
        let (tb, mint, genesis_proof) = genesis_token(&node, None);
        let genesis = CertifiedMintTransaction::new(mint, genesis_proof.clone());

        let recipient = signer(0x88);
        let transfer = TransferTransaction::new(
            genesis.result_state_hash(),
            genesis.recipient().clone(),
            SignaturePredicate::new(recipient.public_key()).to_encoded(),
            alloc::vec![9u8; 32],
            None,
        );

        // The genesis proof does not attest to the transfer's transaction.
        let tampered = Token::new(
            genesis,
            alloc::vec![CertifiedTransferTransaction::new(transfer, genesis_proof)],
        );
        let result = tampered.verify(&tb);
        assert!(
            matches!(result, Err(VerificationError::Transfer { index: 0, .. })),
            "expected a wrapped transfer rejection, got {result:?}"
        );
    }
}
