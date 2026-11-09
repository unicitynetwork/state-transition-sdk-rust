//! Fixtures of the unit tests: a one-entry trust base history.

use alloc::string::String;
use alloc::vec::Vec;

use crate::api::bft::{TrustBaseEntry, TrustBaseHistory, TrustBaseMember};
use crate::api::NetworkId;
use crate::crypto::signature::PublicKey;

/// The genesis entry of `network` at `epoch` (from root round `epoch_start`) with members `(node id, key, weight)` as a history. The quorum
/// threshold is the entry rule `floor(2W/3)+1`; an invalid entry panics.
pub(crate) fn history_of(
    network: NetworkId,
    epoch: u64,
    epoch_start: u64,
    nodes: Vec<(String, PublicKey, u64)>,
) -> TrustBaseHistory {
    let members = nodes
        .into_iter()
        .map(|(id, key, weight)| TrustBaseMember::new(id, key, weight))
        .collect();
    TrustBaseHistory::from_genesis(
        TrustBaseEntry::genesis(network, epoch, epoch_start, members),
        None,
    )
    .expect("a valid one-entry history")
}

/// A history of consecutive epochs `1..=starts.len()` of one committee (a single member `node_id` with `signer`'s key, weight 1);
/// epoch `i + 1` begins at root round `starts[i]`. Every successor is signed by its predecessor's committee, so the chain verifies.
#[cfg(feature = "client")]
pub(crate) fn chain_of(
    network: NetworkId,
    node_id: &str,
    signer: &crate::crypto::signer::Secp256k1Signer,
    starts: &[u64],
) -> TrustBaseHistory {
    use crate::crypto::signer::Signer;
    let member = || alloc::vec![TrustBaseMember::new(node_id, signer.public_key(), 1)];
    let mut history = history_of(
        network,
        1,
        starts[0],
        alloc::vec![(String::from(node_id), signer.public_key(), 1)],
    );
    for (i, start) in starts.iter().enumerate().skip(1) {
        let prev = history.latest().clone();
        let mut entry = TrustBaseEntry::new(
            network,
            i as u64 + 1,
            *start,
            member(),
            prev.quorum_threshold,
            None,
            None,
            prev.entry_id(),
        );
        entry.sign(node_id, signer);
        history.append(entry).expect("a valid successor");
    }
    history
}
