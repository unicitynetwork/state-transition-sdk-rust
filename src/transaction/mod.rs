//! Token transactions and the self-contained [`Token`] aggregate.

pub mod certified;
pub mod ids;
pub mod mint;
pub mod minter;
pub mod token;
pub mod transfer;

use alloc::vec::Vec;

use crate::crypto::hash::{sha256, DataHash};
use crate::predicate::EncodedPredicate;

pub use certified::{CertifiedMintTransaction, CertifiedTransferTransaction};
pub use ids::{MintTransactionState, StateMask, TokenId, TokenSalt, TokenType};
pub use mint::MintTransaction;
pub use minter::Minter;
pub use token::Token;
pub use transfer::TransferTransaction;

/// Common behaviour of mint and transfer transactions.
pub trait Transaction {
    /// The predicate that locks the *source* state being spent.
    fn lock_script(&self) -> &EncodedPredicate;
    /// The predicate that will lock the resulting state.
    fn recipient(&self) -> &EncodedPredicate;
    /// The hash of the source state being spent.
    fn source_state_hash(&self) -> &DataHash;
    /// The hash of the state this transaction produces.
    fn calculate_state_hash(&self) -> DataHash;
    /// CBOR encoding (tagged).
    fn to_cbor(&self) -> Vec<u8>;

    /// `H(toCBOR())` — the transaction hash certified by the aggregator.
    fn calculate_transaction_hash(&self) -> DataHash {
        sha256(&self.to_cbor())
    }
}
