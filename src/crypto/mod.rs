//! Cryptographic primitives: hashing ([`hash`]) and secp256k1 signatures
//! ([`signature`]).
//!
//! Verification-only consumers (zkVM guests) need just these two modules plus
//! the decoders. Key generation and signing live behind the `client` feature in
//! the `signer` module.

pub mod hash;
pub mod signature;

#[cfg(any(feature = "client", test))]
pub mod signer;
