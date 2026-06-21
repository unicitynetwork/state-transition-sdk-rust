//! Built-in predicates (engine id 1).

use alloc::vec::Vec;

use super::{EncodedPredicate, Predicate, PredicateEngine};
use crate::cbor::{encode_uint, Decoder};
use crate::crypto::signature::PublicKey;
use crate::error::Error;

/// Type ids for built-in predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltInPredicateType {
    /// Locks a state to a single secp256k1 public key. Type `0x01`.
    Signature,
    /// Permanently locks a state (unspendable). Type `0x02`.
    Burn,
    /// References a Unicity identifier. Type `0x100`.
    UnicityId,
}

impl BuiltInPredicateType {
    /// The numeric type id.
    pub const fn id(self) -> u64 {
        match self {
            BuiltInPredicateType::Signature => 0x01,
            BuiltInPredicateType::Burn => 0x02,
            BuiltInPredicateType::UnicityId => 0x100,
        }
    }

    /// Resolve from a numeric id.
    pub const fn from_id(id: u64) -> Result<Self, Error> {
        match id {
            0x01 => Ok(BuiltInPredicateType::Signature),
            0x02 => Ok(BuiltInPredicateType::Burn),
            0x100 => Ok(BuiltInPredicateType::UnicityId),
            _ => Err(Error::UnexpectedValue("unknown built-in predicate type")),
        }
    }
}

/// Decode the `code` byte string of a built-in [`EncodedPredicate`] into its
/// type id, checking the engine.
fn builtin_type(predicate: &EncodedPredicate) -> Result<BuiltInPredicateType, Error> {
    if predicate.engine() != PredicateEngine::BuiltIn {
        return Err(Error::UnexpectedValue("predicate engine is not built-in"));
    }
    let decoder = Decoder::new(predicate.code());
    decoder.finish()?;
    let id = decoder.uint()?;
    BuiltInPredicateType::from_id(id)
}

/// Locks a state to a single secp256k1 public key. Spending requires a
/// signature from the matching private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignaturePredicate {
    public_key: PublicKey,
}

impl SignaturePredicate {
    /// Create from a compressed public key.
    pub fn new(public_key: PublicKey) -> Self {
        SignaturePredicate { public_key }
    }

    /// The locked public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Decode from an [`EncodedPredicate`], checking engine and type.
    pub fn from_encoded(predicate: &EncodedPredicate) -> Result<Self, Error> {
        if builtin_type(predicate)? != BuiltInPredicateType::Signature {
            return Err(Error::UnexpectedValue("not a signature predicate"));
        }
        Ok(SignaturePredicate {
            public_key: PublicKey::from_bytes(predicate.parameters())?,
        })
    }

    /// Convert to wire form.
    pub fn to_encoded(&self) -> EncodedPredicate {
        EncodedPredicate::from_predicate(self)
    }
}

impl Predicate for SignaturePredicate {
    fn engine(&self) -> PredicateEngine {
        PredicateEngine::BuiltIn
    }
    fn code(&self) -> Vec<u8> {
        encode_uint(BuiltInPredicateType::Signature.id())
    }
    fn parameters(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }
}

/// Permanently locks a state. The `reason` payload records why and is never
/// spendable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnPredicate {
    reason: Vec<u8>,
}

impl BurnPredicate {
    /// Create with a reason payload.
    pub fn new(reason: impl Into<Vec<u8>>) -> Self {
        BurnPredicate {
            reason: reason.into(),
        }
    }

    /// The burn reason bytes.
    pub fn reason(&self) -> &[u8] {
        &self.reason
    }

    /// Decode from an [`EncodedPredicate`], checking engine and type.
    pub fn from_encoded(predicate: &EncodedPredicate) -> Result<Self, Error> {
        if builtin_type(predicate)? != BuiltInPredicateType::Burn {
            return Err(Error::UnexpectedValue("not a burn predicate"));
        }
        Ok(BurnPredicate {
            reason: predicate.parameters().to_vec(),
        })
    }

    /// Convert to wire form.
    pub fn to_encoded(&self) -> EncodedPredicate {
        EncodedPredicate::from_predicate(self)
    }
}

impl Predicate for BurnPredicate {
    fn engine(&self) -> PredicateEngine {
        PredicateEngine::BuiltIn
    }
    fn code(&self) -> Vec<u8> {
        encode_uint(BuiltInPredicateType::Burn.id())
    }
    fn parameters(&self) -> Vec<u8> {
        self.reason.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_trailing_bytes_in_nested_predicate_code() {
        let key = PublicKey::from_bytes(
            &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        )
        .unwrap();
        let predicate = EncodedPredicate::new(
            PredicateEngine::BuiltIn,
            alloc::vec![0x01, 0xff],
            key.as_bytes().to_vec(),
        );
        assert!(SignaturePredicate::from_encoded(&predicate).is_err());
    }
}
