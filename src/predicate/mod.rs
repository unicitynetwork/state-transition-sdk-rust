//! Predicates: spending conditions that lock a token state.
//!
//! On the wire a predicate is an [`EncodedPredicate`] (CBOR tag 39032): an
//! engine id plus opaque `code` and `parameters` byte strings. Concrete
//! built-in predicates ([`builtin`]) interpret those bytes.

pub mod builtin;
pub mod unlock;

use alloc::vec::Vec;

use crate::cbor::{encode_array, encode_byte_string, encode_tag, encode_uint, Decoder};
use crate::error::Error;

/// CBOR tag for [`EncodedPredicate`].
pub const ENCODED_PREDICATE_TAG: u64 = 39032;

/// Predicate execution engine. Each engine has its own verifier registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PredicateEngine {
    /// The built-in predicate engine (id 1).
    BuiltIn,
}

impl PredicateEngine {
    /// Numeric engine id.
    pub const fn id(self) -> u64 {
        match self {
            PredicateEngine::BuiltIn => 1,
        }
    }

    /// Resolve from a numeric id.
    pub const fn from_id(id: u64) -> Result<Self, Error> {
        match id {
            1 => Ok(PredicateEngine::BuiltIn),
            _ => Err(Error::UnexpectedValue("unknown predicate engine")),
        }
    }
}

/// A predicate that can be reduced to its encoded `(engine, code, parameters)`
/// form. `code` and `parameters` are the raw byte strings stored inside the
/// [`EncodedPredicate`] (the `code` is itself a CBOR-encoded unsigned integer).
pub trait Predicate {
    /// The engine this predicate runs on.
    fn engine(&self) -> PredicateEngine;
    /// The `code` bytes (CBOR-encoded predicate type for built-ins).
    fn code(&self) -> Vec<u8>;
    /// The `parameters` bytes.
    fn parameters(&self) -> Vec<u8>;
}

/// Wire-form predicate (CBOR tag 39032): `[uint(engine), bstr(code), bstr(params)]`.
///
/// Stored without re-decoding `code`/`parameters`, so an unknown predicate type
/// still round-trips losslessly.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EncodedPredicate {
    engine: PredicateEngine,
    code: Vec<u8>,
    parameters: Vec<u8>,
}

impl EncodedPredicate {
    /// Construct directly from parts.
    pub fn new(engine: PredicateEngine, code: Vec<u8>, parameters: Vec<u8>) -> Self {
        EncodedPredicate {
            engine,
            code,
            parameters,
        }
    }

    /// Wrap any [`Predicate`] into its encoded form.
    pub fn from_predicate(p: &impl Predicate) -> Self {
        EncodedPredicate {
            engine: p.engine(),
            code: p.code(),
            parameters: p.parameters(),
        }
    }

    /// The engine.
    pub fn engine(&self) -> PredicateEngine {
        self.engine
    }

    /// The raw `code` bytes.
    pub fn code(&self) -> &[u8] {
        &self.code
    }

    /// The raw `parameters` bytes.
    pub fn parameters(&self) -> &[u8] {
        &self.parameters
    }

    /// Encode to CBOR (tagged).
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_tag(
            ENCODED_PREDICATE_TAG,
            &encode_array(&[
                &encode_uint(self.engine.id()),
                &encode_byte_string(&self.code),
                &encode_byte_string(&self.parameters),
            ]),
        )
    }

    /// Decode from CBOR (tagged).
    pub fn from_cbor(d: Decoder<'_>) -> Result<Self, Error> {
        let inner = d.expect_tag(ENCODED_PREDICATE_TAG)?;
        let items = inner.array(Some(3))?;
        let engine = PredicateEngine::from_id(items[0].uint()?)?;
        Ok(EncodedPredicate {
            engine,
            code: items[1].bytes_value()?.to_vec(),
            parameters: items[2].bytes_value()?.to_vec(),
        })
    }
}

impl Predicate for EncodedPredicate {
    fn engine(&self) -> PredicateEngine {
        self.engine
    }
    fn code(&self) -> Vec<u8> {
        self.code.clone()
    }
    fn parameters(&self) -> Vec<u8> {
        self.parameters.clone()
    }
}

impl core::fmt::Debug for EncodedPredicate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "EncodedPredicate {{ engine: {:?}, code: {}, parameters: {} }}",
            self.engine,
            hex::encode(&self.code),
            hex::encode(&self.parameters)
        )
    }
}
