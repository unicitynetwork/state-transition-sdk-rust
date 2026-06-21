//! Canonical CBOR codec (deterministic, RFC 8949 §4.2).
//!
//! This is a *purpose-built* codec, not a general CBOR library: it produces
//! byte-identical output to the reference Java/TypeScript SDKs and rejects any
//! non-deterministic encoding on the way in. Specifically:
//!
//! * integers and lengths use the minimal power-of-two width (inline `< 24`,
//!   else 1/2/4/8 bytes big-endian; additional-info 24/25/26/27);
//! * maps are emitted with entries sorted by encoded-key bytes; duplicate input
//!   keys are canonicalized to one last-writer value, while decoders reject
//!   duplicate wire keys;
//! * arrays, maps and tags are definite-length only — indefinite lengths and
//!   the reserved additional-info values 28-30 are rejected when decoding.
//!
//! The encoder takes already-encoded child items (`&[u8]`) and frames them,
//! mirroring the reference API shape (`encodeArray(...items)`); the decoder
//! returns borrowed sub-slices that the caller decodes further.

mod decode;
mod encode;

pub use decode::{DecodeLimits, Decoder};
pub use encode::{
    encode_array, encode_bool, encode_byte_string, encode_map, encode_null, encode_nullable,
    encode_tag, encode_text_string, encode_uint,
};

/// CBOR major types (the high 3 bits of the initial byte).
pub(crate) mod major {
    pub const UINT: u8 = 0x00;
    pub const NEGINT: u8 = 0x20;
    pub const BYTES: u8 = 0x40;
    pub const TEXT: u8 = 0x60;
    pub const ARRAY: u8 = 0x80;
    pub const MAP: u8 = 0xa0;
    pub const TAG: u8 = 0xc0;
    pub const SIMPLE: u8 = 0xe0;
}

/// Simple values used by the protocol.
pub(crate) mod simple {
    pub const FALSE: u8 = 0xf4;
    pub const TRUE: u8 = 0xf5;
    pub const NULL: u8 = 0xf6;
}
