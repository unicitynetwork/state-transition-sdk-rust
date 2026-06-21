//! Certification request (CBOR tag 39030): what a client submits to an
//! aggregator to certify a state transition.

use alloc::vec::Vec;

use super::certification::CertificationData;
use super::state_id::StateId;
use crate::cbor::{encode_array, encode_tag, encode_uint};

/// CBOR tag for [`CertificationRequest`].
pub const CERTIFICATION_REQUEST_TAG: u64 = 39030;
const VERSION: u64 = 1;

/// A certification request: the [`StateId`] being certified plus its
/// [`CertificationData`]. Borrows the certification data to avoid a copy.
#[derive(Debug)]
pub struct CertificationRequest<'a> {
    state_id: StateId,
    data: &'a CertificationData,
}

impl<'a> CertificationRequest<'a> {
    /// Build a request from certification data, deriving the state id.
    pub fn new(data: &'a CertificationData) -> Self {
        let state_id = StateId::derive(data.lock_script(), data.source_state_hash());
        CertificationRequest { state_id, data }
    }

    /// The derived state id.
    pub fn state_id(&self) -> &StateId {
        &self.state_id
    }

    /// Encode to CBOR (tagged). The trailing `0` mirrors the reference wire
    /// format (a reserved field).
    pub fn to_cbor(&self) -> Vec<u8> {
        encode_tag(
            CERTIFICATION_REQUEST_TAG,
            &encode_array(&[
                &encode_uint(VERSION),
                &self.state_id.to_cbor(),
                &self.data.to_cbor(),
                &encode_uint(0),
            ]),
        )
    }
}
