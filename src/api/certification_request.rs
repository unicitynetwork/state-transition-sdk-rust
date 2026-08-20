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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Decoder;
    use hex_literal::hex;

    #[test]
    fn certification_request_golden_vector() {
        let certification_data = hex!(
            "d998778602d9987883014101582103a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f9635075820e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e6152415820ed275ff0a0694d1b61ec22f13914a431569220ba7f2f043d7940aac78d02c2f91a689b2cc0584111f0f7929d70e0e32db9159b7e23b6e0043502bc36609728e9dc0353251c241a7b1adb047c9234cd77ed519c409048a6c8bc247f0262c1f161b03d6fee49426e00"
        );
        let data = CertificationData::from_cbor(Decoder::new(&certification_data)).unwrap();
        let request = CertificationRequest::new(&data);

        assert_eq!(
            request.to_cbor(),
            hex!(
                "d9987684015820ffb36b55de9bfaf48b766d1f4e041a6c5d35ba23b402ea2a56a6c7692cb8f81ad998778602d9987883014101582103a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f9635075820e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e6152415820ed275ff0a0694d1b61ec22f13914a431569220ba7f2f043d7940aac78d02c2f91a689b2cc0584111f0f7929d70e0e32db9159b7e23b6e0043502bc36609728e9dc0353251c241a7b1adb047c9234cd77ed519c409048a6c8bc247f0262c1f161b03d6fee49426e0000"
            )
        );
    }
}
