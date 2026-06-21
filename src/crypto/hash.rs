//! Hash algorithms and the protocol's `DataHash` "imprint" representation.
//!
//! A [`DataHash`] pairs a digest with the [`HashAlgorithm`] that produced it.
//! Its *imprint* — a 2-byte big-endian algorithm id followed by the raw digest
//! — is the canonical on-wire/in-hash form. Note carefully which preimages use
//! the imprint (34 bytes for SHA-256) versus the raw [`DataHash::data`]
//! (32 bytes); the two are not interchangeable and getting it wrong breaks
//! binary compatibility.

use alloc::vec::Vec;

use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use crate::error::Error;

/// Supported hash algorithms. The discriminant is the protocol id used in the
/// imprint prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-256 — the algorithm used by every protocol hash. Id `0`.
    Sha256,
    /// SHA-224. Id `1`.
    Sha224,
    /// SHA-384. Id `2`.
    Sha384,
    /// SHA-512. Id `3`.
    Sha512,
    /// RIPEMD-160. Id `4`. Recognised for compatibility but not implemented as
    /// a hasher (the protocol never uses it).
    Ripemd160,
}

impl HashAlgorithm {
    /// The 16-bit protocol id stored in a [`DataHash`] imprint.
    pub const fn id(self) -> u16 {
        match self {
            HashAlgorithm::Sha256 => 0,
            HashAlgorithm::Sha224 => 1,
            HashAlgorithm::Sha384 => 2,
            HashAlgorithm::Sha512 => 3,
            HashAlgorithm::Ripemd160 => 4,
        }
    }

    /// Digest length in bytes.
    pub const fn length(self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha224 => 28,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Ripemd160 => 20,
        }
    }

    /// Resolve an algorithm from its protocol id.
    pub const fn from_id(id: u16) -> Result<Self, Error> {
        match id {
            0 => Ok(HashAlgorithm::Sha256),
            1 => Ok(HashAlgorithm::Sha224),
            2 => Ok(HashAlgorithm::Sha384),
            3 => Ok(HashAlgorithm::Sha512),
            4 => Ok(HashAlgorithm::Ripemd160),
            other => Err(Error::UnknownHashAlgorithm(other)),
        }
    }
}

/// An immutable digest plus the algorithm that produced it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DataHash {
    algorithm: HashAlgorithm,
    data: Vec<u8>,
}

impl DataHash {
    /// Construct from an algorithm and raw digest bytes, checking the length.
    pub fn new(algorithm: HashAlgorithm, data: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let data = data.into();
        if data.len() != algorithm.length() {
            return Err(Error::InvalidLength {
                what: "DataHash digest",
                expected: algorithm.length(),
                actual: data.len(),
            });
        }
        Ok(DataHash { algorithm, data })
    }

    /// Reconstruct from an imprint (2-byte algorithm id followed by the digest).
    pub fn from_imprint(imprint: &[u8]) -> Result<Self, Error> {
        if imprint.len() < 3 {
            return Err(Error::InvalidLength {
                what: "DataHash imprint",
                expected: 3,
                actual: imprint.len(),
            });
        }
        let id = u16::from_be_bytes([imprint[0], imprint[1]]);
        let algorithm = HashAlgorithm::from_id(id)?;
        DataHash::new(algorithm, &imprint[2..])
    }

    /// The algorithm.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// The raw digest bytes. NB: do not use for hashing where the imprint is
    /// required; see the module docs.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The imprint: 2-byte big-endian algorithm id followed by the digest.
    pub fn imprint(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() + 2);
        out.extend_from_slice(&self.algorithm.id().to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}

impl core::fmt::Debug for DataHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "DataHash({:?}, {})",
            self.algorithm,
            hex::encode(&self.data)
        )
    }
}

/// Streaming hasher. Only the SHA-2 family is implemented; constructing one for
/// [`HashAlgorithm::Ripemd160`] returns an error.
#[derive(Debug)]
pub struct DataHasher {
    inner: Inner,
}

#[derive(Debug)]
enum Inner {
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl DataHasher {
    /// Create a hasher for `algorithm`.
    pub fn new(algorithm: HashAlgorithm) -> Result<Self, Error> {
        let inner = match algorithm {
            HashAlgorithm::Sha224 => Inner::Sha224(Sha224::new()),
            HashAlgorithm::Sha256 => Inner::Sha256(Sha256::new()),
            HashAlgorithm::Sha384 => Inner::Sha384(Sha384::new()),
            HashAlgorithm::Sha512 => Inner::Sha512(Sha512::new()),
            HashAlgorithm::Ripemd160 => return Err(Error::Crypto("RIPEMD-160 not supported")),
        };
        Ok(DataHasher { inner })
    }

    /// Feed more data into the digest.
    pub fn update(mut self, data: &[u8]) -> Self {
        match &mut self.inner {
            Inner::Sha224(h) => h.update(data),
            Inner::Sha256(h) => h.update(data),
            Inner::Sha384(h) => h.update(data),
            Inner::Sha512(h) => h.update(data),
        }
        self
    }

    /// Finalise into a [`DataHash`].
    pub fn finalize(self) -> DataHash {
        let (algorithm, data) = match self.inner {
            Inner::Sha224(h) => (HashAlgorithm::Sha224, h.finalize().to_vec()),
            Inner::Sha256(h) => (HashAlgorithm::Sha256, h.finalize().to_vec()),
            Inner::Sha384(h) => (HashAlgorithm::Sha384, h.finalize().to_vec()),
            Inner::Sha512(h) => (HashAlgorithm::Sha512, h.finalize().to_vec()),
        };
        DataHash { algorithm, data }
    }
}

/// Convenience: SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> DataHash {
    DataHash {
        algorithm: HashAlgorithm::Sha256,
        data: Sha256::digest(data).to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn sha256_empty() {
        let h = sha256(&[]);
        assert_eq!(
            h.data(),
            hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn imprint_sha256_prefix() {
        let h = sha256(&[]);
        let imp = h.imprint();
        assert_eq!(imp.len(), 34);
        assert_eq!(&imp[0..2], &[0x00, 0x00]); // SHA-256 id = 0
        assert_eq!(DataHash::from_imprint(&imp).unwrap(), h);
    }

    #[test]
    fn imprint_sha384_prefix() {
        let h = DataHasher::new(HashAlgorithm::Sha384)
            .unwrap()
            .update(&[])
            .finalize();
        assert_eq!(&h.imprint()[0..2], &[0x00, 0x02]); // SHA-384 id = 2
    }

    #[test]
    fn rejects_bad_length() {
        assert!(DataHash::new(HashAlgorithm::Sha256, alloc::vec![0u8; 31]).is_err());
    }
}
