//! Signing (key custody) — `client` feature only. Verification never needs this.

use k256::ecdsa::SigningKey;

use crate::crypto::hash::DataHash;
use crate::crypto::signature::{PublicKey, Signature};
use crate::error::Error;

/// Something that can produce secp256k1 signatures and expose its public key.
pub trait Signer {
    /// The signer's compressed public key.
    fn public_key(&self) -> PublicKey;
    /// Sign a [`DataHash`] (its raw 32-byte digest), producing a recoverable
    /// signature in low-`s` canonical form.
    fn sign(&self, digest: &DataHash) -> Signature;
}

/// A secp256k1 signer wrapping a 32-byte private key.
#[derive(Clone, Debug)]
pub struct Secp256k1Signer {
    key: SigningKey,
}

impl Secp256k1Signer {
    /// Build from a 32-byte private key, validating it is in range.
    pub fn from_bytes(secret: &[u8]) -> Result<Self, Error> {
        let key =
            SigningKey::from_slice(secret).map_err(|_| Error::Crypto("invalid private key"))?;
        Ok(Secp256k1Signer { key })
    }

    /// Generate a fresh random signer using the platform RNG.
    #[cfg(feature = "std")]
    pub fn generate() -> Result<Self, Error> {
        let mut secret = [0u8; 32];
        loop {
            getrandom::getrandom(&mut secret).map_err(|_| Error::Crypto("RNG failure"))?;
            if let Ok(s) = Secp256k1Signer::from_bytes(&secret) {
                return Ok(s);
            }
            // Astronomically unlikely: secret was 0 or >= n; retry.
        }
    }
}

impl Signer for Secp256k1Signer {
    fn public_key(&self) -> PublicKey {
        let enc = self.key.verifying_key().to_encoded_point(true);
        PublicKey::from_bytes(enc.as_bytes()).expect("valid generated key")
    }

    fn sign(&self, digest: &DataHash) -> Signature {
        let (sig, rid) = self
            .key
            .sign_prehash_recoverable(digest.data())
            .expect("sign over 32-byte digest");
        // RustCrypto normalises to low-s and sets the recovery id accordingly.
        Signature::new(sig.to_bytes().into(), rid.to_byte())
            .expect("RustCrypto returned a valid recovery id")
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::crypto::hash::sha256;

    #[test]
    fn sign_verify_recover_roundtrip() {
        let signer = Secp256k1Signer::generate().unwrap();
        let pk = signer.public_key();
        let digest = sha256(b"hello unicity");
        let sig = signer.sign(&digest);

        assert!(sig.verify(digest.data(), &pk));
        assert_eq!(sig.recover(digest.data()).unwrap(), pk);

        // Wrong message must fail.
        let other = sha256(b"goodbye");
        assert!(!sig.verify(other.data(), &pk));
    }
}
