use multibase::{self, Base::Base58Btc};

use rst_common::with_errors::thiserror::Error as ThisError;

use prople_crypto::ecdh::keypair::KeyPair;
use prople_crypto::ecdh::pubkey::PublicKey;
use prople_crypto::keysecure::types::ToKeySecure;
use prople_crypto::keysecure::KeySecure;

use crate::keys::{KeySecureBuilder, KeySecureError};

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("decoding public key error")]
    DecodePublicKeyError,
}

/// `Pairs` contains public and private keys that generated from `ECDH` algorithm
#[derive(Debug, Clone)]
pub struct Pairs {
    pub pub_key: String,
    pub priv_key: KeyPair,
}

impl Pairs {
    pub fn is_valid(&self) -> bool {
        let keypair_hex = self.priv_key.to_hex();
        !self.pub_key.is_empty() || !keypair_hex.is_empty()
    }

    pub fn decode_public_key(&self) -> Result<PublicKey, Error> {
        let (_, pubkey_bytes) =
            multibase::decode(self.pub_key.to_owned()).map_err(|_| Error::DecodePublicKeyError)?;
        let pubkey_string =
            String::from_utf8(pubkey_bytes).map_err(|_| Error::DecodePublicKeyError)?;
        let pubkey =
            PublicKey::from_hex(&pubkey_string).map_err(|_| Error::DecodePublicKeyError)?;

        Ok(pubkey)
    }
}

impl KeySecureBuilder for Pairs {
    fn build_keysecure(&self, password: String) -> Result<KeySecure, KeySecureError> {
        self.priv_key
            .to_keysecure(password)
            .map_err(|_| KeySecureError::BuildKeySecureError)
    }
}

/// `Key` used to generate specific `X25519` keypair
///
/// The public and private keys will be generated from this object
pub struct Key {
    keypair: KeyPair,
}

impl Key {
    pub fn new() -> Self {
        Self {
            keypair: KeyPair::generate(),
        }
    }

    pub fn generate(&self) -> Pairs {
        let pub_key = self.keypair.pub_key().to_hex();
        let pub_key_encoded = multibase::encode(Base58Btc, pub_key.as_bytes());

        Pairs {
            pub_key: pub_key_encoded,
            priv_key: self.keypair.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let key = Key::new();
        let pairs = key.generate();
        assert!(pairs.is_valid())
    }

    #[test]
    fn test_decode_public_key() {
        let key = Key::new();
        let pairs = key.generate();

        let pubkey_decoded = pairs.decode_public_key();
        assert!(!pubkey_decoded.is_err());

        let keypair = pairs.priv_key;
        assert_eq!(keypair.pub_key().to_hex(), pubkey_decoded.unwrap().to_hex());
    }
}
