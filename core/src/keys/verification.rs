use multibase::{self, Base::Base58Btc};

use prople_crypto::eddsa::{keypair::KeyPair, pubkey::PubKey};
use prople_crypto::eddsa::privkey::PrivKey;
use prople_crypto::keysecure::types::ToKeySecure;
use prople_crypto::keysecure::KeySecure;

use crate::keys::{KeySecureBuilder, KeySecureError};

/// `Error` is a specific error types used for verification only
#[derive(Debug, PartialEq)]
pub enum Error {
    GeneratePrivKeyError,
    DecodePublicKeyError,
    GenerateSecureKeyError,
}

/// `Pairs` used to generate public and private keys from `EdDSA` algorithm
#[derive(Debug, Clone)]
pub struct Pairs {
    pub pub_key: String,
    pub priv_key: PrivKey,
}

impl Pairs {
    pub fn is_valid(&self) -> bool {
        let try_to_pem = self.priv_key.to_pem();
        let pem = match try_to_pem {
            Ok(value) => value,
            Err(_) => return false,
        };

        !self.pub_key.is_empty() || !pem.is_empty()
    }

    pub fn decode_pub_key(&self) -> Result<PubKey, Error> {
        let (_, pubkey_bytes) = multibase::decode(self.pub_key.to_owned()).map_err(|_| Error::DecodePublicKeyError)?;
        let pubkey_string = String::from_utf8(pubkey_bytes).map_err(|_| Error::DecodePublicKeyError)?;
        let pubkey = PubKey::from_hex(pubkey_string).map_err(|_| Error::DecodePublicKeyError)?;

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

/// `Key` used to hold a key pair from [`Ed25519::KeyPair`]
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
        let pub_key = self.keypair.pub_key();
        let priv_key = self.keypair.priv_key();

        let pub_key_hex = pub_key.to_hex();
        let pub_key_encoded = multibase::encode(Base58Btc, pub_key_hex.as_bytes());

        Pairs {
            pub_key: pub_key_encoded,
            priv_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypairs() {
        let verification = Key::new();
        let keypairs = verification.generate();
        assert!(keypairs.is_valid())
    }

    #[test]
    fn test_decode_public_key() {
        let verification = Key::new();
        let pairs = verification.generate();

        let privkey_pem = pairs.priv_key.to_pem();
        assert!(!privkey_pem.is_err());

        let keypair_generated = KeyPair::from_pem(privkey_pem.unwrap());
        assert!(!keypair_generated.is_err());

        let pubkey_decoded = pairs.decode_pub_key();
        assert!(!pubkey_decoded.is_err());

        let keypair = keypair_generated.unwrap();
        let pubkey_regenerated = keypair.pub_key().to_hex();
        assert_eq!(pubkey_regenerated, pubkey_decoded.unwrap().to_hex())
    }
}
