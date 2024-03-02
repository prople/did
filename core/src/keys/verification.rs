use multibase::{self, Base::Base58Btc};

use prople_crypto::base::ToKeySecure;
use prople_crypto::KeySecure::KeySecure;
use prople_crypto::EDDSA::{self as Ed25519, PrivKey};

use crate::keys::{KeySecureBuilder, KeySecureError};

#[derive(Debug, PartialEq)]
pub enum Error {
    GeneratePrivKeyError,
    GenerateSecureKeyError,
}

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
}

impl KeySecureBuilder for Pairs {
    fn build_keysecure(&self, password: String) -> Result<KeySecure, KeySecureError> {
        self.priv_key
            .to_keysecure(password)
            .map_err(|_| KeySecureError::BuildKeySecureError)
    }
}

pub struct Key {
    keypair: Ed25519::KeyPair,
}

impl Key {
    pub fn new() -> Self {
        Self {
            keypair: Ed25519::KeyPair::generate(),
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
}
