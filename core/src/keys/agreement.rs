use prople_crypto::base::ToKeySecure;
use prople_crypto::KeySecure::KeySecure;
use prople_crypto::ECDH::{self as X25519, KeyPair};

use crate::keys::{KeySecureBuilder, KeySecureError};

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
}

impl KeySecureBuilder for Pairs {
    fn build_keysecure(&self, password: String) -> Result<KeySecure, KeySecureError> {
        self.priv_key
            .to_keysecure(password)
            .map_err(|_| KeySecureError::BuildKeySecureError)
    }
}

pub struct Key {
    keypair: X25519::KeyPair,
}

impl Key {
    pub fn new() -> Self {
        Self {
            keypair: X25519::KeyPair::generate(),
        }
    }

    pub fn generate(&self) -> Pairs {
        let pub_key = self.keypair.pub_key().to_hex();
        Pairs {
            pub_key,
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
}
