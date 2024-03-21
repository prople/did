use prople_crypto::ecdh::keypair::KeyPair;
use prople_crypto::keysecure::types::ToKeySecure;
use prople_crypto::keysecure::KeySecure;

use crate::keys::{KeySecureBuilder, KeySecureError};

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
