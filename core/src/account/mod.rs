//! `account` is main module used to generate an [`Account`]
//!
//! The generated account will depends on `EdDSA` generated keypairs
//! and used data is the public key
use prople_crypto::passphrase::types::SaltBytes;
use prople_crypto::types::VectorValue;
use rst_common::with_cryptography::hex;
use rst_common::with_errors::thiserror::{self, Error};

use prople_crypto::aead::{Key, KeyEncryption, KeyNonce, MessageCipher, AEAD};
use prople_crypto::keysecure::KeySecure;

use prople_crypto::eddsa::keypair::KeyPair;
use prople_crypto::eddsa::privkey::PrivKey;
use prople_crypto::eddsa::pubkey::PubKey;
use prople_crypto::eddsa::signature::Signature;

use prople_crypto::passphrase::kdf_params::KdfParams;
use prople_crypto::passphrase::Passphrase;

#[derive(Debug, PartialEq, Error)]
pub enum AccountError {
    #[error("unable to decode: {0}")]
    DecodeError(String),

    #[error("unable to parse: {0}")]
    ParseHexError(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("encode pem failed: {0}")]
    EncodePEMError(String),

    #[error("decode pem failed: {0}")]
    DecodePEMError(String),
}

#[derive(Debug, Clone)]
pub struct Account {
    pair: KeyPair,
}

impl Default for Account {
    fn default() -> Self {
        Self::new()
    }
}

impl Account {
    pub fn new() -> Self {
        let keypair = KeyPair::generate();
        Self { pair: keypair }
    }

    pub fn build_pem(&self) -> Result<String, AccountError> {
        self.pair
            .priv_key()
            .to_pem()
            .map_err(|err| AccountError::EncodePEMError(err.to_string()))
    }

    pub fn from_pem(val: String) -> Result<Self, AccountError> {
        let account = KeyPair::from_pem(val)
            .map(|val| Self { pair: val })
            .map_err(|err| AccountError::DecodePEMError(err.to_string()))?;

        Ok(account)
    }

    pub fn from_keysecure(password: String, keysecure: KeySecure) -> Result<Self, AccountError> {
        let encrypted_text = keysecure.crypto.cipher_text;
        let decoded_encrypted_text = hex::decode(encrypted_text)
            .map_err(|err| AccountError::DecodeError(err.to_string()))?;

        let kdf_params = keysecure.crypto.kdf_params;
        let passphrase_kdf_params = KdfParams {
            m_cost: kdf_params.params.m_cost,
            p_cost: kdf_params.params.p_cost,
            t_cost: kdf_params.params.t_cost,
            output_len: kdf_params.params.output_len,
        };

        let kdf = Passphrase::new(passphrase_kdf_params);
        let salt_vec = kdf_params.salt.as_bytes().to_vec();
        let kdf_hash = kdf
            .hash(password, SaltBytes::from(salt_vec.clone()))
            .map_err(|err| AccountError::DecodeError(err.to_string()))?;

        let nonce = keysecure.crypto.cipher_params.nonce;
        let nonce_decoded =
            hex::decode(nonce).map_err(|err| AccountError::DecodeError(err.to_string()))?;

        let nonce_value: [u8; 24] = nonce_decoded
            .clone()
            .try_into()
            .map_err(|_| AccountError::DecodeError("unable to decode nonce".to_string()))?;

        let key = Key::new(KeyEncryption::from(kdf_hash), KeyNonce::from(nonce_value));
        let decrypted = AEAD::decrypt(&key, &MessageCipher::from(decoded_encrypted_text))
            .map_err(|err| AccountError::DecodeError(err.to_string()))?;

        let to_pem = String::from_utf8(decrypted.vec())
            .map_err(|err| AccountError::DecodeError(err.to_string()))?;

        Account::from_pem(to_pem)
    }

    pub fn pubkey(&self) -> PubKey {
        self.pair.pub_key()
    }

    pub fn privkey(&self) -> PrivKey {
        self.pair.priv_key()
    }

    pub fn signature(&self, message: &[u8]) -> Signature {
        self.pair.signature(message)
    }
}

#[cfg(test)]
mod tests {
    use prople_crypto::keysecure::types::{Password, ToKeySecure};

    use super::*;

    #[test]
    fn test_generate_build_pem() {
        let account = Account::new();
        let account_pem = account.build_pem();
        assert!(!account_pem.is_err());
        assert!(!account_pem.unwrap().is_empty())
    }

    #[test]
    fn test_parse_account_from_encoded() {
        let account = Account::new();
        let account_pem = account.build_pem();
        let account_rebuild = Account::from_pem(account_pem.unwrap());
        assert!(!account_rebuild.is_err());

        let account_rebuild_pubkey = account_rebuild.unwrap().pubkey();
        assert_eq!(
            account_rebuild_pubkey.serialize(),
            account.pubkey().serialize()
        )
    }

    #[test]
    fn test_parse_account_error_invalid_input() {
        let account = Account::from_pem(String::from("invalid"));
        assert!(account.is_err());
        assert!(matches!(account, Err(AccountError::DecodePEMError(_))))
    }

    #[test]
    fn test_build_from_keysecure() {
        let account = Account::new();
        let try_pem = account.privkey().to_pem();
        assert!(!try_pem.is_err());

        let original_pem = try_pem.unwrap();
        let try_keysecure = account
            .privkey()
            .to_keysecure(Password::from("password".to_string()));
        assert!(!try_keysecure.is_err());

        let keysecure = try_keysecure.unwrap();
        let try_rebuild_account = Account::from_keysecure("password".to_string(), keysecure);
        assert!(!try_rebuild_account.is_err());

        let rebuild_account = try_rebuild_account.unwrap();
        let rebuild_account_pem = rebuild_account.privkey().to_pem().unwrap();
        assert_eq!(rebuild_account_pem, original_pem)
    }

    #[test]
    fn test_build_from_keysecure_invalid_password() {
        let account = Account::new();
        let try_keysecure = account
            .privkey()
            .to_keysecure(Password::from("password".to_string()));
        assert!(!try_keysecure.is_err());

        let keysecure = try_keysecure.unwrap();
        let try_rebuild_account = Account::from_keysecure("invalid".to_string(), keysecure);
        assert!(try_rebuild_account.is_err());
    }
}
