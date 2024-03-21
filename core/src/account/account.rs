use rst_common::with_errors::thiserror::{self, Error};

use prople_crypto::eddsa::keypair::KeyPair;
use prople_crypto::eddsa::pubkey::PubKey;
use prople_crypto::eddsa::privkey::PrivKey;
use prople_crypto::eddsa::signature::Signature;

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
}
