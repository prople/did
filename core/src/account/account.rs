use prople_crypto::errors::{CommonError, EddsaError};
use prople_crypto::EDDSA::{KeyPair, PubKey};

#[derive(Debug, PartialEq)]
pub enum Error {
    DecodeError(String),
    ParseHexError(String),
    InvalidPublicKey(String),
}

#[derive(Debug)]
pub struct Account {
    key: PubKey,
}

impl Account {
    pub fn new() -> Self {
        let keypair = KeyPair::generate();
        Self {
            key: keypair.pub_key(),
        }
    }

    pub fn build(&self) -> String {
        let pub_key_hex = self.key.to_hex();
        multibase::encode(multibase::Base::Base58Btc, pub_key_hex.as_bytes())
    }

    pub fn from_str(val: String) -> Result<Self, Error> {
        let base_decode = multibase::decode(val);
        let decoded = match base_decode {
            Ok(value) => {
                let to_hex = String::from_utf8(value.1);
                match to_hex {
                    Ok(hex_val) => hex_val,
                    Err(err) => return Err(Error::ParseHexError(err.to_string())),
                }
            }
            Err(err) => return Err(Error::DecodeError(err.to_string())),
        };

        let pub_key = PubKey::from_hex(decoded);
        match pub_key {
            Ok(value) => Ok(Self { key: value }),
            Err(err) => match err {
                EddsaError::Common(CommonError::ParseHexError(msg)) => {
                    Err(Error::ParseHexError(msg))
                }
                _ => Err(Error::InvalidPublicKey("invalid public key".to_string())),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_build() {
        let account = Account::new();
        let account_encoded = account.build();
        assert!(account_encoded.starts_with("z"))
    }

    #[test]
    fn test_parse_account_from_encoded() {
        let account = Account::new();
        let account_encoded = account.build();
        let account_rebuild = Account::from_str(account_encoded.clone());
        assert!(!account_rebuild.is_err());

        let account_rebuild_encoded = account_rebuild.unwrap().build();
        assert_eq!(account_rebuild_encoded, account_encoded)
    }

    #[test]
    fn test_parse_account_error_invalid_input() {
        let account = Account::from_str(String::from("invalid"));
        assert!(account.is_err());

        assert!(matches!(account, Err(Error::DecodeError(_))))
    }

    #[test]
    fn test_parse_account_error_invalid_pub_key() {
        let encoded_invalid = multibase::encode(multibase::Base::Base58Btc, "invalid".as_bytes());
        let account = Account::from_str(encoded_invalid);
        assert!(account.is_err());

        assert!(matches!(account, Err(Error::ParseHexError(_))))
    }
}