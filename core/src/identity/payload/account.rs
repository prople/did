use rst_common::standard::chrono::Utc;
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::with_cryptography::blake3;
use rst_common::with_cryptography::sha2::{Digest, Sha384};

use crate::account::Account as AccountCore;
use crate::types::{DIDError, ToJSON};

/// `Account` is primary key in `Payload` which should be filled
/// with the hashed of generated public key from `EdDSA` algorithm
/// key pairs
///
/// The `account` field is an object that consists of two important fields
///
/// - `key` : a hashed value of generated public key
/// - `version-hash`: a hashed value of when the `Payload` generated (timestamp)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "self::serde")]
pub struct Account {
    #[serde(skip)]
    pub account: Option<AccountCore>,

    #[serde(rename = "version-hash")]
    pub version_hash: Option<String>,

    pub key: Option<String>,
}

impl Account {
    pub fn new() -> Self {
        Self {
            account: Some(AccountCore::new()),
            key: None,
            version_hash: None,
        }
    }

    /// `build` used to generate [`Account::key`] and [`Account::version_hash`]
    ///
    /// Each time this method called it will generate a new `version_hash` based on current
    /// timestamp: [`Utc::now`]. The build process will depends on [`Account::account`], if this
    /// value is still empty it will not build anything
    ///
    /// The `key` will be generated from [`AccountCore`] which take the value in bytes.
    /// The hashed data values will be like this:
    ///
    /// ```text
    /// EdDSA -> SHA384 -> BLAKE3
    /// ```
    pub fn build(&mut self) -> &mut Self {
        if let Some(account) = &self.account {
            self.key = Some(self.build_key(account));
            self.version_hash = Some(self.build_version());
        }

        self
    }

    fn sha384_hasher(&self, data: impl AsRef<[u8]>) -> impl AsRef<[u8]> {
        let mut sha384 = Sha384::new();
        sha384.update(data);

        let sha384_output = sha384.finalize();
        sha384_output
    }

    fn blake3_hasher(&self, data: &[u8]) -> String {
        blake3::hash(data).to_hex().to_string()
    }

    fn build_key(&self, account: &AccountCore) -> String {
        let account_bytes = account.pubkey().serialize();
        let sha384_hashed = self.sha384_hasher(account_bytes);
        self.blake3_hasher(sha384_hashed.as_ref())
    }

    fn build_version(&self) -> String {
        let now = Utc::now().to_rfc3339();
        let sha384_hashed = self.sha384_hasher(now.as_bytes());
        self.blake3_hasher(sha384_hashed.as_ref())
    }
}

impl ToJSON for Account {
    fn to_json(&self) -> Result<String, DIDError> {
        if self.key.is_none() {
            return Err(DIDError::GenerateJSONError(
                "account is still empty".to_string(),
            ));
        }

        serde_json::to_string(self).map_err(|err| DIDError::GenerateJSONError(err.to_string()))
    }
}

impl From<AccountCore> for Account {
    fn from(value: AccountCore) -> Self {
        Self {
            account: Some(value),
            version_hash: None,
            key: None,
        }
    }
}

impl TryFrom<String> for Account {
    type Error = DIDError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let account: Account = serde_json::from_str(value.as_str())
            .map_err(|err| DIDError::DecodeJSONError(err.to_string()))?;
        Ok(account)
    }
}

impl Default for Account {
    fn default() -> Self {
        Account::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_account() {
        let account_core = AccountCore::new();
        let mut account_payload = Account::from(account_core);
        account_payload.build();

        let account_json = account_payload.to_json();
        assert!(!account_json.is_err());
        assert!(!account_json.unwrap().is_empty());
    }

    #[test]
    fn test_decode_json() {
        let account_core = AccountCore::new();
        let mut account_payload = Account::from(account_core);
        account_payload.build();

        let account_json = account_payload.to_json();
        let jsonstr = account_json.unwrap();

        let to_account = Account::try_from(jsonstr);
        assert!(!to_account.is_err());

        let decoded = to_account.unwrap();
        assert_eq!(decoded.key, account_payload.key);
        assert_eq!(decoded.version_hash, account_payload.version_hash);
    }

    #[test]
    fn test_decode_json_error() {
        let to_account = Account::try_from("invalid".to_string());
        assert!(to_account.is_err());
        assert!(matches!(
            to_account.unwrap_err(),
            DIDError::DecodeJSONError(_)
        ))
    }

    #[test]
    fn test_build_json_error_on_empty_account() {
        let account = Account::default();
        let json = account.to_json();

        assert!(json.is_err());
        assert!(matches!(json.unwrap_err(), DIDError::GenerateJSONError(_)));
    }
}
