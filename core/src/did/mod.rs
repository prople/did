//! `did` module used to generated the `DID Syntax` based on generated [`IdentityPayload`] data
use multibase::Base::Base58Btc;

use rst_common::with_cryptography::blake3;
use rst_common::with_cryptography::sha2::{Digest, Sha384};

use crate::account::Account;
use crate::identity::types::Identity;
use crate::types::*;

pub mod query;

use query::Params;

/// `DID` is a main object used to generate an account entity in specific format
/// which is `DID Syntax`
///
/// The format itself will be like this:
/// ```text
///     did:prople:<base58btc_encoded_data>
/// ````
///
/// The **encoded_data** will be a generated public key in bytes
pub struct DID {
    account: Account,
}

impl DID {
    pub fn new() -> Self {
        Self {
            account: Account::new(),
        }
    }

    pub fn from_pem(val: String) -> Result<Self, DIDError> {
        let did = Account::from_pem(val)
            .map(|account| Self { account })
            .map_err(|_| DIDError::InvalidPEM)?;

        Ok(did)
    }

    pub fn identity(&self) -> Result<Identity, DIDError> {
        let pubkey = self.account.pubkey();
        let pubkey_in_bytes = pubkey.serialize();

        let mut sha3_hasher = Sha384::new();
        sha3_hasher.update(pubkey_in_bytes);

        let pubkey_sha3 = sha3_hasher.finalize();
        let pubkey_blake3 = blake3::hash(pubkey_sha3.as_ref());
        let pubkey_hex = pubkey_blake3.to_hex();

        let base58_encoded = multibase::encode(Base58Btc, pubkey_hex.as_bytes());

        let id = format!(
            "{}:{}:{}",
            DID_SYNTAX_SCHEME, DID_SYNTAX_METHOD, base58_encoded
        );

        Ok(Identity::new(id))
    }

    pub fn build_uri(&self, params: Option<Params>) -> Result<String, DIDError> {
        let identity = self.identity()?;
        let primary = identity.value();

        match params {
            Some(query_params) => query_params
                .build_query()
                .map(|val| format!("{}?{}", primary, val))
                .ok_or(DIDError::BuildURIError),
            None => Ok(primary),
        }
    }

    pub fn account(&self) -> Account {
        self.account.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::types::ToDoc;
    use crate::keys::IdentityPrivateKeyPairsBuilder;

    #[test]
    fn test_generate() {
        let did = DID::new();
        let try_identity = did.identity();
        assert!(!try_identity.is_err());

        let identity = try_identity.unwrap();
        assert!(identity.value().contains(DID_SYNTAX_SCHEME));
        assert!(identity.value().contains(DID_SYNTAX_METHOD));
    }

    #[test]
    fn test_regenerate_from_pem() {
        let did = DID::new();
        let pem = did.account().build_pem();
        assert!(!pem.is_err());

        let did_regenerate = DID::from_pem(pem.unwrap());
        assert!(!did_regenerate.is_err());
        assert_eq!(
            did.identity().unwrap().value(),
            did_regenerate.unwrap().identity().unwrap().value()
        )
    }

    #[test]
    fn test_get_account() {
        let did = DID::new();

        let try_identity = did.identity();
        assert!(!try_identity.is_err());

        let identity = try_identity.unwrap();
        let try_account = identity.account();
        assert!(!try_account.is_err());

        let account = try_account.unwrap();
        assert!(account.contains('z'));
    }

    #[test]
    fn test_generate_identity_doc() {
        let did = DID::new();
        let mut identity = did.identity().unwrap();

        let try_build_auth = identity.build_auth_method();
        assert!(!try_build_auth.is_err());

        let try_build_assertion = identity.build_assertion_method();
        assert!(!try_build_assertion.is_err());

        let doc = identity.to_doc();
        let jsondoc = doc.to_json();
        assert!(!jsondoc.is_err());

        let jsondoc_str = jsondoc.unwrap();
        assert!(!jsondoc_str.clone().is_empty());
    }

    #[test]
    fn test_generate_identity_key_pairs() {
        let did = DID::new();

        let mut identity = did.identity().unwrap();

        let try_build_auth = identity.build_auth_method();
        assert!(!try_build_auth.is_err());

        let try_build_assertion = identity.build_assertion_method();
        assert!(!try_build_assertion.is_err());

        let try_private_key_pairs = identity.build_private_keys("test".to_string());
        assert!(!try_private_key_pairs.is_err());

        let try_private_key_pairs_in_json = try_private_key_pairs.unwrap().to_json();
        assert!(!try_private_key_pairs_in_json.is_err());
    }

    #[test]
    fn test_build_did_uri_with_params() {
        let did = DID::new();

        let params = Params{
            address: Some("test-addr".to_string()),
            hl: Some("test-hl".to_string()),
            service: Some("test-svc".to_string()) 
        };

        let uri = did.build_uri(Some(params));
        assert!(!uri.is_err());

        let did_primary = did.identity().unwrap().value();
        let did_query_params = "service=test-svc&address=test-addr&hl=test-hl".to_string();
        let did_uri = format!("{}?{}", did_primary, did_query_params);
        assert_eq!(did_uri, uri.unwrap())
    }

    #[test]
    fn test_build_did_uri_without_params() {
        let did = DID::new();
        let uri = did.build_uri(None);
        assert!(!uri.is_err());
        
        let did_primary = did.identity().unwrap().value();
        assert_eq!(uri.unwrap(), did_primary)
    }
}