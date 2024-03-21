//! `did` module used to generated the `DID Syntax` based on generated [`IdentityPayload`] data
use multibase::Base::Base58Btc;

use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use crate::identity::payload::{hash_payload, sign_payload, Payload};
use crate::identity::types::Identity;
use crate::types::*;

/// `IdentityPayload` used to as primary data structure for account key
///
/// Previous implementation the account key used as main DID key syntax
/// is using Base58BTC format from the generated public key `EdDSA`. New implementation
/// is using this data structure that will generate to JSON and encode it with Base58BTC
///
/// The purpose using this data structure is to provide a self-describe data key,
/// so when people got the DID account key, they will know how to resolve the DID document
/// but still providing secured data by giving `hash` and `signature`
#[derive(Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct IdentityPayload {
    payload: Payload,
    hash: String,
    signature: String,
}

impl IdentityPayload {
    /// `new` used to generate new [`IdentityPayload`] based on given [`Payload`] data
    /// structure
    ///
    /// The given payload will be hashed and make the signature of it using the account
    /// private key
    pub fn new(payload: Payload) -> Result<Self, DIDError> {
        let payload_account = payload
            .clone()
            .account
            .account
            .ok_or(DIDError::BuildPayloadError("missing account".to_string()))?;

        let payload_hash = hash_payload(payload.clone())?;
        let payload_signature = sign_payload(payload.clone(), payload_account)?;

        Ok(Self {
            payload,
            hash: payload_hash,
            signature: payload_signature,
        })
    }
}

impl ToJSON for IdentityPayload {
    fn to_json(&self) -> Result<String, DIDError> {
        serde_json::to_string(self).map_err(|err| DIDError::GenerateJSONError(err.to_string()))
    }
}

/// `DID` is a main object used to generate an entity [`IdentityPayload`] in specific format
/// which is `DID Syntax`
///
/// The format itself will be like this:
/// ```text
///     did:prople:<base58btc_encoded_data>
/// ````
pub struct DID {
    payload: IdentityPayload,
}

impl DID {
    pub fn new(payload: IdentityPayload) -> Self {
        Self { payload }
    }

    pub fn identity(&self) -> Result<Identity, DIDError> {
        let payload_json = self.payload.to_json()?;
        let base58_encoded = multibase::encode(Base58Btc, payload_json.as_bytes());

        let id = format!(
            "{}:{}:{}",
            DID_SYNTAX_SCHEME, DID_SYNTAX_METHOD, base58_encoded
        );

        Ok(Identity::new(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::types::ToDoc;
    use crate::identity::payload::account::Account;
    use crate::identity::payload::resolver::{Address, AddressType, Resolver};
    use crate::keys::IdentityPrivateKeyPairsBuilder;

    fn generate_identity_payload() -> IdentityPayload {
        let address = Address::new(AddressType::Peer, "addres".to_string());
        let resolver = Resolver::new(address);
        let account = Account::new();
        let payload = Payload::new(account, resolver);

        let identity_payload = IdentityPayload::new(payload).unwrap();
        identity_payload
    }

    #[test]
    fn test_generate() {
        let identity_payload = generate_identity_payload();
        let did = DID::new(identity_payload);
        let try_identity = did.identity();
        assert!(!try_identity.is_err());

        let identity = try_identity.unwrap();
        assert!(identity.value().contains(DID_SYNTAX_SCHEME));
        assert!(identity.value().contains(DID_SYNTAX_METHOD));
    }

    #[test]
    fn test_get_account() {
        let identity_payload = generate_identity_payload();
        let did = DID::new(identity_payload);

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
        let identity_payload = generate_identity_payload();
        let did = DID::new(identity_payload);
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
        let identity_payload = generate_identity_payload();
        let did = DID::new(identity_payload);

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
}
