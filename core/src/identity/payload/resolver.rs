use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use crate::types::{DIDError, ToJSON};

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub enum AddressType {
    #[serde(rename = "peer")]
    Peer,

    #[serde(rename = "vir")]
    Vir,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub struct Address {
    #[serde(rename = "type")]
    address_type: AddressType,

    value: String,
}

impl Address {
    pub fn new(addr_type: AddressType, value: String) -> Self {
        Self {
            address_type: addr_type,
            value,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub struct AllowedDID {
    access_token: String,
    did: String,
}

impl AllowedDID {
    pub fn new(access_token: String, did: String) -> Self {
        Self { access_token, did }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub struct Resolver {
    address: Address,
    allowed_did: Option<Vec<AllowedDID>>,
}

impl Resolver {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            allowed_did: Some(Vec::new()),
        }
    }

    pub fn add_did(&mut self, did: AllowedDID) -> &mut Self {
        if let Some(allowed) = &self.allowed_did {
            let mut new_allowed = allowed.to_owned();
            new_allowed.push(did);

            self.allowed_did = Some(new_allowed)
        }
        
        self
    }
}

impl ToJSON for Resolver {
    fn to_json(&self) -> Result<String, DIDError> {
        serde_json::to_string(self).map_err(|err| DIDError::GenerateJSONError(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_resolver() {
        let address = Address::new(AddressType::Peer, "addr".to_string());

        let allowed_did_1 = AllowedDID::new("token1".to_string(), "did1".to_string());
        let allowed_did_2 = AllowedDID::new("token2".to_string(), "did2".to_string());

        let mut resolver = Resolver::new(address);
        resolver.add_did(allowed_did_1).add_did(allowed_did_2);

        let jsonstr = resolver.to_json();
        assert!(!jsonstr.is_err());

        let str = jsonstr.unwrap();
        assert!(!str.is_empty());
        assert!(str.contains("peer"));
        assert!(str.contains("token1"));
        assert!(str.contains("token2"));
        assert!(str.contains("did1"));
        assert!(str.contains("did2"));
    }
}
