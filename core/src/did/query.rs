use multiaddr::Multiaddr;
use rst_common::standard::serde::{self, Deserialize, Serialize};

use crate::types::DIDError;

#[derive(Deserialize, Serialize, Debug)]
#[serde(crate = "self::serde")]
pub struct Params {
    pub service: Option<String>,
    pub address: Option<String>,
    pub hl: Option<String>,
}

impl Params {
    pub fn parse_multiaddr(&self) -> Result<Option<Multiaddr>, DIDError> {
        match &self.address {
            Some(addr) => {
                let address = addr
                    .parse::<Multiaddr>()
                    .map_err(|err| DIDError::GenerateMultiAddrError(err.to_string()))?;

                Ok(Some(address))
            }
            None => Ok(None),
        }
    }

    pub fn build_query(&self) -> Option<String> {
        let mut query_str = Vec::new();
        if let Some(svc) = &self.service {
            query_str.push(format!("service={}", svc))
        }

        if let Some(addr) = &self.address {
            query_str.push(format!("address={}", addr))
        }

        if let Some(hl) = &self.hl {
            query_str.push(format!("hl={}", hl))
        }

        if query_str.is_empty() {
            return None;
        }

        Some(query_str.join("&"))
    }
}

impl Default for Params {
    fn default() -> Self {
        Params {
            service: None,
            address: None,
            hl: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use multiaddr::Protocol;

    #[test]
    fn test_build_query_string() {
        let params = Params {
            address: Some("test-addr".to_string()),
            hl: Some("test-hl".to_string()),
            service: Some("test-svc".to_string()),
        };

        let query_str = params.build_query();
        assert!(query_str.is_some());
        assert_eq!(
            "service=test-svc&address=test-addr&hl=test-hl".to_string(),
            query_str.unwrap()
        )
    }

    #[test]
    fn test_build_query_one_param() {
        let mut params = Params::default();
        params.address = Some("test-addr".to_string());

        let query_str = params.build_query();
        assert!(query_str.is_some());
        assert_eq!("address=test-addr".to_string(), query_str.unwrap())
    }

    #[test]
    fn test_build_query_empty() {
        let params = Params::default();
        let query_str = params.build_query();
        assert!(query_str.is_none())
    }

    #[test]
    fn test_parse_invalid_multiaddr() {
        let mut params = Params::default();
        params.address = Some("invalid".to_string());

        let multiaddr = params.parse_multiaddr();
        assert!(multiaddr.is_err())
    }

    #[test]
    fn test_parse_valid_multiaddr() {
        let mut params = Params::default();
        params.address = Some("/ip4/127.0.0.1/tcp/1234".to_string());

        let multiaddr = params.parse_multiaddr();
        assert!(!multiaddr.is_err());
        assert!(multiaddr.clone().unwrap().is_some());

        let addr = multiaddr.unwrap().unwrap();
        let components = addr.iter().collect::<Vec<_>>();
        assert_eq!(components[0], Protocol::Ip4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(components[1], Protocol::Tcp(1234))
    }
}
