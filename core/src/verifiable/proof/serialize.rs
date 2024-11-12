use multibase::{self, Base::Base58Btc};
use rst_common::with_cryptography::hex;

use prople_crypto::types::ByteHex;
use prople_crypto::eddsa::keypair::KeyPair;

use super::hash::HashedData;

/// ProofByteEncoded is a new type that represent encoded value of [`ProofByte`] 
/// 
/// The string value should be an encoded bytes using Base58-btc format
#[derive(Clone, Debug)]
pub(crate) struct ProofByteEncoded(String);

impl ProofByteEncoded {
    pub(crate) fn get(&self) -> String {
        self.0.to_owned()
    }
}

impl From<String> for ProofByteEncoded {
    fn from(value: String) -> Self {
        ProofByteEncoded(value)
    }
}

/// ProofByte is a new type that represent a digital signature that generated from signing
/// given [`HashedData`] using given private key
#[derive(Clone, Debug)]
pub(crate) struct ProofByte(Vec<u8>);

impl ProofByte {
    pub(crate) fn to_bytes(&self) -> &[u8] {
        &self.0.as_slice()
    }

    pub(crate) fn encode(&self) -> ProofByteEncoded {
        let encoded = multibase::encode(Base58Btc, self.to_bytes());
        ProofByteEncoded::from(encoded)
    }

    pub(crate) fn to_hex(&self) -> ByteHex {
        let out = hex::encode(self.to_bytes());
        ByteHex::from(out)
    }
}

impl From<&[u8]> for ProofByte {
    fn from(value: &[u8]) -> Self {
        ProofByte(value.to_vec())
    }
}

impl From<Vec<u8>> for ProofByte {
    fn from(value: Vec<u8>) -> Self {
        ProofByte(value)
    }
}

/// serialize_hashed_data following algorithm to serialize digital signature
///
/// Current implementation has a little adjustment which doesn't need to depends on proof options.
/// From the formal specification this function should be depends on option verificationMethod, that
/// this property used to get keypair. But because we have a different requirement we just put the [`KeyPair`]
/// directly
///
/// Spec: https://www.w3.org/TR/vc-di-eddsa/#proof-serialization-eddsa-jcs-2022
pub(crate) fn serialize_hashed_data(hashed: HashedData, keypair: KeyPair) -> ProofByte {
    let signature = keypair.signature(hashed.to_bytes());
    let output = signature.sign();
    ProofByte::from(output.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialized_and_verify() {
        let hashed = HashedData::from(b"hello world".as_slice());
        let keypair = KeyPair::generate();
        let serialized = serialize_hashed_data(hashed.clone(), keypair.clone());

        let serialized_bytes = serialized.to_bytes();
        assert_eq!(serialized_bytes.len(), 64);
        
        let public_key = keypair.pub_key();
        let try_verify = public_key.verify(b"hello world", serialized.to_hex());

        assert!(try_verify.is_ok());
        assert!(try_verify.unwrap())
    }
}
