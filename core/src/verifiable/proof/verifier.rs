use prople_crypto::eddsa::pubkey::PubKey;

use super::hash::HashedData;
use super::serialize::ProofByte;
use super::types::ProofError;

pub(crate) fn verify_signature(
    pubkey: PubKey,
    hashed: HashedData,
    signature: ProofByte,
) -> Result<bool, ProofError> {
    let verified = pubkey
        .verify(hashed.to_bytes(), signature.to_hex())
        .map_err(|err| ProofError::ProofVerificationError(err.to_string()))?;

    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifiable::proof::serialize::{serialize_hashed_data, ProofByte};
    use prople_crypto::eddsa::keypair::KeyPair;

    mod expect_errors {
        use super::*;

        #[test]
        fn test_verified_error() {
            let keypair = KeyPair::generate();
            let invalid_sig = ProofByte::from(b"invalid".to_vec());

            let public_key = keypair.pub_key();
            let try_verify = public_key.verify(b"hello world", invalid_sig.to_hex());
            assert!(try_verify.is_err())
        }
    }

    mod expect_success {
        use super::*;

        #[test]
        fn test_verified() {
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
}
