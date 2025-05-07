//! `identity` is a module used to generate an entity [`types::Identity`]
use crate::doc::{Doc, Primary, ToDoc};
use crate::keys::{
    AgreementKey, AgreementPairs, IdentityPrivateKeyPairs, IdentityPrivateKeyPairsBuilder,
    KeySecureBuilder, KeySecureError, PrivateKeyPairs, VerificationKey, VerificationPairs,
};

use crate::types::*;

/// `VerificationMethod` is an object used to generate two important keys, a `verification_pairs`
/// and an `aggreement_pairs`
///
/// A `verification_pairs` is a public and private keys used to verify a context based on some signature
/// An `aggreement_pairs` is a public and private keys used to generate the shared secret through `ECDH` algorithm
#[derive(Debug, Clone)]
pub struct VerificationMethod {
    pub verification_pairs: VerificationPairs,
    pub agreement_pairs: AgreementPairs,
}

/// `Identity` is an object that hold a `DID Syntax` with specific `Prople DID Method` which contains
/// `authentication` and `assertion`
///
/// The `authentication` used to authenticate an access request.
/// The  `assertion` used to assert some given resources
#[derive(Debug, Clone)]
pub struct Identity {
    identity: String,
    authentication: Option<VerificationMethod>,
    assertion: Option<VerificationMethod>,
}

impl Identity {
    pub fn new(val: String) -> Self {
        Self {
            identity: val,
            authentication: None,
            assertion: None,
        }
    }

    pub fn value(&self) -> String {
        self.identity.clone()
    }

    pub fn account(&self) -> Result<String, DIDError> {
        let identity = self.identity.clone();
        let value = identity.as_str().split(DID_SYNTAX_MARK);
        if value.clone().count() < 3 {
            return Err(DIDError::InvalidDID);
        }

        value
            .clone()
            .last()
            .map(|val| val.to_string())
            .ok_or(DIDError::InvalidDID)
    }

    pub fn get_authentication_method(&self) -> Option<VerificationMethod> {
        self.authentication.to_owned()
    }

    pub fn get_assertion_method(&self) -> Option<VerificationMethod> {
        self.assertion.to_owned()
    }

    pub fn build_auth_method(&mut self) -> &mut Self {
        if self.authentication.is_none() {
            let verification_method = self.build_verification_method();
            self.authentication = Some(verification_method);
        }

        self
    }

    pub fn build_assertion_method(&mut self) -> &mut Self {
        if self.assertion.is_none() {
            let verification_method = self.build_verification_method();
            self.assertion = Some(verification_method);
        }

        self
    }

    fn build_verification_method(&self) -> VerificationMethod {
        let verification_key = VerificationKey::new();
        let verification_pairs = verification_key.generate();

        let agreement_key = AgreementKey::new();
        let agreement_pairs = agreement_key.generate();

        VerificationMethod {
            verification_pairs,
            agreement_pairs,
        }
    }
}

impl ToDoc for Identity {
    fn to_doc(&self) -> Doc {
        let auth_verification_id = format!("{}#key-auth-verification", self.identity);
        let auth_aggreement_id = format!("{}#key-auth-aggrement", self.identity);
        let assertion_verification_id = format!("{}#key-assertion-verification", self.identity);
        let assertion_aggreement_id = format!("{}#key-assertion-aggrement", self.identity);

        let mut doc = Doc::generate(self.identity.clone());
        doc.add_context(CONTEXT_ED25519.to_string())
            .add_context(CONTEXT_X25519.to_string());

        if let Some(auth) = &self.authentication {
            let auth_verification_primary = Primary {
                id: auth_verification_id,
                controller: self.identity.clone(),
                verification_type: VERIFICATION_TYPE_ED25519.to_string(),
                multibase: auth.verification_pairs.clone().pub_key,
            };

            let auth_aggreement_primary = Primary {
                id: auth_aggreement_id,
                controller: self.identity.clone(),
                verification_type: VERIFICATION_TYPE_X25519.to_string(),
                multibase: auth.agreement_pairs.clone().pub_key,
            };

            doc.add_authentication(auth_verification_primary)
                .add_authentication(auth_aggreement_primary);
        }

        if let Some(assertion) = &self.assertion {
            let assertion_verification_primary = Primary {
                id: assertion_verification_id,
                controller: self.identity.clone(),
                verification_type: VERIFICATION_TYPE_ED25519.to_string(),
                multibase: assertion.verification_pairs.clone().pub_key,
            };

            let assertion_aggreement_primary = Primary {
                id: assertion_aggreement_id,
                controller: self.identity.clone(),
                verification_type: VERIFICATION_TYPE_X25519.to_string(),
                multibase: assertion.agreement_pairs.clone().pub_key,
            };

            doc.add_assertion(assertion_verification_primary)
                .add_assertion(assertion_aggreement_primary);
        }

        doc
    }
}

impl IdentityPrivateKeyPairsBuilder for Identity {
    fn build_private_keys(
        &self,
        password: String,
    ) -> Result<IdentityPrivateKeyPairs, KeySecureError> {
        let mut pairs = IdentityPrivateKeyPairs::new(self.value());

        if let Some(authentication) = &self.authentication {
            let auth_verification_keysecure = authentication
                .verification_pairs
                .clone()
                .build_keysecure(password.clone())
                .map_err(|_| KeySecureError::BuildIdentityPrivateKeysError)?;

            let auth_aggrement_keysecure = authentication
                .agreement_pairs
                .clone()
                .build_keysecure(password.clone())
                .map_err(|_| KeySecureError::BuildIdentityPrivateKeysError)?;

            pairs.authentication = Some(PrivateKeyPairs {
                verification: auth_verification_keysecure,
                aggrement: auth_aggrement_keysecure,
            })
        }

        if let Some(assertion) = &self.assertion {
            let assertion_verification_keysecure = assertion
                .verification_pairs
                .clone()
                .build_keysecure(password.clone())
                .map_err(|_| KeySecureError::BuildIdentityPrivateKeysError)?;

            let assertion_aggrement_keysecure = assertion
                .agreement_pairs
                .clone()
                .build_keysecure(password.clone())
                .map_err(|_| KeySecureError::BuildIdentityPrivateKeysError)?;

            pairs.assertion = Some(PrivateKeyPairs {
                verification: assertion_verification_keysecure,
                aggrement: assertion_aggrement_keysecure,
            })
        }

        Ok(pairs)
    }
}
