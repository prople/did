use crate::account::Account;
use crate::identity::types::Identity;
use crate::types::*;

pub struct DID {
    account: Account,
}

impl DID {
    pub fn new() -> Self {
        Self {
            account: Account::new(),
        }
    }

    pub fn identity(&self) -> Identity {
        let id = format!(
            "{}:{}:{}",
            DID_SYNTAX_SCHEME,
            DID_SYNTAX_METHOD,
            self.account.build()
        );
        Identity::new(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityPrivateKeyPairsBuilder;

    #[test]
    fn test_generate() {
        let did = DID::new();
        let identity = did.identity();

        assert!(identity.value().contains(DID_SYNTAX_SCHEME));
        assert!(identity.value().contains(DID_SYNTAX_METHOD));
    }

    #[test]
    fn test_get_account() {
        let did = DID::new();
        let identity = did.identity();
        let try_account = identity.account();
        assert!(!try_account.is_err());

        let account = try_account.unwrap();
        assert!(account.contains('z'));
    }

    #[test]
    fn test_generate_identity_doc() {
        let did = DID::new();
        let mut identity = did.identity();

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
        let mut identity = did.identity();

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
