//! Provides a struct `AccountStore` for storing account related data.

use crate::{
    account::{Identity, Secret},
    core::account::GenerateKeys,
};

use super::SerdeLocalStore;

const KEY_ACCOUNT_ID: &str = "accpubk";
const KEY_ACCOUNT_SECRET: &str = "accprivk";

/// AccountStore is a store for account related data. It implements the trait [SerdeLocalStore](crate::store::SerdeLocalStore).
#[derive(Default)]
pub(crate) struct AccountStore {}

impl AccountStore {
    /// Initializes an account and returns the public and secret keys. If the account already exists, it returns the existing keys.
    pub(crate) fn init_keys<G: GenerateKeys<Secret, Identity>>(&mut self) -> (Identity, Secret) {
        match self.public_key() {
            Some(public_key) => (public_key, self.secret_key().unwrap()),
            None => {
                let (private_key, public_key) = G::generate_keys();
                self.set_public_key(public_key.clone());
                self.set_secret_key(private_key.clone());
                (public_key, private_key)
            }
        }
    }

    pub(crate) fn public_key(&self) -> Option<Identity> {
        self.get(KEY_ACCOUNT_ID)
    }

    pub(crate) fn secret_key(&self) -> Option<Secret> {
        self.get(KEY_ACCOUNT_SECRET)
    }

    pub(crate) fn set_public_key(&mut self, value: Identity) {
        self.set(KEY_ACCOUNT_ID, value)
    }

    pub(crate) fn set_secret_key(&mut self, value: Secret) {
        self.set(KEY_ACCOUNT_SECRET, value)
    }
}

impl SerdeLocalStore for AccountStore {}
