//! Provides a struct `AccountStore` for storing account related data.

use crate::{
    account::{Identity, Secret},
    core::account::GenerateKeys,
};

use super::SerdeLocalStore;

const KEY_ACCOUNT_CURRENT_IDX: &str = "accidx";
const KEY_ACCOUNT_LIST: &str = "accs";

/// AccountStore is a store for account related data. It implements the trait [SerdeLocalStore](crate::store::SerdeLocalStore).
#[derive(Default)]
pub(crate) struct AccountStore {}

impl AccountStore {
    /// Initializes an account and returns the public and secret keys. If the account already exists, it returns the existing keys.
    pub(crate) fn initialize<G: GenerateKeys<Secret, Identity>>(&mut self) -> (Identity, Secret) {
        self.current_account()
            .map(|(id, secret)| (id, secret))
            .unwrap_or_else(|| self.new_account::<G>())
    }

    /// Creates a new account and returns the public and secret keys.
    pub(crate) fn new_account<G: GenerateKeys<Secret, Identity>>(&mut self) -> (Identity, Secret) {
        let (private_key, public_key) = G::generate_keys();
        let mut accounts = self.accounts();
        let idx = accounts.len();
        self.set_current_index(idx);
        accounts.push((public_key.clone(), private_key.clone()));
        self.set_accounts(accounts);
        (public_key, private_key)
    }

    /// Deletes an account with the given identity. If the account is the current account, it sets the current account to the previous account.
    pub(crate) fn delete_account(&mut self, identity: &Identity) {
        let accounts = self.accounts();
        let target_idx = accounts
            .iter()
            .enumerate()
            .find_map(|(idx, (id, _))| (id == identity).then_some(idx));

        if let Some(idx) = target_idx {
            let mut accounts = self.accounts();
            accounts.remove(idx);
            self.set_accounts(accounts);

            let current_idx = self.current_index();
            if current_idx == idx {
                self.set_current_index(current_idx.saturating_sub(1));
            } else if current_idx > idx {
                self.set_current_index(current_idx - 1);
            }
        }
    }

    /// Returns the current account.
    pub(crate) fn current_account(&self) -> Option<(Identity, Secret)> {
        let accounts = self.accounts();
        let idx = self.current_index();
        accounts.get(idx).cloned()
    }

    /// Sets the current account with the given identity.
    pub(crate) fn set_current_account(&mut self, identity: Identity) {
        let target_idx = self
            .accounts()
            .into_iter()
            .enumerate()
            .find_map(|(idx, (id, _))| (id == identity).then_some(idx));

        if let Some(idx) = target_idx {
            self.set_current_index(idx);
        }
    }

    pub(crate) fn current_index(&self) -> usize {
        self.get(KEY_ACCOUNT_CURRENT_IDX).unwrap_or_default()
    }

    pub(crate) fn set_current_index(&mut self, value: usize) {
        self.set(KEY_ACCOUNT_CURRENT_IDX, value)
    }

    pub(crate) fn accounts(&self) -> Vec<(Identity, Secret)> {
        self.get(KEY_ACCOUNT_LIST).unwrap_or_default()
    }

    pub(crate) fn set_accounts(&mut self, value: Vec<(Identity, Secret)>) {
        self.set(KEY_ACCOUNT_LIST, value)
    }
}

impl SerdeLocalStore for AccountStore {}
