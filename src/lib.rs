//! # Webmessage
//!
//! Webmessage is a library that stores a sequence of messages in browser's local storage.
//! It uses techniques of hashing and digital signatures to ensure immutability of message sequence
//! and the non-repudiation of the messages.

pub mod account;
mod core;
pub use core::{account::GenerateKeys, group::Group, message::SignedMessage};

pub mod message;
pub mod signer;
pub mod store;
pub mod writer;

use account::Identity;
use store::group::GroupStore;
use wasm_bindgen::prelude::*;

use crate::{
    account::GenKeysAlgorithm,
    message::Hasher,
    signer::Signer,
    store::{account::AccountStore, message::SignedMessageStore},
    writer::Writer,
};

/// Initializes an account and returns the public and secret keys.
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn initAccount() -> Vec<String> {
    let (public_key, secret_key) = AccountStore::default().initialize::<GenKeysAlgorithm>();
    vec![public_key.to_string(), secret_key.to_string()]
}

#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn allAccounts() -> Vec<String> {
    AccountStore::default()
        .accounts()
        .iter()
        .map(|(id, _)| id.to_string())
        .collect()
}

#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn setCurrentAccount(identity: &str) {
    AccountStore::default().set_current_account(Identity::try_from(identity).unwrap());
}

#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn newAccount() -> Vec<String> {
    let (public_key, secret_key) = AccountStore::default().new_account::<GenKeysAlgorithm>();
    vec![public_key.to_string(), secret_key.to_string()]
}

#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn deleteAccount(identity: &str) {
    AccountStore::default().delete_account(&Identity::try_from(identity).unwrap());
}

/// Returns the stored messages for the given group ID.
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn messages(group_id: &str) -> Vec<String> {
    SignedMessageStore::default()
        .messages(group_id)
        .iter()
        .map(|msg| serde_json::to_string(msg).unwrap())
        .collect()
}

#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn groups() -> Vec<String> {
    GroupStore::default()
        .groups()
        .iter()
        .map(|msg| serde_json::to_string(msg).unwrap())
        .collect()
}

/// Validates the stored messages for the given group ID.
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn validateMessages(group_id: &str) -> bool {
    SignedMessageStore::default().validate_messages::<Hasher>(group_id)
}

/// Signs a message with the given group ID and data. It returns the signed message.
/// This method does not validate the message.
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn signMessage(group_id: &str, data: &str) -> String {
    let signed_msg = Signer::default().sign(group_id, data.as_bytes().to_vec());
    let (_, wrote_signed_msg) = Writer::default().write(group_id, signed_msg);

    serde_json::to_string(&wrote_signed_msg).unwrap()
}

/// Adds a signed message to the store for the given group ID. It returns the hash of the message.
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn addSignedMessage(group_id: &str, signed_msg_str: &str) -> Result<String, String> {
    let signed_msg =
        serde_json::from_str(signed_msg_str).map_err(|_| "Fail to parse".to_string())?;

    let (hash, _) = Writer::default().write_with_validation(group_id, signed_msg)?;
    Ok(serde_json::to_string(&hash).unwrap())
}

/// Clears the local storage.
#[wasm_bindgen]
pub fn clear() -> Result<(), String> {
    web_sys::window()
        .ok_or("Fail to get window".to_string())?
        .local_storage()
        .map_err(|_| "Fail to get local storage".to_string())?
        .ok_or("Fail to unwrap local storage".to_string())?
        .clear()
        .map_err(|_| "Fail to clear local storage".to_string())
}
