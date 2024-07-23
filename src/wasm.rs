//! Contains the functions that are exposed to the JavaScript runtime.

use wasm_bindgen::prelude::*;

use crate::{
    account::GenKeysAlgorithm,
    message::{self, Hasher},
    store::{account::AccountStore, message::SignedMessageStore},
};

/// Initializes an account and returns the public and secret keys.
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn initAccount() -> Vec<String> {
    let mut store = AccountStore {};
    let (public_key, secret_key) = store.init_keys::<GenKeysAlgorithm>();
    vec![public_key.to_string(), secret_key.to_string()]
}

/// Returns the stored messages for the given group ID.
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn messages(group_id: &str) -> Vec<String> {
    let store = SignedMessageStore {};
    store
        .messages(group_id)
        .iter()
        .map(|msg| serde_json::to_string(msg).unwrap())
        .collect()
}

/// Validates the stored messages for the given group ID.
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn validateMessages(group_id: &str) -> bool {
    let store = SignedMessageStore {};
    store.validate_messages::<Hasher>(group_id)
}

/// Signs a message with the given group ID and data. It returns the signed message.
/// This method does not validate the message.
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn signMessage(group_id: &str, data: &str) -> String {
    let acc_store = AccountStore {};
    let mut msg_store = SignedMessageStore {};

    let identity = acc_store.public_key().unwrap();
    let secret = acc_store.secret_key().unwrap();

    let data = data.as_bytes().to_vec();
    let signed_msg = match msg_store.latest_message(group_id) {
        Some((previous_hash, prev_message)) => {
            message::new_from_previous_message(identity, &secret, data, previous_hash, prev_message)
        }
        None => message::new_first_message(identity, &secret, data),
    };

    msg_store.save_message::<Hasher>(group_id, &signed_msg);

    serde_json::to_string(&signed_msg).unwrap()
}

/// Adds a signed message to the store for the given group ID. It returns the hash of the message.
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn addSignedMessage(group_id: &str, signed_msg_str: &str) -> Result<String, String> {
    let mut msg_store = SignedMessageStore {};

    let signed_msg =
        serde_json::from_str(signed_msg_str).map_err(|_| "Fail to parse".to_string())?;

    let hash = msg_store.add_message::<Hasher>(group_id, &signed_msg)?;

    Ok(serde_json::to_string(&hash).unwrap())
}
