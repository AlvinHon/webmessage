//! Provides a local storage implementation for the store.

use serde::{de::DeserializeOwned, Serialize};

pub(crate) mod account;
pub(crate) mod message;

/// SerdeLocalStore is a trait that provides methods to get and set values from local storage.
/// The item to store must be serializable and deserializable.
pub(crate) trait SerdeLocalStore {
    fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        get_from_localstorage(key).map(|str_value| serde_json::from_str(&str_value).ok())?
    }

    fn set<T: Serialize>(&mut self, key: &str, value: T) {
        if let Ok(str_value) = serde_json::to_string(&value) {
            set_to_localstorage(key, &str_value)
        }
    }
}

fn get_from_localstorage(key: &str) -> Option<String> {
    web_sys::window()?
        .local_storage()
        .ok()??
        .get_item(key)
        .ok()?
}
fn set_to_localstorage(key: &str, value: &str) {
    web_sys::window()
        .unwrap()
        .local_storage()
        .unwrap()
        .unwrap()
        .set_item(key, value)
        .unwrap();
}
