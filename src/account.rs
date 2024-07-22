//! Contains the implementation of the account system.

use std::fmt::Display;

use serde::{Deserialize, Serialize};

use crate::{core::account::GenerateKeys, message::Hasher};

/// Identity is a wrapper around schnorr_rs::ec::PublicKey, which implements the trait [Identity](crate::core::account::Identity).
#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    public_key: String,
}

impl Identity {
    pub fn new(public_key: schnorr_rs::ec::PublicKey) -> Self {
        // TODO implement PartialEq, Eq, AsRef<[u8]> for schnorr_rs::ec::PublicKey
        Self {
            public_key: serde_json::to_string(&public_key).unwrap(),
        }
    }

    pub fn to_public_key(&self) -> schnorr_rs::ec::PublicKey {
        serde_json::from_str(&self.public_key).unwrap()
    }
}

impl Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.public_key)
    }
}
impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}
impl Eq for Identity {}
impl AsRef<[u8]> for Identity {
    fn as_ref(&self) -> &[u8] {
        self.public_key.as_bytes()
    }
}

impl TryFrom<Vec<u8>> for Identity {
    type Error = ();
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key: String::from_utf8(value).map_err(|_| ())?,
        })
    }
}
impl crate::core::account::Identity for Identity {}

/// Secret is a wrapper around schnorr_rs::ec::SigningKey, which implements the trait [Secret](crate::core::account::Secret).
#[derive(Clone, Serialize, Deserialize)]
pub struct Secret {
    private_key: schnorr_rs::ec::SigningKey,
}
impl crate::core::account::Secret for Secret {}

impl Secret {
    pub fn as_private_key(&self) -> &schnorr_rs::ec::SigningKey {
        &self.private_key
    }
}

impl Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(&self.private_key).unwrap())
    }
}

/// GenKeysAlgorithm is a wrapper around schnorr_rs::SignatureSchemeECP256<Hasher>, which implements the trait [GenerateKeys](crate::core::account::GenerateKeys).
pub struct GenKeysAlgorithm;
impl GenerateKeys<Secret, Identity> for GenKeysAlgorithm {
    fn generate_keys() -> (Secret, Identity) {
        let scheme = schnorr_rs::SignatureSchemeECP256::<Hasher>::new();
        let (private_key, public_key) = scheme.generate_key(&mut rand::thread_rng());
        let id = Identity::new(public_key);
        (Secret { private_key }, id)
    }
}
