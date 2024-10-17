//! Defines the message type and its signature. It also provides a function to sign a message using the Schnorr signature scheme.

use crate::{
    account::{Identity, Secret},
    core::message::{Message, MessageSignature},
};

use sha2::Sha256;

use serde::{Deserialize, Serialize};

type SchnorrSignature = schnorr_rs::Signature<schnorr_rs::SchnorrP256Group>;

/// Signature is a wrapper around schnorr_rs::ec::Signature, which implements the trait [MessageSignature](crate::core::message::MessageSignature).
#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    signature: String,
}

impl Signature {
    pub fn new(signature: SchnorrSignature) -> Self {
        Self {
            signature: serde_json::to_string(&signature).unwrap(),
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.signature.as_ref()
    }
}

impl MessageSignature<Identity> for Signature {
    fn verify(&self, id: &Identity, message: &[u8]) -> bool {
        let signature: schnorr_rs::Signature<schnorr_rs::SchnorrP256Group> =
            serde_json::from_str(&self.signature).unwrap();
        let public_key = id.to_public_key();
        let scheme = schnorr_rs::signature_scheme_p256::<Sha256>();
        scheme.verify(&public_key, message, &signature)
    }
}

/// Implements the trait [MessageSigner](crate::core::message::MessageSigner) using the Schnorr signature scheme.
pub struct MessageSigner {}
impl crate::core::message::MessageSigner<Identity, Secret, Signature> for MessageSigner {
    fn sign(id: &Identity, secret: &Secret, message: &Message) -> Signature {
        let public_key = &id.to_public_key();
        let private_key = secret.as_private_key();
        let scheme = schnorr_rs::signature_scheme_p256::<Sha256>();
        let signature = scheme.sign(
            &mut rand::thread_rng(),
            private_key,
            public_key,
            message.to_hash::<Sha256>(),
        );
        Signature::new(signature)
    }
}
