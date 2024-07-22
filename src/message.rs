//! Defines the message type and its signature. It also provides a function to sign a message using the Schnorr signature scheme.

use crate::{
    account::{Identity, Secret},
    core::message::{Message, MessageHash, MessageHasher, MessageSignature, SignedMessage},
};

use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

/// Hasher is a wrapper around sha2::Sha256, which implements the trait [MessageHasher](crate::core::message::MessageHasher).
pub struct Hasher;

impl MessageHasher for Hasher {
    fn hash<T: AsRef<[u8]>>(value: T) -> MessageHash {
        <Self as schnorr_rs::Hash>::hash(value).try_into().unwrap()
    }
}

impl schnorr_rs::Hash for Hasher {
    fn hash<T: AsRef<[u8]>>(value: T) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(value);
        hasher.finalize().to_vec()
    }
}

/// Signature is a wrapper around schnorr_rs::ec::Signature, which implements the trait [MessageSignature](crate::core::message::MessageSignature).
#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    signature: String,
}

impl Signature {
    pub fn new(signature: schnorr_rs::ec::Signature) -> Self {
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
        let signature: schnorr_rs::ec::Signature = serde_json::from_str(&self.signature).unwrap();
        let public_key = id.to_public_key();
        let scheme = schnorr_rs::SignatureSchemeECP256::<Hasher>::new();
        scheme.verify(&public_key, message, &signature)
    }
}

/// Implements the trait [MessageSigner](crate::core::message::MessageSigner) using the Schnorr signature scheme.
pub(crate) struct MessageSigner {}
impl crate::core::message::MessageSigner<Identity, Secret, Signature> for MessageSigner {
    fn sign(id: &Identity, secret: &Secret, message: &Message) -> Signature {
        let public_key = &id.to_public_key();
        let private_key = secret.as_private_key();
        let scheme = schnorr_rs::SignatureSchemeECP256::<Hasher>::new();
        let signature = scheme.sign(
            &mut rand::thread_rng(),
            private_key,
            public_key,
            message.to_hash::<Hasher>(),
        );
        Signature::new(signature)
    }
}

/// Creates a new first message with the given data and signs it using the Schnorr signature scheme.
pub(crate) fn new_first_message(
    identity: Identity,
    secret: &Secret,
    data: Vec<u8>,
) -> SignedMessage<Identity, Signature> {
    SignedMessage::new_first_message::<Secret, MessageSigner>(identity, secret, data)
}

/// Creates a new message from the previous message with the given data and signs it using the Schnorr signature scheme.
pub(crate) fn new_from_previous_message(
    identity: Identity,
    secret: &Secret,
    data: Vec<u8>,
    hash: MessageHash,
    signed_message: SignedMessage<Identity, Signature>,
) -> SignedMessage<Identity, Signature> {
    SignedMessage::new_from_previous_message::<Secret, MessageSigner>(
        identity,
        secret,
        data,
        hash,
        signed_message,
    )
}
