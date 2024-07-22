//! Contains the structs and traits that are used to represent messages in the system.

use serde::{Deserialize, Serialize};

use super::account::{Identity, Secret};

/// MessageHash is a type alias for a 32-byte array.
pub type MessageHash = [u8; 32];

/// MessageSignature is a trait that represents a signature of a message.
pub(crate) trait MessageSignature<I: Identity>: AsRef<[u8]> {
    fn verify(&self, id: &I, message: &[u8]) -> bool;
}

/// Implements the hash function for messages.
pub(crate) trait MessageHasher {
    fn hash<T: AsRef<[u8]>>(value: T) -> MessageHash;
}

/// Message is a struct that represents a message.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Message {
    /// previous_hash is the hash of the previous message.
    pub(crate) previous_hash: MessageHash,
    /// data is the data of the message.
    pub(crate) data: Vec<u8>,
}

impl Message {
    /// Creates a new message with the given data and a zero hash as the previous hash.
    pub fn root(data: Vec<u8>) -> Self {
        Self {
            previous_hash: [0; 32],
            data,
        }
    }

    /// Hash by hashing the previous hash and the data of the message.
    pub fn to_hash<H: MessageHasher>(&self) -> MessageHash {
        H::hash([self.previous_hash.to_vec(), self.data.clone()].concat())
    }
}

pub(crate) trait MessageSigner<I: Identity, K: Secret, S: MessageSignature<I>> {
    fn sign(id: &I, secret: &K, message: &Message) -> S;
}

/// SignedMessage is a struct that represents a signed message.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SignedMessage<I: Identity, S: MessageSignature<I>> {
    /// message to be signed.
    pub(crate) message: Message,
    /// the identity of the signer.
    pub(crate) id: I,
    /// the sequence number in the chain.
    pub(crate) seq: u32,
    /// the signature of the message.
    pub(crate) signature: S,
}

impl<I, S> SignedMessage<I, S>
where
    I: Identity + AsRef<[u8]>,
    S: MessageSignature<I>,
{
    /// Creates a new first message with the given data and signs it.
    pub(crate) fn new_first_message<K: Secret, A: MessageSigner<I, K, S>>(
        id: I,
        secret: &K,
        data: Vec<u8>,
    ) -> Self {
        let message = Message::root(data);
        let signature = A::sign(&id, secret, &message);
        Self {
            message,
            id,
            seq: 0,
            signature,
        }
    }

    /// Creates a new message from the previous message with the given data and signs it.
    pub(crate) fn new_from_previous_message<K: Secret, A: MessageSigner<I, K, S>>(
        id: I,
        secret: &K,
        data: Vec<u8>,
        hash: MessageHash,
        signed_message: SignedMessage<I, S>,
    ) -> Self {
        let message = Message {
            previous_hash: hash,
            data,
        };
        let signature = A::sign(&id, secret, &message);
        Self {
            message,
            id,
            seq: signed_message.seq + 1,
            signature,
        }
    }

    /// validate checks if the signature of the message is valid.
    pub(crate) fn validate<H: MessageHasher>(&self) -> bool {
        self.signature
            .verify(&self.id, &self.message.to_hash::<H>())
    }

    /// hash returns the hash of the signed message.
    /// The hash is calculated by hashing the data of the message, the id, the sequence number, and the signature.
    pub(crate) fn hash<H: MessageHasher>(&self) -> MessageHash {
        H::hash(
            [
                &self.message.data,
                self.id.as_ref(),
                &self.seq.to_le_bytes(),
                self.signature.as_ref(),
            ]
            .concat(),
        )
    }
}
