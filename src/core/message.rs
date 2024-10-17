//! Contains the structs and traits that are used to represent messages in the system.

use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::account::{Identity, Secret};

/// MessageHash is a type alias for a 32-byte array.
pub type MessageHash = [u8; 32];

/// The Verifiable is implemented on the types that can be verified, such as signature.
pub trait Verifiable<I: Identity>: AsRef<[u8]> {
    fn verify(&self, id: &I, message: &[u8]) -> bool;
}

/// Message is a struct that represents a message.
#[derive(Clone, Serialize, Deserialize)]
pub struct Message {
    /// previous_hash is the hash of the previous message.
    pub previous_hash: MessageHash,
    /// data is the data of the message.
    pub data: Vec<u8>,
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
    pub fn to_hash<H: Digest>(&self) -> MessageHash {
        H::new()
            .chain_update([self.previous_hash.to_vec(), self.data.clone()].concat())
            .finalize()
            .as_ref()
            .try_into()
            .unwrap()
    }
}

pub trait MessageSigner<I: Identity, K: Secret, S: Verifiable<I>> {
    fn sign(id: &I, secret: &K, message: &Message) -> S;
}

/// SignedMessage is a struct that represents a signed message.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedMessage<I: Identity, S: Verifiable<I>> {
    /// message to be signed.
    pub message: Message,
    /// the identity of the signer.
    pub id: I,
    /// the sequence number in the chain.
    pub seq: u32,
    /// the signature of the message.
    pub signature: S,
}

impl<I, S> SignedMessage<I, S>
where
    I: Identity + AsRef<[u8]>,
    S: Verifiable<I>,
{
    /// Creates a new first message with the given data and signs it.
    pub fn new_first_message<K: Secret, A: MessageSigner<I, K, S>>(
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
    pub fn new_from_previous_message<K: Secret, A: MessageSigner<I, K, S>>(
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

    /// verifies if the signature of the message is valid.
    pub fn verify<H: Digest>(&self) -> bool {
        self.signature
            .verify(&self.id, &self.message.to_hash::<H>())
    }

    /// hash returns the hash of the signed message.
    /// The hash is calculated by hashing the data of the message, the id, the sequence number, and the signature.
    pub fn hash<H: Digest>(&self) -> MessageHash {
        H::new()
            .chain_update(
                [
                    &self.message.data,
                    self.id.as_ref(),
                    &self.seq.to_le_bytes(),
                    self.signature.as_ref(),
                ]
                .concat(),
            )
            .finalize()
            .as_ref()
            .try_into()
            .unwrap()
    }

    /// Checks if the message is a valid parent of the other message. It checks the conditions such as
    /// the hash of the message, the sequence number, and the signature validation of other message.
    pub fn is_valid_parent_of<H: Digest>(&self, other: &Self) -> bool {
        self.hash::<H>() == other.message.previous_hash
            && self.seq + 1 == other.seq
            && other.verify::<H>()
    }

    /// Checks if the message is the first message.
    pub fn is_first_message(&self) -> bool {
        self.seq == 0 && self.message.previous_hash == [0u8; 32]
    }
}
