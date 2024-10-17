//! Provides a struct `SignedMessageStore` for storing signed messages.

use sha2::Digest;

use crate::{
    account::Identity,
    core::message::{MessageHash, SignedMessage},
    message::Signature,
};

use super::SerdeLocalStore;

const KEY_MESSAGE: &str = "msg";
const KEY_LATEST_MESSAGEHASH: &str = "latest_msghash";

/// SignedMessageStore is a store for signed messages. It implements the trait [SerdeLocalStore](crate::store::SerdeLocalStore).
#[derive(Default)]
pub(crate) struct SignedMessageStore {}

impl SignedMessageStore {
    /// Returns the message with the given hash.
    pub(crate) fn message(
        &self,
        group_id: &str,
        hash: &MessageHash,
    ) -> Option<SignedMessage<Identity, Signature>> {
        self.get(format!("{KEY_MESSAGE}_{group_id}_{:x?}", hash).as_str())
    }

    /// Returns the latest message for the given group ID.
    pub(crate) fn latest_message(
        &self,
        group_id: &str,
    ) -> Option<(MessageHash, SignedMessage<Identity, Signature>)> {
        self.latest_message_hash(group_id)
            .and_then(|hash| self.message(group_id, &hash).map(|message| (hash, message)))
    }

    /// Returns the latest message hash for the given group ID.
    pub(crate) fn latest_message_hash(&self, group_id: &str) -> Option<MessageHash> {
        self.get(format!("{KEY_LATEST_MESSAGEHASH}_{group_id}",).as_str())
    }

    /// Saves a message to the store. It returns the hash of the message.
    /// This method does not validate the message.
    ///
    /// The steps involved:
    /// 1. Save the message.
    /// 2. Update the latest message hash.
    /// 3. Return the hash of the message.
    pub(crate) fn save_message<H: Digest>(
        &mut self,
        group_id: &str,
        message: &SignedMessage<Identity, Signature>,
    ) -> MessageHash {
        // save message
        let hash = message.hash::<H>();
        self.set_message(group_id, &hash, message.clone());

        // update latest message
        self.set_latest_message_hash(group_id, &hash);

        hash
    }

    /// Returns the stored messages for the given group ID.
    pub(crate) fn messages(&self, group_id: &str) -> Vec<SignedMessage<Identity, Signature>> {
        // get the latest message and iterate through the chain
        let mut messages = vec![];
        let mut latest_hash = match self.latest_message_hash(group_id) {
            Some(hash) => hash,
            None => return messages,
        };
        while let Some(message) = self.message(group_id, &latest_hash) {
            messages.push(message.clone());
            latest_hash = message.message.previous_hash;
        }
        messages
    }

    /// Validates the stored messages for the given group ID.
    pub(crate) fn validate_messages<H: Digest>(&self, group_id: &str) -> bool {
        let mut latest_msg = match self.latest_message(group_id) {
            Some((_, m)) => m,
            None => return true,
        };

        if !latest_msg.verify::<H>() {
            return false;
        }

        while let Some(message) = self.message(group_id, &latest_msg.message.previous_hash) {
            if !message.is_valid_parent_of::<H>(&latest_msg) {
                return false;
            }

            latest_msg = message.clone();
        }

        latest_msg.is_first_message()
    }

    fn set_message(
        &mut self,
        group_id: &str,
        hash: &MessageHash,
        message: SignedMessage<Identity, Signature>,
    ) {
        self.set(
            format!("{KEY_MESSAGE}_{group_id}_{:x?}", hash).as_str(),
            message,
        );
    }

    fn set_latest_message_hash(&mut self, group_id: &str, hash: &MessageHash) {
        self.set(
            format!("{KEY_LATEST_MESSAGEHASH}_{group_id}",).as_str(),
            hash,
        );
    }
}

impl SerdeLocalStore for SignedMessageStore {}
