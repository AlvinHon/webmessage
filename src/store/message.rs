//! Provides a struct `SignedMessageStore` for storing signed messages.

use crate::{
    account::Identity,
    core::message::{MessageHash, MessageHasher, SignedMessage},
    message::Signature,
};

use super::SerdeLocalStore;

const KEY_MESSAGE: &str = "msg";
const KEY_LATEST_MESSAGEHASH: &str = "latest_msghash";

/// SignedMessageStore is a store for signed messages. It implements the trait [SerdeLocalStore](crate::store::SerdeLocalStore).
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

    /// Adds a message to the store. It returns the hash of the message if the message is valid.
    ///
    /// The steps involved:
    /// 1. Validate the message signature.
    /// 2. Validate the sequence number and the previous hash.
    /// 3. Save the message.
    /// 4. Update the latest message hash.
    /// 5. Return the hash of the message.
    pub(crate) fn add_message<H: MessageHasher>(
        &mut self,
        group_id: &str,
        message: &SignedMessage<Identity, Signature>,
    ) -> Result<MessageHash, String> {
        // validate message signature
        if !message.validate::<H>() {
            return Err("fail to validate message".to_string());
        }

        // validate sequence and previous hash
        let (expect_prev_hash, expect_seq) = self
            .latest_message(group_id)
            .map(|(hash, msg)| (hash, msg.seq + 1))
            .unwrap_or(([0u8; 32], 0));

        if message.seq != expect_seq {
            return Err("wrong message sequence".to_string());
        }
        if message.message.previous_hash != expect_prev_hash {
            return Err("wrong previous hash".to_string());
        }

        Ok(self.save_message::<H>(group_id, message))
    }

    /// Saves a message to the store. It returns the hash of the message.
    /// This method does not validate the message.
    ///
    /// The steps involved:
    /// 1. Save the message.
    /// 2. Update the latest message hash.
    /// 3. Return the hash of the message.
    pub(crate) fn save_message<H: MessageHasher>(
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
    pub(crate) fn validate_messages<H: MessageHasher>(&self, group_id: &str) -> bool {
        let (mut latest_hash, latest_msg) = match self.latest_message(group_id) {
            Some(m) => m,
            None => return true,
        };
        let mut seq = latest_msg.seq;

        while let Some(message) = self.message(group_id, &latest_hash) {
            if message.seq != seq || message.hash::<H>() != latest_hash {
                return false;
            }
            if !message.validate::<H>() {
                return false;
            }
            latest_hash = message.message.previous_hash;

            seq = seq.saturating_sub(1);
        }

        latest_hash == [0u8; 32] && seq == 0
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
