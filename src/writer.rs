//! Writer module provides a writer struct to write messages to the store.

use crate::{
    account::Identity,
    core::{
        group::Group,
        message::{MessageHash, SignedMessage},
    },
    message::{Hasher, Signature},
    store::{group::GroupStore, message::SignedMessageStore},
};

/// Writer is a struct that defines the writing process involved with the stores such as `GroupStore` and `SignedMessageStore`.
#[derive(Default)]
pub(crate) struct Writer {
    pub(crate) message_store: SignedMessageStore,
    pub(crate) group_store: GroupStore,
}

impl Writer {
    /// Writes a signed message to the store. It saves the message to the `SignedMessageStore` an
    /// adds the group to the `GroupStore`. It returns the message hash and the signed message.
    pub(crate) fn write(
        &mut self,
        group_id: &str,
        signed_msg: SignedMessage<Identity, Signature>,
    ) -> (MessageHash, SignedMessage<Identity, Signature>) {
        let msg_hash = self
            .message_store
            .save_message::<Hasher>(group_id, &signed_msg);

        self.group_store.add_group(Group::new(group_id.to_string()));

        (msg_hash, signed_msg)
    }

    /// Writes a signed message to the store with validation. It validates the message signature, sequence, and previous hash.
    /// It saves the message to the `SignedMessageStore` and adds the group to the `GroupStore`.
    /// It returns the message hash and the signed message if successful, otherwise it returns a validation error message.
    pub(crate) fn write_with_validation(
        &mut self,
        group_id: &str,
        message: SignedMessage<Identity, Signature>,
    ) -> Result<(MessageHash, SignedMessage<Identity, Signature>), String> {
        // validate message signature
        if !message.verify::<Hasher>() {
            return Err("fail to validate message".to_string());
        }

        // validate sequence and previous hash
        let (expect_prev_hash, expect_seq) = self
            .message_store
            .latest_message(group_id)
            .map(|(hash, msg)| (hash, msg.seq + 1))
            .unwrap_or(([0u8; 32], 0));

        if message.seq != expect_seq {
            return Err("wrong message sequence".to_string());
        }
        if message.message.previous_hash != expect_prev_hash {
            return Err("wrong previous hash".to_string());
        }

        Ok(self.write(group_id, message))
    }
}
