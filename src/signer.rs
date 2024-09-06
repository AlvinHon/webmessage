//! Defines the `Signer` struct and its implementation.

use crate::{
    account::{Identity, Secret},
    core::message::SignedMessage,
    message::{MessageSigner, Signature},
    store::{account::AccountStore, message::SignedMessageStore},
};

/// Signer is a struct that defines the signing process involved with the stores such as `AccountStore` and `SignedMessageStore`.
#[derive(Default)]
pub(crate) struct Signer {
    pub(crate) account_store: AccountStore,
    pub(crate) message_store: SignedMessageStore,
}

impl Signer {
    /// Signs a message with the given group id and data.
    /// The message is signed with the secret key from the `AccountStore`.
    /// Depends on the latest message stored, it signs the message as the first message or a subsequent message.
    pub(crate) fn sign(
        &mut self,
        group_id: &str,
        data: Vec<u8>,
    ) -> SignedMessage<Identity, Signature> {
        let (identity, secret) = self.account_store.current_account().unwrap();

        match self.message_store.latest_message(group_id) {
            Some((previous_hash, prev_message)) => {
                SignedMessage::new_from_previous_message::<Secret, MessageSigner>(
                    identity,
                    &secret,
                    data,
                    previous_hash,
                    prev_message,
                )
            }
            None => {
                SignedMessage::new_first_message::<Secret, MessageSigner>(identity, &secret, data)
            }
        }
    }
}
