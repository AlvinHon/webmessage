use crate::{
    account::{Identity, Secret},
    core::message::SignedMessage,
    message::{MessageSigner, Signature},
    store::{account::AccountStore, message::SignedMessageStore},
};

#[derive(Default)]
pub(crate) struct Signer {
    pub(crate) account_store: AccountStore,
    pub(crate) message_store: SignedMessageStore,
}

impl Signer {
    pub(crate) fn sign(
        &mut self,
        group_id: &str,
        data: Vec<u8>,
    ) -> SignedMessage<Identity, Signature> {
        let identity = self.account_store.public_key().unwrap();
        let secret = self.account_store.secret_key().unwrap();

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
