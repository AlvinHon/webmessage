use wasm_bindgen_test::*;
use webmessage::{
    account::{GenKeysAlgorithm, Identity, Secret},
    groups, initAccount,
    message::{Hasher, MessageSigner, Signature},
    messages, signMessage, validateMessages, GenerateKeys, Group, SignedMessage,
};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_accounts() {
    // accounts should be empty
    let accounts = webmessage::allAccounts();
    assert!(accounts.is_empty());

    // initialize an account
    let id_and_secret = initAccount();
    assert_eq!(id_and_secret.len(), 2);
    let id = Identity::try_from(id_and_secret[0].as_str()).expect("it should parse the identity");

    // accounts should have one account
    let accounts = webmessage::allAccounts();
    assert_eq!(accounts.len(), 1);
    // the account should be the same as the initialized account
    assert_eq!(accounts[0], id.to_string());

    // add another account
    let id_and_secret2 = webmessage::newAccount();
    assert_eq!(id_and_secret2.len(), 2);

    let id2 = Identity::try_from(id_and_secret2[0].as_str()).expect("it should parse the identity");

    // accounts should have two accounts
    let accounts = webmessage::allAccounts();
    assert_eq!(accounts.len(), 2);
    // the accounts should be the same as the initialized accounts
    assert_eq!(accounts[0], id.to_string());
    assert_eq!(accounts[1], id2.to_string());

    // check if current account is the newly added account
    let check_id_and_secret = initAccount();
    assert_eq!(check_id_and_secret.len(), 2);
    let check_id =
        Identity::try_from(check_id_and_secret[0].as_str()).expect("it should parse the identity");
    assert!(check_id == id2);

    // set the current account to the first account
    webmessage::setCurrentAccount(&id.to_string());
    let check_id_and_secret = initAccount();
    assert_eq!(check_id_and_secret.len(), 2);
    let check_id =
        Identity::try_from(check_id_and_secret[0].as_str()).expect("it should parse the identity");
    assert!(check_id == id);

    // delete the first account
    webmessage::deleteAccount(&id.to_string());
    // accounts should have one account
    let accounts = webmessage::allAccounts();
    assert_eq!(accounts.len(), 1);
    // the account should be the same as the second account
    assert_eq!(accounts[0], id2.to_string());

    // check if current account is the second account
    let check_id_and_secret = initAccount();
    assert_eq!(check_id_and_secret.len(), 2);
    let check_id =
        Identity::try_from(check_id_and_secret[0].as_str()).expect("it should parse the identity");
    assert!(check_id == id2);

    // clear the local storage
    webmessage::clear().expect("it should clear the local storage");
}

#[wasm_bindgen_test]
fn test_sign_message() {
    // test initial setup
    let items = initAccount();
    assert_eq!(items.len(), 2);

    let id = Identity::try_from(items[0].as_str()).expect("it should parse the identity");

    assert!(messages("group1").is_empty());
    assert!(groups().is_empty());

    // test signing a new message
    assert!(!signMessage("group1", "some data").is_empty());

    let msgs = messages("group1");
    assert!(!msgs.is_empty());
    let signed_msg: SignedMessage<Identity, Signature> =
        serde_json::from_str(msgs[0].as_str()).expect("it should parse the signed message");

    // validate the signed message
    assert!(signed_msg.id == id);
    assert_eq!(signed_msg.seq, 0);
    assert_eq!(signed_msg.message.data, "some data".as_bytes());
    assert!(!groups().is_empty());

    // test signing another message
    assert!(!signMessage("group1", "some data again").is_empty());
    assert!(messages("group1").len() == 2);
    assert!(groups().len() == 1);

    // validate all the messages
    assert!(validateMessages("group1"));

    // clear the local storage
    webmessage::clear().expect("it should clear the local storage");
}

#[wasm_bindgen_test]
fn test_add_message() {
    initAccount();

    // create a new identity for signing a message
    let (other_msg, other_msg2) = {
        let (other_secret, other_id) = GenKeysAlgorithm::generate_keys();
        let msg1 = SignedMessage::new_first_message::<Secret, MessageSigner>(
            other_id.clone(),
            &other_secret,
            "other data".as_bytes().to_vec(),
        );
        let msg2 = SignedMessage::new_from_previous_message::<Secret, MessageSigner>(
            other_id.clone(),
            &other_secret,
            "other data 2".as_bytes().to_vec(),
            msg1.hash::<Hasher>(),
            msg1.clone(),
        );

        (msg1, msg2)
    };

    // add the signed message from the other identity
    webmessage::addSignedMessage("group1", &serde_json::to_string(&other_msg).unwrap())
        .expect("it should add the signed message");

    assert!(!messages("group1").is_empty());
    assert!(!groups().is_empty());

    // add the signed message from the other identity
    webmessage::addSignedMessage("group1", &serde_json::to_string(&other_msg2).unwrap())
        .expect("it should add the signed message");

    assert!(messages("group1").len() == 2);
    assert!(groups().len() == 1);

    assert!(validateMessages("group1"));

    // clear the local storage
    webmessage::clear().expect("it should clear the local storage");
}

#[wasm_bindgen_test]
fn test_sign_and_then_add_other_message() {
    initAccount();

    // test signing a new message
    let msg_str = signMessage("group1", "some data");
    let signed_msg: SignedMessage<Identity, Signature> =
        serde_json::from_str(&msg_str).expect("it should parse the signed message");
    assert!(signed_msg.verify::<Hasher>());

    // create a new identity for signing a message
    let other_msg = {
        let (other_secret, other_id) = GenKeysAlgorithm::generate_keys();
        SignedMessage::new_from_previous_message::<Secret, MessageSigner>(
            other_id.clone(),
            &other_secret,
            "other data".as_bytes().to_vec(),
            signed_msg.hash::<Hasher>(),
            signed_msg.clone(),
        )
    };
    assert!(other_msg.verify::<Hasher>());

    assert!(signed_msg.is_valid_parent_of::<Hasher>(&other_msg));

    // add the signed message from the other identity
    webmessage::addSignedMessage("group1", &serde_json::to_string(&other_msg).unwrap())
        .expect("it should add the signed message");

    assert!(messages("group1").len() == 2);
    assert!(groups().len() == 1);
    assert!(validateMessages("group1"));

    // clear the local storage
    webmessage::clear().expect("it should clear the local storage");
}

#[wasm_bindgen_test]
fn test_add_other_message_and_then_sign() {
    initAccount();

    // create a new identity for signing a message
    let other_msg = {
        let (other_secret, other_id) = GenKeysAlgorithm::generate_keys();
        SignedMessage::new_first_message::<Secret, MessageSigner>(
            other_id.clone(),
            &other_secret,
            "other data".as_bytes().to_vec(),
        )
    };
    assert!(other_msg.verify::<Hasher>());

    // add the signed message from the other identity
    webmessage::addSignedMessage("group1", &serde_json::to_string(&other_msg).unwrap())
        .expect("it should add the signed message");

    // test signing a new message
    let msg_str = signMessage("group1", "some data");
    let signed_msg: SignedMessage<Identity, Signature> =
        serde_json::from_str(&msg_str).expect("it should parse the signed message");
    assert!(signed_msg.verify::<Hasher>());

    assert!(messages("group1").len() == 2);
    assert!(groups().len() == 1);
    assert!(validateMessages("group1"));

    // clear the local storage
    webmessage::clear().expect("it should clear the local storage");
}

#[wasm_bindgen_test]
fn test_groups() {
    initAccount();

    signMessage("group1", "some data");
    signMessage("group2", "some data");

    assert!(messages("group1").len() == 1);
    assert!(messages("group2").len() == 1);
    assert!(validateMessages("group1"));
    assert!(validateMessages("group2"));

    let grps = groups();
    assert!(grps.len() == 2);
    let gp1: Group = serde_json::from_str(grps[0].as_str()).expect("it should parse the group");
    assert_eq!(gp1.id, "group1");
    let gp2: Group = serde_json::from_str(grps[1].as_str()).expect("it should parse the group");
    assert_eq!(gp2.id, "group2");

    // clear the local storage
    webmessage::clear().expect("it should clear the local storage");
}

#[wasm_bindgen_test]
fn test_invalid_message() {
    initAccount();

    // create a new identity for signing a message
    let mut msg = {
        let (other_secret, other_id) = GenKeysAlgorithm::generate_keys();
        SignedMessage::new_first_message::<Secret, MessageSigner>(
            other_id.clone(),
            &other_secret,
            "other data".as_bytes().to_vec(),
        )
    };

    // modify the message
    msg.message.data = "other data 3".as_bytes().to_vec();

    // add the signed message from the other identity
    webmessage::addSignedMessage("group1", &serde_json::to_string(&msg).unwrap())
        .expect_err("invalid signed message");

    assert!(messages("group1").is_empty());
    assert!(groups().is_empty());
    assert!(validateMessages("group1"));

    // clear the local storage
    webmessage::clear().expect("it should clear the local storage");
}
