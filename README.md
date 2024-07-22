# Webmessage

Webmessage is a library that stores a sequence of messages in browser's local storage. It uses techniques of hashing and digital signatures to ensure immutability of message sequence and the non-repudiation of the messages.


## Build

`Webmessage` requires [wasm-pack](https://rustwasm.github.io/wasm-pack/) to build the package for web application.

To build, run
```sh
wasm-pack build --target web
```

The resulting package is saved into folder `/pkg` after successful build.

## Example - Use in Web app (javascipt)

In this example, the built package (i.e. files in the folder `/pkg`) is copied into the folder `webmessage` in the web app source folder.

```js
import initWebMessage, { initAccount, signMessage, messages, validateMessages } from './webmessage';

initWebMessage().then(() => {
  // Module Initialized. Initialize the account (or use the account initialized before)
  console.log('WebMessage initialized, account: ', initAccount());

  // Sign a message that stores into local storage
  let signed_msg_stored = signMessage("chat 1", 'hello');
  console.log('WebMessage signed message', JSON.parse(signed_msg_stored));

  // Get number of messages stored
  let msgs = messages('chat 1');
  console.log('WebMessage messages count:', msgs.length);

  // Validate the stored messages (self checking)
  console.log('WebMessage validate messages', validateMessages('chat 1'));

  // Show the local storage size
  const {
    size
  } = new Blob(Object.values(localStorage))
  console.log('Local Storage Size: ', size);
})
```

## Specification

The idea is to have users agree on the content of a message as well as the history of this message. 
- Signatures ensures the authenticity of the messages. 
- Attaching hash of previous message ensures the immutability of the history.

```text
M <- (msg, prev_hash)
S <- Sig(Hash(M))
SM(n) <- (I, M, n, S) where 
    I is the identity of the message signer s.t. Verify(I, M, S)=True
    n is a sequence number

SM(n) is said to be valid if
    SM(n-1) is valid
    /\ Hash(SM(n-1)) is the prev_hash in M
    /\ there exists I' and S' where S' <- Sig(Hash(M)) and Verify(I', M, S')=True
    /\ SM(n) <- (I', M, n, S')

n starts with 0.

prev_hash of M in SM(0) is all-zeros.
```

### Consideration

The library does not care about whether multiple sequences of messages share the same partial sequence. In other words, it does not prohibit the scenerio that **there are two different signed messages over same previous hash** or **two different signers created messages over same previous hash** because those signed messages could be considered as valid according to the specification.

The design reasonale is that, the creation of signature indicates the signer's intention to agree on something, which should not be simply ignored. Those signers should be responsible to any messages signed.


## Limitations

Local Storage in browser is size-limited.

There are some improvement to make:
- support multiple accounts
- minimize the size of data to store
- (welcome to add more)

