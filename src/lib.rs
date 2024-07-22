//! # Webmessage
//!
//! Webmessage is a library that stores a sequence of messages in browser's local storage.
//! It uses techniques of hashing and digital signatures to ensure immutability of message sequence
//! and the non-repudiation of the messages.

pub mod account;
mod core;
pub mod message;
pub mod store;
pub mod wasm;
