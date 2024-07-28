//! Defines the account types and traits.

/// The identity that verifies the signature of the message.
pub trait Identity: PartialEq + Eq {}

/// The secret that signs the message.
pub trait Secret {}

/// Implements keypair generation.
pub trait GenerateKeys<S: Secret, I: Identity> {
    fn generate_keys() -> (S, I);
}
