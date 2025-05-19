use crate::crypto::{
    signature::{SigningKey, VerifyingKey},
    symmetric::SymmetricKey,
};

pub fn encrypt_file(path: String, key: &SymmetricKey, signing_key: &SigningKey) {}

pub fn unpack(path: String, key: &SymmetricKey, verifying_key: &VerifyingKey) {}
