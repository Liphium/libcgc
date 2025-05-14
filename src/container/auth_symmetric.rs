use crate::crypto::{
    signature::{self, SigningKey, VerifyingKey},
    symmetric::SymmetricKey,
};

/// Pack a new signed container using symmetric encryption. Encrypts symmetrically and attaches a signature.
///
/// A salt can be added to prevent replay attacks.
pub fn pack(
    key: &mut SymmetricKey,
    signing_key: &mut SigningKey,
    message: &Vec<u8>,
    salt: Option<&Vec<u8>>,
) -> Option<Vec<u8>> {
    let mut encrypted = key.encrypt(message)?;

    // Add the salt to the message (in case there is one)
    if let Some(salt) = salt {
        encrypted.extend(signature::sign(
            signing_key,
            &message.iter().chain(salt).cloned().collect(),
        )?);
    } else {
        encrypted.extend(signature::sign(signing_key, message)?);
    }
    Some(encrypted)
}

/// Unpack a new signed container using symmetric encryption. Decrypts symmetrically and verifies the signature.
/// Returns ``None`` in case of failing to verify the signature.
///
/// A salt can be added to prevent replay attacks.
pub fn unpack(
    key: &mut SymmetricKey,
    verifying_key: &VerifyingKey,
    ciphertext: &Vec<u8>,
    salt: Option<&Vec<u8>>,
) -> Option<Vec<u8>> {
    // Split into signature and ciphertext
    if ciphertext.len() <= signature::SIGNATURE_LEN {
        return None;
    }
    let (ciphertext, signed) = ciphertext.split_at(ciphertext.len() - signature::SIGNATURE_LEN);

    // Decrypt the message
    let decrypted = key.decrypt(&ciphertext.to_vec())?;

    // Verify the signature with the salt (if desired)
    if let Some(salt) = salt {
        if !signature::verify(
            verifying_key,
            &decrypted.iter().chain(salt.iter()).cloned().collect(),
            &signed.to_vec(),
        )? {
            return None;
        }
    } else {
        if !signature::verify(verifying_key, &decrypted, &signed.to_vec())? {
            return None;
        }
    }
    return Some(decrypted);
}
