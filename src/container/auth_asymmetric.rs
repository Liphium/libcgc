use crate::crypto::{
    asymmetric::{self, PublicKey, SecretKey},
    signature::{self, SigningKey, VerifyingKey},
};

/// Pack a new signed container using asymmetric encryption. Encrypts asymmetrically and attaches a signature.
pub fn pack(
    public_key: &PublicKey,
    signing_key: &mut SigningKey,
    message: &Vec<u8>,
    salt: Option<&Vec<u8>>,
) -> Option<Vec<u8>> {
    let mut encrypted = asymmetric::encrypt(public_key, message)?;

    // Sign with salt (in case desired)
    if let Some(salt) = salt {
        encrypted.extend(signature::sign(
            signing_key,
            &message
                .iter()
                .chain(public_key.encode().iter())
                .chain(salt)
                .cloned()
                .collect(),
        )?);
    } else {
        encrypted.extend(signature::sign(signing_key, message)?);
    }
    Some(encrypted)
}

/// Unpack a new signed container using asymmetric encryption. Decrypts asymmetrically and verifies the signature.
///
/// ``public_key`` is your own public key.
///
/// Returns ``None`` in case of failing to verify the signature.
pub fn unpack(
    public_key: &PublicKey,
    secret_key: &SecretKey,
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
    let decrypted = asymmetric::decrypt(&secret_key, &ciphertext.to_vec())?;

    // Verify the signature with salt (if desired)
    if let Some(salt) = salt {
        if !signature::verify(
            verifying_key,
            &decrypted
                .iter()
                .chain(public_key.encode().iter())
                .chain(salt.iter())
                .cloned()
                .collect(),
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
