use sodoken::secretstream;

use super::symmetric::SymmetricKey;

pub struct StreamCipher {
    pub sodium_state: secretstream::State,
}

pub const HEADER_LENGTH: usize = secretstream::HEADERBYTES;
pub const EXTRA_LENGTH: usize = secretstream::ABYTES;

/// Create a new stream cipher for stream symmetric encryption.
///
/// Returns the stream cipher and a header (length is HEADER_LENGTH).
pub fn new_encryption_cipher(key: &mut SymmetricKey) -> Option<(StreamCipher, Vec<u8>)> {
    let mut state = sodoken::secretstream::State::default();
    let mut header = [0u8; secretstream::HEADERBYTES];
    secretstream::init_push(&mut state, &mut header, &key.key.lock()).ok()?;
    Some((
        StreamCipher {
            sodium_state: state,
        },
        header.to_vec(),
    ))
}

/// Encrypt a new message with the stream cipher.
pub fn encrypt(cipher: &mut StreamCipher, message: &Vec<u8>, last: bool) -> Option<Vec<u8>> {
    let mut ciphertext = vec![0; message.len() + sodoken::secretstream::ABYTES];
    secretstream::push(
        &mut cipher.sodium_state,
        &mut ciphertext,
        message,
        None,
        if last {
            secretstream::Tag::Final
        } else {
            secretstream::Tag::Message
        },
    )
    .ok()?;
    Some(ciphertext)
}

/// Create a new symmetric decryption cipher.
pub fn new_decryption_cipher(key: &mut SymmetricKey, header: &Vec<u8>) -> Option<StreamCipher> {
    let mut state = sodoken::secretstream::State::default();
    secretstream::init_pull(
        &mut state,
        &header.as_slice().try_into().ok()?,
        &key.key.lock(),
    )
    .ok()?;
    Some(StreamCipher {
        sodium_state: state,
    })
}

/// Decrypt a new message with the stream cipher.
pub fn decrypt(cipher: &mut StreamCipher, ciphertext: &Vec<u8>) -> Option<(Vec<u8>, bool)> {
    // Make sure the ciphertext is long enough
    if ciphertext.len() <= secretstream::ABYTES {
        return None;
    }

    // Decrypt the ciphertext
    let mut message = vec![0; ciphertext.len() - secretstream::ABYTES];
    let tag = secretstream::pull(
        &mut cipher.sodium_state,
        &mut message,
        &ciphertext.as_slice(),
        None,
    )
    .ok()?;
    Some((message, tag == secretstream::Tag::Final))
}
