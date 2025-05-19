use sodoken::secretstream;

use super::symmetric::SymmetricKey;

pub struct StreamCipher {
    pub sodium_state: secretstream::State,
}

/// Create a new stream cipher for stream symmetric encryption.
///
/// Returns the stream cipher and a header.
pub fn new_stream_cipher(key: &mut SymmetricKey) -> Option<(StreamCipher, Vec<u8>)> {
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
pub fn encrypt(cipher: &mut StreamCipher, message: &Vec<u8>) -> Option<Vec<u8>> {
    let mut ciphertext = vec![0; message.len() + sodoken::secretstream::ABYTES];
    secretstream::push(
        &mut cipher.sodium_state,
        &mut ciphertext,
        message,
        None,
        secretstream::Tag::Message,
    )
    .ok()?;
    Some(ciphertext)
}
