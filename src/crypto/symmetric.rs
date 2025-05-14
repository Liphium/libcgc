use sodoken::{SizedLockedArray, random, secretbox};

pub struct SymmetricKey {
    pub key: SizedLockedArray<{ secretbox::XSALSA_KEYBYTES }>,
}

impl SymmetricKey {
    // Generate a new symmetric key.
    pub fn generate() -> SymmetricKey {
        let mut key = SizedLockedArray::new().expect("Couldn't created SizedLockedArray");
        random::randombytes_buf(&mut *key.lock()).expect("Couldn't generate random key");
        return SymmetricKey { key };
    }

    // Decode a secret key from bytes.
    pub fn decode(encoded: Vec<u8>) -> Option<SymmetricKey> {
        let mut key = SizedLockedArray::new().expect("Couldn't create size locked array");
        key.lock().copy_from_slice(encoded.as_slice());

        return Some(SymmetricKey { key: key });
    }

    // Encode a secret key to bytes.
    pub fn encode(&mut self) -> Vec<u8> {
        return self.key.lock().to_vec();
    }

    // Encrypt a message using the symmetric key.
    pub fn encrypt(&mut self, message: &Vec<u8>) -> Option<Vec<u8>> {
        return encrypt(&self.key.lock(), message);
    }

    // Decrypt a message using the symmetric key.
    pub fn decrypt(&mut self, message: &Vec<u8>) -> Option<Vec<u8>> {
        return decrypt(&self.key.lock(), message);
    }
}

// Encrypt a message using the symmetric key.
pub fn encrypt(key: &[u8; secretbox::XSALSA_KEYBYTES], message: &Vec<u8>) -> Option<Vec<u8>> {
    // Generate a random nonce for the message
    let mut nonce = [0; secretbox::XSALSA_NONCEBYTES];
    match random::randombytes_buf(&mut nonce) {
        Err(_) => return None,
        Ok(_) => (),
    }

    // Encrypt the message using sodium
    let mut encrypted = vec![0; message.len() + secretbox::XSALSA_MACBYTES];
    match secretbox::xsalsa_easy(&mut encrypted, &nonce, &message, key) {
        Err(_) => return None,
        Ok(_) => (),
    }

    // Return the message with the nonce at the end
    encrypted.extend_from_slice(&nonce);
    return Some(encrypted);
}

// Decrypt a message using the symmetric key.
pub fn decrypt(key: &[u8; secretbox::XSALSA_KEYBYTES], ciphertext: &Vec<u8>) -> Option<Vec<u8>> {
    // Make sure the ciphertext is long enough
    if ciphertext.len() <= secretbox::XSALSA_NONCEBYTES + secretbox::XSALSA_MACBYTES {
        return None;
    }

    // Extract nonce and ciphertext
    let (ciphered, nonce_bytes) =
        ciphertext.split_at(ciphertext.len() - secretbox::XSALSA_NONCEBYTES);
    let nonce: [u8; secretbox::XSALSA_NONCEBYTES] = nonce_bytes.try_into().ok()?;

    // Decrypt using the key
    let mut message = vec![0; ciphered.len() - secretbox::XSALSA_MACBYTES];
    secretbox::xsalsa_open_easy(&mut message, &ciphered, &nonce, key).ok()?;
    return Some(message);
}
