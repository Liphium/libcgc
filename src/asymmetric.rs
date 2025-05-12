use ml_kem::kem::{Decapsulate, Encapsulate};
use x_wing::{DecapsulationKey, EncapsulationKey};

use crate::symmetric;

// The secret key for asymmetric encryption. Only keep to yourself.
pub struct SecretKey {
    pub key: x_wing::DecapsulationKey,
}

impl SecretKey {
    // Decode a secret key from bytes.
    pub fn decode(key: Vec<u8>) -> Option<SecretKey> {
        let key_slice: [u8; x_wing::DECAPSULATION_KEY_SIZE] = key.as_slice().try_into().ok()?;
        return Some(SecretKey {
            key: DecapsulationKey::from(key_slice),
        });
    }

    // Encode a secret key to bytes.
    pub fn encode(&mut self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }
}

// The public key for asymmetric encryption. Anyone can have it.
pub struct PublicKey {
    pub key: EncapsulationKey,
}

impl PublicKey {
    // Decode a public key from bytes.
    pub fn decode(key: Vec<u8>) -> Option<PublicKey> {
        let key_slice: [u8; x_wing::ENCAPSULATION_KEY_SIZE] = key.as_slice().try_into().ok()?;
        return Some(PublicKey {
            key: EncapsulationKey::from(&key_slice),
        });
    }

    // Encode a public key to bytes.
    pub fn encode(&mut self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }
}

// Two keys that belong to each other and work together for asymmetric encryption.
pub struct AsymmetricKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl AsymmetricKeyPair {
    // Create a new key pair (uses x_wing under the hood).
    pub fn generate() -> AsymmetricKeyPair {
        let rng = &mut rand::rngs::OsRng;
        let (priv_key, pub_key) = x_wing::generate_key_pair(rng);
        AsymmetricKeyPair {
            public_key: PublicKey { key: pub_key },
            secret_key: SecretKey { key: priv_key },
        }
    }
}

// Encrypt using the reciever's public key. Even the sender won't be able to decrypt this.
pub fn encrypt(key: &PublicKey, message: Vec<u8>) -> Option<Vec<u8>> {
    // Generate a new shared secret
    let rng = &mut rand::rngs::OsRng;
    let (ciphertext, shared_secret) = key.key.encapsulate(rng).ok()?;

    // Use the symmetric module to encrypt the message
    let mut encrypted = symmetric::encrypt(&shared_secret, message)?;

    // Add the ciphertext to the end of the encrypted message
    encrypted.extend(ciphertext.as_bytes());
    return Some(encrypted);
}

// Decrypt using your key pair.
pub fn decrypt(priv_key: &SecretKey, ciphertext: Vec<u8>) -> Option<Vec<u8>> {
    // Make sure the ciphertext has the proper length
    if ciphertext.len() <= x_wing::CIPHERTEXT_SIZE {
        return None;
    }

    // Extract the ciphertext and encrypted message
    let (encrypted_msg, x_ss_enc) = ciphertext.split_at(ciphertext.len() - x_wing::CIPHERTEXT_SIZE);

    // Get the shared secret (symmetric encryption key)
    let x_ss_enc: [u8; x_wing::CIPHERTEXT_SIZE] = x_ss_enc.try_into().ok()?;
    let x_ciph = x_wing::Ciphertext::from(&x_ss_enc);
    let shared_secret = priv_key.key.decapsulate(&x_ciph).ok()?;

    // Decrypt using symmetric
    return Some(symmetric::decrypt(&shared_secret, encrypted_msg.to_vec())?);
}
