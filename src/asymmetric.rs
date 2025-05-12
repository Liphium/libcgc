use libcrux::drbg;
use libcrux_ml_kem::mlkem1024;
use sodoken::{SizedLockedArray, crypto_box};

use crate::symmetric;

// The secret key for asymmetric encryption. Only keep to yourself.
pub struct SecretKey {
    pub sodium_key: SizedLockedArray<{ crypto_box::XSALSA_SECRETKEYBYTES }>,
    pub crux_key: libcrux_ml_kem::MlKemPrivateKey<{ mlkem1024::MlKem1024PrivateKey::len() }>,
}

impl SecretKey {
    // Decode a secret key from bytes.
    pub fn decode(key: Vec<u8>) -> Option<SecretKey> {
        let (sodium_key, crux_key) = key.split_at(crypto_box::XSALSA_SECRETKEYBYTES);

        // Extract the libsodium private key
        let mut sodium_priv = SizedLockedArray::new().expect("Couldn't create size locked array");
        sodium_priv.lock().copy_from_slice(sodium_key);

        // Extract the libcrux private key
        let crux_priv: libcrux_ml_kem::MlKemPrivateKey<{ mlkem1024::MlKem1024PrivateKey::len() }> =
            crux_key.try_into().ok()?;

        return Some(SecretKey {
            sodium_key: sodium_priv,
            crux_key: crux_priv,
        });
    }

    // Encode a secret key to bytes.
    pub fn encode(&mut self) -> Vec<u8> {
        let mut key = self.sodium_key.lock().to_vec().clone();
        key.extend(self.crux_key.as_slice());
        return key;
    }
}

// The public key for asymmetric encryption. Anyone can have it.
pub struct PublicKey {
    pub sodium_key: [u8; crypto_box::XSALSA_PUBLICKEYBYTES],
    pub crux_key: libcrux_ml_kem::MlKemPublicKey<{ mlkem1024::MlKem1024PublicKey::len() }>,
}

impl PublicKey {
    // Decode a public key from bytes.
    pub fn decode(key: Vec<u8>) -> Option<PublicKey> {
        let (sodium_key, crux_key) = key.split_at(crypto_box::XSALSA_PUBLICKEYBYTES);

        // Convert the libsodium public key
        let mut sodium_pub = [0u8; crypto_box::XSALSA_PUBLICKEYBYTES];
        sodium_pub.copy_from_slice(sodium_key);

        // Decode the libcrux public key from the remainder
        let crux_pub: libcrux_ml_kem::MlKemPublicKey<{ mlkem1024::MlKem1024PublicKey::len() }> =
            crux_key.try_into().ok()?;

        return Some(PublicKey {
            sodium_key: sodium_pub,
            crux_key: crux_pub,
        });
    }

    // Encode a public key to bytes.
    pub fn encode(&mut self) -> Vec<u8> {
        let mut key = self.sodium_key.to_vec().clone();
        key.extend(self.crux_key.as_slice());
        return key;
    }
}

// Two keys that belong to each other and work together for asymmetric encryption.
pub struct AsymmetricKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl AsymmetricKeyPair {
    // Create a new key pair (uses sodium and liboqs under the hood).
    pub fn new_keypair() -> AsymmetricKeyPair {
        // Generate a new libsodium key pair
        let mut sodium_pub = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
        let mut sodium_priv = SizedLockedArray::new().unwrap();
        crypto_box::xsalsa_keypair(&mut sodium_pub, &mut sodium_priv.lock())
            .expect("Couldn't generate keypair (sodium)");

        // Generate a new libcrux mlkem keypair
        let mut random = drbg::Drbg::new(libcrux::digest::Algorithm::Sha512)
            .expect("Couldn't create libcrux drbg random");
        let randomness = random
            .generate_array()
            .expect("Couldn't generate random array");
        let keypair = mlkem1024::generate_key_pair(randomness);
        let (crux_priv, crux_pub) = keypair.into_parts();

        // Return the key pair with the correct keys
        AsymmetricKeyPair {
            public_key: PublicKey {
                sodium_key: sodium_pub,
                crux_key: crux_pub,
            },
            secret_key: SecretKey {
                sodium_key: sodium_priv,
                crux_key: crux_priv,
            },
        }
    }
}

// Encrypt using the reciever's public key. Even the sender won't be able to decrypt this.
pub fn encrypt_seal(key: &PublicKey, message: Vec<u8>) -> Option<Vec<u8>> {
    // First encrypt using sodium
    let mut sodium_ciph = vec![0; message.len() + crypto_box::XSALSA_SEALBYTES];
    crypto_box::xsalsa_seal(&mut sodium_ciph, &message, &key.sodium_key).ok()?;

    // Generate a new shared secret with crux
    let mut random = drbg::Drbg::new(libcrux::digest::Algorithm::Sha512)
        .expect("Couldn't create libcrux drbg random");
    let randomness = random
        .generate_array()
        .expect("Couldn't generate random array");
    let (crux_ct, shared_secret) = mlkem1024::encapsulate(&key.crux_key, randomness);

    // Encrypt the sodium ciphertext with the shared secret from crux
    let mut ciphertext = symmetric::encrypt(&shared_secret, sodium_ciph)?;

    // Extend using the ciphertext from crux and return
    ciphertext.extend(crux_ct.as_slice());
    return Some(ciphertext);
}

// Decrypt using the key pair that contains the public key the ciphertext has been encrypted with.
pub fn decrypt_seal(pair: &mut AsymmetricKeyPair, ciphertext: Vec<u8>) -> Option<Vec<u8>> {
    // Make sure the ciphertext is long enough
    const CRUX_CIPHER_LEN: usize = mlkem1024::MlKem1024Ciphertext::len();
    if ciphertext.len() <= CRUX_CIPHER_LEN {
        return None;
    }

    // Split between crux and sodium ciphertext
    let (ciphertext, crux_ct) = ciphertext.split_at(ciphertext.len() - CRUX_CIPHER_LEN);
    let crux_cipher: libcrux_ml_kem::MlKemCiphertext<CRUX_CIPHER_LEN> = crux_ct.try_into().ok()?;
    // Decrypt using the shared secret
    let shared_secret = mlkem1024::decapsulate(&pair.secret_key.crux_key, &crux_cipher);
    let sodium_cipher = symmetric::decrypt(&shared_secret, ciphertext.to_vec())?;

    // Make sure the decrypt ciphertext is long enough
    if sodium_cipher.len() <= crypto_box::XSALSA_SEALBYTES {
        return None;
    }

    // Decrypt the rest using libsodium
    let mut message = vec![0; sodium_cipher.len() - crypto_box::XSALSA_SEALBYTES];
    crypto_box::xsalsa_seal_open(
        &mut message,
        &sodium_cipher,
        &pair.public_key.sodium_key,
        &pair.secret_key.sodium_key.lock(),
    )
    .ok()?;
    return Some(message);
}
