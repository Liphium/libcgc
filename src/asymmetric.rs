use rand::{TryRngCore, rngs::OsRng};
use sodoken::{SizedLockedArray, crypto_box};

// The secret key for asymmetric encryption. Only keep to yourself.
pub struct SecretKey {
    pub sodium_key: SizedLockedArray<{ crypto_box::XSALSA_SECRETKEYBYTES }>,
    pub crux_key: libcrux_kem::PrivateKey,
}

impl SecretKey {
    // Decode a secret key from bytes.
    pub fn decode(key: Vec<u8>) -> Option<SecretKey> {
        let (sodium_key, crux_key) = key.split_at(crypto_box::XSALSA_SECRETKEYBYTES);

        // Extract the libsodium private key
        let mut sodium_priv = SizedLockedArray::new().expect("Couldn't create size locked array");
        sodium_priv.lock().copy_from_slice(sodium_key);

        // Extract the libcrux private key
        let crux_priv =
            match libcrux_kem::PrivateKey::decode(libcrux_kem::Algorithm::MlKem1024, crux_key) {
                Err(_) => return None,
                Ok(key) => key,
            };

        return Some(SecretKey {
            sodium_key: sodium_priv,
            crux_key: crux_priv,
        });
    }

    // Encode a secret key to bytes.
    pub fn encode(&mut self) -> Vec<u8> {
        let mut key = self.sodium_key.lock().to_vec().clone();
        key.extend(self.crux_key.encode());
        return key;
    }
}

// The public key for asymmetric encryption. Anyone can have it.
pub struct PublicKey {
    pub sodium_key: [u8; crypto_box::XSALSA_PUBLICKEYBYTES],
    pub crux_key: libcrux_kem::PublicKey,
}

impl PublicKey {
    // Decode a public key from bytes.
    pub fn decode(key: Vec<u8>) -> Option<PublicKey> {
        let (sodium_key, crux_key) = key.split_at(crypto_box::XSALSA_PUBLICKEYBYTES);

        // Convert the libsodium public key
        let mut sodium_pub = [0u8; crypto_box::XSALSA_PUBLICKEYBYTES];
        sodium_pub.copy_from_slice(sodium_key);

        // Decode the libcrux public key from the remainder
        let crux_pub =
            match libcrux_kem::PublicKey::decode(libcrux_kem::Algorithm::MlKem1024, crux_key) {
                Ok(pk) => pk,
                Err(_) => return None,
            };

        return Some(PublicKey {
            sodium_key: sodium_pub,
            crux_key: crux_pub,
        });
    }

    // Encode a public key to bytes.
    pub fn encode(&mut self) -> Vec<u8> {
        let mut key = self.sodium_key.to_vec().clone();
        key.extend(self.crux_key.encode());
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
        let mut os_rng = OsRng;
        let mut rng = os_rng.unwrap_mut();
        let (crux_priv, crux_pub) =
            libcrux_kem::key_gen(libcrux_kem::Algorithm::MlKem1024, &mut rng)
                .expect("Couldn't generate key (libcrux)");

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
