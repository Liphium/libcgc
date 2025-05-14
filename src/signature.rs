use ml_dsa::{EncodedSigningKey, EncodedVerifyingKey, KeyGen, MlDsa65, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sodoken::{SizedLockedArray, sign};

pub struct PublicKey {
    pub sodium_key: [u8; sign::PUBLICKEYBYTES],
    pub ml_dsa_key: ml_dsa::VerifyingKey<MlDsa65>,
}

impl PublicKey {
    // Encode a public key as a vector of bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut ml_key = self.ml_dsa_key.encode().to_vec();
        ml_key.extend(self.sodium_key);
        return ml_key;
    }

    // Decode a public key from a vector of bytes.
    pub fn decode(encoded: Vec<u8>) -> Option<PublicKey> {
        // Extract the two different keys
        if encoded.len() <= sign::PUBLICKEYBYTES {
            return None;
        }
        let (enc_dsa_key, enc_sodium_key) = encoded.split_at(encoded.len() - sign::PUBLICKEYBYTES);

        // Parse the libsodium key
        let sodium_key: [u8; sign::PUBLICKEYBYTES] = enc_sodium_key.try_into().ok()?;

        // Parse the ml_dsa key
        let enc_dsa_key: EncodedVerifyingKey<MlDsa65> = enc_dsa_key.try_into().ok()?;
        let ml_key = VerifyingKey::decode(&enc_dsa_key);

        return Some(PublicKey {
            sodium_key: sodium_key,
            ml_dsa_key: ml_key,
        });
    }
}

pub struct SecretKey {
    pub sodium_key: SizedLockedArray<{ sign::SECRETKEYBYTES }>,
    pub ml_dsa_key: ml_dsa::SigningKey<MlDsa65>,
}

impl SecretKey {
    // Encode a secret key as a vector of bytes.
    pub fn encode(&mut self) -> Vec<u8> {
        let mut ml_secret_key = self.ml_dsa_key.encode().to_vec();
        ml_secret_key.extend(self.sodium_key.lock().as_slice());
        return ml_secret_key;
    }

    // Decode a secret key from a vector of bytes.
    pub fn decode(encoded: Vec<u8>) -> Option<SecretKey> {
        // Extract the two different keys
        if encoded.len() <= sign::SECRETKEYBYTES {
            return None;
        }
        let (enc_dsa_key, enc_sodium_key) = encoded.split_at(encoded.len() - sign::SECRETKEYBYTES);

        // Parse the libsodium key
        let enc_sodium_key: [u8; sign::SECRETKEYBYTES] = enc_sodium_key.try_into().ok()?;
        let mut sodium_key = SizedLockedArray::new().ok()?;
        sodium_key.lock().copy_from_slice(&enc_sodium_key);

        // Parse the ml_dsa key
        let enc_dsa_key: EncodedSigningKey<MlDsa65> = enc_dsa_key.try_into().ok()?;
        let ml_key = SigningKey::decode(&enc_dsa_key);

        return Some(SecretKey {
            sodium_key: sodium_key,
            ml_dsa_key: ml_key,
        });
    }
}

pub struct SignatureKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl SignatureKeyPair {
    pub fn generate() -> SignatureKeyPair {
        // Generate a key pair for ml-dsa
        let rng = &mut OsRng;
        let (sign_key, verify_key) = {
            let ml_pair = MlDsa65::key_gen(rng);
            let encoded_sign_key: EncodedSigningKey<MlDsa65> = ml_pair.signing_key().encode();
            let encoded_verify_key: EncodedVerifyingKey<MlDsa65> = ml_pair.verifying_key().encode();
            (
                SigningKey::decode(&encoded_sign_key),
                VerifyingKey::decode(&encoded_verify_key),
            )
        };

        // Generate a new signature key pair for libsodium
        let mut pk = [0; sodoken::sign::PUBLICKEYBYTES];
        let mut sk = sodoken::SizedLockedArray::new().unwrap();
        sign::keypair(&mut pk, &mut sk.lock()).unwrap();

        // Return the complete key pair
        return SignatureKeyPair {
            public_key: PublicKey {
                sodium_key: [0; sign::PUBLICKEYBYTES],
                ml_dsa_key: verify_key,
            },
            secret_key: SecretKey {
                sodium_key: sk,
                ml_dsa_key: sign_key,
            },
        };
    }
}
