use ml_dsa::{EncodedSigningKey, EncodedVerifyingKey, KeyGen, MlDsa65, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sodoken::{SizedLockedArray, sign};

pub struct PublicKey {
    pub sodium_key: [u8; sign::PUBLICKEYBYTES],
    pub ml_dsa_key: ml_dsa::VerifyingKey<MlDsa65>,
}
pub struct SecretKey {
    pub sodium_key: SizedLockedArray<{ sign::SECRETKEYBYTES }>,
    pub ml_dsa_key: ml_dsa::SigningKey<MlDsa65>,
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
