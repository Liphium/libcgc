use ml_dsa::{
    EncodedSigningKey, EncodedVerifyingKey, KeyGen, MlDsa65, Signature,
    signature::{SignerMut, Verifier},
};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_512};
use sodoken::{SizedLockedArray, sign};

pub const SIGNATURE_LEN: usize = 3373;

pub struct VerifyingKey {
    pub sodium_key: [u8; sign::PUBLICKEYBYTES],
    pub ml_dsa_key: ml_dsa::VerifyingKey<MlDsa65>,
}

impl VerifyingKey {
    // Encode a public key as a vector of bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut ml_key = self.ml_dsa_key.encode().to_vec();
        ml_key.extend(self.sodium_key);
        return ml_key;
    }

    // Decode a public key from a vector of bytes.
    pub fn decode(encoded: Vec<u8>) -> Option<VerifyingKey> {
        // Extract the two different keys
        if encoded.len() <= sign::PUBLICKEYBYTES {
            return None;
        }
        let (enc_dsa_key, enc_sodium_key) = encoded.split_at(encoded.len() - sign::PUBLICKEYBYTES);

        // Parse the libsodium key
        let sodium_key: [u8; sign::PUBLICKEYBYTES] = enc_sodium_key.try_into().ok()?;

        // Parse the ml_dsa key
        let enc_dsa_key: EncodedVerifyingKey<MlDsa65> = enc_dsa_key.try_into().ok()?;
        let ml_key = ml_dsa::VerifyingKey::decode(&enc_dsa_key);

        return Some(VerifyingKey {
            sodium_key: sodium_key,
            ml_dsa_key: ml_key,
        });
    }
}

pub struct SigningKey {
    pub sodium_key: SizedLockedArray<{ sign::SECRETKEYBYTES }>,
    pub ml_dsa_key: ml_dsa::SigningKey<MlDsa65>,
}

impl SigningKey {
    // Encode a secret key as a vector of bytes.
    pub fn encode(&mut self) -> Vec<u8> {
        let mut ml_secret_key = self.ml_dsa_key.encode().to_vec();
        ml_secret_key.extend(self.sodium_key.lock().as_slice());
        return ml_secret_key;
    }

    // Decode a secret key from a vector of bytes.
    pub fn decode(encoded: Vec<u8>) -> Option<SigningKey> {
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
        let ml_key = ml_dsa::SigningKey::decode(&enc_dsa_key);

        return Some(SigningKey {
            sodium_key: sodium_key,
            ml_dsa_key: ml_key,
        });
    }
}

pub struct SignatureKeyPair {
    pub verify_key: VerifyingKey,
    pub signature_key: SigningKey,
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
                ml_dsa::SigningKey::decode(&encoded_sign_key),
                ml_dsa::VerifyingKey::decode(&encoded_verify_key),
            )
        };

        // Generate a new signature key pair for libsodium
        let mut sodium_pub = [0; sodoken::sign::PUBLICKEYBYTES];
        let mut sodium_priv = sodoken::SizedLockedArray::new().unwrap();
        sign::keypair(&mut sodium_pub, &mut sodium_priv.lock()).unwrap();

        // Return the complete key pair
        return SignatureKeyPair {
            verify_key: VerifyingKey {
                sodium_key: sodium_pub,
                ml_dsa_key: verify_key,
            },
            signature_key: SigningKey {
                sodium_key: sodium_priv,
                ml_dsa_key: sign_key,
            },
        };
    }
}

// Sign a message using the secret key.
pub fn sign(key: &mut SigningKey, message: &Vec<u8>) -> Option<Vec<u8>> {
    // Hash the message for security reasons (ml_dsa might not be able to hide it properly)
    let hashed = compute_hash(message);

    // Create a new ml_dsa signature
    let mut ml_dsa_sig = key.ml_dsa_key.sign(&hashed).encode().to_vec();

    // Also sign with sodium
    let mut signature = [0; sign::SIGNATUREBYTES];
    sign::sign_detached(&mut signature, &hashed, &key.sodium_key.lock()).ok()?;

    // Add both signatures together
    ml_dsa_sig.extend(signature);
    return Some(ml_dsa_sig);
}

// Verify a message using the public key.
pub fn verify(key: &VerifyingKey, message: &Vec<u8>, signature: &Vec<u8>) -> Option<bool> {
    // Hash the message for security reasons (ml_dsa might not be able to hide it properly)
    let hashed = compute_hash(message);

    // Split the signature
    if signature.len() <= sign::SIGNATUREBYTES {
        return None;
    }
    let (ml_dsa_sig, sodium_sig) = signature.split_at(signature.len() - sign::SIGNATUREBYTES);

    // Verify the ml_dsa signature
    let ml_dsa_sig: Signature<MlDsa65> = Signature::decode(ml_dsa_sig.try_into().ok()?)?;
    key.ml_dsa_key.verify(&hashed, &ml_dsa_sig).ok()?;

    // Verify the libsodium signature
    if !sign::verify_detached(&sodium_sig.try_into().ok()?, &hashed, &key.sodium_key) {
        return Some(false);
    }

    return Some(true);
}

// Compute a hash using Sha3_512
fn compute_hash(message: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(message);
    hasher.finalize().to_vec()
}
