use oqs::{kem, sig};
use sodoken::{SizedLockedArray, crypto_box};

// The secret key for asymmetric encryption. Only keep to yourself.
pub struct SecretKey {
    sodium_key: SizedLockedArray<{ crypto_box::XSALSA_SECRETKEYBYTES }>,
}

// The public key for asymmetric encryption. Anyone can have it.
pub struct PublicKey {
    sodium_key: [u8; crypto_box::XSALSA_PUBLICKEYBYTES],
}

// Two keys that belong to each other and work together for asymmetric encryption.
pub struct AsymmetricKeyPair {
    pub publicKey: PublicKey,
    pub secretKey: SecretKey,
}

// Create a new key pair (uses sodium and liboqs under the hood).
pub fn new_keypair() -> AsymmetricKeyPair {
    // Generate a new libsodium key pair
    let mut pub_key = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
    let mut priv_key = SizedLockedArray::new().unwrap();
    crypto_box::xsalsa_keypair(&mut pub_key, &mut priv_key.lock())
        .expect("Couldn't generate keypair");

    // Generate a new liboqs key using KEM
    oqs::init();
    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium3);
    let kemalg = kem::Kem::new(kem::Algorithm::MlKem1024);

    AsymmetricKeyPair {
        publicKey: PublicKey {
            sodium_key: pub_key,
        },
        secretKey: SecretKey {
            sodium_key: priv_key,
        },
    }
}
