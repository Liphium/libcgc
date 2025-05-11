#[test]
// Test asymmetric secret key encoding and decoding
fn test_secret_key_encoding() {
    use crate::asymmetric::{AsymmetricKeyPair, SecretKey};

    let mut keypair = AsymmetricKeyPair::new_keypair();
    let encoded_sct = keypair.secret_key.encode();
    let mut decoded_sct = SecretKey::decode(encoded_sct.clone()).unwrap();

    assert_eq!(
        keypair.secret_key.sodium_key.lock().as_slice(),
        decoded_sct.sodium_key.lock().as_slice()
    );
    assert_eq!(
        keypair.secret_key.crux_key.encode(),
        decoded_sct.crux_key.encode()
    );
}

// Test asymmetric public key encoding and decoding
#[test]
fn test_public_key_encoding() {
    use crate::asymmetric::{AsymmetricKeyPair, PublicKey};

    let mut keypair = AsymmetricKeyPair::new_keypair();
    let encoded_pub = keypair.public_key.encode();
    let decoded_pub = PublicKey::decode(encoded_pub.clone()).unwrap();

    assert_eq!(
        keypair.public_key.sodium_key.as_slice(),
        decoded_pub.sodium_key.as_slice()
    );
    assert_eq!(
        keypair.public_key.crux_key.encode(),
        decoded_pub.crux_key.encode()
    );
}

// Test symmetric key encoding
#[test]
fn test_symmetric_key_encoding() {
    use crate::symmetric::SymmetricKey;

    let mut key = SymmetricKey::generate_key();
    let encoded = key.encode();
    let mut decoded = SymmetricKey::decode(encoded).unwrap();

    assert_eq!(key.key.lock().as_slice(), decoded.key.lock().as_slice());
}

#[test]
fn test_symmetric_encryption() {
    use crate::symmetric::SymmetricKey;

    let mut key = SymmetricKey::generate_key();
    let message = b"Hello symmetric encryption!".to_vec();
    let encrypted = key.encrypt(message.clone()).expect("Encryption failed");
    let decrypted = key.decrypt(encrypted).expect("Decryption failed");
    assert_eq!(message, decrypted);
}
