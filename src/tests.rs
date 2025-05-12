// Test asymmetric secret key encoding and decoding
#[test]
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
        keypair.secret_key.crux_key.as_slice(),
        decoded_sct.crux_key.as_slice()
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
        keypair.public_key.crux_key.as_slice(),
        decoded_pub.crux_key.as_slice()
    );
}

// Test asymmetric sealed encryption and decryption
#[test]
fn test_asymmetric_sealed_encryption() {
    use crate::asymmetric::{self, AsymmetricKeyPair};

    // Make sure regular encryption, decryption and key generation works
    let mut key_pair = AsymmetricKeyPair::new_keypair();
    let to_encrypt = b"Hello asymmetric encryption!".to_vec();
    let ciphertext = asymmetric::encrypt_seal(&key_pair.public_key, to_encrypt.clone())
        .expect("Encryption failure");
    let decrypted =
        asymmetric::decrypt_seal(&mut key_pair, ciphertext).expect("Decryption failure");

    assert_eq!(to_encrypt, decrypted);

    // Make sure decryption fails when invalid input
    assert!(asymmetric::decrypt_seal(&mut key_pair, vec![0u8; 10]).is_none());
    assert!(asymmetric::decrypt_seal(&mut key_pair, vec![0u8; 1000]).is_none());
    assert!(asymmetric::decrypt_seal(&mut key_pair, vec![0u8; 2000]).is_none());
    assert!(asymmetric::decrypt_seal(&mut key_pair, vec![0u8; 3000]).is_none());
    assert!(asymmetric::decrypt_seal(&mut key_pair, vec![0u8; 4000]).is_none());
}

// Test symmetric key encoding and decoding
#[test]
fn test_symmetric_key_encoding() {
    use crate::symmetric::SymmetricKey;

    let mut key = SymmetricKey::generate();
    let encoded = key.encode();
    let mut decoded = SymmetricKey::decode(encoded).unwrap();

    assert_eq!(key.key.lock().as_slice(), decoded.key.lock().as_slice());
}

// Test symmetric encryption and decryption on a sample message
#[test]
fn test_symmetric_encryption() {
    use crate::symmetric::SymmetricKey;

    // Test regular encryption, decryption and key generation
    let mut key = SymmetricKey::generate();
    let message = b"Hello symmetric encryption!".to_vec();
    let encrypted = key.encrypt(message.clone()).expect("Encryption failed");
    let decrypted = key.decrypt(encrypted).expect("Decryption failed");
    assert_eq!(message, decrypted);

    // Make sure the decryption fails with invalid input
    assert!(key.decrypt(vec![0u8; 10]).is_none());
    assert!(key.decrypt(vec![0u8; 1000]).is_none());
    assert!(key.decrypt(vec![0u8; 2000]).is_none());
    assert!(key.decrypt(vec![0u8; 3000]).is_none());
    assert!(key.decrypt(vec![0u8; 4000]).is_none());
}
