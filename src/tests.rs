// Test signature public and secret key encoding and decoding
#[test]
fn test_signature_encoding() {
    use crate::signature::{PublicKey, SecretKey, SignatureKeyPair};

    let mut pair = SignatureKeyPair::generate();

    let encoded_pub = pair.public_key.encode();
    let decoded_pub = PublicKey::decode(encoded_pub).unwrap();
    assert_eq!(
        pair.public_key.sodium_key.as_slice(),
        decoded_pub.sodium_key.as_slice()
    );
    assert_eq!(
        pair.public_key.ml_dsa_key.encode().as_slice(),
        decoded_pub.ml_dsa_key.encode().as_slice(),
    );

    let encoded_priv = pair.secret_key.encode();
    let mut decoded_priv: SecretKey = SecretKey::decode(encoded_priv).unwrap();
    assert_eq!(
        pair.secret_key.ml_dsa_key.encode().as_slice(),
        decoded_priv.ml_dsa_key.encode().as_slice()
    );
    assert_eq!(
        pair.secret_key.sodium_key.lock().as_slice(),
        decoded_priv.sodium_key.lock().as_slice(),
    );
}

// Test asymmetric public and secret key encoding and decoding
#[test]
fn test_asymmetric_encoding() {
    use crate::asymmetric::{AsymmetricKeyPair, PublicKey, SecretKey};

    let mut pair = AsymmetricKeyPair::generate();

    let encoded_pub = pair.public_key.encode();
    let decoded_pub = PublicKey::decode(encoded_pub).unwrap();
    assert_eq!(pair.public_key.key.as_bytes(), decoded_pub.key.as_bytes());

    let encoded_priv = pair.secret_key.encode();
    let decoded_priv: SecretKey = SecretKey::decode(encoded_priv).unwrap();
    assert_eq!(pair.secret_key.key.as_bytes(), decoded_priv.key.as_bytes());
}

// Test encryption and decryption using asymmetric (uses x_wing)
#[test]
fn test_asymmetric_encryption() {
    use crate::asymmetric::{self, AsymmetricKeyPair};

    // Test regular encryption, decryption and key generation
    let pair: AsymmetricKeyPair = AsymmetricKeyPair::generate();
    let message = b"Hello symmetric encryption!".to_vec();
    let encrypted =
        asymmetric::encrypt(&pair.public_key, message.clone()).expect("Encryption failed");
    let decrypted = asymmetric::decrypt(&pair.secret_key, encrypted).expect("Decryption failed");
    assert_eq!(message, decrypted);

    // Make sure the decryption fails with invalid input
    assert!(asymmetric::decrypt(&pair.secret_key, vec![0u8; 10]).is_none());
    assert!(asymmetric::decrypt(&pair.secret_key, vec![0u8; 1000]).is_none());
    assert!(asymmetric::decrypt(&pair.secret_key, vec![0u8; 2000]).is_none());
    assert!(asymmetric::decrypt(&pair.secret_key, vec![0u8; 3000]).is_none());
    assert!(asymmetric::decrypt(&pair.secret_key, vec![0u8; 4000]).is_none());
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
