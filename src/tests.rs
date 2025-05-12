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
