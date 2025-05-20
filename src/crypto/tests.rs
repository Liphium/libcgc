// Test signature public and secret key encoding and decoding
#[test]
fn test_signature_encoding() {
    use super::signature::{SignatureKeyPair, SigningKey, VerifyingKey};

    let mut pair = SignatureKeyPair::generate();

    let encoded_pub = pair.verify_key.encode();
    let decoded_pub = VerifyingKey::decode(encoded_pub).unwrap();
    assert_eq!(
        pair.verify_key.sodium_key.as_slice(),
        decoded_pub.sodium_key.as_slice()
    );
    assert_eq!(
        pair.verify_key.ml_dsa_key.encode().as_slice(),
        decoded_pub.ml_dsa_key.encode().as_slice(),
    );

    let encoded_priv = pair.signature_key.encode();
    let mut decoded_priv: SigningKey = SigningKey::decode(encoded_priv).unwrap();
    assert_eq!(
        pair.signature_key.ml_dsa_key.encode().as_slice(),
        decoded_priv.ml_dsa_key.encode().as_slice()
    );
    assert_eq!(
        pair.signature_key.sodium_key.lock().as_slice(),
        decoded_priv.sodium_key.lock().as_slice(),
    );
}

// Test signature signing and verifiying
#[test]
fn test_signature_signing() {
    use super::signature::{self, SignatureKeyPair};

    let mut pair = SignatureKeyPair::generate();

    let message = b"some signature".as_slice();
    let signed =
        signature::sign(&mut pair.signature_key, &message.to_vec()).expect("Signing failed");

    assert!(
        signature::verify(&mut pair.verify_key, &message.to_vec(), &signed)
            .expect("Verification failed")
    );
    assert!(signed.len() == signature::SIGNATURE_LEN);

    let message = b"some longer signature".as_slice();
    let signed =
        signature::sign(&mut pair.signature_key, &message.to_vec()).expect("Signing failed");

    assert!(
        signature::verify(&mut pair.verify_key, &message.to_vec(), &signed)
            .expect("Verification failed")
    );
    assert!(signed.len() == signature::SIGNATURE_LEN);

    // Make sure it fails with a tampered message
    let mut tampered_msg = message.to_vec();
    tampered_msg.extend(b"tamper");
    assert!(
        signature::verify(&mut pair.verify_key, &tampered_msg, &signed).is_none_or(|b| b == false)
    );

    // Make sure it fails with a tampered signature
    let mut tampered_sig = signed.to_vec();
    tampered_sig[0] = 0xFF;
    assert!(
        signature::verify(&mut pair.verify_key, &message.to_vec(), &tampered_sig)
            .is_none_or(|b| b == false)
    );
}

// Test asymmetric public and secret key encoding and decoding
#[test]
fn test_asymmetric_encoding() {
    use super::asymmetric::{AsymmetricKeyPair, PublicKey, SecretKey};

    let pair = AsymmetricKeyPair::generate();

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
    use super::asymmetric::{self, AsymmetricKeyPair};

    // Test regular encryption, decryption and key generation
    let pair: AsymmetricKeyPair = AsymmetricKeyPair::generate();
    let message = b"Hello symmetric encryption!".to_vec();
    let encrypted = asymmetric::encrypt(&pair.public_key, &message).expect("Encryption failed");
    let decrypted = asymmetric::decrypt(&pair.secret_key, &encrypted).expect("Decryption failed");
    assert_eq!(message, decrypted);

    // Make sure the decryption fails with invalid input
    assert!(asymmetric::decrypt(&pair.secret_key, &vec![0u8; 10]).is_none());
    assert!(asymmetric::decrypt(&pair.secret_key, &vec![0u8; 1000]).is_none());
    assert!(asymmetric::decrypt(&pair.secret_key, &vec![0u8; 2000]).is_none());
    assert!(asymmetric::decrypt(&pair.secret_key, &vec![0u8; 3000]).is_none());
    assert!(asymmetric::decrypt(&pair.secret_key, &vec![0u8; 4000]).is_none());
}

// Test symmetric key encoding and decoding
#[test]
fn test_symmetric_key_encoding() {
    use super::symmetric::SymmetricKey;

    let mut key = SymmetricKey::generate();
    let encoded = key.encode();
    let mut decoded = SymmetricKey::decode(encoded).unwrap();

    assert_eq!(key.key.lock().as_slice(), decoded.key.lock().as_slice());
}

// Test symmetric encryption and decryption on a sample message
#[test]
fn test_symmetric_encryption() {
    use super::symmetric::SymmetricKey;

    // Test regular encryption, decryption and key generation
    let mut key = SymmetricKey::generate();
    let message = b"Hello symmetric encryption!".to_vec();
    let encrypted = key.encrypt(&message).expect("Encryption failed");
    let decrypted = key.decrypt(&encrypted).expect("Decryption failed");
    assert_eq!(message, decrypted);

    // Make sure the decryption fails with invalid input
    assert!(key.decrypt(&vec![0u8; 10]).is_none());
    assert!(key.decrypt(&vec![0u8; 1000]).is_none());
    assert!(key.decrypt(&vec![0u8; 2000]).is_none());
    assert!(key.decrypt(&vec![0u8; 3000]).is_none());
    assert!(key.decrypt(&vec![0u8; 4000]).is_none());
}

// Test symmetric stream cipher
#[test]
fn test_symmetric_stream_encryption() {
    use super::stream_symmetric::{
        HEADER_LENGTH, decrypt, encrypt, new_decryption_cipher, new_encryption_cipher,
    };
    use super::symmetric::SymmetricKey;

    let mut key = SymmetricKey::generate();
    let (mut enc_cipher, header) =
        new_encryption_cipher(&mut key).expect("Failed to init encryption cipher");
    assert_eq!(header.len(), HEADER_LENGTH);

    let mut dec_cipher =
        new_decryption_cipher(&mut key, &header).expect("Failed to init decryption cipher");

    let chunks = vec![
        b"Hello ".to_vec(),
        b"stream ".to_vec(),
        b"encryption!".to_vec(),
    ];
    let mut accumulated = Vec::new();

    for (_, chunk) in chunks.iter().enumerate() {
        let ct = encrypt(&mut enc_cipher, chunk, false).expect("Encryption failed");
        let (pt, is_last) = decrypt(&mut dec_cipher, &ct).expect("Decryption failed");
        assert_eq!(pt, *chunk);
        assert_eq!(is_last, false);
        accumulated.extend(pt);
    }

    assert_eq!(accumulated, b"Hello stream encryption!".to_vec());

    // invalid ciphertext should return None
    assert!(decrypt(&mut dec_cipher, &vec![0u8; 2]).is_none());
    assert!(decrypt(&mut dec_cipher, &vec![0u8; HEADER_LENGTH]).is_none());
}
