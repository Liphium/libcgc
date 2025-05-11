#[test]
// Test asymmetric secret key encoding and decoding
fn test_secret_key_encoding() {
    use crate::asymmetric::{SecretKey, new_keypair};

    let mut keypair = new_keypair();
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
    use crate::asymmetric::{PublicKey, new_keypair};

    let mut keypair = new_keypair();
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
