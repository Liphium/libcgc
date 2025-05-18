// Test the asymmetric auth container
#[test]
fn test_auth_asymmetric() {
    use crate::crypto::{asymmetric, signature};

    use super::auth_asymmetric;

    // Make keypairs
    let mut sender_s_kp = signature::SignatureKeyPair::generate();
    let receiver_e_kp = asymmetric::AsymmetricKeyPair::generate();
    let receiver_s_kp = signature::SignatureKeyPair::generate();

    // Verify basic functionality
    let msg = b"Hello asymmetric auth!".to_vec();
    let packed = auth_asymmetric::pack(
        &receiver_e_kp.public_key,
        &mut sender_s_kp.signature_key,
        &msg,
        None,
    )
    .expect("Packing failed");
    let unpacked = auth_asymmetric::unpack(
        &receiver_e_kp.public_key,
        &receiver_e_kp.secret_key,
        &sender_s_kp.verify_key,
        &packed,
        None,
    )
    .expect("Unpacking failed");
    assert_eq!(msg.as_slice(), unpacked.as_slice());

    // Verify failure in case of changing the message
    let mut copy = packed.clone();
    copy.extend(b"b");
    assert!(
        auth_asymmetric::unpack(
            &receiver_e_kp.public_key,
            &receiver_e_kp.secret_key,
            &sender_s_kp.verify_key,
            &copy,
            None
        )
        .is_none()
    );
    copy.extend(b"adhuasuduaiui");
    assert!(
        auth_asymmetric::unpack(
            &receiver_e_kp.public_key,
            &receiver_e_kp.secret_key,
            &sender_s_kp.verify_key,
            &copy,
            None
        )
        .is_none()
    );

    // Make sure verifying with an invalid key doesn't work
    assert!(
        auth_asymmetric::unpack(
            &receiver_e_kp.public_key,
            &receiver_e_kp.secret_key,
            &receiver_s_kp.verify_key,
            &packed,
            None
        )
        .is_none()
    );

    // Test with salt
    let salt = b"random_salt_data".to_vec();
    let packed_with_salt = auth_asymmetric::pack(
        &receiver_e_kp.public_key,
        &mut sender_s_kp.signature_key,
        &msg,
        Some(&salt),
    )
    .expect("Packing with salt failed");

    // Unpacking with correct salt should work
    let unpacked_with_salt = auth_asymmetric::unpack(
        &receiver_e_kp.public_key,
        &receiver_e_kp.secret_key,
        &sender_s_kp.verify_key,
        &packed_with_salt,
        Some(&salt),
    )
    .expect("Unpacking with salt failed");
    assert_eq!(msg.as_slice(), unpacked_with_salt.as_slice());

    // Unpacking with wrong salt should fail
    let wrong_salt = b"wrong_salt_value".to_vec();
    assert!(
        auth_asymmetric::unpack(
            &receiver_e_kp.public_key,
            &receiver_e_kp.secret_key,
            &sender_s_kp.verify_key,
            &packed_with_salt,
            Some(&wrong_salt)
        )
        .is_none()
    );
}

// Test symmetric auth encryption
#[test]
fn test_auth_symmetric() {
    use crate::crypto::signature;
    use crate::crypto::symmetric;

    use super::auth_symmetric; // Make keypairs/keys
    let mut key = symmetric::SymmetricKey::generate();
    let mut sender_s_kp = signature::SignatureKeyPair::generate();
    let receiver_s_kp = signature::SignatureKeyPair::generate();

    // Verify basic functionality
    let msg = b"Hello symmetric auth!".to_vec();
    let packed = auth_symmetric::pack(&mut key, &mut sender_s_kp.signature_key, &msg, None)
        .expect("Packing failed");
    let unpacked = auth_symmetric::unpack(&mut key, &sender_s_kp.verify_key, &packed, None)
        .expect("Unpacking failed");
    assert_eq!(msg.as_slice(), unpacked.as_slice());

    // Verify failure in case of changing the message
    let mut copy = packed.clone();
    copy.extend(b"b");
    assert!(auth_symmetric::unpack(&mut key, &sender_s_kp.verify_key, &copy, None).is_none());
    copy.extend(b"adhuasuduaiui");
    assert!(auth_symmetric::unpack(&mut key, &sender_s_kp.verify_key, &copy, None).is_none());

    // Make sure verifying with an invalid key doesn't work
    assert!(auth_symmetric::unpack(&mut key, &receiver_s_kp.verify_key, &packed, None).is_none());

    // Test with salt
    let salt = b"random_salt_data".to_vec();
    let packed_with_salt =
        auth_symmetric::pack(&mut key, &mut sender_s_kp.signature_key, &msg, Some(&salt))
            .expect("Packing with salt failed");

    // Unpacking with correct salt should work
    let unpacked_with_salt = auth_symmetric::unpack(
        &mut key,
        &sender_s_kp.verify_key,
        &packed_with_salt,
        Some(&salt),
    )
    .expect("Unpacking with salt failed");
    assert_eq!(msg.as_slice(), unpacked_with_salt.as_slice());

    // Unpacking with wrong salt should fail
    let wrong_salt = b"wrong_salt_value".to_vec();
    assert!(
        auth_symmetric::unpack(
            &mut key,
            &sender_s_kp.verify_key,
            &packed_with_salt,
            Some(&wrong_salt)
        )
        .is_none()
    );
}
