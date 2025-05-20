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

// Test the symmetric file encryption container
#[tokio::test]
async fn test_file_symmetric() {
    use super::file_symmetric;
    use crate::crypto::signature::SignatureKeyPair;
    use crate::crypto::symmetric::SymmetricKey;
    use std::env::temp_dir;
    use tokio::fs::{File, remove_file};
    use tokio::io::AsyncWriteExt;

    // prepare file paths
    let dir = temp_dir();
    let input = dir.join("test_input.txt");
    let packed = dir.join("test_input.txt.enc");
    let output = dir.join("test_output.txt");

    // write original data
    let data = b"Hello file symmetric container!";
    let mut f = File::create(&input).await.unwrap();
    f.write_all(data).await.unwrap();

    // generate keys
    let mut key = SymmetricKey::generate();
    let mut skp = SignatureKeyPair::generate();

    // pack
    assert!(
        file_symmetric::pack(
            input.to_string_lossy().into_owned(),
            packed.to_string_lossy().into_owned(),
            &mut key,
            &mut skp.signature_key,
        )
        .await
        .is_some()
    );

    // unpack
    assert!(
        file_symmetric::unpack(
            packed.to_string_lossy().into_owned(),
            output.to_string_lossy().into_owned(),
            &mut key,
            &skp.verify_key,
        )
        .await
        .is_some()
    );

    // verify output matches input
    let content = tokio::fs::read(&output).await.unwrap();
    assert_eq!(content.as_slice(), data);

    // tamper with encrypted file
    let mut f_enc = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&packed)
        .await
        .unwrap();
    f_enc.write_all(b"tamper").await.unwrap();

    assert!(
        file_symmetric::unpack(
            packed.to_string_lossy().into_owned(),
            output.to_string_lossy().into_owned(),
            &mut key,
            &skp.verify_key,
        )
        .await
        .is_none()
    );

    // cleanup
    let _ = remove_file(input).await;
    let _ = remove_file(packed).await;
    let _ = remove_file(output).await;
}
