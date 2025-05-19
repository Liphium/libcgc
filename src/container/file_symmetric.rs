use blake3::Hasher;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::crypto::{
    signature::{self, SigningKey, VerifyingKey},
    stream_symmetric,
    symmetric::SymmetricKey,
};

pub async fn pack(
    path: String,
    result_path: String,
    key: &mut SymmetricKey,
    signing_key: &mut SigningKey,
) -> Option<()> {
    let mut file = File::open(path).await.ok()?;
    let mut result_file = File::create(result_path).await.ok()?;

    // Create a new stream cipher and add header to the file
    let (mut cipher, header) = stream_symmetric::new_encryption_cipher(key)?;
    result_file.write(&header).await.ok()?;

    // Encrypt the file in 1 MB chunks
    let mut hasher = Hasher::new();
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let n = file.read(&mut buffer).await.ok()?;
        if n == 0 {
            break;
        }
        let (chunk, _) = buffer.split_at(n);

        // Encrypt the chunk and add to file
        let encrypted = stream_symmetric::encrypt(&mut cipher, &chunk.to_vec(), false)?;
        hasher.update(&chunk);
        result_file.write(&encrypted).await.ok()?;
    }

    // Sign the file with a signature that contains the hash
    let sig = signature::sign(signing_key, &hasher.finalize().as_bytes().to_vec())?;
    result_file.write(&sig).await.ok()?;
    Some(())
}

pub async fn unpack(
    path: String,
    result_path: String,
    key: &mut SymmetricKey,
    verifying_key: &VerifyingKey,
) -> Option<()> {
    let mut file = File::open(path).await.ok()?;
    let mut result_file = File::create(result_path).await.ok()?;

    // Read the header at the beginning
    let mut header = [0u8; stream_symmetric::HEADER_LENGTH];
    file.read(&mut header).await.ok()?;

    // Create the decryption cipher
    let mut cipher = stream_symmetric::new_decryption_cipher(key, &header.to_vec())?;

    // Read the file in chunks
    let mut hasher = Hasher::new();
    let mut buffer = vec![0; 1024 * 1024 + stream_symmetric::EXTRA_LENGTH];
    loop {
        let n = file.read(&mut buffer).await.ok()?;
        if n == 0 {
            break;
        }
        let (chunk, _) = buffer.split_at(n);

        // Decrypt the file and write decrypted content to the result file
        let (decrypted, _) = stream_symmetric::decrypt(&mut cipher, &chunk.to_vec())?;
        hasher.update(&decrypted);
        result_file.write(&decrypted).await.ok()?;
    }

    // Verify the signature
    let mut signature = [0u8; signature::SIGNATURE_LEN];
    file.read(&mut signature).await.ok();
    if signature::verify(
        verifying_key,
        &hasher.finalize().as_bytes().to_vec(),
        &signature.to_vec(),
    )? {
        None
    } else {
        Some(())
    }
}
