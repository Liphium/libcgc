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

/// Chunk size of the encrypted chunks (longer by stream_symmetric::EXTRA_LENGTH) in encrypted form.
const CHUNK_SIZE: usize = 1024 * 1024;

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
    let mut buffer = vec![0; CHUNK_SIZE];
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
    let mut read_sig: Option<[u8; signature::SIGNATURE_LEN]> = None;
    let mut buffer = vec![0; CHUNK_SIZE + stream_symmetric::EXTRA_LENGTH];
    loop {
        let n = file.read(&mut buffer).await.ok()?;
        if n == 0 {
            break;
        }

        // Make sure to split the file correctly (make sure signature isn't in there)
        let chunk = if n != CHUNK_SIZE + stream_symmetric::EXTRA_LENGTH {
            if n <= signature::SIGNATURE_LEN {
                println!("Invalid chunk length");
                return None;
            }

            // Cut off the signature and chunk. Save the signature for later.
            let (chunk, sig) = buffer.split_at(n - signature::SIGNATURE_LEN);

            read_sig = Some((sig[..signature::SIGNATURE_LEN]).try_into().ok()?);
            Some(chunk.to_vec())
        } else {
            Some(buffer.clone())
        }?;

        // Decrypt the file and write decrypted content to the result file
        let (decrypted, _) = stream_symmetric::decrypt(&mut cipher, &chunk)?;
        hasher.update(&decrypted);
        result_file.write(&decrypted).await.ok()?;
    }

    // Verify the signature
    if read_sig.is_none() {
        let mut signature = [0u8; signature::SIGNATURE_LEN];
        file.read(&mut signature).await.ok();
        read_sig = Some(signature);
    }
    if signature::verify(
        verifying_key,
        &hasher.finalize().as_bytes().to_vec(),
        &read_sig.unwrap().to_vec(),
    )? {
        Some(())
    } else {
        None
    }
}
