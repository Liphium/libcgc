use std::time::Duration;

use libcgc::{
    container::file_symmetric,
    crypto::{signature, symmetric},
};
use tokio::time;

#[tokio::main]
async fn main() {
    let mut key = symmetric::SymmetricKey::generate();
    let mut kp = signature::SignatureKeyPair::generate();

    file_symmetric::pack(
        "README.md".into(),
        "test.enc".into(),
        &mut key,
        &mut kp.signature_key,
    )
    .await;

    time::sleep(Duration::from_secs(2)).await;

    file_symmetric::unpack(
        "test.enc".into(),
        "README2.md".into(),
        &mut key,
        &kp.verify_key,
    )
    .await;

    println!("File copied")
}
