mod keychain; // Import the keychain module
mod load_key; // Import the load_key module

use keychain::Keychain; // Use the Keychain struct from the keychain module
use load_key::{Decapsulation, Encapsulation}; // Use the load function from the load_key module
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut kc = Keychain::new().await?;

    kc.save("keychain").await?;

    let public_key_path = "keychain/keychain.pub";
    let secret_key_path = "keychain/keychain.sec";
    let ciphertext_path = "keychain/keychain.ct";

    let encapsulation = Encapsulation::load(public_key_path).await?;
    println!("Encapsulated shared secret: {}", encapsulation.shared_secret.as_bytes());
    println!("Ciphertext: {:?}", encapsulation.ciphertext.as_bytes());

    let decapsulation = Decapsulation::load(secret_key_path, ciphertext_path).await?;
    println!("Decapsulated shared secret: {}", decapsulation.shared_secret.as_bytes());

    Ok(())
}