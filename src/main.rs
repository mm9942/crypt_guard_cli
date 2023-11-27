mod keychain; // Import the keychain module

use keychain::Keychain; // Use the Keychain struct from the keychain module
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new Keychain instance
    let mut kc = Keychain::new().await?;

    // Test the save method
    kc.save("keychain").await?;

    Ok(())
}