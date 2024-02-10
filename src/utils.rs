use std::fs;
use std::path::Path;

pub async fn list_keyfiles() -> Result<(), Box<dyn std::error::Error>> {
    let keyfiles_path = dirs::home_dir().unwrap().join(".CryptGuardKeys");
    println!("Listing all saved keyfiles in {:?}", keyfiles_path);

    // Check if the directory exists
    if !keyfiles_path.exists() {
        println!("No keyfiles directory found.");
        return Ok(());
    }

    // Read the directory and list each file
    let entries = fs::read_dir(keyfiles_path)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            println!("{}", path.display());
        }
    }

    Ok(())
}