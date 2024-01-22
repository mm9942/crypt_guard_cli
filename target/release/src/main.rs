mod keychain;
mod decrypt;
mod encrypt;

use crate::keychain::*;
use crate::encrypt::*;
use crate::decrypt::*;
use std::{
    path::PathBuf,
    fs
};
use pqcrypto::kem::kyber1024::decapsulate;
use hex;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use tokio;
pub use clap::{
    self,
    Arg,
    Command,
    arg,
    Parser,
    command,
    builder::OsStr,
    ArgAction
};

async fn cli() -> Command {
    Command::new("pqencrypt")
        .about("A post-quantum encryption tool")
        .long_about("A command-line tool for post-quantum encryption using Kyber1024")
        .author("mm29942, mm29942@pm.me")
        .display_name("PostQuantum Encrypt")
        .arg(arg!(-l --list "List all saved keyfiles.").action(ArgAction::SetTrue).required(false))
        .subcommand(
            Command::new("new")
                .about("Create new encryption keys")
                .arg(arg!(-n --name <NAME> "Set the keyname you want to use").required(true))
                .arg(arg!(-p --path <PATH> "Set the path to save the keyfiles into.").required(false).default_value("."))
        )
        .subcommand(
            Command::new("encrypt")
                .about("Encrypt a file, message or DataDrive using the public key")
                .arg(arg!(-k --passphrase <PASSPHRASE> "Passphrase to derive encryption key").required(true))
                .arg(arg!(-p --public <PUBLIC> "Path to the public key file for encryption").required(false))
                .arg(arg!(-s --save "Saves the encrypted output to a file. If not specified, the output will be printed to the console.").action(ArgAction::SetTrue).required(false))
                .arg(arg!(-f --file <FILE> "Select the file you want to encrypt.").required(false))
                .arg(arg!(-m --message <MESSAGE> "Define the message you want to encrypt.").required(false))
                .arg(arg!(-d --drive <DRIVE> "Select the DataDrive you want to encrypt").required(false))
                .arg(arg!(--dir <DIR> "Select the directory, where you want to save the encrypted file/ message").required(false))
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt encrypted files, messages or DataDrive using the secret key and the ciphertext")
                .arg(arg!(-p --passphrase <PASSPHRASE> "Passphrase to derive decryption key").required(true))
                .arg(arg!(-s --secret <SECRET> "Path to the secret key file for decryption").required(true))
                .arg(arg!(-c --ciphertext <CIPHERTEXT> "Select the ciphertext which is needed to retrieve the shared secret").required(true))
                .arg(arg!(-f --file <FILE> "Select the file you want to decrypt.").required(false))
                .arg(arg!(-m --message <MESSAGE> "Define the message you want to decrypt.").required(false))
                .arg(arg!(-d --drive <DRIVE> "Select the DataDrive you want to decrypt").required(false))
        )
}

async fn check() {
    let matches = cli().await.get_matches();

    let _public = String::new();
    let _secret = String::new();
    let _ciphertext = String::new();
    let _shared = String::new();
    let _file = String::new();
    let _message = String::new();
    let _drive = String::new();
    let _name = String::new();
    let _path = String::new();
    let _key = String::new();

    if let Some(sub_matches) = matches.subcommand_matches("new") {
        let keyname = sub_matches.get_one::<String>("name");
        let keypath = sub_matches.get_one::<String>("path");
        let mut keychain = Keychain::new().expect("Failed to initialize keychain");
        let _ = keychain.show();
        let _ = keychain.save(keypath.unwrap().as_str(), keyname.unwrap().as_str()).await;
    }
    if let Some(sub_matches) = matches.subcommand_matches("encrypt") {
        let passphrase = sub_matches.get_one::<String>("passphrase").expect("Passphrase is required");
        let hmac_key = passphrase.as_bytes();
        let public_key_path = sub_matches.get_one::<String>("public").expect("Public key path is required").into();

        let encrypt_result = if let Some(file_path) = sub_matches.get_one::<String>("file") {
            Encrypt::encrypt(public_key_path, Some(&PathBuf::from(file_path)), None, hmac_key).await
        } else if let Some(message) = sub_matches.get_one::<String>("message") {
            let message_result = Encrypt::encrypt(public_key_path, None, Some(message), hmac_key).await;
            match message_result {
                Ok(message) => {
                    if sub_matches.get_flag("save") {
                        let _ = Encrypt::save_encrypted_message(&message, PathBuf::from("./message.enc"))
                            .await;
                    } else {
                        let hex_message = format!(
                            "-----BEGIN ENCRYPTED MESSAGE-----\n{}\n-----END ENCRYPTED MESSAGE-----",
                            hex::encode(&message)
                        );
                        println!("{}", hex_message);
                    }
                    Ok(message)
                },
                Err(e) => Err(e),
            }
        } else {
            Err(CryptError::InvalidParameters)
        };
    }
    if let Some(sub_matches) = matches.subcommand_matches("decrypt") {
        let passphrase = sub_matches.get_one::<String>("passphrase").expect("Passphrase is required");
        let hmac_key = passphrase.as_bytes();
        let secret_key_path = PathBuf::from(sub_matches.get_one::<String>("secret").expect("Secret key path is required"));
        let ciphertext_path = PathBuf::from(sub_matches.get_one::<String>("ciphertext").expect("Ciphertext path is required"));

        let keychain = Keychain::new().expect("Failed to initialize keychain");

        let decrypt_result = if let Some(file_path) = sub_matches.get_one::<String>("file") {
            let file_path_buf = PathBuf::from(file_path);
            Decrypt::decrypt(secret_key_path, ciphertext_path, Some(&file_path_buf), None, hmac_key).await
        } else if let Some(message) = sub_matches.get_one::<String>("message") {
            Decrypt::decrypt(secret_key_path, ciphertext_path, None, Some(&hex::decode(message).unwrap()), hmac_key).await
        } else {
            Err(CryptError::InvalidParameters)
        };

        match decrypt_result {
            Ok(decrypted_data) => {
                // Code to handle decrypted data
            },
            Err(e) => eprintln!("Decryption error: {:?}", e),
        }
    }

    if matches.get_flag("list") {
    }


}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    check().await;
    Ok(())
}