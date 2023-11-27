use pqcrypto_kyber::kyber1024::{self, *};
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret};
use hex::*;
use std::{
    error::Error,
    fmt,
    fs::{self, *},
    io,
    result::Result,
};
use tokio;

#[derive(Debug)]
pub enum KeychainError {
    IOError(std::io::Error),
    HexError(hex::FromHexError),
    EncapsulationError,
    DecapsulationError,
    WriteError(std::io::Error),
}

impl fmt::Display for KeychainError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeychainError::IOError(ref err) => write!(f, "IO error: {}", err),
            KeychainError::HexError(ref err) => write!(f, "Hex error: {}", err),
            KeychainError::EncapsulationError => write!(f, "Encapsulation error"),
            KeychainError::DecapsulationError => write!(f, "Decapsulation error"),
            KeychainError::WriteError(ref err) => write!(f, "Write error: {}", err),
        }
    }
}

impl Error for KeychainError {}

pub struct Keychain {
    public_key: kyber1024::PublicKey,
    secret_key: kyber1024::SecretKey,
    shared_secret: kyber1024::SharedSecret,
    ciphertext: kyber1024::Ciphertext,
}

impl Keychain {
    pub async fn new() -> Result<Self, KeychainError> {
        let (pk, sk) = keypair();
        let (ss, ct) = encapsulate(&pk);
        Ok(Self {
            public_key: pk,
            secret_key: sk,
            shared_secret: ss,
            ciphertext: ct,
        })
    }

    pub async fn show(&self) -> Result<(), KeychainError> {
        let ss2 = decapsulate(&self.ciphertext, &self.secret_key);
        println!("Public Key: {}\n\nSecret Key: {}\n\nShared secret: {}\n\nDecapsulated shared secret: {}", 
                 hex::encode(&self.public_key.as_bytes()), 
                 hex::encode(&self.secret_key.as_bytes()), 
                 hex::encode(&self.shared_secret.as_bytes()), 
                 hex::encode(&ss2.as_bytes()));
        Ok(())
    }

    pub async fn save(&self, path: &str) -> Result<(), KeychainError> {
        let public_key_path = format!("{}.pub", path);
        let secret_key_path = format!("{}.sec", path);
        fs::write(
            &public_key_path, 
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                hex::encode(&self.public_key.as_bytes())
            )
        ).map_err(KeychainError::WriteError)?;

        fs::write(
            &secret_key_path, 
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
                hex::encode(&self.secret_key.as_bytes())
            )
        ).map_err(KeychainError::WriteError)?;

        println!(
            "\nPlease write down: {}\n\nKeychain saved successfully.\n",
            hex::encode(&self.shared_secret.as_bytes())
        );
        Ok(())
    }
}
