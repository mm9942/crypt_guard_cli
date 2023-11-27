use pqcrypto_kyber::kyber1024::{self, *};
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
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
enum KeychainError {
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

pub struct File {
    path: String,
    data: Vec<u8>,
}

pub enum FileType {
    PublicKey,
    SecretKey,
    SharedSecret,
    Ciphertext,
}

pub struct Encapsulation {
    public_key: kyber1024::PublicKey,
    shared_secret: kyber1024::SharedSecret,
    ciphertext: kyber1024::Ciphertext,
}

pub struct Decapsulation {
    secret_key: kyber1024::SecretKey,
    ciphertext: kyber1024::Ciphertext,
    shared_secret: kyber1024::SharedSecret,
}

impl Encapsulation {
    pub async fn load(path: &str) -> Result<Self, KeychainError> {
        let public_key_bytes = File::load(path, FileType::PublicKey).await;
        let public_key = PublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| KeychainError::EncapsulationError)?;
        Ok(Self::new(public_key).await)
    }

    pub async fn new(public_key: kyber1024::PublicKey) -> Self {
        let (shared_secret, ciphertext) = encapsulate(&public_key);
        Self {
            public_key,
            shared_secret,
            ciphertext,
        }
    }
}

impl Decapsulation {
    pub async fn load(sec_path: &str, cipher_path: &str) -> Result<Self, KeychainError> {
        let secret_key_bytes = File::load(sec_path, FileType::SecretKey).await;
        let secret_key = SecretKey::from_bytes(&secret_key_bytes)
            .map_err(|_| KeychainError::DecapsulationError)?;
        let ciphertext_bytes = File::load(cipher_path, FileType::Ciphertext).await;
        let ciphertext = Ciphertext::from_bytes(&ciphertext_bytes)
            .map_err(|_| KeychainError::DecapsulationError)?;
        Ok(Self::new(secret_key, ciphertext).await)
    }

    pub async fn new(secret_key: kyber1024::SecretKey, ciphertext: kyber1024::Ciphertext) -> Self {
        let shared_secret = decapsulate(&ciphertext, &secret_key);
        Self {
            secret_key,
            ciphertext,
            shared_secret,
        }
    }
}

impl File {
    pub async fn load(path: &str, file_type: FileType) -> Result<Vec<u8>, KeychainError> {
        let file_content = fs::read_to_string(path)
            .map_err(KeychainError::IOError)?;

        let (start_label, end_label) = match file_type {
            FileType::PublicKey => ("-----BEGIN PUBLIC KEY-----\n", "\n-----END PUBLIC KEY-----"),
            FileType::SecretKey => ("-----BEGIN PRIVATE KEY-----\n", "\n-----END PRIVATE KEY-----"),
            FileType::SharedSecret => ("-----BEGIN SHARED SECRET-----\n", "\n-----END SHARED SECRET-----"),
            FileType::Ciphertext => ("-----BEGIN CIPHERTEXT-----\n", "\n-----END CIPHERTEXT-----"),
        };

        let start = file_content.find(start_label)
            .ok_or_else(|| KeychainError::IOError(std::io::Error::new(std::io::ErrorKind::InvalidData, "Start label not found")))?;
        let end = file_content.find(end_label)
            .ok_or_else(|| KeychainError::IOError(std::io::Error::new(std::io::ErrorKind::InvalidData, "End label not found")))?;

        let content = &file_content[start + start_label.len()..end];
        
        hex::decode(content)
            .map_err(KeychainError::HexError)
    }
}
