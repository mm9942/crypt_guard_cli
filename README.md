# RustCryptGuard

## Introduction
RustCryptGuard is a Rust-based command-line tool for encryption and decryption, leveraging the post-quantum Kyber1024 algorithm. It's designed to protect files and messages from quantum-computing threats, offering advanced security.

## Prerequisites
Before installing RustCryptGuard, your system should have:
- Rust and Cargo (latest stable version)
- Tokio runtime environment

## Installation
To install RustCryptGuard, follow these steps:
1. Clone the GitHub repository:
   ```bash
   git clone https://github.com/mm9942/RustCryptGuard.git
   ```
2. Navigate to the RustCryptGuard directory:
   ```bash
   cd RustCryptGuard
   ```
3. Compile the project using Cargo:
   ```bash
   cargo build --release
   ```

## Usage
RustCryptGuard is accessed through the `crypt_guard` command-line interface. Key commands include:
1. **List Keyfiles**:
   ```bash
   crypt_guard -l
   ```
2. **Generate New Encryption Keys**:
   ```bash
   crypt_guard new -n [keyname] -p [path]
   ```
3. **Encrypt Data**:
   ```bash
   crypt_guard encrypt -k [passphrase] -p [public key path] -f [file path] -m [message]
   ```
4. **Decrypt Data**:
   ```bash
   crypt_guard decrypt -p [passphrase] -s [secret key path] -c [ciphertext path] -f [file path] -m [message]
   ```

## Dependencies
RustCryptGuard relies on the following dependencies as specified in `cargo.toml`:
- `aes`: Version 0.8.3 for AES encryption.
- `clap`: Version 4.4.18 for parsing command-line arguments, with `cargo` and `derive` features.
- `env`: Version 0.0.0.
- `hex`: Version 0.4.3 for handling hexadecimal values.
- `hmac`: Version 0.12.1 for Hash-based Message Authentication Code support.
- `pqcrypto`: Version 0.17.0 with serialization feature for post-quantum cryptography.
- `pqcrypto-kyber`: Version 0.8.0 with serialization feature for the Kyber1024 algorithm.
- `pqcrypto-traits`: Version 0.3.5.
- `sha2`: Version 0.10.8 for SHA-256 hashing.
- `tempdir`: Version 0.3.7 for creating temporary directories.
- `tempfile`: Version 3.9.0 for managing temporary files.
- `tokio`: Version 1.35.1 with the `full` feature for asynchronous programming.

## License
RustCryptGuard is licensed under the GNU GENERAL PUBLIC LICENSE Version 3. The full license text can be found in the `LICENSE` file in the repository.
