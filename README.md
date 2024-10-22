# CryptGuard CLI

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Documentation][doc-badge]][doc-url]
[![Hashnode Blog][blog-badge]][blog-url]
[![GitHub Library][lib-badge]][lib-link]
[![GitHub CLI][cli-badge]][cli-link]

This project is based on the Rust crate `crypt_guard`. You can read more about the crate [here](https://crates.io/crates/crypt_guard).

### Stable Pre-Release

This is a pre-release version which is stable but currently lacks proper error handling. The foundation is already laid and will soon integrate improved error handling and additional security features. Despite this, by following the README and CLI help, you should not encounter major issues. Currently, the highest security key types (Kyber 1024, Falcon 1024, and Dilithium 5) have been tested. Also tested is encryption with AES, AES_GCM_SIV, AES_CTR, XChaCha20, and XChaCha20Poly1305.

Note that basic AES uses ECB mode, which is the simplest mode of operation and is considered insecure because it encrypts each block of data independently. For better security, use AES_GCM_SIV or AES_CTR.

Regarding the differences between AES_CTR, AES_GCM_SIV, and XChaCha20Poly1305:

- **AES_CTR**: AES in Counter (CTR) mode is a symmetric key algorithm that provides confidentiality by turning a block cipher into a stream cipher. It requires careful management of the nonce to ensure security. Unlike ECB, it does not reveal data patterns, but without additional authentication, it only ensures confidentiality, not integrity. Therefore, it is recommended to pair it with an integrity check for added security.

- **AES_GCM_SIV**: AES in Galois/Counter Mode (GCM-SIV) combines both encryption and authentication, offering confidentiality and data integrity. GCM-SIV is designed to be nonce-misuse resistant, which means that even if a nonce is reused by mistake, it does not compromise security as badly as traditional GCM. It is particularly useful in situations where unique nonce management is difficult.

- **XChaCha20 vs XChaCha20Poly1305**: XChaCha20 focuses purely on encryption with a longer nonce, while XChaCha20-Poly1305 combines encryption with message authentication, making it a stronger choice for securing both the confidentiality and integrity of data.

## Overview

`CryptGuard CLI` is a command-line tool for cryptographic operations, including key generation, signing, verification, encryption, and decryption using various algorithms.

## Installation

To use this tool, ensure you have Rust installed on your machine. Clone this repository and build the project using Cargo:

```sh
git clone https://github.com/mm9942/crypt_guard_cli
cd crypt_guard_cli
cargo build --release
```

## Usage

### KeyGen commands

#### **Falcon key generation** size: 1024 (available: 1024, 512)

```sh
./target/debug/crypt_guard keygen -a Falcon1024 -d test/falcon_keys
```

#### **Dilithium key generation** size: 5 (available: 5, 3, 2)

```sh
./target/debug/crypt_guard keygen -a Dilithium5 -d test/dilithium_keys
```

#### **Kyber key generation** size: 1024 (available: 1024, 768, 512)

```sh
./target/debug/crypt_guard keygen -a Kyber1024 -d test/kyber_keys
```

### Creation of detached signature

#### **Create Detached Signature**

```sh
./target/debug/crypt_guard sign --type detached -i test/Cargo.lock -a falcon -k test/falcon_keys/falcon_keys.sec -K 1024 -o test/Files/detached/Cargo.toml.sig
```

#### **Verify Detached Signature**

```sh
./target/debug/crypt_guard verify detached -i test/Files/detached/Cargo.toml.sig -a falcon -k test/falcon_keys/falcon_keys.pub -K 1024 -s test/Files/detached/Cargo.lock.sig
```

### Creating Signed data

#### **Signing Data**

```sh
./target/debug/crypt_guard sign --type signed -i test/Cargo.lock -a falcon -k falcon_keys/falcon_keys.sec -K 1024 -o test/Files/signed/Cargo.lock.sig
```

#### **Opening Signed Data**

```sh
./target/debug/crypt_guard verify signed -o test/Files/signed/Cargo.lock -a falcon -k falcon_keys/falcon_keys.pub -K 1024 -i test/Files/signed/Cargo.lock.sig
```

### Encryption using AES

#### **Encryption**

```sh
./target/debug/crypt_guard encrypt -i test/Cargo.lock -o test/Files/AES/enc/Cargo.lock.enc -K 1024 -k test/kyber_keys/kyber_keys.pub -p "keyphrase" -a AES
```

#### **Decryption**

```sh
./target/debug/crypt_guard decrypt -i test/Files/AES/enc/Cargo.lock.enc -o test/Files/AES/dec/Cargo.lock -c test/Files/AES/enc/Cargo.lock.ct -K 1024 -k test/kyber_keys/kyber_keys.sec -p "keyphrase" -a AES
```

### Encryption using AES_GCM_SIV

#### **Encryption**

```sh
./target/debug/crypt_guard encrypt -i test/Cargo.lock -o test/Files/AES_GCM_SIV/enc/Cargo.lock.enc -K 1024 -k test/kyber_keys/kyber_keys.pub -p "keyphrase" -a AES_GCM_SIV
```

#### **Decryption**

```sh
./target/debug/crypt_guard decrypt -i test/Files/AES_GCM_SIV/enc/Cargo.lock.enc -o test/Files/AES_GCM_SIV/dec/Cargo.lock -c test/Files/AES_GCM_SIV/enc/Cargo.lock.ct -K 1024 -k test/kyber_keys/kyber_keys.sec -p "keyphrase" -a AES_GCM_SIV -n="887d90f06541bc9a1891ca1e"
```

### Encryption using AES_CTR

#### **Encryption**

```sh
./target/debug/crypt_guard encrypt -i test/Cargo.lock -o test/Files/AES_CTR/enc/Cargo.lock.enc -K 1024 -k test/kyber_keys/kyber_keys.pub -p "keyphrase" -a AES_CTR
```

#### **Decryption**

```sh
./target/debug/crypt_guard decrypt -i test/Files/AES_CTR/enc/Cargo.lock.enc -o test/Files/AES_CTR/dec/Cargo.lock -c test/Files/AES_CTR/enc/Cargo.lock.ct -K 1024 -k test/kyber_keys/kyber_keys.sec -p "keyphrase" -a AES_CTR -n="3a4e921d25679f232fc1d8dc5317e90f"
```

### Encryption using XChaCha20

#### **Encryption**

```sh
./target/debug/crypt_guard encrypt -i test/Cargo.lock -o test/Files/XChaCha20/enc/Cargo.lock.enc -K 1024 -k test/kyber_keys/kyber_keys.pub -p "keyphrase" -a XChaCha20
```

#### **Decryption**

```sh
./target/debug/crypt_guard decrypt -i test/Files/XChaCha20/enc/Cargo.lock.enc -o test/Files/XChaCha20/dec/Cargo.lock -c test/Files/XChaCha20/enc/Cargo.lock.ct -K 1024 -k test/kyber_keys/kyber_keys.sec -p "keyphrase" -a XChaCha20 -n="54643ed8ce9d454690b0d6263de59159fb1826f75043c19e"
```

### Encryption using XChaCha20Poly1305

#### **Encryption**

```sh
./target/debug/crypt_guard encrypt -i test/Cargo.lock -o test/Files/XChaCha20Poly1305/enc/Cargo.lock.enc -K 1024 -k test/kyber_keys/kyber_keys.pub -p "keyphrase" -a XChaCha20Poly1305
```

#### **Decryption**

```sh
./target/debug/crypt_guard decrypt -i test/Files/XChaCha20Poly1305/enc/Cargo.lock.enc -o test/Files/XChaCha20Poly1305/dec/Cargo.lock -c test/Files/XChaCha20Poly1305/enc/Cargo.lock.ct -K 1024 -k test/kyber_keys/kyber_keys.sec -p "keyphrase" -a XChaCha20Poly1305 -n="54643ed8ce9d454690b0d6263de59159fb1826f75043c19e"
```

**Please note that each AES_GCM_SIV, AES_CTR, XChaCha20 and XChaCha20Poly1305 return a nonce that is not automatically saved and needs to be noted down!**

[blog-badge]: https://img.shields.io/badge/blog-hashnode-lightblue.svg?style=for-the-badge
[blog-url]: https://blog.mm29942.com/
[crates-badge]: https://img.shields.io/badge/crates.io-v1.2-blue.svg?style=for-the-badge
[crates-url]: https://crates.io/crates/crypt_guard
[mit-badge]: https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge
[mit-url]: https://github.com/mm9942/crypt_guard/blob/main/LICENSE
[doc-badge]: https://img.shields.io/badge/docs-v1.2-yellow.svg?style=for-the-badge
[doc-url]: https://docs.rs/crypt_guard/
[lib-badge]: https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge
[lib-link]: https://github.com/mm9942/crypt_guard
[cli-badge]: https://img.shields.io/badge/github-cli-white.svg?style=for-the-badge
[cli-link]: https://github.com/mm9942/crypt_guard_cli
