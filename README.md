# CryptGuard CLI

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Documentation][doc-badge]][doc-url]
[![Hashnode Blog][blog-badge]][blog-url]
[![GitHub Library][lib-badge]][lib-link]
[![GitHub CLI][cli-badge]][cli-link]

This project is based on the Rust crate `crypt_guard`. You can read more about the crate [here](https://crates.io/crates/crypt_guard).

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

### Encryption using XChaCha20

#### **Encryption**

```sh
./target/debug/crypt_guard encrypt -i test/Cargo.lock -o test/Files/XChaCha20/enc/Cargo.lock.enc -K 1024 -k test/kyber_keys/kyber_keys.pub -p "keyphrase" -a XChaCha20
```

#### **Decryption**

```sh
./target/debug/crypt_guard decrypt -i test/Files/XChaCha20/enc/Cargo.lock.enc -o test/Files/XChaCha20/dec/Cargo.lock -c test/Files/XChaCha20/enc/Cargo.lock.ct -K 1024 -k test/kyber_keys/kyber_keys.sec -p "keyphrase" -a XChaCha20 -n="54643ed8ce9d454690b0d6263de59159fb1826f75043c19e"
```

**Please note that XChaCha20 returns a nonce that is not automatically saved and needs to be noted down!**

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
