
### KeyGen commands
#### **Falcon key generation** size: 1024 (available: 1024, 512)
`./target/debug/crypt_guard keygen -a Falcon1024 -d test/falcon_keys`

#### **Dilithium key generation** size: 5 (available: 5, 3, 2)
`./target/debug/crypt_guard keygen -a Dilithium5 -d test/dilithium_keys`

#### **Kyber key generation** size: 1024 (available: 1024, 768, 512) 
`./target/debug/crypt_guard keygen -a Kyber1024 -d test/kyber_keys`

### Creation of detached signature
#### **Create Detached Signature** 
`./target/debug/crypt_guard sign --type detached -i test/Cargo.lock -a falcon -k test/falcon_keys/falcon_keys.sec -K 1024 -o test/Files/detached/Cargo.toml.sig`

#### **Verify Detached Signature** 
`./target/debug/crypt_guard verify detached -i test/Files/detached/Cargo.toml.sig -a falcon -k test/falcon_keys/falcon_keys.pub -K 1024 -s test/Files/detached/Cargo.lock.sig`

### Creating Signed data
#### **Signing Data** 
`./target/debug/crypt_guard sign --type signed -i  test/Cargo.lock -a falcon -k falcon_keys/falcon_keys.sec -K 1024 -o test/Files/signed/Cargo.lock.sig`

#### **Opening Signed Data**  `./target/debug/crypt_guard verify signed -o test/Files/signed/Cargo.lock -a falcon -k falcon_keys/falcon_keys.pub -K 1024 -i test/Files/signed/Cargo.lock.sig`

### Encryption using AES
#### **Encryption** 
`./target/debug/crypt_guard encrypt -i test/Cargo.lock -o test/Files/AES/enc/Cargo.lock.enc -K 1024 -k test/kyber_keys/kyber_keys.pub -p "keyphrase" -a AES`

#### **Decryption** 
`./target/debug/crypt_guard decrypt -i test/Files/AES/enc/Cargo.lock.enc -o test/Files/AES/dec/Cargo.lock -c test/Files/AES/enc/Cargo.lock.ct -K 1024 -k test/kyber_keys/kyber_keys.sec -p "keyphrase" -a AES`

### Encryption using XChaCha20
#### **Encryption** 
`./target/debug/crypt_guard encrypt -i test/Cargo.lock -o test/Files/XChaCha20/enc/Cargo.lock.enc -K 1024 -k test/kyber_keys/kyber_keys.pub -p "keyphrase" -a XChaCha20`
#### **Decryption** 
`./target/debug/crypt_guard decrypt -i test/Files/XChaCha20/enc/Cargo.lock.enc -o test/Files/XChaCha20/dec/Cargo.lock -c test/Files/XChaCha20/enc/Cargo.lock.ct -K 1024 -k test/kyber_keys/kyber_keys.sec -p "keyphrase" -a XChaCha20 -n="54643ed8ce9d454690b0d6263de59159fb1826f75043c19e"`
**please regard that XChaCha returns a nonce that is not automatically saved and needs to be noted down!**