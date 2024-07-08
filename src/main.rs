use clap::{arg, Arg, ArgAction, Command};
use std::{path::PathBuf, fmt, fs::{File, self}, io::Write};
use ::crypt_guard::{*, error::*, KDF::*};
use hex;

#[derive(Debug)]
enum CryptGuardError {
    IoError(std::io::Error),
    ParseError(String),
    CryptError(CryptError),
}

impl From<std::io::Error> for CryptGuardError {
    fn from(error: std::io::Error) -> Self {
        CryptGuardError::IoError(error)
    }
}

impl From<CryptError> for CryptGuardError {
    fn from(error: CryptError) -> Self {
        CryptGuardError::CryptError(error)
    }
}

impl fmt::Display for CryptGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptGuardError::IoError(err) => write!(f, "I/O Error: {}", err),
            CryptGuardError::ParseError(err) => write!(f, "Parse Error: {}", err),
            CryptGuardError::CryptError(err) => write!(f, "Cryptographic Error: {}", err),
        }
    }
}


#[derive(Debug, PartialEq)]
enum KeyTypes {
    Falcon1024,
    Falcon512,
    Kyber1024,
    Kyber768,
    Kyber512,
    Dilithium5,
    Dilithium3,
    Dilithium2,
}

impl fmt::Display for KeyTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                KeyTypes::Falcon1024 => "falcon1024",
                KeyTypes::Falcon512 => "falcon512",
                KeyTypes::Kyber1024 => "kyber1024",
                KeyTypes::Kyber768 => "kyber768",
                KeyTypes::Kyber512 => "kyber512",
                KeyTypes::Dilithium5 => "dilithium5",
                KeyTypes::Dilithium3 => "dilithium3",
                KeyTypes::Dilithium2 => "dilithium2",
            }
        )
    }
}

impl KeyTypes {
    fn from_str(input: &str) -> Result<Self, CryptError> {
        match input.to_lowercase().as_str() {
            "falcon1024" => Ok(KeyTypes::Falcon1024),
            "falcon512" => Ok(KeyTypes::Falcon512),
            "kyber1024" => Ok(KeyTypes::Kyber1024),
            "kyber768" => Ok(KeyTypes::Kyber768),
            "kyber512" => Ok(KeyTypes::Kyber512),
            "dilithium5" => Ok(KeyTypes::Dilithium5),
            "dilithium3" => Ok(KeyTypes::Dilithium3),
            "dilithium2" => Ok(KeyTypes::Dilithium2),
            _ => Err(CryptError::new(format!("Invalid algorithm: {}", input).as_str())),
        }
    }
}

#[derive(Debug, PartialEq)]
enum SignatureType {
    SignedData,
    Detached,
}

impl fmt::Display for SignatureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SignatureType::SignedData => "signeddata",
                SignatureType::Detached => "detached",
            }
        )
    }
}

impl SignatureType {
    fn from_str(input: &str) -> Result<Self, CryptError> {
        match input.to_lowercase().as_str() {
            "signeddata" => Ok(SignatureType::SignedData),
            "detached" => Ok(SignatureType::Detached),
            _ => Err(CryptError::new(format!("Invalid algorithm: {}", input).as_str())),
        }
    }
}

#[derive(Debug, PartialEq)]
enum SymmetricAlgorithm {
    AES,
    XChaCha20,
}

impl fmt::Display for SymmetricAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SymmetricAlgorithm::AES => "aes",
                SymmetricAlgorithm::XChaCha20 => "xchacha20",
            }
        )
    }
}

impl SymmetricAlgorithm {
    fn from_str(input: &str) -> Result<Self, CryptError> {
        match input.to_lowercase().as_str() {
            "aes" => Ok(SymmetricAlgorithm::AES),
            "xchacha20" => Ok(SymmetricAlgorithm::XChaCha20),
            _ => Err(CryptError::new(format!("Invalid algorithm: {}", input).as_str())),
        }
    }
}

#[derive(Debug, PartialEq)]
enum SignatureAlgorithm {
    Falcon,
    Dilithium,
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SignatureAlgorithm::Falcon => "falcon",
                SignatureAlgorithm::Dilithium => "dilithium",
            }
        )
    }
}

impl SignatureAlgorithm {
    fn from_str(input: &str) -> Result<Self, CryptError> {
        match input.to_lowercase().as_str() {
            "falcon" => Ok(SignatureAlgorithm::Falcon),
            "dilithium" => Ok(SignatureAlgorithm::Dilithium),
            _ => Err(CryptError::new(format!("Invalid algorithm: {}", input).as_str())),
        }
    }
}

fn applet_commands() -> [Command; 2] {
    [
        Command::new("detached")
            .about("Verify a detached signature")
            .arg(
                arg!(-i --input <INPUT>)
                    .required(true)
                    .help("Path to the input file or message"),
            )
            .arg(
                arg!(-s --signature <SIGNATURE>)
                    .required(true)                    
                    .value_parser(clap::value_parser!(PathBuf))
                    .help("Path to the detached signature file"),
            )
            .arg(
                arg!(-k --key <KEY>)
                    .required(true)                    
                    .value_parser(clap::value_parser!(PathBuf))
                    .help("Public key for verification"),
            )
            .arg(
                arg!(-K --keysize <KEYSIZE>)
                    .required(true)
                    .value_parser(clap::value_parser!(usize))
                    .help("Size of the key in bits"),
            )
            .arg(
                arg!(-a --algorithm <ALGORITHM>)
                    .required(true)
                    .help("Specify the verification algorithm (e.g., falcon1024, dilithium5)"),
            ),
        Command::new("signed")
            .about("Verify a signed message or file")
            .arg(
                arg!(-i --input <INPUT>)
                    .required(true)                    
                    .value_parser(clap::value_parser!(PathBuf))
                    .help("Path to the signed input file or message"),
            )
            .arg(
                arg!(-k --key <KEY>)
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf))
                    .help("Public key for verification"),
            )
            .arg(
                arg!(-K --keysize <KEYSIZE>)
                    .required(true)
                    .value_parser(clap::value_parser!(usize))
                    .help("Size of the key in bits"),
            )
            .arg(
                arg!(-a --algorithm <ALGORITHM>)
                    .required(true)
                    .help("Specify the verification algorithm (e.g., falcon1024, dilithium5)"),
            ),
    ]
}

fn main() {
    let matches = build_cli().get_matches();
    parse_cli(matches);
}

fn build_cli() -> Command {
    Command::new("crypt_guard")
        .about("A CLI tool for cryptographic operations")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .version("1.0")
        .author("mm29942 <mm29942@cryptguard.org>")
        
        .subcommand(
            Command::new("keygen")
                .about("Generate a new key pair")
                .arg(
                    arg!(-a --algorithm <ALGORITHM>)
                        .required(true)
                        .help("Specify the algorithm (e.g., kyber1024, falcon1024, dilithium5)"),
                )
                .arg(
                    arg!(-d --directory <DIR>)
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Directory to save the keys"),
                ),
        )
        
        .subcommand(
            Command::new("encrypt")
                .about("Encrypt a message or file")
                .arg(
                    arg!(-i --input <INPUT>)
                        .required(true)
                        .help("Path to the input file or message"),
                )
                .arg(
                    arg!(-o --output <OUTPUT>)
                        .required(true)
                        .help("Path to save the encrypted output"),
                )
                .arg(
                    arg!(-k --key <KEY>)
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Public key for encryption"),
                )
                .arg(
                    arg!(-K --keysize <KEYSIZE>)
                        .required(true)
                        .value_parser(clap::value_parser!(usize))
                        .help("Size of the key in bits"),
                )
                .arg(
                    arg!(-p --passphrase <PASSPHRASE>)
                        .help("Passphrase for encryption (optional)"),
                )
                .arg(
                    arg!(-a --algorithm <ALGORITHM>)
                        .required(true)
                        .help("Specify the encryption algorithm (e.g., aes, xchacha20)"),
                )
                .arg(
                    arg!(-m --message)
                        .action(ArgAction::SetTrue)
                        .help("Indicates that the input is a message string rather than a file"),
                ),
        )
        
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt a message or file")
                .arg(
                    arg!(-i --input <INPUT>)
                        .required(true)
                        .help("Path to the encrypted input file or message"),
                )
                .arg(
                    arg!(-o --output <OUTPUT>)
                        .required(true)
                        .help("Path to save the decrypted output"),
                )
                .arg(
                    arg!(-k --key <KEY>)
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Secret key for decryption"),
                )
                .arg(
                    arg!(-K --keysize <KEYSIZE>)
                        .required(true)
                        .value_parser(clap::value_parser!(usize))
                        .help("Size of the key in bits"),
                )
                .arg(
                    arg!(-c --cipher <CIPHER>)
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Ciphertext for decryption"),
                )
                .arg(
                    arg!(-p --passphrase <PASSPHRASE>)
                        .help("Passphrase for decryption (if used during encryption)"),
                )
                .arg(
                    arg!(-a --algorithm <ALGORITHM>)
                        .required(true)
                        .help("Specify the decryption algorithm (e.g., aes, xchacha20)"),
                )
                .arg(
                    arg!(-n --nonce <NONCE>)
                        .help("Nonce for decryption (required for xchacha20)"),
                ),
        )
        
        .subcommand(
            Command::new("sign")
                .about("Sign a message or file")
                .arg(
                    arg!(-i --input <INPUT>)
                        .required(true)
                        .help("Path to the input file or message"),
                )
                .arg(
                    arg!(-o --output <OUTPUT>)
                        .required(true)
                        .help("Path to save the signature"),
                )
                .arg(
                    arg!(-k --key <KEY>)
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Secret key for signing"),
                )
                .arg(
                    arg!(-K --keysize <KEYSIZE>)
                        .required(true)
                        .value_parser(clap::value_parser!(usize))
                        .help("Size of the key in bits"),
                )
                .arg(
                    arg!(-a --algorithm <ALGORITHM>)
                        .required(true)
                        .help("Specify the signing algorithm (e.g., falcon, dilithium)"),
                )
                .arg(
                    arg!(-t --type <ALGORITHM>)
                        .required(true)
                        .help("Specify the signing variant (detached or signeddata)"),
                )
                .arg(
                    arg!(-m --message)
                        .action(ArgAction::SetTrue)
                        .help("Indicates that the input is a message string rather than a file"),
                ),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a signature")
                .arg_required_else_help(true)
                .subcommand_value_name("APPLET")
                .subcommand_help_heading("APPLET TYPES")
                .subcommands(applet_commands()),
        )
}

fn parse_cli(matches: clap::ArgMatches) -> Result<(), CryptError> {
    match matches.subcommand() {
        Some(("keygen", sub_matches)) => {
            let algorithm = sub_matches.get_one::<String>("algorithm").expect("required");
            let directory = sub_matches.get_one::<PathBuf>("directory").expect("required");
            println!("Generating key pair with algorithm {} in directory {:?}", algorithm, directory);

            match KeyTypes::from_str(algorithm.as_str()) {
                Ok(keytype) => {
                    let (public, secret) = match keytype {
                        KeyTypes::Falcon1024 => Ok(FalconKeypair!(1024)),
                        KeyTypes::Falcon512 => Ok(FalconKeypair!(512)),
                        KeyTypes::Kyber1024 => Ok(KyberKeypair!(1024)),
                        KeyTypes::Kyber768 => Ok(KyberKeypair!(768)),
                        KeyTypes::Kyber512 => Ok(KyberKeypair!(512)),
                        KeyTypes::Dilithium5 => Ok(DilithiumKeypair!(5)),
                        KeyTypes::Dilithium3 => Ok(DilithiumKeypair!(3)),
                        KeyTypes::Dilithium2 => Ok(DilithiumKeypair!(2)),
                        _ => Err(CryptError::new("Keygen failed!"))
                    }.expect("Keygen failed!");

                    let dir_name = directory.file_name().expect("Directory should have a name").to_str().expect("Invalid directory name");
                    let public_key_path = directory.join(format!("{}.pub", dir_name));
                    let secret_key_path = directory.join(format!("{}.sec", dir_name));

                    // Create the directory if it does not exist
                    std::fs::create_dir_all(directory).expect("Failed to create directories");

                    // Save the public key
                    {
                        let mut public_file = File::create(&public_key_path).expect("Failed to create public key file");
                        public_file.write_all(&public).expect("Failed to write public key");
                    }

                    // Save the secret key
                    {
                        let mut secret_file = File::create(&secret_key_path).expect("Failed to create secret key file");
                        secret_file.write_all(&secret).expect("Failed to write secret key");
                    }

                    println!("Keys generated and saved to {} and {}", public_key_path.display(), secret_key_path.display());
                    Ok(())
                },
                Err(e) => {
                    Err(CryptError::new(format!("Error: {}", e).as_str()))
                }
            }
        }
        Some(("encrypt", sub_matches)) => {
            let input = sub_matches.get_one::<String>("input").expect("required");
            let output = sub_matches.get_one::<String>("output").expect("required");
            let mut output_path = PathBuf::from(output);

            let key = sub_matches.get_one::<PathBuf>("key").expect("required");
            let keysize = sub_matches.get_one::<usize>("keysize").expect("required");
            let passphrase = sub_matches.get_one::<String>("passphrase");
            let algorithm_str = sub_matches.get_one::<String>("algorithm").expect("required");
            let algorithm = SymmetricAlgorithm::from_str(algorithm_str).unwrap();

            match sub_matches.get_flag("message") {
                true => {
                    println!("Encrypting {} to {} using {} with algorithm {} and is message: {}", input, output, key.display(), algorithm, sub_matches.get_flag("message"));
                    let (encrypted, cipher) = match keysize {
                        1024 => Encryption!(fs::read(key).unwrap(), 1024, input.clone().as_bytes().to_owned(), passphrase.clone().unwrap().as_str(), AES),
                        768 => Encryption!(fs::read(key).unwrap(), 768, input.clone().as_bytes().to_owned(), passphrase.clone().unwrap().as_str(), AES),
                        512 => Encryption!(fs::read(key).unwrap(), 512, input.clone().as_bytes().to_owned(), passphrase.clone().unwrap().as_str(), AES),
                        _ => Err(CryptError::new("Encryption failed!"))
                    }.expect("Encryption failed!");

                    let mut output_file = File::create(&output_path).expect("Failed to create output file");
                    output_file.write_all(&encrypted).expect("Failed to write encrypted data");
                    
                    let _ = output_path.set_extension("ct");
                    let mut output_file = File::create(&output_path).expect("Failed to create output file");
                    output_file.write_all(&cipher).expect("Failed to write encrypted data");

                    println!("Finished encryption of the message, it's saved at: {}", output_path.display());
                    Ok(())
                },
                false => {
                    let input_path = PathBuf::from(input);
                    let input_data = fs::read(input).unwrap();
                    let mut output_path = PathBuf::from(output);

                    match algorithm {
                        SymmetricAlgorithm::AES => {
                            let (encrypted, cipher) = match keysize {
                                1024 => Encryption!(fs::read(key).unwrap(), 1024, input_data, passphrase.clone().unwrap().as_str(), AES),
                                768 => Encryption!(fs::read(key).unwrap(), 768, input_data, passphrase.clone().unwrap().as_str(), AES),
                                512 => Encryption!(fs::read(key).unwrap(), 512, input_data, passphrase.clone().unwrap().as_str(), AES),
                                _ => Err(CryptError::new("Encryption failed!"))
                            }.expect("Encryption failed!");

                            let mut output_file = File::create(&output_path).expect("Failed to create output file");
                            output_file.write_all(&encrypted).expect("Failed to write encrypted data");

                            let _ = output_path.set_extension("ct");
                            let mut output_file = File::create(&output_path).expect("Failed to create output file");
                            output_file.write_all(&cipher).expect("Failed to write encrypted data");

                            println!("Encrypting {} to {} using {} with algorithm {} has finished, the ciphertext is of size {}", input_path.display(), output_path.display(), key.display(), algorithm, cipher.len());
                        },
                        SymmetricAlgorithm::XChaCha20 => {
                            let (encrypted, cipher, nonce) = match keysize {
                                1024 => Encryption!(fs::read(key).unwrap(), 1024, input_data, passphrase.clone().unwrap().as_str(), XChaCha20),
                                768 => Encryption!(fs::read(key).unwrap(), 768, input_data, passphrase.clone().unwrap().as_str(), XChaCha20),
                                512 => Encryption!(fs::read(key).unwrap(), 512, input_data, passphrase.clone().unwrap().as_str(), XChaCha20),
                                _ => todo!(),
                            };

                            let mut output_file = File::create(&output_path).expect("Failed to create output file");
                            output_file.write_all(&encrypted).expect("Failed to write encrypted data");

                            let _ = output_path.set_extension("ct");
                            let mut output_file = File::create(&output_path).expect("Failed to create output file");
                            output_file.write_all(&cipher).expect("Failed to write encrypted data");

                            println!("Encrypting {} to {} using {} with algorithm {} has finished, the ciphertext is of size {}. Note down the nonce: {}", input_path.display(), output_path.display(), key.display(), algorithm, cipher.len(), nonce);
                        },
                        _ => todo!(),
                    };
                    Ok(())
                }
            }
        }
        Some(("decrypt", sub_matches)) => {
            let input = sub_matches.get_one::<String>("input").expect("required");
            let output = sub_matches.get_one::<String>("output").expect("required");

            let key = sub_matches.get_one::<PathBuf>("key").expect("required");
            let keysize = sub_matches.get_one::<usize>("keysize").expect("required");
            let cipher_path = sub_matches.get_one::<PathBuf>("cipher").expect("required");
            let cipher = fs::read(cipher_path).unwrap();

            let passphrase = sub_matches.get_one::<String>("passphrase");
            let algorithm_str = sub_matches.get_one::<String>("algorithm").expect("required");
            let algorithm: SymmetricAlgorithm = SymmetricAlgorithm ::from_str(algorithm_str).unwrap();

            let nonce = sub_matches.get_one::<String>("nonce");

            println!("Decrypting {} to {} using {} with algorithm {}", input, output, key.display(), algorithm);
            
            let input_path = PathBuf::from(input);
            let input_data = fs::read(input).unwrap();
            let mut output_path = PathBuf::from(output);

            let decrypted = match algorithm {
                SymmetricAlgorithm::AES => match keysize {
                    1024 => Decryption!(fs::read(key).unwrap(), 1024, input_data, passphrase.clone().unwrap().as_str(), cipher, AES),
                    768 => Decryption!(fs::read(key).unwrap(), 768, input_data, passphrase.clone().unwrap().as_str(), cipher, AES),
                    512 => Decryption!(fs::read(key).unwrap(), 512, input_data, passphrase.clone().unwrap().as_str(), cipher, AES),
                    _ => Err(CryptError::new("Decryption failed!"))
                },
                SymmetricAlgorithm::XChaCha20 => {
                    let nonce = nonce.expect("Nonce is required for XChaCha20");
                    match keysize {
                        1024 => Decryption!(fs::read(key).unwrap(), 1024, input_data, passphrase.clone().unwrap().as_str(), cipher, Some(nonce.to_string()), XChaCha20),
                        768 => Decryption!(fs::read(key).unwrap(), 768, input_data, passphrase.clone().unwrap().as_str(), cipher, Some(nonce.to_string()), XChaCha20),
                        512 => Decryption!(fs::read(key).unwrap(), 512, input_data, passphrase.clone().unwrap().as_str(), cipher, Some(nonce.to_string()), XChaCha20),
                        _ => Err(CryptError::new("Decryption failed!"))
                    }
                },
            }.expect("Decryption failed!");

            let mut output_file = File::create(&output_path).expect("Failed to create output file");
            output_file.write_all(&decrypted).expect("Failed to write decrypted data");

            println!("Finished decryption of: {}", input_path.display());     
            Ok(())
        }
        Some(("sign", sub_matches)) => {
            use ::crypt_guard::KDF::*;
            let input = sub_matches.get_one::<String>("input").expect("required");
            let output = sub_matches.get_one::<String>("output").expect("required");
            let mut output_path = PathBuf::from(output);

            let key = sub_matches.get_one::<PathBuf>("key").expect("required");
            let keysize = sub_matches.get_one::<usize>("keysize").expect("required");
            let algorithm_str = sub_matches.get_one::<String>("algorithm").expect("required");
            let algorithm = SignatureAlgorithm::from_str(algorithm_str).expect("");

            let type_str = sub_matches.get_one::<String>("type").expect("required");
            let r#type = SignatureType::from_str(type_str).unwrap();

            let signature = match sub_matches.get_flag("message") {
                true => {
                    let key_data = fs::read(key).unwrap();

                    match r#type {
                        SignatureType::SignedData => {
                            match algorithm {
                                SignatureAlgorithm::Falcon => {
                                    match keysize {
                                        1024 => Signature!(Falcon, key_data, 1024, input.as_bytes().to_owned(), Message),
                                        512 => Signature!(Falcon, key_data, 512, input.as_bytes().to_owned(), Message),
                                        _ => return Err(CryptError::new("Signing Failed!")),
                                    }
                                },
                                SignatureAlgorithm::Dilithium => {
                                    match keysize {
                                        5 => Signature!(Dilithium, key_data, 5, input.as_bytes().to_owned(), Message),
                                        3 => Signature!(Dilithium, key_data, 3, input.as_bytes().to_owned(), Message),
                                        2 => Signature!(Dilithium, key_data, 2, input.as_bytes().to_owned(), Message),
                                        _ => return Err(CryptError::new("Signing Failed!")),
                                    }
                                },
                                _ => return Err(CryptError::new("Signing Failed!")),
                            }
                        },
                        SignatureType::Detached => {
                            match algorithm {
                                SignatureAlgorithm::Falcon => {
                                    match keysize {
                                        1024 => Signature!(Falcon, key_data, 1024, input.as_bytes().to_owned(), Detached),
                                        512 => Signature!(Falcon, key_data, 512, input.as_bytes().to_owned(), Detached),
                                        _ => return Err(CryptError::new("Signing Failed!")),
                                    }
                                },
                                SignatureAlgorithm::Dilithium => {
                                    match keysize {
                                        5 => Signature!(Dilithium, key_data, 5, input.as_bytes().to_owned(), Detached),
                                        3 => Signature!(Dilithium, key_data, 3, input.as_bytes().to_owned(), Detached),
                                        2 => Signature!(Dilithium, key_data, 2, input.as_bytes().to_owned(), Detached),
                                        _ => return Err(CryptError::new("Signing Failed!")),
                                    }
                                },
                                _ => return Err(CryptError::new("Signing Failed!")),
                            }
                        },
                    }
                },
                false => {
                    let input_data = fs::read(input).unwrap();
                    let key_data = fs::read(key).unwrap();

                    match r#type {
                        SignatureType::SignedData => {
                            match algorithm {
                                SignatureAlgorithm::Falcon => {
                                    match keysize {
                                        1024 => Signature!(Falcon, key_data, 1024, input_data, Message),
                                        512 => Signature!(Falcon, key_data, 512, input_data, Message),
                                        _ => return Err(CryptError::new("Signing Failed!")),
                                    }
                                },
                                SignatureAlgorithm::Dilithium => {
                                    match keysize {
                                        5 => Signature!(Dilithium, key_data, 5, input_data, Message),
                                        3 => Signature!(Dilithium, key_data, 3, input_data, Message),
                                        2 => Signature!(Dilithium, key_data, 2, input_data, Message),
                                        _ => return Err(CryptError::new("Signing Failed!")),
                                    }
                                },
                                _ => return Err(CryptError::new("Signing Failed!")),
                            }
                        },
                        SignatureType::Detached => {
                            match algorithm {
                                SignatureAlgorithm::Falcon => {
                                    match keysize {
                                        1024 => Signature!(Falcon, key_data, 1024, input_data, Detached),
                                        512 => Signature!(Falcon, key_data, 512, input_data, Detached),
                                        _ => return Err(CryptError::new("Signing Failed!")),
                                    }
                                },
                                SignatureAlgorithm::Dilithium => {
                                    match keysize {
                                        5 => Signature!(Dilithium, key_data, 5, input_data, Detached),
                                        3 => Signature!(Dilithium, key_data, 3, input_data, Detached),
                                        2 => Signature!(Dilithium, key_data, 2, input_data, Detached),
                                        _ => return Err(CryptError::new("Signing Failed!")),
                                    }
                                },
                                _ => return Err(CryptError::new("Signing Failed!")),
                            }
                        },
                    }
                }
            };
            match signature {
                sig => {
                    fs::write(output_path, sig).unwrap();
                    println!("Signing {} to {} using {} with algorithm {}", input, output, key.display(), algorithm);
                    Ok(())
                },
                _ => {
                    return Err(CryptError::new("Signing Failed!"))
                }
            }
        }
        Some(("verify", sub_matches)) => {
            let subcommand = sub_matches.subcommand();

            match subcommand {
                Some(("Detached", cmd)) => {                    
                    let input = cmd.get_one::<String>("input").expect("required");
                    let signature = cmd.get_one::<String>("signature").expect("required");
                    let key = cmd.get_one::<PathBuf>("key").expect("required");
                    let algorithm_str = cmd.get_one::<String>("algorithm").expect("required");
                    let algorithm = KeyTypes::from_str(algorithm_str.as_str()).unwrap();

                    println!("Verifying detached signature for {} with signature {} using {} with algorithm {}", input, signature, key.display(), algorithm);
                    
                }
                Some(("SignedData", cmd)) => {                    
                    let input = cmd.get_one::<String>("input").expect("required");
                    let key = cmd.get_one::<PathBuf>("key").expect("required");
                    let algorithm_str = cmd.get_one::<String>("algorithm").expect("required");
                    let algorithm = SignatureType::from_str(algorithm_str.as_str()).unwrap();

                    println!("Verifying signed data for {} using {} with algorithm {}", input, key.display(), algorithm);
                    
                }
                _ => unreachable!(),
            }
            Ok(())
        }
        _ => unreachable!(),

    }
}
