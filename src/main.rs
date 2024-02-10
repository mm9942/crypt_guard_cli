mod utils;

use crate::utils::list_keyfiles;
use crypt_guard_sign::{Sign, SignDilithium};
use crypt_guard_kyber::*;
use crypt_guard::generate_nonce;
use std::{
    path::{Path, PathBuf},
    fs,
    io,
};
use pqcrypto_kyber::kyber1024::{decapsulate, encapsulate, self};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_falcon::falcon1024;
use hex;
use pqcrypto_traits::{
    kem::{PublicKey, SecretKey, SharedSecret, Ciphertext},
    sign
};
use tokio;
use dirs::home_dir;
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

#[derive(Debug)]
struct File;

pub enum KeyTypes {
    All,
    PublicKey,
    SecretKey,
    SharedSecret,
    Ciphertext,
}

impl File {
    pub async fn load(path: PathBuf, file_type: KeyTypes) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let file_content = fs::read_to_string(&path)?;

        let (start_label, end_label) = match file_type {
            KeyTypes::PublicKey => ("-----BEGIN PUBLIC KEY-----\n", "\n-----END PUBLIC KEY-----"),
            KeyTypes::SecretKey => ("-----BEGIN SECRET KEY-----\n", "\n-----END SECRET KEY-----"),
            KeyTypes::SharedSecret => ("-----BEGIN SHARED SECRET-----\n", "\n-----END SHARED SECRET-----"),
            KeyTypes::Ciphertext => ("-----BEGIN CIPHERTEXT-----\n", "\n-----END CIPHERTEXT-----"),
            KeyTypes::All => unreachable!(),
        };

        let start = file_content.find(start_label);
        let end = file_content.rfind(end_label);

        let start = start.ok_or("Start label not found")?;
        let end = end.ok_or("End label not found")?;

        let content = &file_content[start + start_label.len()..end];
        Ok(hex::decode(content)?)
    }
}


async fn cli() -> Command {
    Command::new("crypt_guard")
        .about("A post-quantum encryption tool")
        //.long_about("A command-line tool for post-quantum encryption using Kyber1024")
        .author("mm29942, mm29942@pm.me")
        .display_name("PostQuantum Encrypt")
        .arg(arg!(-l --list "List all saved keyfiles.").action(ArgAction::SetTrue).required(false))
        .subcommand(
            Command::new("keygen")
                .about("Create new encryption keys")
                .short_flag('k')
                .long_flag("key")
                .arg(arg!(-e --enc "Create the keys required for encryption and decryption.").action(ArgAction::SetTrue))
                .arg(arg!(-s --sig "Create the keys required for signature handling.").action(ArgAction::SetTrue))
                .arg(arg!(-d --dilithium  "Create the keys required for signature handling. But specially for the dilithium algorithm!").action(ArgAction::SetTrue))
                .arg(arg!(-n --name <NAME> "Set the keyname you want to use").required(true))
                .arg(arg!(-p --path <PATH> "Set the path to save the keyfiles into.").required(false).default_value(".CryptGuardKeys/"))
        )
        .subcommand(
            Command::new("Process")
                .short_flag('P')
                .long_flag("process")
                .about("En-/ Decrypt or Sign/ Verify a file (or folder)")
                .subcommand(
                    Command::new("encrypt")
                        .short_flag('e')
                        .long_flag("enc")
                        .about("Encrypt a file, message or DataDrive using the public key")
                        .arg(arg!(-p --passphrase <PASSPHRASE> "Passphrase to sign the encrypted data").required(true))
                        .arg(arg!(-i --ident <IDENT> "Path to the public key file for encryption").required(false))
                        .arg(arg!(-f --file <FILE> "Select the file you want to encrypt.").required(false).conflicts_with("message"))
                        .arg(arg!(-m --message <MESSAGE> "Define the message you want to encrypt.").required(false).conflicts_with("file"))

                        .arg(arg!(-s --save "Save encrypted message as file.").required(false).action(ArgAction::SetTrue).conflicts_with("file"))
                        .arg(arg!(-d --dir <DIR> "Select the directory for saving, when non selected, file is safed at same directory as targed.").required(false).conflicts_with("file"))
                )
                .subcommand(
                    Command::new("decrypt")
                        .short_flag('d')
                        .long_flag("dec")
                        .about("Decrypt encrypted files, messages or DataDrive using the secret key and the ciphertext")
                        .arg(arg!(-p --passphrase <PASSPHRASE> "Passphrase to verify encryption key").required(true))
                        .arg(arg!(-n --nonce <NONCE> "Nonce generated to encrypt the data.").required(false))
                        .arg(arg!(-i --ident <IDENT> "Path to the secret key file for decryption").required(true))
                        .arg(arg!(-c --ciphertext <CIPHERTEXT> "Select the ciphertext which is needed to retrieve the shared secret").required(true))
                        .arg(arg!(-f --file <FILE> "Select the file you want to decrypt.").required(false).conflicts_with("message"))
                        .arg(arg!(-m --message <MESSAGE> "Define the message you want to decrypt.").required(false).conflicts_with("file"))
                )

                .subcommand(
                    Command::new("sign")
                        .short_flag('s')
                        .long_flag("sign")
                        .about("Create the signature of a file, folder or message using the secret key.")
                        //.arg(arg!(-p --passphrase <PASSPHRASE> "Passphrase to derive encryption key").required(false))
                        .arg(arg!(-i --ident <IDENT> "Path to the secret key file for signing").required(false))
                        .arg(arg!(-f --file <FILE> "Select the file (or folder) you want to create the signature from.").required(false).conflicts_with("message"))
                        .arg(arg!(-m --message <MESSAGE> "Define the message you want to create the signature from.").required(false).conflicts_with("file"))

                        .arg(arg!(-s --save "Save signature of message as file.").required(false).action(ArgAction::SetTrue).conflicts_with("file"))
                        .arg(arg!(-d --dir <DIR> "Select the directory for saving, when non selected, file is safed at same directory as targed.").required(false).conflicts_with("file"))
                
                )
                .subcommand(
                    Command::new("verify")
                        .short_flag('v')
                        .long_flag("verify")
                        .about("Verify the signature of a file, folder or message using the public key of the person who signed it.")
                        //.arg(arg!(-p --passphrase <PASSPHRASE> "Passphrase to derive encryption key").required(true))
                        .arg(arg!(-i --ident <IDENT> "Path to the public key file for encryption").required(false))
                        .arg(arg!(-s --signature <SIGNATURE> "Select the you used to safe the signature.").required(false))
                        .arg(arg!(-f --file <FILE> "Select the file you want to decrypt.").required(false).conflicts_with("message"))
                        .arg(arg!(-m --message <MESSAGE> "The message signature you want.").required(false).conflicts_with("file"))
                )
                .arg(arg!(-A --Alternative "If selected at en-/decryption XChaCha20 will as algorithm be used, and for signing/ verification, dilithium will be used instead of falcon.").required(false))
        ).to_owned()
}
async fn check() -> Result<(), Box<dyn std::error::Error>> {
    let matches = cli().await.get_matches();

    let mut keychain = Keychain::new().unwrap();
    match matches.subcommand() {
        Some(("keygen", sub_matches)) => {
            let name = sub_matches.get_one::<String>("name").map(|s| s.as_str()).unwrap();
            let path = sub_matches.get_one::<String>("path");
            let mut home = home_dir().unwrap();

            let directory = if let Some(p) = path {
                if p.trim().is_empty() {
                    ".CryptGuardKeys/"
                } else {
                    p
                }
            } else {
                ".CryptGuardKeys/"
            };
            
            let _ = home.push(".CryptGuardKeys/");
            if !home.exists() {
                fs::create_dir_all(&home).unwrap();
            }

            if sub_matches.get_flag("enc") {
                let _ = keychain.save_keys(&directory, &name).await;
                //list_keyfiles().await.unwrap();
                return Ok(());
            }
            if sub_matches.get_flag("sig") {
                let mut sign = Sign::new().unwrap();
                let _ = sign.save_keys(&directory, &name).await;
                //list_keyfiles().await.unwrap();
                return Ok(());

                if sub_matches.get_flag("dilithium") {
                    let mut sign = SignDilithium::new().unwrap();
                    let target_path = directory;
                    let _ = sign.save_keys(&directory, &name).await;
                    //list_keyfiles().await.unwrap();
                    return Ok(());
                }
            }
        },
        Some(("Process", sub_matches)) => {
            let sub_subcommand = &sub_matches.subcommand();
            let algorithm: bool = sub_matches.get_flag("Alternative");

            let save: bool = match sub_subcommand {
                Some(("save", save_subcommand)) => true,
                _ => false
            };

            match sub_subcommand {
                Some(("encrypt", encrypt_matches)) => {
                    let encrypt = Encrypt::new(); 

                    let pub_key = PathBuf::from(encrypt_matches.get_one::<String>("ident").map(|s| s.as_str()).unwrap());
                    let public_key = keychain.load_public_key(pub_key.clone()).await.unwrap();
                    let (shared_secret, ciphertext) = kyber1024::encapsulate(&public_key);

                    let ciphertext_path = Keychain::generate_unique_filename(format!("{}/{}", &pub_key.parent().unwrap().display(), &pub_key.file_stem().unwrap().to_string_lossy()).as_str(), "ct");

                    let _ = fs::write(
                        &ciphertext_path, 
                        format!(
                            "-----BEGIN CIPHERTEXT-----\n{}\n-----END CIPHERTEXT-----",
                            hex::encode(&ciphertext.as_bytes())
                        )
                    );

                    let pass = encrypt_matches.get_one::<String>("passphrase").map(|s| s.as_str()).unwrap().as_bytes();
                    let message_option = encrypt_matches.get_one::<String>("message");
                    let file_option = encrypt_matches.get_one::<String>("file");

                    if algorithm {
                        let nonce = Some(generate_nonce());
                        match (message_option, file_option) {
                            (Some(message), _) if !message.is_empty() => {
                                if let Some(nonce) = nonce {
                                    let encrypted_data = encrypt.encrypt_msg_xchacha20(message, &shared_secret, &nonce, pass).await.unwrap();
                                    let encrypted_hex = hex::encode(&encrypted_data);
                                    println!("Encrypted message: {:?}", &encrypted_hex);

                                    if encrypt_matches.get_flag("save") {
                                        let dir_option = encrypt_matches.get_one::<String>("dir");
                                        let file_option = encrypt_matches.get_one::<String>("file");

                                        match dir_option {
                                            Some(dir) if !dir.is_empty() => {
                                                let dir_path = PathBuf::from(dir);
                                                let file_path = match file_option {
                                                    Some(file_name) if !file_name.is_empty() => dir_path.join(file_name),
                                                    _ => dir_path.join("message.enc"),
                                                };

                                                if !dir_path.exists() {
                                                    fs::create_dir_all(&dir_path).unwrap();
                                                }

                                                fs::write(&file_path, &encrypted_data).unwrap();
                                                println!("Encrypted message saved to {:?}", file_path);
                                            },
                                            _ => println!("Directory not specified or is empty, encrypted message not saved."),
                                        }
                                    }
                                } else {
                                    println!("Nonce not provided for xchacha20 encryption.");
                                }
                            },


                            (_, Some(file)) if !file.is_empty() => {
                                if let Some(nonce) = nonce {
                                    let encrypted_data = encrypt.encrypt_file_xchacha20(PathBuf::from(&file), &shared_secret, &nonce, pass).await.unwrap();

                                  if encrypt_matches.get_flag("save") {
                                        let dir_option = encrypt_matches.get_one::<String>("dir");
                                        let file_path = match dir_option {
                                            Some(dir) if !dir.is_empty() => {
                                                let dir_path = PathBuf::from(dir);

                                                if !dir_path.exists() {
                                                    fs::create_dir_all(&dir_path).unwrap();
                                                }
                                                dir_path.join(file)
                                            },
                                            _ => PathBuf::from(file).with_extension("enc")
                                        };

                                        fs::write(&file_path, &encrypted_data).unwrap();
                                        println!("Encrypted file saved to {:?}", file_path);
                                    }
                                } else {
                                    println!("Nonce not provided for xchacha20 encryption.");
                                }
                            },
                            (None, None) => {
                                eprintln!("Error: Both message and file options are missing. Please provide at least one.");
                            },
                            _ => {
                                eprintln!("Error: Provided message or file is empty. Please provide valid content.");
                            }
                        }
                    } else {
                        match (message_option, file_option) {
                            (Some(message), _) if !message.is_empty() => {
                                let encrypted_data = encrypt.encrypt_msg(message, &shared_secret, pass).await.unwrap();
                                let encrypted_hex = hex::encode(&encrypted_data);
                                println!("Encrypted message: {:?}", &encrypted_hex);

                                if encrypt_matches.get_flag("save") {
                                    let dir_option = encrypt_matches.get_one::<String>("dir");
                                    let file_option = encrypt_matches.get_one::<String>("file");

                                    match dir_option {
                                        Some(dir) if !dir.is_empty() => {
                                            let dir_path = PathBuf::from(dir);
                                            let file_path = match file_option {
                                                Some(file_name) if !file_name.is_empty() => dir_path.join(file_name),
                                                _ => dir_path.join("message.enc"),
                                            };

                                            if !dir_path.exists() {
                                                fs::create_dir_all(&dir_path).unwrap();
                                            }

                                            fs::write(&file_path, &encrypted_data).unwrap();
                                            println!("Encrypted message saved to {:?}", file_path);
                                        },
                                        _ => println!("Directory not specified or is empty, encrypted message not saved."),
                                    }
                                }

                            },
                            (_, Some(file)) if !file.is_empty() => {
                                let encrypted_data = encrypt.encrypt_file(PathBuf::from(&file), &shared_secret, pass).await.unwrap();

                                if encrypt_matches.get_flag("save") {
                                    let dir_option = encrypt_matches.get_one::<String>("dir");
                                    let file_path = match dir_option {
                                        Some(dir) if !dir.is_empty() => {
                                            let dir_path = PathBuf::from(dir);

                                            if !dir_path.exists() {
                                                fs::create_dir_all(&dir_path).unwrap();
                                            }
                                            dir_path.join(file)
                                        },
                                        _ => PathBuf::from(file).with_extension("enc")
                                    };

                                    fs::write(&file_path, &encrypted_data).unwrap();
                                    println!("Encrypted file saved to {:?}", file_path);
                                }
                           },
                            (None, None) => {
                                eprintln!("Error: Both message and file options are missing. Please provide at least one.");
                                // Handle the error, possibly exiting the program or asking for input again
                            },
                            _ => {
                                eprintln!("Error: Provided message or file is empty. Please provide valid content.");
                                // Handle the case where either message or file is provided but is an empty string
                            }
                        }
                    }
                    
                },
                Some(("decrypt", decrypt_matches)) => {
                    let decrypt = Decrypt::new();

                    let sec_key = PathBuf::from(decrypt_matches.get_one::<String>("ident").map(|s| s.as_str()).unwrap());
                    let sk = keychain.load_secret_key(sec_key).await.unwrap();

                    let cipher = PathBuf::from(decrypt_matches.get_one::<String>("ciphertext").map(|s| s.as_str()).unwrap());
                    let ct = keychain.load_ciphertext(cipher).await.unwrap();

                    let shared_secret = decapsulate(&ct, &sk);

                    let pass = decrypt_matches.get_one::<String>("passphrase").map(|s| s.as_str()).unwrap();
                    let message_option = decrypt_matches.get_one::<String>("message");
                    let file_option = decrypt_matches.get_one::<String>("file");

                    match (message_option, file_option) {
                        (Some(message), _) if !message.is_empty() => {
                            let decoded_message = hex::decode(message).unwrap();
                            let decrypted_data = match algorithm {
                                true => {
                                    let nonce: &[u8; 24] = str_to_byte_24(decrypt_matches.get_one::<String>("nonce").map(|s| s.as_str()).unwrap()).unwrap();
                                    decrypt.decrypt_msg_xchacha20(&decoded_message, &shared_secret, &nonce, pass.as_bytes(), save).await
                                },
                                false => decrypt.decrypt_msg(&decoded_message, &shared_secret, pass.as_bytes(), save).await,
                            };
                            match decrypted_data {
                                Ok(data) => {
                                    return Ok(());
                                },
                                Err(err) => {
                                    eprintln!("Error decrypting message: {:?}", err);
                                    return Err(err.into());
                                },
                            }
                        },
                        (_, Some(file)) if !file.is_empty() => {
                            let decrypted_data = match algorithm {
                                true => {
                                    let nonce: &[u8; 24] = str_to_byte_24(decrypt_matches.get_one::<String>("nonce").map(|s| s.as_str()).unwrap()).unwrap();
                                    decrypt.decrypt_file_xchacha20(&PathBuf::from(file), &shared_secret, &nonce, pass.as_bytes()).await
                                },
                                false => decrypt.decrypt_file(&PathBuf::from(file), &shared_secret, pass.as_bytes()).await,
                            };
                            match decrypted_data {
                                Ok(data) => {
                                    //println!("Decrypted file: {:?}", data);
                                    return Ok(());
                                },
                                Err(err) => {
                                    eprintln!("Error decrypting file: {:?}", err);
                                    return Err(err.into());
                                },
                            }
                        },
                        (None, None) => {
                            eprintln!("Error: Both message and file options are missing. Please provide at least one.");
                        },
                        _ => {
                            eprintln!("Error: Provided message or file is empty. Please provide valid content.");
                        }
                    }

                },
                Some(("sign", sign_matches)) => {
                    let file = sign_matches.get_one::<String>("file");
                    let message = sign_matches.get_one::<String>("message");
                    if algorithm {
                        let mut sign = SignDilithium::new().unwrap();

                        let sec_key: dilithium5::SecretKey = sign::SecretKey::from_bytes(&File::load(PathBuf::from(sign_matches.get_one::<String>("ident").map(|s| s.as_str()).unwrap()), KeyTypes::SecretKey).await.unwrap()).unwrap();
                        let secret = sign.set_secret_key(sec_key).await;

                        if let Some(file_path) = file {
                            let signature = sign.sign_file(PathBuf::from(file_path)).await.unwrap();
                            //println!("Signed file saved to: {:?}", signature);
                        } else if let Some(message) = message {
                            let signature = sign.sign_msg(message.as_bytes()).await.unwrap();

                            println!(
                                "Message Signature: {}",
                                hex::encode(signature)
                            );     

                            if sign_matches.get_flag("save") {
                                let dir_option = sign_matches.get_one::<String>("dir");

                                match dir_option {
                                    Some(dir) if !dir.is_empty() => {
                                        let mut dir_path = PathBuf::from(dir);

                                        if !dir_path.exists() {
                                            fs::create_dir_all(&dir_path).unwrap();
                                        }

                                        dir_path.push("message.enc");

                                        fs::write(&dir_path, &signature).unwrap();
                                        println!("Signed message saved to {:?}", dir_path);
                                    },
                                    _ => {
                                        let mut dir_path = home_dir().unwrap();
                                        dir_path.push("message.enc");
                                        fs::write(&dir_path, &signature).unwrap()
                                    },
                                }
                            }
                        } else {
                            println!("No file or message provided for signing.");
                        }
                    } else {
                        let mut sign = Sign::new().unwrap();

                        let sec_key: falcon1024::SecretKey = sign::SecretKey::from_bytes(&File::load(PathBuf::from(sign_matches.get_one::<String>("ident").map(|s| s.as_str()).unwrap()), KeyTypes::SecretKey).await.unwrap()).unwrap();
                        let secret = sign.set_secret_key(sec_key).await;

                        if let Some(file_path) = file {
                            let signature = sign.sign_file(PathBuf::from(file_path)).await.unwrap();
                            //println!("Signed file saved to: {:?}", signature);
                        } else if let Some(message) = message {let signature = sign.sign_msg(message.as_bytes()).await.unwrap();
                            println!(
                                "Message Signature: {}",
                                hex::encode(signature)
                            );     

                            if sign_matches.get_flag("save") {
                                let dir_option = sign_matches.get_one::<String>("dir");

                                match dir_option {
                                    Some(dir) if !dir.is_empty() => {
                                        let mut dir_path = PathBuf::from(dir);

                                        if !dir_path.exists() {
                                            fs::create_dir_all(&dir_path).unwrap();
                                        }

                                        dir_path.push("message.enc");

                                        fs::write(&dir_path, &signature).unwrap();
                                        println!("Signed message saved to {:?}", dir_path);
                                    },
                                    _ => {
                                        let mut dir_path = home_dir().unwrap();
                                        dir_path.push("message.enc");
                                        fs::write(&dir_path, &signature).unwrap()
                                    },
                                }
                            }
                        } else {
                            println!("No file or message provided for signing.");
                        }
                    };
                }

                Some(("verify", verify_matches)) => {
                    let file = verify_matches.get_one::<String>("file");
                    let sign_path = verify_matches.get_one::<String>("signature");
                    let message = verify_matches.get_one::<String>("message");
                    if algorithm {
                        let mut sign = SignDilithium::new().unwrap();

                        let pub_key: dilithium5::PublicKey = sign::PublicKey::from_bytes(&File::load(PathBuf::from(verify_matches.get_one::<String>("ident").map(|s| s.as_str()).unwrap()), KeyTypes::PublicKey).await.unwrap()).unwrap();
                        let public = sign.set_public_key(pub_key).await;

                        if let Some(file_path) = file {
                            let file = fs::read(PathBuf::from(file_path)).unwrap();

                            let sign_file = fs::read(PathBuf::from(sign_path.map(|s| s.as_str()).unwrap())).unwrap();
                            let signature: dilithium5::DetachedSignature = sign::DetachedSignature::from_bytes(&sign_file).unwrap();
                            sign.set_signature(signature).await;

                            let verification = sign.verify_detached(file.as_slice()).await;
                            println!("\nverified file: {}", verification.unwrap());
                        } else if let Some(message) = message {
                            let verification = sign.verify_msg(message.as_bytes()).await.unwrap();
                            println!("\nverified message: {:?}", verification);
                        } else {
                            println!("No file or message provided for signing.");
                        }
                    } else {
                        let mut sign = Sign::new().unwrap();

                        let pub_key: falcon1024::PublicKey = sign::PublicKey::from_bytes(&File::load(PathBuf::from(verify_matches.get_one::<String>("ident").map(|s| s.as_str()).unwrap()), KeyTypes::PublicKey).await.unwrap()).unwrap();
                        let public = sign.set_public_key(pub_key).await;

                        if let Some(file_path) = file {
                            let file = fs::read(PathBuf::from(file_path)).unwrap();

                            let sign_file = fs::read(PathBuf::from(sign_path.map(|s| s.as_str()).unwrap())).unwrap();
                            let signature: falcon1024::DetachedSignature = sign::DetachedSignature::from_bytes(&sign_file).unwrap();
                            sign.set_signature(signature).await;

                            let verification = sign.verify_detached(file.as_slice()).await;
                            println!("\nverified file: {}", verification.unwrap());
                        } else if let Some(message) = message {
                            let verification = sign.verify_msg(message.as_bytes()).await.unwrap();
                            println!("\nverified message: {:?}", verification);
                        } else {
                            println!("No file or message provided for signing.");
                        }
                    };

                },
                _ => {
                    println!("Invalid file operation. Please check the help for correct usage.");
                }
            }
        },
        _ => println!("Invalid command. Please check the help for correct usage."),
    }

    if matches.get_flag("list") {
        list_keyfiles().await.unwrap();
        return Ok(());
    }
    Ok(())
}

fn str_to_byte_24(input_str: &str) -> Result<&[u8; 24], &'static str> {
    let bytes = input_str.as_bytes();
    
    if bytes.len() == 24 {
        match bytes.try_into() {
            Ok(array) => Ok(array),
            Err(_) => Err("Failed to convert slice to array"),
        }
    } else {
        Err("Input string is not 24 bytes long")
    }
}

#[tokio::main]
pub async fn main() {
    let _ = check().await;
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use crypt_guard::*;
    use pqcrypto_kyber::kyber1024::{decapsulate, encapsulate, self};
    use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
    use hex;
    use tokio;

    #[tokio::test]
    async fn file_works() {
        let mut keychain = Keychain::new().unwrap();
        let data = PathBuf::from("target/Cargo.toml.enc");
        let decrypt = Decrypt::new();

        let ct = keychain.load_ciphertext(PathBuf::from(".CryptGuardKeys/key/key_5.ct")).await.unwrap();
        let sk = keychain.load_secret_key(PathBuf::from(".CryptGuardKeys/key/key.sec")).await.unwrap();
        let shared_secret: kyber1024::SharedSecret = decapsulate(&ct, &sk);
        let pass = "Ai#31415926535*";

        let decrypt_msg = decrypt.decrypt_file(&data, &shared_secret, pass.as_bytes()).await.unwrap();
    }
    #[tokio::test]
    async fn message_works() {
        let mut keychain = Keychain::new().unwrap();
        let data = hex::decode("bcf42d637a3b415b276cbbbb9aa28c4cb050de1fb7de44fba66ce74a4f8d5499cf5e83bac37c8033818333cc1e010494fc27471bdc423f0ba3ad4c8fe472df8573c84c52ed9ff5471905d6129b5081e8").unwrap();
        let decrypt = Decrypt::new();

        let ct = keychain.load_ciphertext(PathBuf::from(".CryptGuardKeys/key/key_2.ct")).await.unwrap();
        let sk = keychain.load_secret_key(PathBuf::from(".CryptGuardKeys/key/key.sec")).await.unwrap();
        let shared_secret: kyber1024::SharedSecret = decapsulate(&ct, &sk);
        let pass = b"Ai#31415926535*";

        let decrypt_msg = decrypt.decrypt_msg(&data, &shared_secret, pass, false).await.unwrap();
        println!("{}", decrypt_msg);
        assert_eq!("Cargo.toml.enc", decrypt_msg);
    }
}