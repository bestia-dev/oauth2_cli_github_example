// crates_io_api_token.rs

//! Publish to crates.io needs the crates.io secret_token. This is a secret important just like a password.
//! There is the original "cargo login" function that saves this critical secret in plain text. This is a big no no.
//! I don't want to pass secret to an "obscure" library crate that is difficult to
//! review and can change in any point in time and become malicious.
//! Instead of that, copy and paste this module "mod" file into your project.
//! The secrets will stay in your codebase that is easy to inspect and guaranteed that will never change without your consent.

use std::str::FromStr;

use secrecy::{ExposeSecret, SecretBox, SecretString};

use crate::encrypt_decrypt_with_ssh_key_mod as ende;
use crate::encrypt_decrypt_with_ssh_key_mod::{BLUE, GREEN, RED, RESET, YELLOW};

pub(crate) fn get_crates_io_secret_token(file_bare_name: &str) -> anyhow::Result<SecretString> {
    // check if the plain-text file from `cargo login` exists and warn the user
    // because it is a security vulnerability.
    println!("{YELLOW}  Check if credentials.toml from 'cargo login' exists.{RESET}");
    let file_credentials = camino::Utf8Path::new("/home/rustdevuser/.cargo/credentials.toml");
    if file_credentials.exists() {
        eprintln!("{RED}Security vulnerability: Found the cargo credentials file with plain-text secret_token: {RESET}");
        eprintln!("{RED}{file_credentials}. It would be better to inspect and remove it. {RESET}");
        anyhow::bail!("Found security vulnerability");
    }

    println!("{YELLOW}  Check if the ssh private key exists.{RESET}");
    let identity_private_file_path = camino::Utf8PathBuf::from(format!("/home/rustdevuser/.ssh/{file_bare_name}").as_str());
    if !std::fs::exists(&identity_private_file_path)? {
        println!("{RED}Error: Private key {identity_private_file_path} does not exist.{RESET}");
        println!("{YELLOW}  Create the private key in bash terminal:{RESET}");
        println!(r#"{GREEN}ssh-keygen -t ed25519 -f "{identity_private_file_path}" -C "crates.io secret_token"{RESET}"#);
        anyhow::bail!("Private key file not found.");
    }

    println!("{YELLOW}  Check if the encrypted file exists.{RESET}");
    let encrypted_file_name = camino::Utf8PathBuf::from(format!("/home/rustdevuser/.ssh/{file_bare_name}.enc").as_str());
    if !std::fs::exists(&encrypted_file_name)? {
        println!("{YELLOW}  Encrypted file {encrypted_file_name} does not exist.{RESET}");
        println!("{YELLOW}  Get your secret token from: https://crates.io/settings/tokens {RESET}");
        println!("{YELLOW}  Never use 'cargo login' to store this secret locally. It will store it in plain-text in the file ~/.cargo.credentials.toml. {RESET}");
        println!("{YELLOW}  Plain-text for secrets in a well-known file is a big no-no. Every malware will just upload it in a millisecond. {RESET}");
        println!("{YELLOW}  This function will encrypt the secret with your ssh private key. {RESET}");
        println!("");
        eprintln!("   {BLUE}Enter the secret_access_token to encrypt:{RESET}");
        let secret_access_token = secrecy::SecretString::from(inquire::Password::new("").without_confirmation().with_display_mode(inquire::PasswordDisplayMode::Masked).prompt()?);

        // prepare the random bytes, sign it with the private key, that is the true passcode used to encrypt the secret
        let plain_seed_bytes_32bytes = ende::random_seed_32bytes();
        let plain_seed_string = ende::encode64_from_32bytes_to_string(plain_seed_bytes_32bytes)?;
        // first try to use the private key from ssh-agent, else use the private file with user interaction
        let secret_passcode_32bytes: SecretBox<[u8; 32]> = ende::sign_seed_with_ssh_agent_or_identity_file(&identity_private_file_path, plain_seed_bytes_32bytes)?;
        let plain_encrypted_text = ende::encrypt_symmetric(secret_passcode_32bytes, secret_access_token)?;

        // prepare a struct to save as encoded string
        let encrypted_text_with_metadata = ende::EncryptedTextWithMetadata {
            identity_file_path: identity_private_file_path.to_string(),
            plain_seed_string,
            plain_encrypted_text: plain_encrypted_text,
            access_token_expiration: None,
            refresh_token_expiration: None,
        };
        let file_text = serde_json::to_string_pretty(&encrypted_text_with_metadata)?;
        // encode it just to obscure it a little bit
        let file_text = ende::encode64_from_string_to_string(&file_text);

        std::fs::write(&encrypted_file_name, file_text)?;
        println!("{YELLOW}  Encrypted text saved to file.{RESET}");
    }

    println!("{YELLOW}  Open and read the encrypted file.{RESET}");
    let encrypted_text_with_metadata: String = ende::open_file_get_string(&encrypted_file_name)?;
    // parse json
    let encrypted_text_with_metadata: ende::EncryptedTextWithMetadata = serde_json::from_str(&encrypted_text_with_metadata)?;
    println!("{YELLOW}  Decrypt the file with ssh-agent or private key.{RESET}");
    let plain_seed_bytes_32bytes = ende::decode64_from_string_to_32bytes(&encrypted_text_with_metadata.plain_seed_string)?;
    let identity_file_path = camino::Utf8PathBuf::from_str(&encrypted_text_with_metadata.identity_file_path)?;
    let secret_passcode_32bytes: SecretBox<[u8; 32]> = ende::sign_seed_with_ssh_agent_or_identity_file(&identity_file_path, plain_seed_bytes_32bytes)?;

    // decrypt the secret access token string
    let secret_access_token: SecretString = ende::decrypt_symmetric(secret_passcode_32bytes, encrypted_text_with_metadata.plain_encrypted_text.clone())?;

    Ok(secret_access_token)
}
