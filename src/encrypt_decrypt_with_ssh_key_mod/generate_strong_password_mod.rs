// generate_strong_password_mod.rs

#![allow(dead_code)]

//use anyhow::Context;
use rsa::sha2::Digest;
use secrecy::{ExposeSecret, SecretBox};

use crate::encrypt_decrypt_with_ssh_key_mod as ende;
use crate::encrypt_decrypt_with_ssh_key_mod::{BLUE, GREEN, RED, RESET, YELLOW};

pub(crate) fn generate_strong_password(file_bare_name: &str) -> anyhow::Result<String> {
    println!("{YELLOW}  Check if the ssh private key exists.{RESET}");
    let private_key_file_path = camino::Utf8PathBuf::from(format!("/home/rustdevuser/.ssh/{file_bare_name}").as_str());
    if !std::fs::exists(&private_key_file_path)? {
        println!("{RED}Error: Private key {private_key_file_path} does not exist.{RESET}");
        println!("{YELLOW}  Create the private key in bash terminal:{RESET}");
        println!(r#"{GREEN}ssh-keygen -t ed25519 -f "{private_key_file_path}" -C "strong password"{RESET}"#);
        anyhow::bail!("Private key file not found.");
    }
    println!("{YELLOW}  This function will convert your human password into a digital form hopefully harder to guess. {RESET}");
    println!("");
    eprintln!("   {BLUE}Enter the human easy password to convert:{RESET}");
    let secret_human_password = secrecy::SecretString::from(inquire::Password::new("").without_confirmation().with_display_mode(inquire::PasswordDisplayMode::Masked).prompt()?);
    let secret_first_human_hash_32bytes: [u8; 32] = rsa::sha2::Sha256::digest(secret_human_password.expose_secret().as_bytes()).into();
    // first try to use the private key from ssh-agent, else use the private file with user interaction
    let secret_passcode_32bytes: SecretBox<[u8; 32]> = ende::sign_seed_with_ssh_agent_or_private_key_file(&private_key_file_path, secret_first_human_hash_32bytes)?;
    // hash one more time because signature with private key can be decrypted with the public key
    let secret_final_human_hash_32bytes: [u8; 32] = rsa::sha2::Sha256::digest(secret_passcode_32bytes.expose_secret()).into();
    // encode into string that has ascii uppercase, lowercase, numbers and special characters: !, @, $, %, ^, &, *, +, #
    // This lookup table is missing some letters and numbers to make it non-standard
    const LOOKUP_TABLE: [char; 64] = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
        'q', 'r', 's', 't', 'u', 'w', 'y', 'z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '@', '$', '%', '^', '&', '*', '+', '#',
    ];

    let mut vec_char: Vec<char> = Vec::new();
    for one_byte in secret_final_human_hash_32bytes.iter() {
        let index: usize = (one_byte % 64).into();
        vec_char.push(LOOKUP_TABLE[index]);
    }
    let strong_password = vec_char.into_iter().collect();

    // Strong passwords must use the clipboard. The risk is that it can stay in the clipboard and can be read from the clipboard.
    // But the same problem is when using a password manager.
    Ok(strong_password)
}
