// github_oauth2_device_workflow_mod.rs

// region: auto_md_to_doc_comments include doc_comments/github_oauth2_device_workflow_mod.md A //!
//! # github_oauth2_device_workflow_mod
//!
//! ## Secrets
//!
//! In this module there will be a lot of work with secrets.  
//! It is difficult to trust an external crate with your secrets.  
//! External crates can get updated unexpectedly and change to malicious code.  
//!
//! ## Copy code instead of dependency crate
//!
//! It is best to have the Rust code under your fingertips when dealing with secrets.  
//! Than you know, nobody will touch this code except of you.  
//! You can copy this code directly into your codebase as a module,
//! inspect and review it and know exactly what is going on.  
//! The code is as linear and readable with comments as possible.
//! The dependencies in Cargo.toml must also be copied.  
//!
//! ## Store encrypted secret to file
//!
//! The secrets will be encrypted with an ssh private key and stored in the ~/.ssh folder.  
//! This way the data is protected at rest in storage drive.  
//!
//! ## In memory protection
//!
//! This is a tough one! There is no 100% software protection of secrets in memory.  
//! Theoretically an attacker could dump the memory in any moment and read the secrets.  
//! There is always a moment when the secret is used in its plaintext form. This cannot be avoided.
//! All we can do now is to be alert what data is secret and take better care of it.  
//! Every variable that have secrets will have the word `secret` in it.
//! When a variable is confusing I will use the word `plain` to express it is `not a secret`.
//! To avoid leaking in logs I will use the `secrecy` crate. This is not 100% protection.  
//! This is important just to express intent when the secrets are really used.  
//! `Secrecy` needs the trait `zeroize` to empty the memory after use for better memory hygiene.
//! I will add the type names explicitly to emphasis the secrecy types used.
//! To understand the code try to ignore all this secrecy game back and forth.
//!
// endregion: auto_md_to_doc_comments include doc_comments/github_oauth2_device_workflow_mod.md A //!

use anyhow::Context;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};

use crate::encrypt_decrypt_with_ssh_key_mod::{BLUE, GREEN, RED, RESET, YELLOW};

#[derive(serde::Deserialize, serde::Serialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct ResponseSecretAccessToken {
    access_token: String,
    expires_in: i64,
    refresh_token: String,
    refresh_token_expires_in: i64,
    scope: String,
    token_type: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct EncFileJson {
    identity: String,
    seed: String,
    encrypted: String,
    access_token_expiration: String,
    refresh_token_expiration: String,
}

/// Start the github oauth2 device workflow
/// It will use the private key from the .ssh folder.
/// The encrypted file has the same bare name with the "enc" extension.
/// Returns access_token to use as bearer for api calls
pub(crate) fn github_oauth2_device_workflow(client_id: &str, file_bare_name: &str) -> anyhow::Result<SecretString> {
    println!("{YELLOW}  Start the github oauth2 device workflow for CLI apps{RESET}");

    println!("{YELLOW}  Check if the ssh private key exists.{RESET}");
    let private_file_name = camino::Utf8PathBuf::from(format!("/home/rustdevuser/.ssh/{file_bare_name}").as_str());
    if !std::fs::exists(&private_file_name)? {
        println!("{RED}Error: Private key {private_file_name} does not exist.{RESET}");
        println!("{YELLOW}  Create the private key in bash terminal:{RESET}");
        println!(r#"{GREEN}ssh-keygen -t ed25519 -f "{private_file_name}" -C "github api secret_token"{RESET}"#);
        anyhow::bail!("Private key file not found.");
    }

    println!("{YELLOW}  Check if the encrypted file exists.{RESET}");
    let encrypted_file_name = camino::Utf8PathBuf::from(format!("/home/rustdevuser/.ssh/{file_bare_name}.enc").as_str());
    if !std::fs::exists(&encrypted_file_name)? {
        println!("{YELLOW}  Encrypted file {encrypted_file_name} does not exist.{RESET}");
        println!("{YELLOW}  Continue to authentication with the browser{RESET}");
        let secret_access_token = authenticate_with_browser_and_save_file(client_id, &private_file_name, &encrypted_file_name)?;
        return Ok(secret_access_token);
    } else {
        println!("{YELLOW}  Encrypted file {encrypted_file_name} exist.{RESET}");
        let enc_file_json = open_file_get_json(&encrypted_file_name)?;
        // check the expiration
        let utc_now = chrono::Utc::now();
        let refresh_token_expiration = chrono::DateTime::parse_from_rfc3339(&enc_file_json.refresh_token_expiration)?;
        if refresh_token_expiration <= utc_now {
            println!("{RED}Refresh token has expired, start authentication_with_browser{RESET}");
            let secret_access_token = authenticate_with_browser_and_save_file(client_id, &private_file_name, &encrypted_file_name)?;
            return Ok(secret_access_token);
        }
        let access_token_expiration = chrono::DateTime::parse_from_rfc3339(&enc_file_json.access_token_expiration)?;
        if access_token_expiration != utc_now {
            println!("{RED}Access token has expired, use refresh token{RESET}");
            let response_secret_refresh_token = decrypt_file_json(enc_file_json)?;
            let response_secret_access_token: SecretBox<ResponseSecretAccessToken> = refresh_tokens(client_id, response_secret_refresh_token.expose_secret().refresh_token.clone())?;
            let secret_access_token = SecretString::from(response_secret_access_token.expose_secret().access_token.clone());
            println!("{YELLOW}  Encrypt data and save file{RESET}");
            encrypt_and_save_file(&private_file_name, &encrypted_file_name, response_secret_access_token)?;
            return Ok(secret_access_token);
        }
        println!("{YELLOW}  Decrypt the file with the private key.{RESET}");
        let response_secret_access_token = decrypt_file_json(enc_file_json)?;
        let secret_access_token = SecretString::from(response_secret_access_token.expose_secret().access_token.clone());
        Ok(secret_access_token)
    }
}

/// use refresh token to get new access_token and refresh_token
fn refresh_tokens(client_id: &str, refresh_token: String) -> anyhow::Result<SecretBox<ResponseSecretAccessToken>> {
    // https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens

    #[derive(serde::Serialize)]
    struct RequestWithRefreshToken {
        client_id: String,
        grant_type: String,
        refresh_token: String,
    }

    println!("{YELLOW}  Send request with client_id and refresh_token and retrieve access tokens{RESET}");
    println!("{YELLOW}  wait...{RESET}");
    let response_secret_access_token: SecretBox<ResponseSecretAccessToken> = SecretBox::new(Box::new(
        reqwest::blocking::Client::new()
            .post("https://github.com/login/oauth/access_token")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&RequestWithRefreshToken {
                client_id: client_id.to_owned(),
                grant_type: "refresh_token".to_string(),
                refresh_token: refresh_token,
            })
            .send()?
            .json()?,
    ));

    Ok(response_secret_access_token)
}

fn authenticate_with_browser_and_save_file(client_id: &str, private_file_name: &camino::Utf8Path, encrypted_file_name: &camino::Utf8Path) -> anyhow::Result<SecretString> {
    let response_secret_access_token: SecretBox<ResponseSecretAccessToken> = authentication_with_browser(client_id)?;
    let secret_access_token = SecretString::from(response_secret_access_token.expose_secret().access_token.clone());
    println!("{YELLOW}  Encrypt data and save file{RESET}");
    encrypt_and_save_file(private_file_name, encrypted_file_name, response_secret_access_token)?;
    Ok(secret_access_token)
}

/// Oauth2 device workflow needs to be authenticated with a browser
fn authentication_with_browser(client_id: &str) -> anyhow::Result<SecretBox<ResponseSecretAccessToken>> {
    // https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow
    // https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app#using-the-device-flow-to-generate-a-user-access-token
    println!("{YELLOW}  Send request with client_id and retrieve device_code and user_code{RESET}");
    println!("{YELLOW}  wait...{RESET}");

    #[derive(serde::Serialize)]
    struct RequestDeviceCode {
        client_id: String,
    }

    #[derive(serde::Deserialize)]
    struct ResponseDeviceCode {
        device_code: String,
        user_code: String,
    }

    let response_device_code: ResponseDeviceCode = reqwest::blocking::Client::new()
        .post("https://github.com/login/device/code")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&RequestDeviceCode { client_id: client_id.to_owned() })
        .send()?
        .json()?;

    println!("{YELLOW}  Copy this user_code:{RESET}");
    println!("{GREEN}{}{RESET}", response_device_code.user_code);
    println!("{YELLOW}  Open browser on and paste the user_code:{RESET}");
    println!("{GREEN}https://github.com/login/device?skip_account_picker=true{RESET}");
    println!("{YELLOW}  After the tokens are prepared on the server, press enter to continue...{RESET}");

    let _user_input_just_enter_to_continue: String = inquire::Text::new("").prompt()?;

    #[derive(serde::Serialize)]
    struct RequestAccessToken {
        client_id: String,
        device_code: String,
        grant_type: String,
    }

    println!("{YELLOW}  Send request with device_id and retrieve access tokens{RESET}");
    println!("{YELLOW}  wait...{RESET}");
    let response_secret_access_token: SecretBox<ResponseSecretAccessToken> = SecretBox::new(
        reqwest::blocking::Client::new()
            .post(" https://github.com/login/oauth/access_token")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&RequestAccessToken {
                client_id: client_id.to_string(),
                device_code: response_device_code.device_code.to_string(),
                grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            })
            .send()?
            .json()?,
    );

    Ok(response_secret_access_token)
}

/// encrypt and save file
///
/// The "seed" are just some random 32 bytes.
/// The "seed" will be "signed" with the private key.
/// Only the "owner" can unlock the private key and sign correctly.
/// This signature will be used as the true passcode for symmetrical encryption.
/// The "seed" and the private key path will be stored in plain text in the file
/// together with the encrypted data in json format.
/// To avoid plain text in the end encode in base64 just for obfuscate a little bit.
fn encrypt_and_save_file(
    identity_private_file_path: &camino::Utf8Path,
    encrypted_file_name: &camino::Utf8Path,
    response_secret_access_token: SecretBox<ResponseSecretAccessToken>,
) -> anyhow::Result<()> {
    /// Internal unction Generate a random seed
    fn random_seed_bytes() -> [u8; 32] {
        let mut password = [0_u8; 32];
        use aes_gcm::aead::rand_core::RngCore;
        aes_gcm::aead::OsRng.fill_bytes(&mut password);
        password
    }
    /// Internal function
    /// Encrypts secret_string with secret_passcode_bytes
    ///
    /// secret_passcode_bytes must be 32 bytes
    /// returns the encrypted_string
    fn encrypt_symmetric(secret_passcode_bytes: SecretBox<[u8; 32]>, secret_string: SecretString) -> anyhow::Result<String> {
        // nonce is salt
        let nonce = <aes_gcm::Aes256Gcm as aes_gcm::AeadCore>::generate_nonce(&mut aes_gcm::aead::OsRng);
        let Ok(cipher_text_encrypted) = aes_gcm::aead::Aead::encrypt(
            // cipher_secret is the true passcode, here I don't know how to use secrecy, because the type has not the trait Zeroize
            &<aes_gcm::Aes256Gcm as aes_gcm::KeyInit>::new(secret_passcode_bytes.expose_secret().into()),
            &nonce,
            secret_string.expose_secret().as_bytes(),
        ) else {
            panic!("{RED}Error: Encryption failed. {RESET}");
        };

        let mut encrypted_bytes = nonce.to_vec();
        encrypted_bytes.extend_from_slice(&cipher_text_encrypted);
        let encrypted_string = <base64ct::Base64 as base64ct::Encoding>::encode_string(&encrypted_bytes);
        Ok(encrypted_string)
    }
    let secret_string = SecretString::from(serde_json::to_string(&response_secret_access_token.expose_secret())?);

    let seed_bytes_plain_32bytes = random_seed_bytes();
    println!("{YELLOW}  Unlock private key to encrypt the secret symmetrically{RESET}");
    let secret_passcode_32bytes: SecretBox<[u8; 32]> = user_input_passphrase_and_sign_seed_x(seed_bytes_plain_32bytes, &identity_private_file_path)?;

    println!("{YELLOW}  Encrypt the secret symmetrically {RESET}");
    let encrypted_string = encrypt_symmetric(secret_passcode_32bytes, secret_string)?;

    // the file will contain json with 3 plain text fields: fingerprint, seed, encrypted, expiration
    let seed_string_plain = <base64ct::Base64 as base64ct::Encoding>::encode_string(&seed_bytes_plain_32bytes);
    // calculate expiration minus 10 minutes or 600 seconds
    let utc_now = chrono::Utc::now();
    let access_token_expiration = utc_now
        .checked_add_signed(chrono::Duration::seconds(response_secret_access_token.expose_secret().expires_in - 600))
        .context("checked_add_signed")?
        .to_rfc3339();
    let refresh_token_expiration = utc_now
        .checked_add_signed(chrono::Duration::seconds(response_secret_access_token.expose_secret().refresh_token_expires_in - 600))
        .context("checked_add_signed")?
        .to_rfc3339();

    let enc_file_json = EncFileJson {
        identity: identity_private_file_path.to_string(),
        seed: seed_string_plain,
        encrypted: encrypted_string,
        access_token_expiration: access_token_expiration,
        refresh_token_expiration: refresh_token_expiration,
    };
    let file_text = serde_json::to_string_pretty(&enc_file_json)?;
    // encode it just to obscure it a little bit
    let file_text = <base64ct::Base64 as base64ct::Encoding>::encode_string(file_text.as_bytes());

    std::fs::write(encrypted_file_name, file_text)?;
    println!("{YELLOW}  Encrypted text saved to file.{RESET}");

    Ok(())
}

/// get the file json with expiration dates
fn open_file_get_json(encrypted_file_name: &camino::Utf8Path) -> anyhow::Result<EncFileJson> {
    if !camino::Utf8Path::new(&encrypted_file_name).exists() {
        anyhow::bail!("{RED}Error: File {encrypted_file_name} does not exist! {RESET}");
    }

    let file_text = std::fs::read_to_string(encrypted_file_name)?;
    // it is encoded just to obscure it a little
    let file_text = <base64ct::Base64 as base64ct::Encoding>::decode_vec(&file_text)?;
    let file_text = String::from_utf8(file_text)?;
    // deserialize json into struct
    let enc_file_json: EncFileJson = serde_json::from_str(&file_text)?;
    Ok(enc_file_json)
}

/// decrypt file
///
/// The encrypted file is encoded in base64 just to obfuscate it a little bit.  
/// In json format in plain text there is the "seed", the private key path and the encrypted secret.  
/// The "seed" will be "signed" with the private key.  
/// Only the "owner" can unlock the private key and sign correctly.  
/// This signature will be used as the true passcode for symmetrical decryption.  
fn decrypt_file_json(enc_file_json: EncFileJson) -> anyhow::Result<SecretBox<ResponseSecretAccessToken>> {
    /// Internal function
    /// Decrypts encrypted_string with secret_passcode_bytes
    ///
    /// secret_passcode_bytes must be 32 bytes or more
    /// Returns the secret_string
    fn decrypt_symmetric(secret_passcode_32bytes: SecretBox<[u8; 32]>, encrypted_string: String) -> anyhow::Result<SecretBox<ResponseSecretAccessToken>> {
        let encrypted_bytes = <base64ct::Base64 as base64ct::Encoding>::decode_vec(&encrypted_string)?;
        // nonce is salt
        let nonce = rsa::sha2::digest::generic_array::GenericArray::from_slice(&encrypted_bytes[..12]);
        let cipher_text = &encrypted_bytes[12..];

        let Ok(decrypted_bytes) = aes_gcm::aead::Aead::decrypt(
            // cipher_secret is the true passcode, here I don't know how to use secrecy, because the type has not the trait Zeroize
            &<aes_gcm::Aes256Gcm as aes_gcm::KeyInit>::new(secret_passcode_32bytes.expose_secret().into()),
            nonce,
            cipher_text,
        ) else {
            panic!("{RED}Error: Decryption failed. {RESET}");
        };
        let decrypted_string = String::from_utf8(decrypted_bytes).unwrap();
        let response_secret_access_token: SecretBox<ResponseSecretAccessToken> = SecretBox::new(Box::new(serde_json::from_str(&decrypted_string)?));

        Ok(response_secret_access_token)
    }

    // the private key file is written inside the file
    let identity_private_file_path = camino::Utf8Path::new(&enc_file_json.identity);
    if !camino::Utf8Path::new(&identity_private_file_path).exists() {
        anyhow::bail!("{RED}Error: File {identity_private_file_path} does not exist! {RESET}");
    }

    let seed_bytes_plain = <base64ct::Base64 as base64ct::Encoding>::decode_vec(&enc_file_json.seed)?;
    let seed_bytes_plain_32bytes: [u8; 32] = seed_bytes_plain[..32].try_into()?;

    // first try to use the private key from ssh-agent, else use the private file with user interaction
    let maybe_secret_passcode_32bytes = use_ssh_agent_to_sign_seed(seed_bytes_plain_32bytes, identity_private_file_path);
    let secret_passcode_32bytes: SecretBox<[u8; 32]> = if maybe_secret_passcode_32bytes.is_ok() {
        maybe_secret_passcode_32bytes.unwrap()
    } else {
        // ask user to think about adding key into ssh-agent with ssh-add
        println!("   {YELLOW}SSH key for encrypted secret_token is not found in the ssh-agent.{RESET}");
        println!("   {YELLOW}Without ssh-agent, you will have to type the private key passphrase every time.{RESET}");
        println!("   {YELLOW}This is more secure, but inconvenient.{RESET}");
        println!("   {YELLOW}WARNING: using ssh-agent is less secure, because there is no need for user interaction.{RESET}");
        println!("   {YELLOW}Knowing this, you can manually add the SSH identity to ssh-agent for 1 hour:{RESET}");
        println!("{GREEN}ssh-add -t 1h {identity_private_file_path}{RESET}");
        println!("   {YELLOW}Unlock the private key to decrypt the saved file.{RESET}");

        user_input_passphrase_and_sign_seed_x(seed_bytes_plain_32bytes, identity_private_file_path)?
    };

    // decrypt the data
    let response_secret_access_token = decrypt_symmetric(secret_passcode_32bytes, enc_file_json.encrypted)?;

    Ok(response_secret_access_token)
}

/// User must input the passphrase to unlock the private key file.
/// Sign the seed with the private key into 32 bytes.
/// This will be the true passcode for symmetrical encryption and decryption.
fn user_input_passphrase_and_sign_seed_x(seed_bytes_plain_32bytes: [u8; 32], identity_private_file_path: &camino::Utf8Path) -> anyhow::Result<SecretBox<[u8; 32]>> {
    /// Internal function for user input passphrase
    fn user_input_secret_passphrase() -> anyhow::Result<SecretString> {
        eprintln!(" ");
        eprintln!("   {BLUE}Enter the passphrase for the SSH private key:{RESET}");

        let secret_passphrase = SecretString::from(inquire::Password::new("").without_confirmation().with_display_mode(inquire::PasswordDisplayMode::Masked).prompt()?);

        Ok(secret_passphrase)
    }
    // the user is the only one that knows the passphrase to unlock the private key
    let secret_user_passphrase: SecretString = user_input_secret_passphrase()?;

    // sign_with_ssh_identity_file
    println!("{YELLOW}  Use ssh private key from file {RESET}");
    let private_key = ssh_key::PrivateKey::read_openssh_file(identity_private_file_path.as_std_path())?;
    println!("{YELLOW}  Unlock the private key {RESET}");

    // cannot use secrecy: PrivateKey does not have trait Zeroize
    let mut private_key_secret = private_key.decrypt(secret_user_passphrase.expose_secret())?;

    // FYI: this type of signature is compatible with ssh-agent because it does not involve namespace
    println!("{YELLOW}  Sign the seed {RESET}");

    let mut secret_passcode_32bytes = SecretBox::new(Box::new([0u8; 32]));
    // only the data part of the signature goes into as_bytes.
    // only the first 32 bytes
    secret_passcode_32bytes
        .expose_secret_mut()
        .copy_from_slice(&rsa::signature::SignerMut::try_sign(&mut private_key_secret, &seed_bytes_plain_32bytes)?.as_bytes().to_owned()[0..32]);

    Ok(secret_passcode_32bytes)
}

/// Sign seed with ssh-agent
///
/// returns secret_password_bytes
fn use_ssh_agent_to_sign_seed(seed_bytes_plain_32bytes: [u8; 32], identity_private_file_path: &camino::Utf8Path) -> anyhow::Result<SecretBox<[u8; 32]>> {
    /// Internal function returns the public_key inside ssh-add
    fn public_key_from_ssh_agent(client: &mut ssh_agent_client_rs::Client, fingerprint_from_file: &str) -> anyhow::Result<ssh_key::PublicKey> {
        let vec_public_key = client.list_identities()?;

        for public_key in vec_public_key.iter() {
            let fingerprint_from_agent = public_key.key_data().fingerprint(Default::default()).to_string();

            if fingerprint_from_agent == fingerprint_from_file {
                return Ok(public_key.to_owned());
            }
        }
        anyhow::bail!("This identity is not added to ssh-agent.")
    }
    let identity_public_file_path = format!("{identity_private_file_path}.pub");
    let identity_public_file_path = camino::Utf8Path::new(&identity_public_file_path);
    let public_key = ssh_key::PublicKey::read_openssh_file(&identity_public_file_path.as_std_path())?;
    let fingerprint_from_file = public_key.fingerprint(Default::default()).to_string();

    println!("{YELLOW}  Connect to ssh-agent on SSH_AUTH_SOCK{RESET}");
    let var_ssh_auth_sock = std::env::var("SSH_AUTH_SOCK")?;
    let path_ssh_auth_sock = camino::Utf8Path::new(&var_ssh_auth_sock);
    let mut ssh_agent_client = ssh_agent_client_rs::Client::connect(&path_ssh_auth_sock.as_std_path())?;

    let public_key = public_key_from_ssh_agent(&mut ssh_agent_client, &fingerprint_from_file)?;

    let mut secret_passcode_32bytes = SecretBox::new(Box::new([0u8; 32]));
    // sign with public key from ssh-agent
    // only the data part of the signature goes into as_bytes.
    secret_passcode_32bytes
        .expose_secret_mut()
        .copy_from_slice(&ssh_agent_client.sign(&public_key, &seed_bytes_plain_32bytes)?.as_bytes().to_owned()[0..32]);

    Ok(secret_passcode_32bytes)
}
