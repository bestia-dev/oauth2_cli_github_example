// github_oauth2_device_workflow.rs

/// In this module there will be a lot of work with secrets.
/// It is difficult to trust an external crate with your secrets.
/// The crates can get updated unexpectedly and change to malicious code.
/// It is best to have the Rust code under your fingertips when dealing with secrets.
/// Than you know nobody will touch this code except of you.
/// You can copy this code directly into your codebase as a module,
/// inspect and review it and know exactly what is going on.
/// The dependencies in Cargo.toml must also be copied.

// TODO: use zeroize and secrecy to avoid leaking secrets
// TODO: use ssh-agent to store passphrase in memory for 1 hour
// to avoid typing it every time

// region: Public API constants
// ANSI colors for Linux terminal
// https://github.com/shiena/ansicolor/blob/master/README.md
/// ANSI color
pub const RED: &str = "\x1b[31m";
/// ANSI color
#[allow(dead_code)]
pub const GREEN: &str = "\x1b[32m";
/// ANSI color
pub const YELLOW: &str = "\x1b[33m";
/// ANSI color
#[allow(dead_code)]
pub const BLUE: &str = "\x1b[34m";
/// ANSI color
pub const RESET: &str = "\x1b[0m";
// endregion: Public API constants

#[derive(serde::Deserialize, serde::Serialize)]
struct ResponseAccessToken {
    access_token: String,
    expires_in: i32,
    refresh_token: String,
    refresh_token_expires_in: i32,
    scope: String,
    token_type: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct FileEncryptedJson {
    identity: String,
    seed: String,
    encrypted: String,
}

/// Start the github oauth2 device workflow
/// It will use the private key from the .ssh folder.
/// The encrypted file has the same bare name with the "enc" extension.
pub(crate) fn github_oauth2_device_workflow(client_id: &str, file_bare_name: &str) -> anyhow::Result<()> {
    println!("{YELLOW}  Start the github oauth2 device workflow for CLI apps{RESET}");

    println!("{YELLOW}  Check if the ssh private key exists.{RESET}");
    let private_file_name = camino::Utf8PathBuf::from(&format!("/home/rustdevuser/.ssh/{file_bare_name}"));
    if !std::fs::exists(&private_file_name)? {
        println!("{RED}Error: Private key {private_file_name} does not exist.{RESET}");
        println!("{YELLOW}  Create the private key in bash terminal:{RESET}");
        println!(r#"{GREEN}ssh-keygen -t ed25519 -f "{private_file_name}" -C "github api secret_token"{RESET}"#);
        anyhow::bail!("Private key file not found.");
    }

    println!("{YELLOW}  Check if the encrypted file exists.{RESET}");
    let encrypted_file_name = camino::Utf8PathBuf::from(format!("/home/rustdevuser/.ssh/{file_bare_name}.enc"));
    if !std::fs::exists(&encrypted_file_name)? {
        println!("{YELLOW}  Encrypted file {encrypted_file_name} does not exist.{RESET}");
        println!("{YELLOW}  Continue to authentication with the browser{RESET}");
        let response_access_token = authentication_with_browser(client_id)?;
        // println!("{}", serde_json::to_string_pretty(&response_access_token)?);
        // Mock the response for easy development
        // let response_access_token = std::fs::read_to_string("/home/rustdevuser/rustprojects/oauth2_cli_github_example_config/mock_response.txt")?;
        // let response_access_token = serde_json::from_str(&response_access_token)?;
        encrypt_and_save_file(private_file_name, encrypted_file_name, response_access_token)?;
    } else {
        println!("{YELLOW}  Encrypted file {encrypted_file_name} exist.{RESET}");
        println!("{YELLOW}  Decrypt the file with the private key.{RESET}");
        let response_access_token = open_and_decrypt_file(encrypted_file_name)?;

        println!("{}", serde_json::to_string_pretty(&response_access_token)?);
    }

    Ok(())
}

/// Oauth2 device workflow needs to be authenticated with a browser
fn authentication_with_browser(client_id: &str) -> anyhow::Result<ResponseAccessToken> {
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

    let _x: String = inquire::Text::new("").prompt()?;

    #[derive(serde::Serialize)]
    struct RequestAccessToken {
        client_id: String,
        device_code: String,
        grant_type: String,
    }

    println!("{YELLOW}  Send request with device_id and retrieve access tokens{RESET}");
    println!("{YELLOW}  wait...{RESET}");
    let response_access_token: ResponseAccessToken = reqwest::blocking::Client::new()
        .post(" https://github.com/login/oauth/access_token")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&RequestAccessToken {
            client_id: client_id.to_string(),
            device_code: response_device_code.device_code.to_string(),
            grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        })
        .send()?
        .json()?;

    Ok(response_access_token)
}

/// The "seed" are just some random 32 bytes.
/// The "seed" will be "signed" with the private key. 
/// Only the "owner" can unlock the private key. 
/// This signature will be used as the true passcode for symmetrical encryption.
/// The "seed" and the private key path will be stored in plain text in the file 
/// together with the encrypted data in json format.
/// To avoid plain text in the end encode in base64 just for obfuscate a little bit.
fn encrypt_and_save_file(identity_private_file_path: camino::Utf8PathBuf, encrypted_file_name: camino::Utf8PathBuf, response_access_token: ResponseAccessToken) -> anyhow::Result<()> {
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
    /// secret_passcode_bytes must be 32 bytes or more
    /// returns the encrypted_string
    fn encrypt_symmetric(secret_passcode_bytes: [u8; 32], secret_string: String) -> anyhow::Result<String> {
        let cipher = <aes_gcm::Aes256Gcm as aes_gcm::KeyInit>::new(&secret_passcode_bytes.into());
        // nonce is salt
        let nonce = <aes_gcm::Aes256Gcm as aes_gcm::AeadCore>::generate_nonce(&mut aes_gcm::aead::OsRng);

        let Ok(cipher_text) = aes_gcm::aead::Aead::encrypt(&cipher, &nonce, secret_string.as_bytes()) else {
            panic!("{RED}Error: Encryption failed. {RESET}");
        };

        let mut encrypted_bytes = nonce.to_vec();
        encrypted_bytes.extend_from_slice(&cipher_text);
        let encrypted_string = <base64ct::Base64 as base64ct::Encoding>::encode_string(&encrypted_bytes);
        Ok(encrypted_string)
    }

    let secret_string = serde_json::to_string(&response_access_token)?;

    let seed_bytes_not_a_secret_32bytes = random_seed_bytes();
    let secret_passcode_32bytes = user_input_passphrase_and_sign_seed(seed_bytes_not_a_secret_32bytes, &identity_private_file_path)?;

    println!("{YELLOW}  Encrypt the secret symmetrically {RESET}");
    let encrypted_string = encrypt_symmetric(secret_passcode_32bytes, secret_string)?;

    // the file will contain json with 3 non-secret fields: fingerprint, seed, encrypted
    let seed_string_not_a_secret = <base64ct::Base64 as base64ct::Encoding>::encode_string(&seed_bytes_not_a_secret_32bytes);
    let file_encrypted_json = FileEncryptedJson {
        identity: identity_private_file_path.to_string(),
        seed: seed_string_not_a_secret,
        encrypted: encrypted_string,
    };
    let file_text = serde_json::to_string_pretty(&file_encrypted_json)?;
    // encode it just to obscure it a little bit
    let file_text = <base64ct::Base64 as base64ct::Encoding>::encode_string(file_text.as_bytes());

    std::fs::write(encrypted_file_name, file_text)?;
    println!("{YELLOW}  Encrypted text saved in file.{RESET}");

    Ok(())
}

/// The encrypted file is encoded in base64 just to obfuscate it a little bit.
/// In json format in plain text there is the "seed", the private key path and the encrypted secret.
/// The "seed" will be "signed" with the private key. 
/// Only the "owner" can unlock the private key. 
/// This signature will be used as the true passcode for symmetrical decryption.
fn open_and_decrypt_file(encrypted_file_name: camino::Utf8PathBuf) -> anyhow::Result<ResponseAccessToken> {
    /// Internal function
    /// Decrypts encrypted_string with secret_passcode_bytes
    ///
    /// secret_passcode_bytes must be 32 bytes or more
    /// Returns the secret_string
    fn decrypt_symmetric(secret_passcode_32bytes: [u8; 32], encrypted_string: String) -> anyhow::Result<ResponseAccessToken> {
        let encrypted_bytes = <base64ct::Base64 as base64ct::Encoding>::decode_vec(&encrypted_string)?;

        let cipher = <aes_gcm::Aes256Gcm as aes_gcm::KeyInit>::new(&secret_passcode_32bytes.into());
        // nonce is salt
        let nonce = rsa::sha2::digest::generic_array::GenericArray::from_slice(&encrypted_bytes[..12]);
        let cipher_text = &encrypted_bytes[12..];

        let Ok(decrypted_bytes) = aes_gcm::aead::Aead::decrypt(&cipher, nonce, cipher_text) else {
            panic!("{RED}Error: Decryption failed. {RESET}");
        };
        let decrypted_string = String::from_utf8(decrypted_bytes).unwrap();
        let response_access_token: ResponseAccessToken = serde_json::from_str(&decrypted_string)?;

        Ok(response_access_token)
    }

    if !camino::Utf8Path::new(&encrypted_file_name).exists() {
        anyhow::bail!("{RED}Error: File {encrypted_file_name} does not exist! {RESET}");
    }

    let file_text = std::fs::read_to_string(encrypted_file_name)?;
    // it is encoded just to obscure it a little
    let file_text = <base64ct::Base64 as base64ct::Encoding>::decode_vec(&file_text)?;
    let file_text = String::from_utf8(file_text)?;
    // deserialize json into struct
    let file_encrypted_json: FileEncryptedJson = serde_json::from_str(&file_text)?;
    // the private key file is written inside the file
    let identity_private_file_path = camino::Utf8Path::new(&file_encrypted_json.identity);
    if !camino::Utf8Path::new(&identity_private_file_path).exists() {
        anyhow::bail!("{RED}Error: File {identity_private_file_path} does not exist! {RESET}");
    }

    let seed_bytes_not_a_secret = <base64ct::Base64 as base64ct::Encoding>::decode_vec(&file_encrypted_json.seed)?;
    let seed_bytes_not_a_secret_32bytes: [u8; 32] = seed_bytes_not_a_secret[..32].try_into()?;
    let secret_passcode_32bytes = user_input_passphrase_and_sign_seed(seed_bytes_not_a_secret_32bytes, identity_private_file_path)?;

    // decrypt the data
    let response_access_token = decrypt_symmetric(secret_passcode_32bytes, file_encrypted_json.encrypted)?;

    Ok(response_access_token)
}

/// User must input the passphrase to unlock the private key file.
/// Sign the seed with the private key into 32 bytes.
/// This will be the true passcode for symmetrical encryption and decryption.
fn user_input_passphrase_and_sign_seed(seed_bytes_not_a_secret_32bytes: [u8; 32], identity_private_file_path: &camino::Utf8Path) -> anyhow::Result<[u8; 32]> {
    /// Internal function for user input passphrase
    fn user_input_secret_passphrase() -> anyhow::Result<String> {
        eprintln!(" ");
        eprintln!("   {BLUE}Enter the passphrase for the SSH private key:{RESET}");

        let secret_passphrase = inquire::Password::new("").without_confirmation().with_display_mode(inquire::PasswordDisplayMode::Masked).prompt()?;

        Ok(secret_passphrase)
    }
    // the user is the only one that knows the passphrase to unlock the private key
    let secret_user_passphrase = user_input_secret_passphrase()?;

    // sign_with_ssh_identity_file
    println!("{YELLOW}  Use ssh private key from file {RESET}");
    let private_key = ssh_key::PrivateKey::read_openssh_file(identity_private_file_path.as_std_path())?;
    println!("{YELLOW}  Unlock the private key {RESET}");
    let mut private_key = private_key.decrypt(secret_user_passphrase)?;

    // FYI: this type of signature is compatible with ssh-agent because it does not involve namespace
    println!("{YELLOW}  Sign the seed {RESET}");
    let signature_is_the_new_secret_password = rsa::signature::SignerMut::try_sign(&mut private_key, &seed_bytes_not_a_secret_32bytes)?;
    // only the data part of the signature goes into as_bytes.
    let signed_passcode_is_a_secret = signature_is_the_new_secret_password.as_bytes().to_owned();

    // only the first 32 bytes
    let mut secret_passcode_32bytes = [0u8; 32];
    secret_passcode_32bytes.copy_from_slice(&signed_passcode_is_a_secret[0..32]);

    Ok(secret_passcode_32bytes)
}
