// oauth2_cli_github_example/examples/github_example.rs

// cargo run --example github_example

#[path = "../src/github_oauth2_device_workflow_mod.rs"]
mod github_oauth2_device_workflow_mod;

#[path = "../src/encrypt_decrypt_with_ssh_key_mod.rs"]
mod encrypt_decrypt_with_ssh_key_mod;

use secrecy::ExposeSecret;

fn main() -> anyhow::Result<()> {
    // read config client id
    let client_id = std::fs::read_to_string("/home/rustdevuser/rustprojects/oauth2_cli_github_example_config/client_id.txt")?;
    // the private key, public key and the encrypted file will have the same bare name
    let file_bare_name = std::fs::read_to_string("/home/rustdevuser/rustprojects/oauth2_cli_github_example_config/file_bare_name.txt")?;

    let github_access_secret_token = github_oauth2_device_workflow_mod::github_oauth2_device_workflow(&client_id, &file_bare_name)?;
    println!("{}", github_access_secret_token.expose_secret());

    Ok(())
}
