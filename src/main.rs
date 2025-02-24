// oauth2_cli_github_example/src/main.rs

//! region: auto_md_to_doc_comments include README.md A //!

//! endregion: auto_md_to_doc_comments include README.md A //!

mod crates_io_api_token;
mod encrypt_decrypt_with_ssh_key_mod;
mod github_oauth2_device_workflow_mod;

use secrecy::ExposeSecret;

fn main() -> anyhow::Result<()> {
    // region: github access token
    // read config client id
    // let client_id = std::fs::read_to_string("/home/rustdevuser/rustprojects/oauth2_cli_github_example_config/client_id.txt")?;
    // the private key, public key and the encrypted file will have the same bare name
    // let file_bare_name = std::fs::read_to_string("/home/rustdevuser/rustprojects/oauth2_cli_github_example_config/file_bare_name.txt")?;
    // endregion: read config from files outside the repository

    // let github_access_secret_token = github_oauth2_device_workflow_mod::github_oauth2_device_workflow(&client_id, &file_bare_name)?;
    // println!("{}", github_access_secret_token.expose_secret());
    // endregion: github access token

    let crates_io_access_secret_token = crates_io_api_token::get_crates_io_secret_token("crates_io_secret_token_ssh_1")?;
    println!("{}", crates_io_access_secret_token.expose_secret());

    Ok(())
}
