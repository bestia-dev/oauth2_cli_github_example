// oauth2_cli_github_example/src/main.rs

//! region: auto_md_to_doc_comments include README.md A //!

//! endregion: auto_md_to_doc_comments include README.md A //!

mod crates_io_api_token_mod;
mod encrypt_decrypt_with_ssh_key_mod;
// mod github_oauth2_device_workflow_mod;

use secrecy::ExposeSecret;

fn main() -> anyhow::Result<()> {
    let crates_io_access_secret_token = crates_io_api_token_mod::get_crates_io_secret_token("crates_io_secret_token_ssh_1")?;
    println!("{}", crates_io_access_secret_token.expose_secret());

    Ok(())
}
