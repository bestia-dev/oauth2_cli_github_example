// oauth2_cli_github_example/src/main.rs

//! region: auto_md_to_doc_comments include README.md A //!

//! endregion: auto_md_to_doc_comments include README.md A //!

mod github_oauth2_device_workflow_mod;
use github_oauth2_device_workflow_mod as wf;
mod crates_io_api_token;

use secrecy::ExposeSecret;

fn main() -> anyhow::Result<()> {
    // region: read config from files outside the repository
    // read config client id
    let client_id = std::fs::read_to_string("/home/rustdevuser/rustprojects/oauth2_cli_github_example_config/client_id.txt")?;
    // the private key, public key and the encrypted file will have the same bare name
    let file_bare_name = std::fs::read_to_string("/home/rustdevuser/rustprojects/oauth2_cli_github_example_config/file_bare_name.txt")?;
    // endregion: read config from files outside the repository

    let github_access_secret_token = wf::github_oauth2_device_workflow(&client_id, &file_bare_name)?;
    println!("{}", github_access_secret_token.expose_secret());

    //let crates_io_access_secret_token = wf::crates_io(&client_id, &file_bare_name)?;
    //println!("{}", access_secret_token.expose_secret());

    Ok(())
}
