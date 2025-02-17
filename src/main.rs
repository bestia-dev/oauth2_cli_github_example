// oauth2_cli_github_example/src/main.rs

mod github_oauth2_device_workflow_mod;
use github_oauth2_device_workflow_mod as wf;

fn main() -> anyhow::Result<()> {
    // region: read config from files outside the repository
    // read config client id
    let client_id = std::fs::read_to_string("/home/rustdevuser/rustprojects/oauth2_cli_github_example_config/client_id.txt")?;
    // the private key, public key and the encrypted file will have the same bare name
    let file_bare_name = std::fs::read_to_string("/home/rustdevuser/rustprojects/oauth2_cli_github_example_config/file_bare_name.txt")?;
    // endregion: read config from files outside the repository

    wf::github_oauth2_device_workflow(&client_id, &file_bare_name)?;
    Ok(())
}
