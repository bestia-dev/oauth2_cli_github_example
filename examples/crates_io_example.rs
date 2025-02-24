// oauth2_cli_github_example/examples/crates_io_example.rs

// cargo run --example crates_io_example

#[path = "../src/crates_io_api_token_mod.rs"]
mod crates_io_api_token_mod;

#[path = "../src/encrypt_decrypt_with_ssh_key_mod.rs"]
mod encrypt_decrypt_with_ssh_key_mod;

use secrecy::ExposeSecret;

fn main() -> anyhow::Result<()> {

    let crates_io_access_secret_token = crates_io_api_token_mod::get_crates_io_secret_token("crates_io_secret_token_ssh_1")?;
    println!("{}", crates_io_access_secret_token.expose_secret());

    Ok(())
}
