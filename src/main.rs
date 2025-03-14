// oauth2_cli_github_example/src/main.rs

// region: auto_md_to_doc_comments include README.md A //!
//! # oauth2_cli_github_example
//!
//! **Example of GitHub api with Oauth2 CLI**  
//! ***version: 2025.310.1800 date: 2025-03-10 author: [bestia.dev](https://bestia.dev) repository: [GitHub](https://github.com/bestia-dev/oauth2_cli_github_example)***
//!
//!  ![work-in-progress](https://img.shields.io/badge/work_in_progress-yellow)
//!  ![tutorial](https://img.shields.io/badge/tutorial-orange)
//!  ![oauth2](https://img.shields.io/badge/oauth2-orange)
//!  ![cli](https://img.shields.io/badge/cli-orange)
//!
//!  ![License](https://img.shields.io/badge/license-MIT-blue.svg)
//!  ![oauth2_cli_github_example](https://bestia.dev/webpage_hit_counter/get_svg_image/1096479376.svg)
//!
//! Hashtags: #tutorial #oauth #rust #cli  
//! My projects on GitHub are more like a tutorial than a finished product: [bestia-dev tutorials](https://github.com/bestia-dev/tutorials_rust_wasm).
//!
//! ## Motivation
//!
//! I want to use the GitHub api to automate the build and release workflow of my rust projects.  
//! I used a personal secret token, but this is now short lived, cumbersome to generate and not recommended anymore.  
//! Oauth2 is now recommended.
//!
//! ## Github app
//!
//! Github has the concept of [GitHub app](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/about-creating-github-apps)  
//!
//! In the settings of GitHub create a new GitHub App <https://github.com/settings/apps>.  
//! App name: oauth2-cli-github-example  
//! The name cannot contain underscore!  
//! Homepage URL: <https://bestia.dev/oauth2_cli_github_example/homepage.html>  
//! Callback URL: <https://bestia.dev/oauth2_cli_github_example/callback.html>  
//!
//! Enable device flow: this is mandatory for CLI applications
//!
//! Repository permission
//! Contents: read and write  
//! Repository contents, commits, branches, downloads, releases, and merges.  
//! Metadata  mandatory: read only  
//! Search repositories, list collaborators, and access repository metadata.  
//!
//! App ID: xxx  
//! Using your App ID to get installation tokens? You can now use your Client ID instead.  
//! Client ID: xxx  
//!
//! ## Device workflow with Oauth
//!
//! There are many different workflows in Oauth2. That makes it so confusing.  
//! For a CLI program it is recommended the `device workflow`. This must be enabled when creating the GitHub app.
//!
//! I will save the tokens in a file encrypted with an SSH key.  
//!
//! For every app start check if the tokens are still valid and if needed [use the refresh_token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens).  
//! In case of any error start the "workflow to authentication with the browser".
//!
//! ```plaintext
//! Check if the file with encrypted tokens is present
//!   Decrypt the tokens
//!   Check if the access_token is still valid
//!     store access_token in global variable for use
//!   Else check if the refresh_token is valid
//!     Send the request to obtain new tokens
//!     Save the tokens encrypted with an SSH key
//!     store access_token in global variable for use
//! ```
//!
//! Workflow to [authentication with the browser](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app#using-the-device-flow-to-generate-a-user-access-token) for [device flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow):
//!
//! ```plaintext
//! In the CLI program send a request to GitHub with client_id
//! Get a response with  device_code and user_code
//! Open a browser on GitHub, authenticate and type the user_code
//! GitHub will prepare the tokens on the server
//! Return to the CLI program and send a request to GitHub with  client_id and device_code
//! Get a response with access_token and refresh_token
//! Save the tokens encrypted with an SSH key
//! ```
//!
//! ## Open-source and free as a beer
//!
//! My open-source projects are free as a beer (MIT license).  
//! I just love programming.  
//! But I need also to drink. If you find my projects and tutorials helpful, please buy me a beer by donating to my [PayPal](https://paypal.me/LucianoBestia).  
//! You know the price of a beer in your local bar ;-)  
//! So I can drink a free beer for your health :-)  
//! [Na zdravje!](https://translate.google.com/?hl=en&sl=sl&tl=en&text=Na%20zdravje&op=translate) [Alla salute!](https://dictionary.cambridge.org/dictionary/italian-english/alla-salute) [Prost!](https://dictionary.cambridge.org/dictionary/german-english/prost) [Nazdravlje!](https://matadornetwork.com/nights/how-to-say-cheers-in-50-languages/) 🍻
//!
//! [//bestia.dev](https://bestia.dev)  
//! [//github.com/bestia-dev](https://github.com/bestia-dev)  
//! [//bestiadev.substack.com](https://bestiadev.substack.com)  
//! [//youtube.com/@bestia-dev-tutorials](https://youtube.com/@bestia-dev-tutorials)  
//!
// endregion: auto_md_to_doc_comments include README.md A //!

mod auto_github_api_mod;
mod encrypt_decrypt_with_ssh_key_mod;

// use secrecy::ExposeSecret;

/// This is all just an example.
/// In the main() function I must call all other functions
/// to avoid the warning `Code is never used`.  
/// But the true code separated by topic is in the `examples` folder.  
fn main() -> anyhow::Result<()> {
    let strong_password = encrypt_decrypt_with_ssh_key_mod::generate_strong_password_mod::generate_strong_password("vault_ssh_1")?;
    println!("{}", strong_password);
    /*
       encrypt_decrypt_with_ssh_key_mod::secret_vault_mod::store_secret_token_to_vault("vault_ssh_1", "test_1")?;
       encrypt_decrypt_with_ssh_key_mod::secret_vault_mod::store_secret_token_to_vault("vault_ssh_1", "test_2")?;

       let vec_string = encrypt_decrypt_with_ssh_key_mod::secret_vault_mod::list_token_from_vault("vault_ssh_1")?;
       println!("{:?}", vec_string);

       let secret_token = encrypt_decrypt_with_ssh_key_mod::secret_vault_mod::show_secret_token_from_vault("vault_ssh_1", "test_1")?;
       println!("{}", secret_token.expose_secret());
       let secret_token = encrypt_decrypt_with_ssh_key_mod::secret_vault_mod::show_secret_token_from_vault("vault_ssh_1", "test_2")?;
       println!("{}", secret_token.expose_secret());

       encrypt_decrypt_with_ssh_key_mod::secret_vault_mod::delete_token_from_vault("vault_ssh_1", "test_1")?;
       encrypt_decrypt_with_ssh_key_mod::secret_vault_mod::delete_token_from_vault("vault_ssh_1", "test_2")?;

       let secret_docker_hub_access_token = encrypt_decrypt_with_ssh_key_mod::docker_io_api_token_mod::get_docker_hub_secret_token("docker_io_secret_token_ssh_1")?;
       println!("{}", secret_docker_hub_access_token.expose_secret());

       let secret_crates_io_access_token = encrypt_decrypt_with_ssh_key_mod::crates_io_api_token_mod::get_crates_io_secret_token("crates_io_secret_token_ssh_1")?;
       println!("{}", secret_crates_io_access_token.expose_secret());

       // read config client id
       let client_id = std::fs::read_to_string("../oauth2_cli_github_example_config/client_id.txt")?;
       // the private key, public key and the encrypted file will have the same bare name
       let file_bare_name = std::fs::read_to_string("../oauth2_cli_github_example_config/file_bare_name.txt")?;

       let secret_github_access_token = encrypt_decrypt_with_ssh_key_mod::github_api_token_with_oauth2_mod::get_github_secret_token(&client_id, &file_bare_name)?;
       println!("{}", secret_github_access_token.expose_secret());
    */

    Ok(())
}
