// github_oauth2_device_workflow.rs

use std::str::FromStr;

/// In this module there will be a lot of work with secrets.
/// It is difficult to trust an external crate with your secrets.
/// The crates can get updated unexpectedly and change to malicious code.
/// It is best to have the Rust code under your fingertips when dealing with secrets.
/// Than you know nobody will touch this code except of you.
/// You can copy this code directly into your codebase, inspect and review it
/// and know exactly what is going on.

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

pub(crate) fn github_oauth2_device_workflow(client_id: &str, file_bare_name: &str) -> anyhow::Result<()> {
    println!("{YELLOW}  Start the github oauth2 device workflow for CLI apps{RESET}");

    println!("{YELLOW}  Check if the ssh private key exists.{RESET}");
    let private_file_name = camino::Utf8PathBuf::from_str(&format!("/home/rustdevuser/.ssh/{file_bare_name}"))?;
    if !std::fs::exists(&private_file_name)? {
        println!("{RED}Error: Private key {private_file_name} does not exist.{RESET}");
        println!("{YELLOW}  Create the private key in bash terminal:{RESET}");
        println!(r#"{GREEN}ssh-keygen -t ed25519 -C "github api secret_token"{RESET}"#);
        println!(r#"{GREEN}file name: {private_file_name}"{RESET}"#);
    }

    println!("{YELLOW}  Check if the ssh public key exists.{RESET}");
    let public_file_name = camino::Utf8PathBuf::from_str(&format!("/home/rustdevuser/.ssh/{file_bare_name}.pub"))?;
    if !std::fs::exists(&public_file_name)? {
        println!("{RED}Error: Private key {public_file_name} does not exist.{RESET}");
        println!("{YELLOW}  Create the private key in bash terminal:{RESET}");
        println!(r#"{GREEN}ssh-keygen -t ed25519 -C "github api secret_token"{RESET}"#);
        println!(r#"{GREEN}file name: {private_file_name}"{RESET}"#);
    }

    println!("{YELLOW}  Check if the encrypted file exists.{RESET}");
    let encrypted_file_name = camino::Utf8PathBuf::from_str(&format!("/home/rustdevuser/.ssh/{file_bare_name}.enc"))?;
    if !std::fs::exists(&encrypted_file_name)? {
        println!("{YELLOW}  Encrypted file {encrypted_file_name} does not exist.{RESET}");
        println!("{YELLOW}  Continue to first authentication with the browser{RESET}");
        first_authentication_with_browser();
    }

    Ok(())
}

fn first_authentication_with_browser() {}
