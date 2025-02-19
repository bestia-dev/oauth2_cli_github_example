<!-- markdownlint-disable MD041 -->
[//]: # (auto_md_to_doc_comments segment start A)

# github_oauth2_device_workflow_mod

## Secrets

In this module there will be a lot of work with secrets.  
It is difficult to trust an external crate with your secrets.  
External crates can get updated unexpectedly and change to malicious code.  

## Copy code instead of dependency crate

It is best to have the Rust code under your fingertips when dealing with secrets.  
Than you know, nobody will touch this code except of you.  
You can copy this code directly into your codebase as a module,
inspect and review it and know exactly what is going on.  
The code is as linear and readable with comments as possible.
The dependencies in Cargo.toml must also be copied.  

## Store encrypted secret to file

The secrets will be encrypted with an ssh private key and stored in the ~/.ssh folder.  
This way the data is protected at rest in storage drive.  

## In memory protection

This is a tough one! There is no 100% software protection of secrets in memory.  
Theoretically an attacker could dump the memory in any moment and read the secrets.  
There is always a moment when the secret is used in its plaintext form. This cannot be avoided.
All we can do now is to be alert what data is secret and take better care of it.  
Every variable that have secrets will have the word `secret` in it.
When a variable is confusing I will use the word `plain` to express it is `not a secret`.
To avoid leaking in logs I will use the `secrecy` crate. This is not 100% protection.  
This is important just to express intent when the secrets are really used.  
`Secrecy` needs the trait `zeroize` to empty the memory after use for better memory hygiene.
I will add the type names explicitly to emphasis the secrecy types used.
To understand the code try to ignore all this secrecy game back and forth.

[//]: # (auto_md_to_doc_comments segment end A)
