<!-- markdownlint-disable MD041 -->
[//]: # (auto_md_to_doc_comments segment start A)

# decrypt github api token from file or use the oauth2 device workflow to get the access token and encrypt it and save into file

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

## Store encrypted secret to file

The secrets will be encrypted with an ssh private key and stored in the `~/.ssh` folder.  
This way the data is protected at rest in storage drive.  

## In memory protection

This is a tough one! There is no 100% software protection of secrets in memory.  
Theoretically an attacker could dump the memory in any moment and read the secrets.  
There is always a moment when the secret is used in its plaintext form. This cannot be avoided.
All we can do now is to be alert what data is secret and take better care of it.  
Every variable that have secrets will have the word `secret` in it.
When a variable is confusing I will use the word `plain` to express it is `not a secret`.
To avoid leaking in logs I will use the `secrecy` crate. This is not 100% protection. It is important just to express intent when the secrets are really used.  
`Secrecy` needs the trait `zeroize` to empty the memory after use for better memory hygiene.
I will add the type names explicitly to emphasis the secrecy types used.

## encrypt_decrypt_with_ssh_key_mod

This module depends on the generic module for encryption `encrypt_decrypt_with_ssh_key_mod.rs`. That module also needs to be copy and paste into your project.

## Other dependencies

In `Cargo.toml` there are a group od dependencies needed for this to work. They are so generic that I don't expect any malware in them to be able to steal some usable secrets.  

Beware that the versions of crates in `Cargo.toml` are not precisely pinpointed. In rust the symbol '=' means "the same major number equal or newer to". This means from one compilation to another, it can automatically change to a newer version without the programmer even noticing it.

This is great if the newer version is solving some security issue. But this is super-bad if the newer version is malware supply chain attack. We have no idea how to distinguish one from another.

Just to mention: there exists the trick to control the `Cargo.lock` file and forbid the change of the version number, but more times than not, you will not want to commit the lock file into the GitHub repository.

```toml
[dependencies]
anyhow="1.0.95"
reqwest={version="0.12.12", features=["json","blocking"]}
serde ={ version= "1.0.217", features=["std","derive"]}
serde_json = "1.0.138"
ssh-key = { version = "0.6.7", features = [ "rsa", "encryption","ed25519"] }
ssh-agent-client-rs = "0.9.1"
rsa = { version = "0.9.7", features = ["sha2","pem"] }
zeroize = {version="1.8.1", features=["derive"]}
aes-gcm = "0.10.3"
camino = "1.1.6"
base64ct = {version = "1.6.0", features = ["alloc"] }
inquire = "0.7.0"
secrecy = "0.10.3"
chrono ="0.4.39"
```

[//]: # (auto_md_to_doc_comments segment end A)
