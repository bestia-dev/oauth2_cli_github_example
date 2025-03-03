<!-- markdownlint-disable MD041 -->
[//]: # (auto_md_to_doc_comments segment start A)

# generate strong password

I'd like to have a CLI where to input a humane easy to memorize password.  
Then sign it with a private key (this encryption is reversible using the public key).  
Then hash it (this is a one way encryption, so nobody can come back to the first secret).  
Finally, convert it into a string long 32 characters with ascii7 characters (lowercase, uppercase, numeric and special characters).  
What makes this conversion secure is: only the user of the private key can convert the easy password into the same strong_password.

Strong passwords must use the clipboard. The risk is that it can stay in the clipboard and can be read from the clipboard.

## encrypt_decrypt_with_ssh_key_mod

This module depends on the generic module for encryption `encrypt_decrypt_with_ssh_key_mod.rs`. That module also needs to be copy and paste into your project.

## Other dependencies

In `Cargo.toml` there are a group od dependencies needed for this to work. They are so generic that I don't expect any malware in them to be able to steal some usable secrets.  

Beware that the versions of crates in `Cargo.toml` are not precisely pinpointed. In rust the symbol '=' means "the same major number equal or newer to". This means from one compilation to another, it can automatically change to a newer version without the programmer even noticing it.

This is great if the newer version is solving some security issue. But this is super-bad if the newer version is malware supply chain attack. We have no idea how to distinguish one from another.

Just to mention: there exists the trick to control the `Cargo.lock` file and forbid the change of the version number, but more times than not, you will not want to commit the lock file into the GitHub repository.

```toml
[dependencies]
ssh-key = { version = "0.6.7", features = [ "rsa", "encryption","ed25519"] }
ssh-agent-client-rs = "0.9.1"
rsa = { version = "0.9.7", features = ["sha2","pem"] }
zeroize = {version="1.8.1", features=["derive"]}
aes-gcm = "0.10.3"
camino = "1.1.6"
base64ct = {version = "1.6.0", features = ["alloc"] }
inquire = "0.7.0"
secrecy = "0.10.3"
```

[//]: # (auto_md_to_doc_comments segment end A)
