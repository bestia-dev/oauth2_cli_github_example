<!-- markdownlint-disable MD041 -->
[//]: # (auto_md_to_doc_comments segment start A)

# crates_io_api_token_mod

Publish to crates.io needs the crates.io secret_token. This is a secret important just like a password.
There is the original "cargo login" function that saves this critical secret in plain text. This is a big no no.
I don't want to pass secret to an "obscure" library crate that is difficult to
review and can change in any point in time and become malicious.
Instead of that, copy and paste this module "mod" file into your project.
The secrets will stay in your codebase that is easy to inspect and guaranteed that will never change without your consent.

[//]: # (auto_md_to_doc_comments segment end A)
