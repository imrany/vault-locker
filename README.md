# Vault Locker 🦀🔒

`vault_locker` is a lightweight, blazing-fast Command Line Interface (CLI) tool built in Rust to safely encrypt and decrypt local directories. It protects your sensitive files by recursively walking through folders and encrypting individual files using military-grade **AES-256-GCM** encryption.


## 🚀 Features

* **Secure Key Derivation:** Uses the **Argon2** password hashing algorithm to safely stretch your plain-text password into a cryptographically secure 32-byte encryption key.
* **Strong Encryption:** Implements authenticated encryption using **AES-256-GCM**, ensuring both confidentiality and integrity (tamper-proofing) of your files.
* **Recursive Directory Walking:** Traverses nested folders flawlessly using the efficient `walkdir` crate.
* **In-Place Modification:** Replaces vulnerable files with their encrypted `.enc` counterparts instantly, removing unencrypted traces from your filesystem.


## 🛠️ Architecture: How It Works

1.  **Key Derivation:** Your password + a static unique salt are fed into `Argon2`, producing a 256-bit key.
2.  **Encryption Cycle:** * Generates a unique 12-byte random **Nonce** for every single file.
    * Encrypts the file contents.
    * Prepends the 12-byte Nonce to the encrypted payload and writes it out as a `.enc` file.
    * Safely removes the original raw file.
3.  **Decryption Cycle:**
    * Reads the first 12 bytes of the `.enc` file to extract the Nonce.
    * Decrypts the remainder of the file using the derived key.
    * Restores the original file name and extension, purging the encrypted copy.


## 📋 Prerequisites

To compile and run this project, you need the Rust toolchain installed on your Ubuntu system. If you don't have it yet, install it via `rustup`:

```bash
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
source $HOME/.cargo/env
```


## 📦 Installation & Setup

1. Clone or navigate to your project directory:
```bash
cd vault_locker
```


2. Build the project in release mode for maximum performance:
```bash
cargo build --release
```


The compiled binary will be available at `./target/release/vault_locker`.


## 💻 Usage

Run the binary using Cargo:

```bash
cargo run
```

Or

Once compiled, you can run it directly using your specified parameters:

```bash
# Encrypting a directory
cargo run -- encrypt ./my_secrets --password MySuperSecretPassword123
```


```bash
# Decrypting a directory
cargo run -- decrypt ./my_secrets --password MySuperSecretPassword123
```

### Step-by-Step Prompt Flow:

1. **Target Folder:** Provide the absolute or relative path to the folder you want to secure (e.g., `/home/user/Documents/SecretFolder`).
2. **Password:** Input your secure passphrase.
3. **Action:** * Enter `1` to **Encrypt (Lock)** the folder.
* Enter `2` to **Decrypt (Unlock)** the folder.



> ⚠️ **Important Note:** Make sure you use the *exact* same password to decrypt the folder that you used to encrypt it. If the password differs by even a single character, decryption will fail to prevent unauthorized access.


## 🛡️ Security Disclaimer

This tool is designed for educational and personal use.

* **Backup Your Data:** Always test this tool on a backup or a dummy folder containing non-critical data before running it on production files.
* **Hardcoded Salt:** This implementation uses a static `STATIC_SALT`. For an enterprise-grade environment, it is highly recommended to generate random salts per file/session and append them to the file headers.
