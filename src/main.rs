use clap::{Parser, Subcommand};

mod crypto;
use crypto::{open_file, Crypto};

#[derive(Parser)]
#[command(
    version,
    about = "Vault (Vault-locker) is a file encryption and decryption tool."
)]
struct VaultArgs {
    #[command(subcommand)]
    command: VaultCommands,

    #[arg(short, long, global = true)]
    password: Option<String>,
}

#[derive(Subcommand)]
enum VaultCommands {
    Init,
    Encrypt { folder_path: String },
    Decrypt { folder_path: String },
}

pub const VAULT_LOCK: &str = "vault.lock";
pub const VAULT_CONFIG: &str = ".vault_config";

#[tokio::main]
async fn main() {
    let vault_args = VaultArgs::parse();
    let password = if let Some(p) = &vault_args.password {
        if !p.is_empty() {
            p
        } else {
            eprintln!("No password provided. -p <password> or --password <password>");
            std::process::exit(1);
        }
    } else {
        eprintln!("No password provided. -p <password> or --password <password>");
        std::process::exit(1);
    };

    let crypto = Crypto {
        password: password.to_string(),
    };

    let hashed = open_file(VAULT_LOCK, None).unwrap_or_default();
    match &vault_args.command {
        VaultCommands::Init => {
            println!("Initializing vault...");
            println!("Generating System Salt...");
            crypto.generate_salt();
            println!("use vault encrypt <folder_path> --password <your_password>");
            println!("use vault decrypt <folder_path> --password <your_password>");
        }
        VaultCommands::Decrypt { folder_path } => {
            if crypto.verify_password(&hashed) {
                println!("Decrypting folder: {} , {}", folder_path, password);
            } else {
                eprintln!("Invalid password.");
                std::process::exit(1);
            }
        }
        VaultCommands::Encrypt { folder_path } => {
            if !hashed.is_empty() {
                if crypto.verify_password(&hashed) {
                    println!("encrypting folder: {} , {}", folder_path, password);
                } else {
                    eprintln!("Invalid password.");
                    std::process::exit(1);
                }
            } else {
                crypto.hash_password();
                println!("Encrypting folder: {} , {}", folder_path, password);
            }
        }
    }
}
