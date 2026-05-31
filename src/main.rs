use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use rand::RngCore;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use walkdir::WalkDir;

// A constant salt for password hashing (In production, store this safely or prepend to files)
const STATIC_SALT: &[u8] = b"super_secret_salt_123";

fn print_usage() {
    println!("Usage:");
    println!("  vault encrypt <folder_path> --password <your_password>");
    println!("  vault decrypt <folder_path> --password <your_password>");
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    // Variables to store parameters determined either via CLI or Interactive mode
    let folder_path: String;
    let password: String;
    let action: String;

    // 1. If arguments are provided on the CLI, parse them directly
    if args.len() > 1 {
        if args.len() < 5 {
            print_usage();
            std::process::exit(1);
        }

        let raw_action = &args[1];
        folder_path = args[2].clone();
        let password_flag = &args[3];
        password = args[4].clone();

        if password_flag != "--password" {
            eprintln!("Error: Missing parameter flag '--password'");
            print_usage();
            std::process::exit(1);
        }

        action = match raw_action.as_str() {
            "encrypt" => "1".to_string(),
            "decrypt" => "2".to_string(),
            _ => {
                eprintln!("Error: Unknown action '{}'", raw_action);
                print_usage();
                std::process::exit(1);
            }
        };
    } else {
        // Fall back to original interactive behavior if no arguments are passed
        println!("--- Custom Rust Folder Vault ---");

        println!("Enter target folder path:");
        let mut f_path = String::new();
        io::stdin().read_line(&mut f_path)?;
        folder_path = f_path.trim().to_string();

        println!("Enter password:");
        let mut pwd = String::new();
        io::stdin().read_line(&mut pwd)?;
        password = pwd.trim().to_string();

        println!("Choose action: [1] Encrypt (Lock)  [2] Decrypt (Unlock)");
        let mut act = String::new();
        io::stdin().read_line(&mut act)?;
        action = act.trim().to_string();
    }

    // 2. Derive a secure key from the password using Argon2
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();
    let password_bytes = password.as_bytes();
    let salt = SaltString::encode_b64(STATIC_SALT).unwrap();
    if let Ok(hash) = argon2.hash_password(password_bytes, &salt) {
        let hash_output = hash.hash.expect("Failed to retrieve hash output");

        // Convert that specific output to bytes
        let hash_bytes = hash_output.as_bytes();
        key.copy_from_slice(&hash_bytes[..32]);
    } else {
        panic!("Failed to generate cryptographic key.");
    }

    let cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid key length");

    // 3. Process the directory using the parameters resolved above
    match action.as_str() {
        "1" => {
            println!("Encrypting files...");
            process_directory(&folder_path, &cipher, true)?;
            println!("Folder Locked successfully!");
        }
        "2" => {
            println!("Decrypting files...");
            process_directory(&folder_path, &cipher, false)?;
            println!("Folder Unlocked successfully!");
        }
        _ => println!("Invalid action selected."),
    }

    Ok(())
}

fn process_directory(dir_path: &str, cipher: &Aes256Gcm, encrypt: bool) -> io::Result<()> {
    for entry in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if encrypt {
                // Skip already encrypted files
                if path.extension().map_or(false, |ext| ext == "enc") {
                    continue;
                }
                encrypt_file(path, cipher)?;
            } else {
                // Only decrypt .enc files
                if path.extension().map_or(true, |ext| ext != "enc") {
                    continue;
                }
                decrypt_file(path, cipher)?;
            }
        }
    }
    Ok(())
}

fn encrypt_file(path: &Path, cipher: &Aes256Gcm) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    // Generate a unique 12-byte nonce (initialization vector) for AES-GCM
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt contents
    let ciphertext = cipher
        .encrypt(nonce, contents.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    // Create new file data: Nonce + Ciphertext
    let mut encrypted_data = Vec::new();
    encrypted_data.extend_from_slice(&nonce_bytes);
    encrypted_data.extend_from_slice(&ciphertext);

    // Write back to a new file with .enc extension and delete original
    let new_path = path.with_extension("enc");
    fs::write(&new_path, encrypted_data)?;
    fs::remove_file(path)?;
    println!("Encrypted: {:?}", path.file_name().unwrap());
    Ok(())
}

fn decrypt_file(path: &Path, cipher: &Aes256Gcm) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    if contents.len() < 12 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "File too short"));
    }

    // Split the 12-byte nonce from the rest of the encrypted payload
    let (nonce_bytes, ciphertext) = contents.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt contents
    let decrypted_text = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Decryption failed! Wrong password?",
        )
    })?;

    // Restore original file extension
    let mut new_path = path.to_path_buf();
    new_path.set_extension(""); // removes .enc

    fs::write(&new_path, decrypted_text)?;
    fs::remove_file(path)?;
    println!("Decrypted: {:?}", new_path.file_name().unwrap());
    Ok(())
}
