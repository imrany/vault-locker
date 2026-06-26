use crate::{VAULT_CONFIG, VAULT_LOCK};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::{fs::File, io::prelude::*, path::Path};

pub struct Crypto {
    pub password: String,
}

impl Crypto {
    pub fn hash_password(&self) -> String {
        // Read the stored salt string from the configuration file
        let salt_str = open_file(VAULT_CONFIG, None).expect("Failed to read system salt");

        // Parse the raw string into a structured SaltString
        let salt =
            SaltString::from_b64(&salt_str).expect("Stored system salt is not valid B64 format");

        let argon2 = Argon2::default();
        let hashed = argon2
            .hash_password(self.password.as_bytes(), &salt)
            .expect("Password hashing failed structural constraints")
            .to_string();

        open_file(VAULT_LOCK, Some(&hashed)).expect(&format!("Failed to create {}", VAULT_LOCK))
    }

    pub fn verify_password(&self, hashed: &str) -> bool {
        let parsed_hash = match PasswordHash::new(hashed) {
            Ok(hash) => hash,
            Err(_) => return false,
        };

        Argon2::default()
            .verify_password(self.password.as_bytes(), &parsed_hash)
            .is_ok()
    }

    pub fn generate_salt(&self) -> String {
        let salt = SaltString::generate(&mut OsRng).to_string();
        // Pass the new salt to overwrite/create the config file
        open_file(VAULT_CONFIG, Some(&salt)).expect("Failed to initialize system salt file")
    }
}

pub fn open_file(path: &str, content: Option<&str>) -> Result<String, std::io::Error> {
    let file_path = Path::new(path);
    let mut s = String::new();

    if file_path.exists() {
        if let Some(c) = content {
            // Overwrite existing configuration safely (Truncates old contents)
            let mut file = File::create(&file_path)?;
            file.write_all(c.as_bytes())?;
            s.push_str(c);
        } else {
            // Read existing configuration
            let mut file = File::open(&file_path)?;
            file.read_to_string(&mut s)?;
        }
    } else {
        // Create completely new configuration file
        let c = match content {
            Some(c) => c,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No content to write",
                ))
            }
        };

        let mut file = File::create(&file_path)?;
        file.write_all(c.as_bytes())?;
        s.push_str(c);
    }

    Ok(s)
}
