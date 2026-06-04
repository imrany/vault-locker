use crate::CONFIG_FILE_NAME;
use rand::RngCore;
use std::{io, path::PathBuf};

// ─── Key & Config Management ──────────────────────────────────────────────────

pub fn generate_random_salt() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn get_config_path() -> PathBuf {
    let dev_path = PathBuf::from(CONFIG_FILE_NAME);
    if dev_path.exists() {
        return dev_path;
    }

    let mut config_path = if cfg!(target_os = "windows") {
        std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
    } else {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"))
    };

    if cfg!(target_os = "windows") {
        config_path.push(".config"); // Or "AppData/Roaming" to match Windows standards
    } else {
        config_path.push(".config");
    }

    config_path.push("vault_locker");
    let _ = std::fs::create_dir_all(&config_path);
    config_path.push(CONFIG_FILE_NAME);
    config_path
}

pub fn get_or_create_salt() -> io::Result<String> {
    let config_path = get_config_path();
    if config_path.exists() {
        let salt = std::fs::read_to_string(config_path)?;
        Ok(salt.trim().to_string())
    } else {
        let new_salt = generate_random_salt();
        std::fs::write(config_path, &new_salt)?;
        Ok(new_salt)
    }
}
