use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use humansize::{format_size, BINARY};
use rand::RngCore;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Wrap,
    },
    Terminal,
};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    fs,
    sync::mpsc::{self, UnboundedReceiver},
};
use walkdir::WalkDir;

mod utils;
use utils::{generate_random_salt, get_config_path, get_or_create_salt};

// ─── Constants ────────────────────────────────────────────────────────────────

const LOCK_FILE_NAME: &str = ".vault_lock";
const TICK_RATE: Duration = Duration::from_millis(50);
const CONCURRENCY: usize = 8;
pub const CONFIG_FILE_NAME: &str = ".vault_config";

// ─── Worker ↔ UI message ──────────────────────────────────────────────────────

#[derive(Debug)]
struct FileResult {
    display: String,
    size: u64,
    ok: bool,
    err: Option<String>,
}

// ─── App state ────────────────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Screen {
    FolderPicker,
    PasswordEntry,
    ConfirmPassword,
    ActionPicker,
    Processing,
    Done,
}

#[derive(PartialEq, Clone, Copy)]
enum Action {
    Encrypt,
    Decrypt,
}

struct LogEntry {
    icon: &'static str,
    text: String,
    color: Color,
}

struct App {
    screen: Screen,
    folders: Vec<PathBuf>,
    list_state: ListState,
    password: String,
    confirm_password: String,
    password_error: Option<String>,
    action: Action,
    action_index: usize,
    total_files: usize,
    processed_files: usize,
    active_workers: usize,
    current_files: Vec<String>,
    log: Vec<LogEntry>,
    stats_processed: usize,
    stats_failed: usize,
    stats_bytes: u64,
    result_rx: Option<UnboundedReceiver<FileResult>>,
    show_password: bool,
    flash_timer: Option<Instant>,
    // Persistent Dynamic Salt tracking
    salt: String,
}

impl App {
    fn new(salt: String) -> io::Result<Self> {
        let current_dir = std::env::current_dir()?;
        let mut folders: Vec<PathBuf> = std::fs::read_dir(&current_dir)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
            .map(|e| e.path())
            .collect();
        folders.sort();

        let mut list_state = ListState::default();
        if !folders.is_empty() {
            list_state.select(Some(0));
        }

        Ok(Self {
            screen: Screen::FolderPicker,
            folders,
            list_state,
            password: String::new(),
            confirm_password: String::new(),
            password_error: None,
            action: Action::Encrypt,
            action_index: 0,
            total_files: 0,
            processed_files: 0,
            active_workers: 0,
            current_files: Vec::new(),
            log: Vec::new(),
            stats_processed: 0,
            stats_failed: 0,
            stats_bytes: 0,
            result_rx: None,
            show_password: false,
            flash_timer: None,
            salt,
        })
    }

    fn selected_folder(&self) -> Option<&PathBuf> {
        self.list_state.selected().and_then(|i| self.folders.get(i))
    }

    fn progress_pct(&self) -> u16 {
        if self.total_files == 0 {
            return 0;
        }
        ((self.processed_files as f64 / self.total_files as f64) * 100.0).min(100.0) as u16
    }

    fn push_log(&mut self, icon: &'static str, text: String, color: Color) {
        self.log.push(LogEntry { icon, text, color });
    }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // 1. Explicit Initialization Command
    if args.len() == 2 && args[1] == "init" {
        let new_salt = generate_random_salt();
        std::fs::write(get_config_path(), &new_salt)?;
        println!("Vault dynamic configurations initialized securely.");
        println!("Generated system salt: {}", new_salt);
        return Ok(());
    }

    // Load or lazily instantiate salt configuration
    let system_salt = get_or_create_salt()?;

    // Route directly to headless layout execution if arguments are fed
    if args.len() > 1 {
        if args.len() < 5 {
            println!("Usage:");
            println!("  vault init");
            println!("  vault encrypt <folder_path> --password <your_password>");
            println!("  vault decrypt <folder_path> --password <your_password>");
            std::process::exit(1);
        }

        let action = &args[1];
        let folder_path = &args[2];
        let password_flag = &args[3];
        let password = &args[4];

        if password_flag != "--password" {
            eprintln!("Error: Missing parameter flag '--password'");
            std::process::exit(1);
        }

        let folder = Path::new(folder_path);
        if !folder.exists() {
            eprintln!("Error: Target folder path '{}' does not exist", folder_path);
            std::process::exit(1);
        }

        let lock_path = folder.join(LOCK_FILE_NAME);
        let argon2 = Argon2::default();
        let password_bytes = password.as_bytes();
        let salt_param = SaltString::encode_b64(system_salt.as_bytes()).unwrap();

        let hash_string = argon2
            .hash_password(password_bytes, &salt_param)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .to_string();

        if lock_path.exists() {
            let stored = std::fs::read_to_string(&lock_path)?;
            let parsed = PasswordHash::new(&stored)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            if argon2.verify_password(password_bytes, &parsed).is_err() {
                eprintln!("Error: Wrong password for this vault!");
                std::process::exit(1);
            }
        } else if action == "decrypt" {
            eprintln!("Error: No vault lock found — folder not encrypted");
            std::process::exit(1);
        } else {
            std::fs::write(&lock_path, &hash_string)?;
        }

        let key = derive_key(&hash_string)?;
        let encrypt = match action.as_str() {
            "encrypt" => true,
            "decrypt" => false,
            _ => {
                eprintln!("Error: Unknown action sub-command '{}'", action);
                std::process::exit(1);
            }
        };

        println!("--- Headless Vault Engine Initialized ---");
        println!("Target Folder : {}", folder.display());
        println!("Concurrency   : {} tasks", CONCURRENCY);
        println!("System Salt   : {}", system_salt);
        // println!("Vault Config  : {}", get_config_path().display());

        // Collect files
        let files: Vec<PathBuf> = WalkDir::new(&folder)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter(|e| {
                let name = e.path().file_name().unwrap_or_default().to_string_lossy();
                if name == LOCK_FILE_NAME {
                    return false;
                }
                if encrypt {
                    e.path().extension().map_or(true, |x| x != "enc")
                } else {
                    e.path().extension().map_or(false, |x| x == "enc")
                }
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        let total = files.len();
        println!("Processing {} files...", total);

        let active = Arc::new(Mutex::new(0usize));
        let (tx, mut rx) = mpsc::unbounded_channel::<FileResult>();
        let key_arc = Arc::new(key);

        for path in files {
            loop {
                let count = *active.lock().unwrap();
                if count < CONCURRENCY {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            {
                let mut count = active.lock().unwrap();
                *count += 1;
            }

            let display = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let tx2 = tx.clone();
            let key2 = Arc::clone(&key_arc);
            let active2 = Arc::clone(&active);

            tokio::spawn(async move {
                let size = tokio::fs::metadata(&path)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(0);
                let (ok, err_msg) = if encrypt {
                    match encrypt_file(&path, &key2).await {
                        Ok(_) => (true, None),
                        Err(e) => (false, Some(e.to_string())),
                    }
                } else {
                    match decrypt_file(&path, &key2).await {
                        Ok(_) => (true, None),
                        Err(e) => (false, Some(e.to_string())),
                    }
                };

                {
                    let mut count = active2.lock().unwrap();
                    *count -= 1;
                }

                let _ = tx2.send(FileResult {
                    display,
                    size,
                    ok,
                    err: err_msg,
                });
            });
        }

        drop(tx);

        let mut processed = 0;
        let mut failed = 0;
        let mut total_bytes = 0;

        while let Some(r) = rx.recv().await {
            processed += 1;
            if r.ok {
                total_bytes += r.size;
                println!(
                    "  [{}/{}] Verified: {} ({})",
                    processed,
                    total,
                    r.display,
                    format_size(r.size, BINARY)
                );
            } else {
                failed += 1;
                eprintln!(
                    "  [{}/{}] FAILED  : {} -> {}",
                    processed,
                    total,
                    r.display,
                    r.err.unwrap_or_default()
                );
            }
        }

        println!("\nOperation Summary Completed.");
        println!(
            "  Success: {} files ({})",
            processed - failed,
            format_size(total_bytes, BINARY)
        );
        if failed > 0 {
            println!("  Failure: {} files failed structurally", failed);
        }
        return Ok(());
    }

    // Standard GUI fallback behavior when launched with no args
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(system_salt)?;
    let result = run_app(&mut terminal, &mut app).await;

    terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

// ─── Event loop ───────────────────────────────────────────────────────────────

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if key.code == KeyCode::Esc && app.screen != Screen::Processing {
                    return Ok(());
                }

                match app.screen {
                    Screen::FolderPicker => handle_folder_picker(app, key.code)?,
                    Screen::PasswordEntry => handle_password_entry(app, key.code),
                    Screen::ConfirmPassword => handle_confirm_password(app, key.code),
                    Screen::ActionPicker => handle_action_picker(app, key.code).await?,
                    Screen::Processing => {}
                    Screen::Done => {
                        if matches!(key.code, KeyCode::Char('q') | KeyCode::Enter | KeyCode::Esc) {
                            return Ok(());
                        }
                    }
                }
            }
        }

        if app.screen == Screen::Processing {
            drain_results(app);
            if app.processed_files >= app.total_files && app.active_workers == 0 {
                drain_results(app);
                let verb = if app.action == Action::Encrypt {
                    "Encrypted"
                } else {
                    "Decrypted"
                };
                app.push_log(
                    "✅",
                    format!(
                        "{} {} file(s) — {}",
                        verb,
                        app.stats_processed,
                        format_size(app.stats_bytes, BINARY),
                    ),
                    Color::Yellow,
                );
                if app.stats_failed > 0 {
                    app.push_log(
                        "⚠",
                        format!("{} file(s) failed", app.stats_failed),
                        Color::Red,
                    );
                }
                app.current_files.clear();
                app.screen = Screen::Done;
            }
        }

        if let Some(t) = app.flash_timer {
            if t.elapsed() > Duration::from_millis(1400) {
                app.flash_timer = None;
                app.password_error = None;
            }
        }

        tokio::time::sleep(TICK_RATE).await;
    }
}

fn drain_results(app: &mut App) {
    let mut rx = match app.result_rx.take() {
        Some(rx) => rx,
        None => return,
    };

    let mut results = Vec::new();
    while let Ok(r) = rx.try_recv() {
        results.push(r);
    }

    app.result_rx = Some(rx);

    let encrypt = app.action == Action::Encrypt;
    for r in results {
        app.processed_files += 1;
        app.active_workers = app.active_workers.saturating_sub(1);
        app.current_files.retain(|f| f != &r.display);
        if r.ok {
            app.stats_processed += 1;
            app.stats_bytes += r.size;
            let icon = if encrypt { "🔒" } else { "🔓" };
            let text = format!("{} ({})", r.display, format_size(r.size, BINARY));
            app.push_log(icon, text, Color::Green);
        } else {
            app.stats_failed += 1;
            let text = format!("FAILED: {} — {}", r.display, r.err.unwrap_or_default());
            app.push_log("✗", text, Color::Red);
        }
    }
}

// ─── Input handlers ───────────────────────────────────────────────────────────

fn handle_folder_picker(app: &mut App, key: KeyCode) -> io::Result<()> {
    let max = app.folders.len().saturating_sub(1);
    match key {
        KeyCode::Up | KeyCode::Char('k') => {
            let cur = app.list_state.selected().unwrap_or(0);
            app.list_state.select(Some(cur.saturating_sub(1)));
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let cur = app.list_state.selected().unwrap_or(0);
            app.list_state.select(Some((cur + 1).min(max)));
        }
        // App-wide trigger to rotate and store a brand-new system salt configuration
        KeyCode::Char('G') => {
            let new_salt = generate_random_salt();
            std::fs::write(get_config_path(), &new_salt)?;
            app.salt = new_salt;
            app.password_error = Some("🔄 Brand new runtime system salt regenerated!".into());
            app.flash_timer = Some(Instant::now());
        }
        KeyCode::Enter => {
            if app.selected_folder().is_some() {
                app.screen = Screen::PasswordEntry;
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_password_entry(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char(c) => app.password.push(c),
        KeyCode::Backspace => {
            app.password.pop();
        }
        KeyCode::Tab => app.show_password = !app.show_password,
        KeyCode::Enter => {
            if app.password.is_empty() {
                app.password_error = Some("Password cannot be empty".into());
                app.flash_timer = Some(Instant::now());
                return;
            }
            let folder = app.selected_folder().unwrap().clone();
            if folder.join(LOCK_FILE_NAME).exists() {
                app.screen = Screen::ActionPicker;
            } else {
                app.screen = Screen::ConfirmPassword;
            }
        }
        KeyCode::BackTab => app.screen = Screen::FolderPicker,
        _ => {}
    }
}

fn handle_confirm_password(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char(c) => app.confirm_password.push(c),
        KeyCode::Backspace => {
            app.confirm_password.pop();
        }
        KeyCode::Tab => app.show_password = !app.show_password,
        KeyCode::Enter => {
            if app.password != app.confirm_password {
                app.password_error = Some("Passwords do not match!".into());
                app.confirm_password.clear();
                app.flash_timer = Some(Instant::now());
                return;
            }
            app.screen = Screen::ActionPicker;
        }
        KeyCode::BackTab => {
            app.confirm_password.clear();
            app.screen = Screen::PasswordEntry;
        }
        _ => {}
    }
}

async fn handle_action_picker(app: &mut App, key: KeyCode) -> io::Result<()> {
    match key {
        KeyCode::Left | KeyCode::Right | KeyCode::Char('h') | KeyCode::Char('l') => {
            app.action_index = 1 - app.action_index;
            app.action = if app.action_index == 0 {
                Action::Encrypt
            } else {
                Action::Decrypt
            };
        }
        KeyCode::Enter => {
            let folder = app.selected_folder().unwrap().clone();
            let lock_path = folder.join(LOCK_FILE_NAME);
            let argon2 = Argon2::default();
            let password_bytes = app.password.as_bytes();
            let salt_param = SaltString::encode_b64(app.salt.as_bytes()).unwrap();

            let hash_string = argon2
                .hash_password(password_bytes, &salt_param)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
                .to_string();

            if lock_path.exists() {
                let stored = std::fs::read_to_string(&lock_path)?;
                let parsed = PasswordHash::new(&stored)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                if argon2.verify_password(password_bytes, &parsed).is_err() {
                    app.password_error = Some("❌ Wrong password for this vault!".into());
                    app.flash_timer = Some(Instant::now());
                    app.password.clear();
                    app.confirm_password.clear();
                    app.screen = Screen::PasswordEntry;
                    return Ok(());
                }
            } else if app.action == Action::Decrypt {
                app.password_error = Some("No vault lock found — folder not encrypted".into());
                app.flash_timer = Some(Instant::now());
                return Ok(());
            } else {
                std::fs::write(&lock_path, &hash_string)?;
            }

            let key = derive_key(&hash_string)?;
            let key = Arc::new(key);
            let encrypt = app.action == Action::Encrypt;

            // Collect files
            let files: Vec<PathBuf> = WalkDir::new(&folder)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
                .filter(|e| {
                    let name = e.path().file_name().unwrap_or_default().to_string_lossy();
                    if name == LOCK_FILE_NAME {
                        return false;
                    }
                    if encrypt {
                        e.path().extension().map_or(true, |x| x != "enc")
                    } else {
                        e.path().extension().map_or(false, |x| x == "enc")
                    }
                })
                .map(|e| e.path().to_path_buf())
                .collect();

            let total = files.len();
            app.total_files = total;
            app.processed_files = 0;
            app.active_workers = 0;
            app.log.clear();
            app.stats_processed = 0;
            app.stats_failed = 0;
            app.stats_bytes = 0;
            app.current_files.clear();

            app.push_log(
                "🔑",
                format!("Vault: {}", folder.display()),
                Color::DarkGray,
            );
            app.push_log(
                if encrypt { "🔒" } else { "🔓" },
                format!(
                    "{} files to {}",
                    total,
                    if encrypt { "encrypt" } else { "decrypt" }
                ),
                Color::Cyan,
            );

            let (tx, rx) = mpsc::unbounded_channel::<FileResult>();
            app.result_rx = Some(rx);
            let active = Arc::new(Mutex::new(0usize));

            for path in files {
                loop {
                    let count = *active.lock().unwrap();
                    if count < CONCURRENCY {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                {
                    let mut count = active.lock().unwrap();
                    *count += 1;
                    app.active_workers += 1;
                }

                let display = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                app.current_files.push(display.clone());

                let tx2 = tx.clone();
                let key2 = Arc::clone(&key);
                let active2 = Arc::clone(&active);

                tokio::spawn(async move {
                    let size = tokio::fs::metadata(&path)
                        .await
                        .map(|m| m.len())
                        .unwrap_or(0);
                    let (ok, err_msg) = if encrypt {
                        match encrypt_file(&path, &key2).await {
                            Ok(_) => (true, None),
                            Err(e) => (false, Some(e.to_string())),
                        }
                    } else {
                        match decrypt_file(&path, &key2).await {
                            Ok(_) => (true, None),
                            Err(e) => (false, Some(e.to_string())),
                        }
                    };

                    {
                        let mut count = active2.lock().unwrap();
                        *count -= 1;
                    }

                    let _ = tx2.send(FileResult {
                        display,
                        size,
                        ok,
                        err: err_msg,
                    });
                });
            }

            app.screen = Screen::Processing;
        }
        KeyCode::BackTab => app.screen = Screen::PasswordEntry,
        _ => {}
    }
    Ok(())
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

fn derive_key(hash_string: &str) -> io::Result<[u8; 32]> {
    let parsed = PasswordHash::new(hash_string)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let binding = parsed.hash.expect("hash output");
    let hash_bytes = binding.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes[..32]);
    Ok(key)
}

fn random_hex_name() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

async fn encrypt_file(path: &Path, key: &[u8; 32]) -> io::Result<()> {
    let plaintext = fs::read(path).await?;
    let original_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no filename"))?
        .to_string_lossy();
    let name_bytes = original_name.as_bytes();
    let name_len = name_bytes.len() as u32;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key).expect("key length");
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut out = Vec::with_capacity(4 + name_bytes.len() + 12 + ciphertext.len());
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    let new_path = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{}.enc", random_hex_name()));
    fs::write(&new_path, out).await?;
    fs::remove_file(path).await?;
    Ok(())
}

async fn decrypt_file(path: &Path, key: &[u8; 32]) -> io::Result<()> {
    let contents = fs::read(path).await?;
    if contents.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file too short for header",
        ));
    }
    let name_len = u32::from_le_bytes(contents[..4].try_into().unwrap()) as usize;
    let header_end = 4 + name_len;
    if contents.len() < header_end + 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file too short for name+nonce",
        ));
    }

    let original_name = std::str::from_utf8(&contents[4..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid filename encoding"))?
        .to_string();
    let nonce_bytes = &contents[header_end..header_end + 12];
    let ciphertext = &contents[header_end + 12..];
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key).expect("key length");
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "decryption failed — wrong password?",
        )
    })?;

    let out_path = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&original_name);
    fs::write(&out_path, plaintext).await?;
    fs::remove_file(path).await?;
    Ok(())
}

// ─── UI ───────────────────────────────────────────────────────────────────────

fn ui(f: &mut ratatui::Frame, app: &App) {
    let size = f.size();
    f.render_widget(
        Block::default().style(Style::default().bg(Color::Rgb(10, 12, 18))),
        size,
    );

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(size);

    render_header(f, outer[0]);
    render_footer(f, outer[2], app.screen);

    match app.screen {
        Screen::FolderPicker => render_folder_picker(f, outer[1], app),
        Screen::PasswordEntry => render_password(f, outer[1], app, false),
        Screen::ConfirmPassword => render_password(f, outer[1], app, true),
        Screen::ActionPicker => render_action_picker(f, outer[1], app),
        Screen::Processing => render_processing(f, outer[1], app),
        Screen::Done => render_done(f, outer[1], app),
    }
}

fn render_header(f: &mut ratatui::Frame, area: Rect) {
    let title = Paragraph::new(Line::from(vec![
        Span::styled("  🛡  ", Style::default().fg(Color::Rgb(255, 200, 50))),
        Span::styled(
            "VAULT LOCKER",
            Style::default()
                .fg(Color::Rgb(255, 200, 50))
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::Rgb(40, 50, 70)))
            .border_type(BorderType::Plain),
    );
    f.render_widget(title, area);
}

fn render_footer(f: &mut ratatui::Frame, area: Rect, screen: Screen) {
    let hints = match screen {
        Screen::FolderPicker => " ↑↓ navigate  Enter: select  G: generate salt  Esc: quit",
        Screen::PasswordEntry => " Type password  Tab: show/hide  Enter: confirm  Esc: quit",
        Screen::ConfirmPassword => " Confirm password  Tab: show/hide  BackTab: back  Esc: quit",
        Screen::ActionPicker => " ←→ choose action  Enter: run  BackTab: back  Esc: quit",
        Screen::Processing => " Processing in parallel… please wait",
        Screen::Done => " Enter / q to exit",
    };
    f.render_widget(
        Paragraph::new(hints).style(Style::default().fg(Color::Rgb(70, 80, 100))),
        area,
    );
}

fn render_folder_picker(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let items: Vec<ListItem> = app
        .folders
        .iter()
        .map(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            let locked = p.join(LOCK_FILE_NAME).exists();
            let badge = if locked { " 🔒" } else { "   " };
            ListItem::new(Line::from(vec![
                Span::raw("  📁 "),
                Span::styled(
                    name.to_string(),
                    Style::default().fg(Color::Rgb(200, 210, 230)),
                ),
                Span::styled(badge, Style::default().fg(Color::Rgb(255, 200, 50))),
            ]))
        })
        .collect();

    let mut state = app.list_state.clone();
    let list = List::new(items)
        .block(
            Block::default()
                .title(Span::styled(
                    " Select Folder ",
                    Style::default()
                        .fg(Color::Rgb(255, 200, 50))
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Rgb(60, 80, 120))),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(30, 45, 80))
                .fg(Color::Rgb(100, 180, 255))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, cols[0], &mut state);

    let info = if let Some(folder) = app.selected_folder() {
        let file_count = WalkDir::new(folder)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .count();
        let enc_count = WalkDir::new(folder)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter(|e| e.path().extension().map_or(false, |x| x == "enc"))
            .count();
        let locked = folder.join(LOCK_FILE_NAME).exists();
        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Path    ", Style::default().fg(Color::Rgb(100, 110, 135))),
                Span::styled(
                    folder.display().to_string(),
                    Style::default().fg(Color::Rgb(200, 210, 230)),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Files   ", Style::default().fg(Color::Rgb(100, 110, 135))),
                Span::styled(
                    file_count.to_string(),
                    Style::default().fg(Color::Rgb(200, 210, 230)),
                ),
                Span::styled(
                    format!("  ({} encrypted)", enc_count),
                    Style::default().fg(Color::Rgb(255, 200, 50)),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Status  ", Style::default().fg(Color::Rgb(100, 110, 135))),
                if locked {
                    Span::styled(
                        "🔒 Vault exists",
                        Style::default().fg(Color::Rgb(255, 200, 50)),
                    )
                } else {
                    Span::styled(
                        "🟢 No vault (new)",
                        Style::default().fg(Color::Rgb(100, 220, 120)),
                    )
                },
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "  Active Salt ",
                    Style::default().fg(Color::Rgb(100, 110, 135)),
                ),
                Span::styled(
                    app.salt.clone(),
                    Style::default().fg(Color::Rgb(130, 210, 150)),
                ),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  No folders found.",
            Style::default().fg(Color::Rgb(120, 130, 150)),
        ))]
    };

    f.render_widget(
        Paragraph::new(info)
            .block(
                Block::default()
                    .title(Span::styled(
                        " System Context ",
                        Style::default().fg(Color::Rgb(100, 180, 255)),
                    ))
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Rgb(40, 60, 100))),
            )
            .wrap(Wrap { trim: true }),
        cols[1],
    );

    if let Some(err) = &app.password_error {
        if err.contains("salt") {
            let msg_area = Rect::new(area.x + 2, area.y + area.height - 2, area.width - 4, 1);
            f.render_widget(
                Paragraph::new(Span::styled(
                    format!(" {}", err),
                    Style::default()
                        .fg(Color::LightGreen)
                        .add_modifier(Modifier::BOLD),
                )),
                msg_area,
            );
        }
    }
}

fn render_password(f: &mut ratatui::Frame, area: Rect, app: &App, confirm: bool) {
    let popup_w = 54u16;
    let popup_h = 10u16;
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup_area = Rect::new(x, y, popup_w.min(area.width), popup_h.min(area.height));
    f.render_widget(Clear, popup_area);

    let title = if confirm {
        " Confirm Password "
    } else {
        " Enter Password "
    };
    let active_pw = if confirm {
        &app.confirm_password
    } else {
        &app.password
    };
    let display = if app.show_password {
        active_pw.clone()
    } else {
        "●".repeat(active_pw.len())
    };
    let show_hint = if app.show_password {
        "[Tab] Hide"
    } else {
        "[Tab] Show"
    };

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  Password: ",
                Style::default().fg(Color::Rgb(120, 130, 150)),
            ),
            Span::styled(
                display,
                Style::default()
                    .fg(Color::Rgb(200, 220, 255))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("█", Style::default().fg(Color::Rgb(100, 180, 255))),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", show_hint),
            Style::default().fg(Color::Rgb(80, 100, 130)),
        )),
        Line::from(""),
        Line::from(if let Some(err) = &app.password_error {
            if !err.contains("salt") {
                Span::styled(
                    format!("  {}", err),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )
            } else {
                Span::raw("")
            }
        } else {
            Span::raw("")
        }),
    ];

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title(Span::styled(
                    title,
                    Style::default()
                        .fg(Color::Rgb(255, 200, 50))
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Color::Rgb(80, 120, 200))),
        ),
        popup_area,
    );
}

fn render_action_picker(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let popup_w = 62u16;
    let popup_h = 12u16;
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup_area = Rect::new(x, y, popup_w.min(area.width), popup_h.min(area.height));
    f.render_widget(Clear, popup_area);

    let make_btn = |label: &str, icon: &str, active: bool| -> Vec<Span<'static>> {
        let (label, icon) = (label.to_string(), icon.to_string());
        if active {
            vec![
                Span::styled(
                    format!(" {} ", icon),
                    Style::default()
                        .fg(Color::Rgb(10, 12, 18))
                        .bg(Color::Rgb(255, 200, 50)),
                ),
                Span::styled(
                    format!(" {} ", label),
                    Style::default()
                        .fg(Color::Rgb(10, 12, 18))
                        .bg(Color::Rgb(255, 200, 50))
                        .add_modifier(Modifier::BOLD),
                ),
            ]
        } else {
            vec![
                Span::styled(
                    format!(" {} ", icon),
                    Style::default()
                        .fg(Color::Rgb(80, 90, 110))
                        .bg(Color::Rgb(25, 30, 45)),
                ),
                Span::styled(
                    format!(" {} ", label),
                    Style::default()
                        .fg(Color::Rgb(80, 90, 110))
                        .bg(Color::Rgb(25, 30, 45)),
                ),
            ]
        }
    };

    let mut row = vec![Span::raw("  ")];
    row.extend(make_btn("ENCRYPT (LOCK)", "🔒", app.action_index == 0));
    row.push(Span::raw("   "));
    row.extend(make_btn("DECRYPT (UNLOCK)", "🔓", app.action_index == 1));

    let folder_name = app
        .selected_folder()
        .map(|p| {
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        })
        .unwrap_or_default();

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Folder: ", Style::default().fg(Color::Rgb(120, 130, 150))),
            Span::styled(
                folder_name,
                Style::default()
                    .fg(Color::Rgb(200, 210, 230))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(row),
        Line::from(""),
        Line::from(Span::styled(
            format!("  ⚡ {} parallel workers", CONCURRENCY),
            Style::default().fg(Color::Rgb(100, 180, 100)),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Use ← → to switch, Enter to start",
            Style::default().fg(Color::Rgb(80, 100, 130)),
        )),
    ];

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title(Span::styled(
                    " Choose Action ",
                    Style::default()
                        .fg(Color::Rgb(255, 200, 50))
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Rgb(80, 120, 200))),
        ),
        popup_area,
    );

    if let Some(err) = &app.password_error {
        if !err.contains("salt") {
            let err_area = Rect::new(
                popup_area.x,
                popup_area.y + popup_area.height,
                popup_area.width,
                1,
            );
            f.render_widget(
                Paragraph::new(Span::styled(
                    format!("  ⚠ {}", err),
                    Style::default().fg(Color::Red),
                )),
                err_area,
            );
        }
    }
}

fn render_processing(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(4),
            Constraint::Min(0),
        ])
        .split(area);

    let pct = app.progress_pct();
    let label = format!(
        " {}/{} files · {} · {}% ",
        app.processed_files,
        app.total_files,
        format_size(app.stats_bytes, BINARY),
        pct
    );
    let verb = if app.action == Action::Encrypt {
        "Encrypting"
    } else {
        "Decrypting"
    };

    // 1. Progress Gauge widget
    f.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .title(Span::styled(
                        format!(" {} ", verb),
                        Style::default()
                            .fg(Color::Rgb(255, 200, 50))
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Rgb(60, 80, 120))),
            )
            .gauge_style(
                Style::default()
                    .fg(Color::Rgb(80, 200, 120))
                    .bg(Color::Rgb(25, 35, 50)),
            )
            .percent(pct)
            .label(label),
        rows[0],
    );

    // 2. Worker lines collector
    let worker_lines: Vec<Line> = {
        let mut lines: Vec<Line> = app
            .current_files
            .iter()
            .take(CONCURRENCY)
            .map(|name| {
                Line::from(vec![
                    Span::styled(" ⚡ ", Style::default().fg(Color::Rgb(255, 200, 50))),
                    Span::styled(name.clone(), Style::default().fg(Color::Rgb(180, 190, 210))),
                ])
            })
            .collect();
        while lines.len() < 2 {
            lines.push(Line::from(""));
        }
        lines
    };

    // 3. Active Workers display
    f.render_widget(
        Paragraph::new(worker_lines).block(
            Block::default()
                .title(Span::styled(
                    format!(" Active Workers ({}/{}) ", app.active_workers, CONCURRENCY),
                    Style::default().fg(Color::Rgb(100, 180, 255)),
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Rgb(40, 60, 95))),
        ),
        rows[1],
    );

    // 4. Activity Logs
    render_log(f, rows[2], app);
}

fn render_log(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let inner_h = area.height.saturating_sub(2) as usize;
    let skip = app.log.len().saturating_sub(inner_h);
    let items: Vec<ListItem> = app
        .log
        .iter()
        .skip(skip)
        .map(|e| {
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {} ", e.icon), Style::default().fg(e.color)),
                Span::styled(e.text.clone(), Style::default().fg(e.color)),
            ]))
        })
        .collect();
    f.render_widget(
        List::new(items).block(
            Block::default()
                .title(" Activity Log ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Rgb(40, 60, 90))),
        ),
        area,
    );
}

fn render_done(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);
    let verb = if app.action == Action::Encrypt {
        "Encryption"
    } else {
        "Decryption"
    };
    let icon = if app.action == Action::Encrypt {
        "🔒"
    } else {
        "🔓"
    };

    let summary = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {} {} Complete!", icon, verb),
            Style::default()
                .fg(Color::Rgb(100, 220, 120))
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  Files processed : ",
                Style::default().fg(Color::Rgb(120, 130, 150)),
            ),
            Span::styled(
                app.stats_processed.to_string(),
                Style::default()
                    .fg(Color::Rgb(200, 220, 255))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  Data handled : ",
                Style::default().fg(Color::Rgb(120, 130, 150)),
            ),
            Span::styled(
                format_size(app.stats_bytes, BINARY),
                Style::default()
                    .fg(Color::Rgb(200, 220, 255))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  Workers used : ",
                Style::default().fg(Color::Rgb(120, 130, 150)),
            ),
            Span::styled(
                format!("{} concurrent tasks", CONCURRENCY),
                Style::default()
                    .fg(Color::Rgb(100, 180, 100))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        if app.stats_failed > 0 {
            Line::from(vec![
                Span::styled(" Failed : ", Style::default().fg(Color::Rgb(120, 130, 150))),
                Span::styled(
                    app.stats_failed.to_string(),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ])
        } else {
            Line::from(Span::styled(
                " No errors ✓",
                Style::default().fg(Color::Rgb(100, 220, 120)),
            ))
        },
    ];

    f.render_widget(
        Paragraph::new(summary)
            .block(
                Block::default()
                    .title(" Summary ")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Double)
                    .border_style(Style::default().fg(Color::Rgb(100, 220, 120))),
            )
            .alignment(Alignment::Left),
        rows[0],
    );
    render_log(f, rows[1], app);
}
