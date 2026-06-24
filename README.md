# Vault Locker 🔒⚡

**Vault Locker** — A Command Line Interface (CLI) & Terminal User Interface (TUI) utility designed to encrypt and decrypt contents inside a target folder.

Built on **Ratatui**, **Crossterm** and **Tokio runtime** which distributes encryption workloads across worker pools running concurrent cryptographic tasks simultaneously.

Files are transformed into scrambled byte blocks using authenticated **AES-256-GCM** encryption and brute-force resistant **Argon2** key-stretching, all while rendering live data logs, bandwidth numbers, and responsive progress metrics in real time.

## 🕹️ Dashboard Experience

```text
 🛡  VAULT LOCKER  v0.5.1 ───────────────────────────────────────────────────────
 ┌── Select Folder ─────────────────────┐┌── Folder Info ──────────────────┐
 │ ▶ bashadi-agency                     ││                                 │
 │   TaskSentinel                       ││   Path    ./bashadi-agency      │
 │   boot                         🔒    ││   Files   1,420 (0 encrypted)   │
 │                                      ││   Status  🔒 Vault exists       │
 │                                      ││   Workers 8 concurrent tasks    │
 └──────────────────────────────────────┘└─────────────────────────────────┘
 ┌── Active Workers (2/8) ─────────────────────────────────────────────────┐
 │  ⚡ core_backend.rs                                                      │
 │  ⚡ index.ts                                                             │
 └─────────────────────────────────────────────────────────────────────────┘
  ↑↓ navigate   Enter: select   Esc: quit
```

## 🚀 Engine Architecture & Performance Layout

Vault Locker handles file encryption using an asynchronous, event-driven pattern designed for modern multi-core architecture:

### 1. Multi-Threaded Async Worker Pools

* **Tokio Pipeline Architecture:** The application scans target nodes recursively using `WalkDir`. Instead of a linear loop, file items are dispatched over an asynchronous job cluster bounded by a strict allocation limit (`CONCURRENCY = 8`).
* **Non-Blocking Channel Synchronization:** Workers pass performance telemetry up to the visual thread via an unbounded Single-Consumer Multi-Producer (`mpsc::unbounded_channel`) ring. The UI loops every `50ms` (`TICK_RATE = 50ms`), draining the event pipe to update indicators without blocking file system operations.

### 2. File Obfuscation & Envelope Metadata Format

* **Cryptographic Name Shuffling:** To prevent side-channel information exposure via structural path leakage, the original directory architecture is flattened. File targets inside a folder have their paths randomized using a high-entropy 16-byte hex generator.
* **Envelope Format:** Files are encrypted with individual 12-byte initialization vectors (**Nonces**). The metadata needed to safely reconstruct the file structure later is packed directly into the binary file envelope before the encrypted ciphertext:

```text
┌──────────────────┬─────────────────────┬─────────────┬────────────────────────┐
│ Name Len (4B LE) │   Original Filename  │ Nonce (12B) │   Encrypted Ciphertext  │
└──────────────────┴─────────────────────┴─────────────┴────────────────────────┘
```

### 3. Permanent Directory Binding Lock

* When a folder structure is locked for the first time, an immutable `.vault_lock` state signature is written directly into its root path containing a calculated Argon2 hash string.
* Any consecutive manipulation attempts verify the password against this block using strict validation rules. **The password cannot be modified or updated**, preventing malicious tampering.

### 4. Smart Configuration Space

The system automatically senses its environment to resolve its operational layout using a cascading configuration lookup path:

* **Development Mode:** Checks for a local `.vault_config` file directly in the current executing path context.
* **Production Sandbox Fallback:** If absent, it safely shifts to system standard layout nodes (e.g., `~/.config/vault_locker/.vault_config` or `%USERPROFILE%\.config\vault_locker\.vault_config` on windows ), building nested parent nodes cleanly without throwing environment faults.


## 🛠️ Local Engine Compilation & Development Build

If you are expanding the TUI dashboard layout configuration or rewriting target core crypto blocks, build your dependencies completely from the workspace source block. Ensure you have the latest stable Rust toolchain configured on your machine (`Ubuntu 22.04 LTS` or higher recommended).

1. Move directly into your current workspace folder:

```bash
cd vault_locker
```

2. Instruct `cargo` to run profile optimizations, layout flattening, and dead-code stripping during compilation:

```bash
cargo build --release
```

The high-performance compiled binary will generate inside `./target/release/vault`.

### Running the interactive TUI Dashboard

Launch your local engine dashboard layout frame in fullscreen mode with an active directory layout scanning mechanism:

```bash
cargo run --release
```

### Headless CLI Engine Routing (Automated Environments)

If argument patterns are directly fed, the engine skips the alternate screen initialization sequence entirely and pipes progress tracking cleanly to standard output streams.

* **Encrypting a Target Folder:**

```bash
cargo run -- encrypt /path/to/target --password YourSecretPassphrase123
```

* **Decrypting a Target Folder:**

```bash
cargo run -- decrypt /path/to/target --password YourSecretPassphrase123
```

## ⚡ Quick Production Installation

For modern standard Linux environments (`Ubuntu / Debian / Mint`), use our high-speed, authenticated delivery channels to get up and running instantly.

### 1. Automated Script Installation (Recommended)

Execute this command in your local machine terminal to query GitHub API asset metadata, pull the latest compiled binary archive automatically, map it into local target binaries, and link global desktop system references:

```bash
curl -fsSL https://raw.githubusercontent.com/imrany/vault-locker/refs/heads/main/scripts/install.sh | bash
```

### 2. Manual Package Installation Flow

If you prefer running sandboxed manual packages, fetch the target elements manually from the GitHub Release Registry page:

#### Option A: Native Debian Package Platform (`.deb`)

```bash
# Fetch the compiled package distribution binary map
wget https://github.com/imrany/vault-locker/releases/latest/download/vault-v0.5.1-linux-x86_64.deb

# Install package through standard packaging engines
sudo apt install ./vault-v0.5.1-linux-x86_64.deb
```

#### Option B: Standalone Compressed Tarball (`.tar.gz`)

```bash
# Download the high-speed static production container binary layout
wget https://github.com/imrany/vault-locker/releases/latest/download/vault-linux-v0.5.1.tar.gz

# Extract context elements and bind execute privileges to your local binaries path
tar -xzvf vault-linux-v0.5.1.tar.gz
sudo mv vault /usr/local/bin/vault
```

## 🧹 Clean Uninstallation

If you need to completely remove Vault Locker, its desktop metadata layers, and system-wide configurations, run the one-liner script below or use the manual package manager commands:

### One-Liner Uninstallation Script

```bash
curl -fsSL https://raw.githubusercontent.com/imrany/vault-locker/refs/heads/main/scripts/install.sh | bash -s -- uninstall
```

### Manual Package Clean-up Commands

* If installed via `.deb` package manager:

```bash
sudo apt remove --purge vault
```

* If installed via binary tarball layout:

```bash
sudo rm -f /usr/local/bin/vault
sudo rm -f /usr/share/applications/vault.desktop
sudo rm -f ~/.config/vault_locker/.vault_config
```


## 🕵️‍♂️ TARGET CHALLENGE: Operation Boot Sector!

Are your cryptographic credentials working correctly? Let's verify the operational capacity of your build with a data restoration exercise.

See [Challenge](https://www.google.com/search?q=./boot/challenge.md)
