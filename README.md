# Vault Locker TUI 🔒⚡

Welcome to **Vault Locker TUI**—an industrial-grade, multi-threaded Command Line Interface & Terminal User Interface utility built entirely in Rust. Securing directories containing massive quantities of files or raw gigabytes of data doesn't have to mean watching a frozen terminal.

This application couples a slick asynchronous frame engine built on **Ratatui** and **Crossterm** with a high-throughput **Tokio runtime**, distributing encryption workloads across worker pools running concurrent cryptographic tasks simultaneously.

Your files are transformed securely into scrambled byte blocks using authenticated **AES-256-GCM** encryption and brute-force resistant **Argon2** key-stretching, all while rendering live data logs, bandwidth numbers, and responsive progress metrics in real time.

## 🕹️ Dashboard Experience

```text
 🛡  VAULT LOCKER  vX.X.X ────────────────────────────────────────────────────────
 ┌── Select Folder ─────────────────────┐┌── Folder Info ──────────────────┐
 │ ▶ FolderPicker                       ││                                 │
 │   bashadi-agency                     ││   Path   ./FolderPicker         │
 │   TaskSentinel                       ││   Files  1,420 (0 encrypted)  │
 │   boot                         🔒    ││   Status 🔒 Vault exists        │
 │                                      ││   Workers 8 concurrent tasks    │
 └──────────────────────────────────────┘└─────────────────────────────────┘
 ┌── Live Processing Progress ─────────────────────────────────────────────┐
 │ ████████████████████████████████████████████████░░░░░░░░░░░ [ 81% ]     │
 └─────────────────────────────────────────────────────────────────────────┘
  ↑↓ navigate   Enter: select   Esc: quit
```

## 🚀 Engine Architecture & Performance Layout

Vault Locker handles file encryption using an asynchronous, event-driven pattern designed for modern multi-core storage architecture:

### 1. Multi-Threaded Async Worker Pools

* **Tokio Pipeline Architecture:** The application scans target nodes recursively using `WalkDir`. Instead of a linear loop, file items are dispatched over an asynchronous job cluster bounded by a strict allocation limit (`CONCURRENCY = 8`).
* **Non-Blocking Channel Synchronization:** Workers pass performance telemetry up to the visual thread via an unbounded Single-Consumer Multi-Producer (`mpsc::unbounded_channel`) ring. The UI loops every `50ms` (`TICK_RATE`), draining the event pipe to update indicators without blocking file system operations.

### 2. File Obfuscation & Envelope Metadata Format

* **Cryptographic Name Shuffling:** To prevent side-channel information exposure via structural path leakage, the original directory architecture is flattened. File targets inside a folder have their paths randomized using a high-entropy 16-byte hex generator.
* **Envelope Format:** Files are encrypted with individual 12-byte initialization vectors (**Nonces**). The metadata needed to safely reconstruct the file structure later is packed directly into the binary file envelope before the encrypted ciphertext:

```text
┌──────────────────┬─────────────────────┬─────────────┬────────────────────────┐
│ Name Len (4B LE) │   Original Filename  │ Nonce (12B) │  Encrypted Ciphertext  │
└──────────────────┴─────────────────────┴─────────────┴────────────────────────┘
```

### 3. Permanent Directory Binding Lock

* When a folder structure is locked for the first time, an immutable `.vault_lock` state signature is written directly into its root path containing a calculated Argon2 metadata signature.
* Any consecutive manipulation attempts verify the password against this block using strict validation rules. **The password cannot be modified or updated**, preventing malicious tampering.

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
wget https://github.com/imrany/vault-locker/releases/latest/download/vault-v0.3.0-linux-x86_64.deb

# Install package through standard packaging engines
sudo apt install ./vault-v0.3.0-linux-x86_64.deb
```

#### Option B: Standalone Compressed Tarball (`.tar.gz`)

```bash
# Download the high-speed static production container binary layout
wget https://github.com/imrany/vault-locker/releases/latest/download/vault-linux-v0.3.0.tar.gz

# Extract context elements and bind execute privileges to your local binaries path
tar -xzvf vault-linux-v0.3.0.tar.gz
sudo mv vault /usr/local/bin/vault
```

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

The high-performance compiled binary container will generate inside `./target/release/vault`.

3. Launch your local engine dashboard layout frame:

```bash
cargo run --release
```

## 🧹 Clean Uninstallation

If you need to completely remove Vault Locker, its desktop metadata layers, and system-wide configurations, run the one-liner script below or use the manual package manager commands:

### One-Liner Uninstallation Script

```bash
curl -fsSL https://raw.githubusercontent.com/imrany/vault-locker/refs/heads/main/scripts/install.sh | bash -- uninstall
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
```



## 🕵️‍♂️ TARGET CHALLENGE: Operation Boot Sector!

Are your cryptographic credentials working correctly? Let's verify the operational capacity of your build with a data restoration exercise.

See [Challenge](./boot/challenge.md)
