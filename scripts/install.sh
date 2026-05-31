#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  vault installer — Linux & macOS
#  https://github.com/imrany/vault-locker
#
#  One-liner (auto-detects OS, downloads the right installer):
#    curl -fsSL https://raw.githubusercontent.com/imrany/vault-locker/main/scripts/install.sh | bash
#
#  Options:
#    --version v0.5.0   install a specific release (default: latest)
#    --prefix  /path    override install prefix    (default: /usr/local)
#    --binary-only      skip .deb/.dmg, install bare binary only
#    --uninstall        remove vault from this system
#
#  Environment:
#    PREFIX=$HOME/.local   user-only install, no sudo needed
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO="imrany/vault-locker"
APP="vault"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
SHARE_DIR="$PREFIX/share"
DESKTOP_DIR="$SHARE_DIR/applications"
VERSION=""
BINARY_ONLY=false

# ── colours ───────────────────────────────────────────────────────────────────
if [ -t 1 ] && command -v tput &>/dev/null && tput colors &>/dev/null; then
    BOLD='\033[1m'; GREEN='\033;32m'; YELLOW='\033[1;33m'
    RED='\033[0;31m'; CYAN='\033[0;36m'; DIM='\033[2m'; RESET='\033[0m'
else
    BOLD=''; GREEN=''; YELLOW=''; RED=''; CYAN=''; DIM=''; RESET=''
fi

say()    { printf "${GREEN}==>${RESET}${BOLD} %s${RESET}\n" "$*"; }
info()   { printf "    ${DIM}%s${RESET}\n" "$*"; }
warn()   { printf "${YELLOW}  ! %s${RESET}\n" "$*"; }
die()    { printf "${RED}   ✗ error:${RESET} %s\n" "$*" >&2; exit 1; }
header() { printf "\n${BOLD}${CYAN}%s${RESET}\n" "$*"; }

# ── parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --uninstall)    UNINSTALL=true;     shift ;;
        --binary-only)  BINARY_ONLY=true;    shift ;;
        --version|-v)   VERSION="$2";         shift 2 ;;
        --prefix)       PREFIX="$2"
                        BIN_DIR="$PREFIX/bin"
                        SHARE_DIR="$PREFIX/share"
                        DESKTOP_DIR="$SHARE_DIR/applications"
                        shift 2 ;;
        --help|-h)
            sed -n '3,12p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *)  die "Unknown argument: $1 (try --help)" ;;
    esac
done
UNINSTALL="${UNINSTALL:-false}"

# ── detect OS ─────────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  PLATFORM="linux";  EXT="tar.gz" ;;
    Darwin) PLATFORM="macos";  EXT="tar.gz" ;;
    *)      die "Unsupported OS '$OS'. On Windows build from source." ;;
esac

case "$ARCH" in
    x86_64|amd64) ;;
    arm64|aarch64)
        if [[ "$PLATFORM" == "macos" ]]; then
            warn "No native arm64 build yet — x86_64 binary runs under Rosetta 2."
        else
            die "No arm64 Linux build available. Build from source: cargo build --release"
        fi ;;
    *) warn "Unknown arch '$ARCH' — trying x86_64 binary." ;;
esac

# ── sudo helper ───────────────────────────────────────────────────────────────
SUDO=""
setup_sudo() {
    if [[ ! -d "$BIN_DIR" ]] || [[ ! -w "$BIN_DIR" ]]; then
        if command -v sudo &>/dev/null; then
            SUDO="sudo"
            info "sudo will be used to write to $BIN_DIR"
        else
            die "Cannot write to $BIN_DIR. Run as root, use sudo, or set PREFIX to a writable path:\n    PREFIX=\$HOME/.local bash install.sh"
        fi
    fi
}

# ── downloader ────────────────────────────────────────────────────────────────
if   command -v curl &>/dev/null; then DL="curl -fsSL";  DL_O="curl -fSL --progress-bar -o"
elif command -v wget &>/dev/null; then DL="wget -qO-";  DL_O="wget --progress=bar:force -O"
else die "curl or wget is required. Install one and re-run."
fi

# ── uninstall ─────────────────────────────────────────────────────────────────
if $UNINSTALL; then
    header "Uninstalling vault"
    setup_sudo
    $SUDO rm -f "$BIN_DIR/$APP"
    $SUDO rm -f "$DESKTOP_DIR/$APP.desktop"
    [[ "$PLATFORM" == "macos" ]] && $SUDO rm -rf "/Applications/vault.app" && say "Removed /Applications/vault.app"
    command -v update-desktop-database &>/dev/null && $SUDO update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
    say "vault uninstalled cleanly."
    exit 0
fi

# ── resolve version ───────────────────────────────────────────────────────────
if [[ -z "$VERSION" ]]; then
    info "Fetching latest release from GitHub…"
    VERSION="$($DL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    [[ -n "$VERSION" ]] || die "Could not determine latest version. Pass --version vX.Y.Z manually."
fi
[[ "$VERSION" == v* ]] || VERSION="v${VERSION}"
VER_NUM="${VERSION#v}"

BASE_URL="https://github.com/$REPO/releases/download/$VERSION"

# ── print banner ─────────────────────────────────────────────────────────────
header "vault $VERSION · $PLATFORM"
echo ""

# ──────────────────────────────────────────────────────────────────────────────
# Runtime Scratch Area
# ──────────────────────────────────────────────────────────────────────────────
TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_WORK"' EXIT

download_and_verify() {
    local url="$1" dest="$2" sha_url="$3"
    info "Downloading $(basename "$dest")…"
    $DL_O "$dest" "$url" || die "Download failed: $url"

    local sha_dest="${dest}.sha256"
    local skip=false
    $DL_O "$sha_dest" "$sha_url" 2>/dev/null || { warn "Checksum file not found — skipping verification."; skip=true; }

    if ! $skip; then
        local expected actual
        expected="$(awk '{print tolower($1)}' "$sha_dest")"
        if   command -v sha256sum &>/dev/null; then actual="$(sha256sum "$dest" | awk '{print $1}')"
        elif command -v shasum    &>/dev/null; then actual="$(shasum -a 256 "$dest" | awk '{print $1}')"
        else warn "No sha256sum/shasum — skipping checksum."; skip=true; fi

        if ! $skip; then
            [[ "$expected" == "$actual" ]] || \
                die "Checksum mismatch!\n  expected: $expected\n  got:      $actual"
            info "✓ Checksum verified (${actual:0:16}…)"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#  LINUX ARCHITECTURE TARGETS
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$PLATFORM" == "linux" ]]; then
    DEB_NAME="vault-${VERSION}-linux-x86_64.deb"
    DEB_URL="$BASE_URL/$DEB_NAME"

    # Auto-detect fallback options
    USE_DEB=false
    if ! $BINARY_ONLY && command -v dpkg &>/dev/null; then
        if curl -fsIo /dev/null "$DEB_URL" 2>/dev/null || wget -q --spider "$DEB_URL" 2>/dev/null; then
            USE_DEB=true
        fi
    fi

    if $USE_DEB; then
        say "Installing via .deb package Manager..."
        DEB_PATH="$TMPDIR_WORK/$DEB_NAME"
        download_and_verify "$DEB_URL" "$DEB_PATH" "$DEB_URL.sha256"

        say "Running system installation package logic…"
        if [[ -w /usr/bin ]]; then
            dpkg -i "$DEB_PATH"
        else
            sudo dpkg -i "$DEB_PATH"
        fi
        say "vault $VERSION deployed using native package constraints."
        command -v update-desktop-database &>/dev/null && { sudo update-desktop-database /usr/share/applications 2>/dev/null || true; }
    else
        setup_sudo
        ARCHIVE="vault-linux-${VERSION}.tar.gz"
        ARCHIVE_PATH="$TMPDIR_WORK/$ARCHIVE"
        download_and_verify "$BASE_URL/$ARCHIVE" "$ARCHIVE_PATH" "$BASE_URL/$ARCHIVE.sha256"

        say "Unpacking local package payload..."
        tar -xzf "$ARCHIVE_PATH" -C "$TMPDIR_WORK"
        chmod +x "$TMPDIR_WORK/vault"

        $SUDO mkdir -p "$BIN_DIR"
        $SUDO install -m755 "$TMPDIR_WORK/vault" "$BIN_DIR/vault"
        say "Binary targets assigned to path -> $BIN_DIR/vault"

        DESKTOP_URL="https://raw.githubusercontent.com/$REPO/main/vault.desktop"
        $DL_O "$TMPDIR_WORK/vault.desktop" "$DESKTOP_URL" 2>/dev/null || true

        if [[ -f "$TMPDIR_WORK/vault.desktop" ]]; then
            $SUDO mkdir -p "$DESKTOP_DIR"
            $SUDO install -Dm644 "$TMPDIR_WORK/vault.desktop" "$DESKTOP_DIR/vault.desktop"
            say "Sourced desktop shortcut to system path -> $DESKTOP_DIR/vault.desktop"
            command -v update-desktop-database &>/dev/null && $SUDO update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
#  MACOS ARCHITECTURE TARGETS
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$PLATFORM" == "macos" ]]; then
    DMG_NAME="vault-${VERSION}-macos.dmg"
    DMG_URL="$BASE_URL/$DMG_NAME"

    USE_DMG=false
    if ! $BINARY_ONLY; then
        if curl -fsIo /dev/null "$DMG_URL" 2>/dev/null || wget -q --spider "$DMG_URL" 2>/dev/null; then
            USE_DMG=true
        fi
    fi

    if $USE_DMG; then
        say "Installing via native App Container (.dmg)"
        DMG_PATH="$TMPDIR_WORK/$DMG_NAME"
        download_and_verify "$DMG_URL" "$DMG_PATH" "$DMG_URL.sha256"

        MOUNT_DIR="$(mktemp -d)"
        hdiutil attach "$DMG_PATH" -mountpoint "$MOUNT_DIR" -nobrowse -quiet

        APP_SRC="$(find "$MOUNT_DIR" -name "vault.app" -maxdepth 2 | head -1)"
        if [[ -n "$APP_SRC" ]]; then
            rm -rf /Applications/vault.app
            cp -R "$APP_SRC" /Applications/vault.app
            say "Application configuration mapped to root -> /Applications/vault.app"
        else
            warn "DMG execution context failed — shifting tracking to bare binaries."
            USE_DMG=false
        fi
        hdiutil detach "$MOUNT_DIR" -quiet || true
        rm -rf "$MOUNT_DIR"
    fi

    if ! $USE_DMG; then
        say "Building localized app envelopes..."
        ARCHIVE="vault-macos-${VERSION}.tar.gz"
        ARCHIVE_PATH="$TMPDIR_WORK/$ARCHIVE"
        download_and_verify "$BASE_URL/$ARCHIVE" "$ARCHIVE_PATH" "$BASE_URL/$ARCHIVE.sha256"

        tar -xzf "$ARCHIVE_PATH" -C "$TMPDIR_WORK"
        chmod +x "$TMPDIR_WORK/vault"

        APP_BUNDLE="$TMPDIR_WORK/vault.app"
        mkdir -p "$APP_BUNDLE/Contents/MacOS"
        mkdir -p "$APP_BUNDLE/Contents/Resources"
        cp "$TMPDIR_WORK/vault" "$APP_BUNDLE/Contents/MacOS/vault"

        cat > "$APP_BUNDLE/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleName</key><string>vault</string>
    <key>CFBundleDisplayName</key><string>vault</string>
    <key>CFBundleIdentifier</key><string>dev.vault.app</string>
    <key>CFBundleVersion</key><string>$VER_NUM</string>
    <key>CFBundleShortVersionString</key><string>$VER_NUM</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleExecutable</key><string>vault</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>LSMinimumSystemVersion</key><string>10.14</string>
</dict></plist>
PLIST

        rm -rf /Applications/vault.app
        cp -R "$APP_BUNDLE" /Applications/vault.app
        say "Local App structure bundled -> /Applications/vault.app"
    fi

    setup_sudo
    $SUDO mkdir -p "$BIN_DIR"
    $SUDO install -m755 /Applications/vault.app/Contents/MacOS/vault "$BIN_DIR/vault"
    say "Symlink configurations attached safely -> $BIN_DIR/vault"

    LSREG="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
    [[ -x "$LSREG" ]] && "$LSREG" -f /Applications/vault.app 2>/dev/null || true
fi

# ── PATH verification ─────────────────────────────────────────────────────────
if ! command -v vault &>/dev/null 2>&1; then
    echo ""
    warn "$BIN_DIR is currently excluded from your active environment path."
    warn "Append this statement to your profile schema (~/.bashrc or ~/.zshrc):"
    warn "    export PATH=\"\$PATH:$BIN_DIR\""
fi

echo ""
printf "${GREEN}  ✓ vault ${VERSION} successfully compiled & deployed.${RESET}\n"
echo ""
printf "  ${CYAN}Execute:${RESET}    vault\n"
echo ""
