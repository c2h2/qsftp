#!/bin/sh
# QSFTP Installer - SFTP/SCP over QUIC (UDP)
# Usage: curl -fsSL https://github.com/c2h2/qsftp/releases/latest/download/install.sh | sh
#
# Environment variables:
#   QSFTP_VERSION   - specific version to install (default: latest)
#   INSTALL_DIR     - binary install path (default: /usr/local/bin)
#   SKIP_SERVICE    - set to 1 to skip systemd service setup

set -eu

REPO="c2h2/qsftp"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
SKIP_SERVICE="${SKIP_SERVICE:-0}"
DEFAULT_PORT=1022

# --- Helpers ---

info()  { printf '  \033[1;34m→\033[0m %s\n' "$*"; }
ok()    { printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
warn()  { printf '  \033[1;33m!\033[0m %s\n' "$*"; }
error() { printf '  \033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        error "Required command not found: $1"
    fi
}

detect_arch() {
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)   arch="x86_64" ;;
        aarch64|arm64)   arch="aarch64" ;;
        *)               error "Unsupported architecture: $arch" ;;
    esac
    echo "$arch"
}

detect_os() {
    os=$(uname -s)
    case "$os" in
        Linux)   os="linux" ;;
        Darwin)  os="darwin" ;;
        *)       error "Unsupported OS: $os" ;;
    esac
    echo "$os"
}

get_latest_version() {
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//'
    elif command -v wget > /dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//'
    else
        error "Neither curl nor wget found"
    fi
}

download() {
    url="$1"
    dest="$2"
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url"
    elif command -v wget > /dev/null 2>&1; then
        wget -qO "$dest" "$url"
    fi
}

# --- Main ---

main() {
    printf '\n\033[1m  QSFTP Installer\033[0m\n'
    printf '  SFTP/SCP over QUIC (UDP)\n\n'

    # Detect platform
    OS=$(detect_os)
    ARCH=$(detect_arch)
    info "Platform: ${OS}-${ARCH}"

    # Determine version
    if [ -n "${QSFTP_VERSION:-}" ]; then
        VERSION="$QSFTP_VERSION"
    else
        info "Fetching latest version..."
        VERSION=$(get_latest_version)
    fi
    [ -z "$VERSION" ] && error "Could not determine version"
    info "Version: $VERSION"

    # Build download URL
    TARBALL="qsftp-${VERSION}-${ARCH}-${OS}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"
    info "Downloading ${URL}"

    # Download and extract
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    download "$URL" "${TMPDIR}/${TARBALL}"
    tar -xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

    # Install binaries
    BINARIES="qsftp-server qsftp qscp"
    info "Installing to ${INSTALL_DIR}/"

    if [ -w "$INSTALL_DIR" ]; then
        for bin in $BINARIES; do
            if [ -f "${TMPDIR}/${bin}" ]; then
                install -m 755 "${TMPDIR}/${bin}" "${INSTALL_DIR}/${bin}"
                ok "Installed ${bin}"
            fi
        done
    else
        warn "Need root to install to ${INSTALL_DIR}"
        for bin in $BINARIES; do
            if [ -f "${TMPDIR}/${bin}" ]; then
                sudo install -m 755 "${TMPDIR}/${bin}" "${INSTALL_DIR}/${bin}"
                ok "Installed ${bin}"
            fi
        done
    fi

    # Verify
    if command -v qsftp-server > /dev/null 2>&1; then
        ok "qsftp-server is available in PATH"
    else
        warn "${INSTALL_DIR} may not be in your PATH"
        # Add to PATH via /etc/profile.d if possible
        PROFILE_SCRIPT="/etc/profile.d/qsftp.sh"
        if [ -d "/etc/profile.d" ]; then
            EXPORT_LINE="export PATH=\"${INSTALL_DIR}:\$PATH\""
            if [ -w "/etc/profile.d" ]; then
                echo "$EXPORT_LINE" > "$PROFILE_SCRIPT"
            else
                echo "$EXPORT_LINE" | sudo tee "$PROFILE_SCRIPT" > /dev/null
            fi
            ok "Added ${INSTALL_DIR} to PATH in ${PROFILE_SCRIPT}"
            info "Run 'source ${PROFILE_SCRIPT}' or start a new shell"
        fi
    fi

    # Install systemd service
    if [ "$SKIP_SERVICE" = "1" ]; then
        info "Skipping systemd service setup (SKIP_SERVICE=1)"
    elif [ "$OS" != "linux" ]; then
        info "Skipping systemd service (not Linux)"
    elif ! command -v systemctl > /dev/null 2>&1; then
        info "Skipping systemd service (systemctl not found)"
    else
        install_service
    fi

    printf '\n\033[1m  Installation complete!\033[0m\n\n'
    printf '  Usage:\n'
    printf '    qsftp-server              Start server on :1022\n'
    printf '    qsftp user@host           Interactive SFTP session\n'
    printf '    qscp file user@host:path  Copy files\n\n'

    if [ "$SKIP_SERVICE" != "1" ] && [ "$OS" = "linux" ] && command -v systemctl > /dev/null 2>&1; then
        printf '  Service:\n'
        printf '    sudo systemctl start qsftp-server\n'
        printf '    sudo systemctl enable qsftp-server   # start on boot\n'
        printf '    sudo journalctl -u qsftp-server -f   # view logs\n\n'
    fi
}

install_service() {
    SERVICE_FILE="/etc/systemd/system/qsftp-server.service"
    info "Installing systemd service..."

    SERVICE_CONTENT="[Unit]
Description=QSFTP Server - SFTP/SCP over QUIC (UDP)
After=network.target
Documentation=https://github.com/${REPO}

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/qsftp-server --listen [::]:${DEFAULT_PORT} --listen 0.0.0.0:${DEFAULT_PORT}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
ReadWritePaths=/

[Install]
WantedBy=multi-user.target
"

    if [ -w "/etc/systemd/system" ]; then
        printf '%s' "$SERVICE_CONTENT" > "$SERVICE_FILE"
    else
        printf '%s' "$SERVICE_CONTENT" | sudo tee "$SERVICE_FILE" > /dev/null
    fi
    ok "Created ${SERVICE_FILE}"

    # Open firewall port if ufw is present
    if command -v ufw > /dev/null 2>&1; then
        info "Opening UDP port ${DEFAULT_PORT} in ufw..."
        sudo ufw allow "${DEFAULT_PORT}/udp" > /dev/null 2>&1 && ok "Firewall rule added (${DEFAULT_PORT}/udp)" || warn "Could not add firewall rule"
    fi

    # Reload systemd
    if [ -w "/etc/systemd/system" ]; then
        systemctl daemon-reload
    else
        sudo systemctl daemon-reload
    fi
    ok "Systemd daemon reloaded"

    info "Run 'sudo systemctl start qsftp-server' to start"
}

main "$@"
