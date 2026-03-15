#!/bin/bash
# Build and install qsftp binaries locally + set up systemd service
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARIES="qsshd qsftp qscp qssh"
DEFAULT_PORT=1022
SERVICE_NAME="qsshd"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo "==> Building qsftp (release)..."
cargo build --release

echo "==> Installing to ${INSTALL_DIR}/"
for bin in $BINARIES; do
    src="target/release/${bin}"
    if [ ! -f "$src" ]; then
        echo "  SKIP ${bin} (not found)"
        continue
    fi
    sudo install -m 755 "$src" "${INSTALL_DIR}/${bin}"
    echo "  OK   ${bin}"
done

echo "==> Done. Installed: $(echo $BINARIES | tr ' ' ',')"

# Install systemd service unit
echo "==> Installing systemd service..."
sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=QSFTP Server - SFTP/SCP/SSH over QUIC (UDP)
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/qsshd --listen 0.0.0.0:${DEFAULT_PORT}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
ReadWritePaths=/

[Install]
WantedBy=multi-user.target
EOF
echo "  OK   ${SERVICE_FILE}"

sudo systemctl daemon-reload

# Restart or start the service
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "==> Restarting ${SERVICE_NAME}..."
    sudo systemctl restart "$SERVICE_NAME"
else
    echo "==> Starting ${SERVICE_NAME}..."
    sudo systemctl start "$SERVICE_NAME"
fi

# Enable on boot
sudo systemctl enable --quiet "$SERVICE_NAME" 2>/dev/null

# Verify
sleep 0.5
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "  OK   ${SERVICE_NAME} running ($(systemctl show -p MainPID --value $SERVICE_NAME))"
else
    echo "  WARN ${SERVICE_NAME} failed to start. Check: sudo journalctl -u ${SERVICE_NAME} -n 20"
fi

echo "==> Service commands:"
echo "     sudo systemctl status ${SERVICE_NAME}"
echo "     sudo journalctl -u ${SERVICE_NAME} -f"
