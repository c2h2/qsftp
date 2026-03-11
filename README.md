# qsftp

SFTP and SCP reimplemented over **QUIC** (UDP). Drop-in replacements for `sftp` and `scp` that use the QUIC transport protocol instead of TCP/SSH.

## Why QUIC?

- **Faster connection setup** -- 0-RTT and 1-RTT handshakes vs TCP+TLS+SSH multi-round-trip
- **Better on lossy networks** -- no head-of-line blocking; individual streams recover independently
- **UDP-based** -- works through more NAT configurations, avoids TCP-level throttling
- **Built-in encryption** -- TLS 1.3 baked into the protocol

## Performance

Benchmarked on localhost with a 1 GiB file:

| Direction | Throughput |
|-----------|-----------|
| Upload    | ~700-800 MiB/s |
| Download  | ~450-650 MiB/s |

256 KiB chunk size, 4 MiB stream window, 16 MiB connection window.

## Quick Install

```sh
curl -fsSL https://github.com/c2h2/qsftp/releases/latest/download/install.sh | sh
```

This installs three binaries (`qsftp-server`, `qsftp`, `qscp`) to `/usr/local/bin` and optionally sets up a systemd service.

Environment variables:
- `INSTALL_DIR` -- install path (default: `/usr/local/bin`)
- `QSFTP_VERSION` -- pin a specific version (default: latest)
- `SKIP_SERVICE=1` -- skip systemd service setup

## Build from Source

Requires Rust 1.70+ and system dependencies for PAM:

```sh
# Debian/Ubuntu
sudo apt install libpam0g-dev libclang-dev

# Build
cargo build --release

# Binaries in target/release/
#   qsftp-server  - server daemon
#   qsftp         - interactive SFTP client
#   qscp          - SCP-style batch copy
```

## Usage

### Server

```sh
# Start with defaults (listens on 0.0.0.0:1022/udp)
qsftp-server

# Custom listen address
qsftp-server --listen 0.0.0.0:2222

# Provide your own TLS cert/key
qsftp-server --cert server.crt --key server.key

# Disable auth (testing only!)
qsftp-server --no-auth
```

TLS certificates are auto-generated and stored in `~/.qsftp/` if not provided.

As a systemd service:

```sh
sudo systemctl start qsftp-server
sudo systemctl enable qsftp-server   # start on boot
sudo journalctl -u qsftp-server -f   # view logs
```

### Interactive SFTP Client

```sh
# Connect (uses current username)
qsftp myserver.com

# Specify user and port
qsftp user@myserver.com -P 2222

# Use a specific SSH key
qsftp -i ~/.ssh/id_ed25519 user@myserver.com
```

Interactive commands:

```
ls [path]          List remote directory
cd <path>          Change remote directory
pwd                Print remote working directory
lpwd               Print local working directory
lcd <path>         Change local directory
get <remote> [local]   Download file
put <local> [remote]   Upload file
mkdir <path>       Create remote directory
rm <path>          Remove remote file/directory
rename <old> <new> Rename remote file
chmod <mode> <path>    Change remote file permissions
stat <path>        Show file info
exit               Disconnect
```

### SCP-style Copy

```sh
# Upload a file
qscp localfile.txt user@host:/remote/path/

# Download a file
qscp user@host:/remote/file.txt ./local/

# Recursive directory copy
qscp -r ./mydir user@host:/remote/path/

# Custom port and identity
qscp -P 2222 -i ~/.ssh/id_ed25519 file.txt user@host:
```

## Authentication

Authentication is tried in this order:

1. **SSH key** (automatic) -- the client looks for `~/.ssh/id_ed25519` then `~/.ssh/id_rsa`. The server verifies the key against `~/.ssh/authorized_keys` using a challenge-response protocol. Use `-i` to specify a key explicitly.
2. **Password** (fallback) -- PAM-based authentication. Prompts interactively if no key is found or key auth is rejected.

Supported key types: **Ed25519** and **RSA**.

## Default Port

qsftp uses UDP port **1022** by default (vs SSH's TCP port 22). Make sure your firewall allows UDP traffic on this port:

```sh
# ufw
sudo ufw allow 1022/udp

# iptables
sudo iptables -A INPUT -p udp --dport 1022 -j ACCEPT
```

## Protocol

- **Transport**: QUIC (via `quinn`) over UDP
- **Wire format**: Length-prefixed bincode serialization
- **TLS**: Self-signed certificates with TLS 1.3 (via `rustls`)
- **ALPN**: `qsftp/1`
- **File transfers**: Separate unidirectional QUIC streams for data, multiplexed on a single connection

## License

MIT
