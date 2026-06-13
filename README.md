# qsftp

SFTP and SCP reimplemented over **QUIC** (UDP). Drop-in replacements for `sftp` and `scp` that use the QUIC transport protocol instead of TCP/SSH.

## Why QUIC?

- **Faster connection setup** -- 0-RTT and 1-RTT handshakes vs TCP+TLS+SSH multi-round-trip
- **Better on lossy networks** -- no head-of-line blocking; individual streams recover independently
- **UDP-based** -- works through more NAT configurations, avoids TCP-level throttling
- **Built-in encryption** -- TLS 1.3 baked into the protocol

## Performance

Benchmarked on localhost (loopback) with a 1 GiB file using `qsftp-bench`.
Test machine: Apple M-series, release build (`cargo build --release`).

### Uncompressed vs zstd compressed (level 3)

**Compressible data** (text-like, high redundancy):

| Mode             | Upload       | Download     | Wire size | Speedup         |
|------------------|-------------|-------------|-----------|-----------------|
| Uncompressed     | 242 MiB/s   | 374 MiB/s   | 100%      | baseline        |
| zstd compressed  | 3,510 MiB/s | 3,070 MiB/s | ~0%       | 14x up / 8x dl  |

**Incompressible data** (per-byte random, truly uncompressible):

| Mode             | Upload       | Download     | Wire size | Speedup         |
|------------------|-------------|-------------|-----------|-----------------|
| Uncompressed     | 242 MiB/s   | 376 MiB/s   | 100%      | baseline        |
| zstd compressed  | 241 MiB/s   | 365 MiB/s   | ~100%     | 1.0x (no gain)  |

**Key insight:** compression only helps when data is actually compressible. For random/
encrypted data the wire size stays the same and you pay a small CPU overhead (~1%
slowdown). For compressible data (logs, text, source code, JSON) the speedup is dramatic
— up to 14x — because less data crosses the QUIC/TLS/UDP stack. On a real network with
limited bandwidth the benefit is even larger.

### Transfer settings

- Dynamic chunk size: 256 KiB (< 1 MiB) → 1 MiB → 4 MiB → 16 MiB (≥ 256 MiB)
- Pipelined I/O: disk reader and network writer run as concurrent tasks (queue depth 8)
- QUIC windows: 32 MiB stream / 64 MiB connection / 64 MiB send
- Compression: zstd level 3 (good ratio, very fast encode/decode)

Run the benchmark yourself:

```sh
# Terminal 1 — start server in no-auth mode on a test port
qsftp-server --no-auth --listen 127.0.0.1:10222

# Terminal 2 — run benchmark (port, size in MiB)
qsftp-bench 10222 1024
```

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

### SSH-style Shell and Port Forwarding (`qssh`)

`qssh` is an SSH-style client over QUIC: interactive shell, single-command exec,
and TCP port forwarding (`-L` / `-R`).

```sh
# Interactive shell
qssh user@host -p 1022

# Run a single command
qssh user@host -- uname -a

# Local forward: listen locally, tunnel to a host:port reachable from the server
qssh -N -L 8080:intranet.local:80 user@host

# Remote forward: server listens on its port, tunnels back to a local host:port
qssh -N -R 9000:localhost:3000 user@host
```

`-N` means "no shell" — set up the forwards and stay connected (like `ssh -N`).
Multiple `-L`/`-R` flags are allowed. Forward spec format is `[bind:]port:host:port`.

#### Tunneling a SOCKS proxy

A common setup is a SOCKS proxy running on the remote server (e.g. on
`localhost:1180`). Forward a local port to it and point your SOCKS client there:

```sh
# Local 1188 → remote's localhost:1180 (the SOCKS proxy), forward-only
qssh -N -L 1188:localhost:1180 user@host -p 10022

# Use it
curl --socks5-hostname localhost:1188 https://example.com/
export ALL_PROXY=socks5h://localhost:1188
```

For a resilient always-on tunnel (auto-reconnect), use the helper script
[`qtunnel`](qtunnel) — see [Resilient tunnels](#resilient-tunnels) below.

#### Non-interactive auth

`qssh` tries SSH key auth first (`~/.ssh/id_ed25519`, `id_ecdsa`, then `id_rsa`,
or `-i <key>`), falling back to a password prompt. For background/forward-only use
with no terminal, supply a password via the `QSSH_PASSWORD` environment variable
instead of relying on the prompt — otherwise key auth must succeed.

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

## Resilient tunnels

The [`qtunnel`](qtunnel) helper keeps a `qssh -N` forward alive across drops,
the way `autossh` wraps `ssh`. It restarts `qssh` whenever it exits.

```sh
# Local 1188 → remote SOCKS proxy on its localhost:1180, auto-reconnecting
./qtunnel -p 10022 -L 1188:localhost:1180 user@host

# Multiple forwards work too
./qtunnel -p 10022 -L 3078:localhost:3128 -L 2222:192.168.0.61:22 user@host
```

It passes every argument straight through to `qssh`, so any `qssh` flag works.
Use `QSSH_PASSWORD` for non-interactive password auth if you don't use keys.

## Protocol

- **Transport**: QUIC (via `quinn`) over UDP
- **Wire format**: Length-prefixed bincode serialization
- **TLS**: Self-signed certificates with TLS 1.3 (via `rustls`)
- **ALPN**: `qsftp/1`
- **File transfers**: Separate unidirectional QUIC streams for data, multiplexed on a single connection
- **Compression**: Optional per-transfer zstd (level 3) with 4-byte LE length-prefixed frames; negotiated per request

## License

MIT
