# QUICS - QUIC File Transfer and Remote Command Execution

A secure file transfer and remote command execution application built on the QUIC protocol using quic-go.

## Features

- Secure mutual authentication with X.509 certificates
- **Identity mapping**: client certificate CN mapped to local system user via NSS
- **Virtual root**: per-session file isolation (user home or subdirectory)
- **Process jail**: `CMD` and `EXEC` run inside the session virtual root via `chroot`
- File upload/download with binary and ASCII modes (line ending conversion)
- Remote command execution with configurable whitelist and environment variables
- Interactive client mode with local command execution
- Configurable server via YAML configuration
- Concurrent connection handling

## Building

```bash
go build -o quicsd ./cmd/server
go build -o quicsc ./cmd/client
```

## Configuration

Server configuration file (`config/server.yaml`):

```yaml
listen_addr: "0.0.0.0"
listen_port: 4242

tls:
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"

auth:
  client_ca_file: "certs/ca.crt"  # mandatory – CA certificate for client authentication
  certs_dir: "./certs"            # directory for CA and user certificates

identity:
  map_client_cn_to_local_user: true   # CN must match a local system user
  reject_if_local_user_missing: true  # reject if user not found

storage:
  mode: "virtual-root"            # shared | virtual-root
  root_dir: "./files"
  user_root_policy: "home"        # home | subdir
  user_subdir: ""                 # optional subdirectory inside root

# QUIC connection settings (optional - defaults shown)
quic:
  max_idle_timeout_seconds: 120     # default: 120 seconds (2 minutes)
  keep_alive_period_seconds: 15     # default: 15 seconds, set to -1 to disable

shell:
  enabled: true
  # Allowed commands can be literal strings or regex patterns (containing ^ $ . * + ? ( ) [ ] { } | \)
  allowed_commands: ["^ls.*", "mkdir", "^rm.*", "cat", "echo", "pwd"]
  max_execution_time_seconds: 30
  allowed_env_vars: ["PATH", "HOME", "USER", "CUSTOM_VAR"]
```

When `storage.mode: "virtual-root"` is enabled, the effective root is computed per session:

- `user_root_policy: "home"`: the mapped user's home directory is used as virtual root
- `user_subdir` can further confine the session inside a subdirectory of that root
- remote processes are started with `chroot` into the computed virtual root

Operational consequence: commands executed through `CMD` or `EXEC` can only use binaries and libraries visible inside that virtual root. If the jail does not contain `/bin/ls`, shared libraries, or other runtime dependencies, the command will fail even if it is whitelisted.

## Certificate Generation

Test certificates are included in `certs/`. You can regenerate them using the built‑in commands or the external OpenSSL script.

### Built‑in Certificate Management (PKCS#12 format)

The server includes two commands for creating a Certificate Authority and user certificates using PKCS#12 format (`.p12` files):

```bash
# Create a new ECDSA P‑256 CA (saved in certs_dir)
./bin/quicsd create-ca --userid ca --name "QUICS CA" --email "admin@example.com" --password ""

# Create a user certificate signed by the CA
./bin/quicsd create-cert --userid alice --name "Alice" --surname "Smith" --email "alice@example.com" --password "secret123"
```

The CA will be saved as:
- `certs/ca.p12` – PKCS#12 file containing both certificate and private key (optional password)
- `certs/ca.crt` – PEM certificate only (for server configuration)

User certificates are saved as `certs/<userid>.p12` (PKCS#12 format) containing the client certificate, private key, and the CA certificate (for client-side verification). Passwords are optional but recommended for security.

### Importing External Certificates

The client includes an `import` subcommand to copy a PKCS#12 file into the client's certificate store:

```bash
quicsc import --file /path/to/certificate.p12 --hostname myserver
```

If `--hostname` is omitted, the hostname is extracted from the `--server-addr` flag (default: `localhost`). The imported file will be placed at `~/.quicsc/servers/<hostname>.p12`.

### Using OpenSSL Script

Alternatively, you can use the OpenSSL script in `certs/`:

```bash
cd certs
./generate.sh  # or follow README.md in certs/
```

## Default Client Certificate Setup

**Preferred format**: PKCS#12 (`.p12`) files that contain the client certificate, private key, and CA certificate chain. This single encrypted file simplifies distribution and improves security.

The client searches for certificates in the following order:

1. **Server-specific PKCS#12**: `~/.quicsc/servers/<hostname>.p12` (where `<hostname>` is extracted from the server address, port removed)
2. **Global PKCS#12**: `~/.quicsc/client.p12`
3. **Legacy PEM format** (server-specific directory): `~/.quicsc/servers/<hostname>/public.crt` and `private.key`
4. **Legacy PEM format** (global): `~/.quicsc/public.crt` and `private.key`

### Global Configuration (single server)

For a single server, place a PKCS#12 file in the global directory:

```bash
mkdir -p ~/.quicsc
# Copy or generate PKCS#12 file (contains client cert, key, and CA)
cp certs/client.p12 ~/.quicsc/client.p12
```

If you still use PEM files (legacy):

```bash
mkdir -p ~/.quicsc
cp certs/client.crt ~/.quicsc/public.crt
cp certs/client.key ~/.quicsc/private.key
chmod 600 ~/.quicsc/private.key
# Optional: copy CA certificate for server verification
cp certs/ca.crt ~/.quicsc/ca.crt
```

### Server-specific Configuration (multiple servers)

For multiple servers with different certificates, organize by hostname:

**PKCS#12 (recommended)** – one file per server:

```bash
# For server example.com:4243
mkdir -p ~/.quicsc/servers
cp certs/client-for-example.p12 ~/.quicsc/servers/example.com.p12

# For server other.example.com:4243
cp certs/client-for-other.p12 ~/.quicsc/servers/other.example.com.p12
```

**Legacy PEM format** – directory per server:

```bash
# For server example.com:4243
mkdir -p ~/.quicsc/servers/example.com
cp certs/client-for-example.crt ~/.quicsc/servers/example.com/public.crt
cp certs/client-for-example.key ~/.quicsc/servers/example.com/private.key
chmod 600 ~/.quicsc/servers/example.com/private.key
cp certs/ca-for-example.crt ~/.quicsc/servers/example.com/ca.crt

# For server other.example.com:4243
mkdir -p ~/.quicsc/servers/other.example.com
cp certs/client-for-other.crt ~/.quicsc/servers/other.example.com/public.crt
# ... etc.
```

The private key must have permissions `600` (read/write for owner only). If permissions are incorrect, the client will report an error.

When using PKCS#12 files, the CA certificate is automatically extracted from the file (no need for separate `ca.crt`). For PEM files, the client will look for a `ca.crt` in the same directory.

## Usage

### Server

```bash
./quicsd --config ./config/server.yaml
# or short form
./quicsd -c ./config/server.yaml
```

The server also provides certificate‑management commands:

```bash
# Create a new CA
./quicsd create-ca --userid ca --name "QUICS CA"

# Create a user certificate
./quicsd create-cert --userid alice --name "Alice" --surname "Smith"
```

See `./quicsd --help` for all available commands.

### Client

#### Default Configuration

The client defaults to non-interactive mode; use `--interactive` to start an interactive session. Certificate paths default to `~/.quicsc/servers/<hostname>.p12` (PKCS#12 format) or legacy PEM files `~/.quicsc/public.crt` and `~/.quicsc/private.key`. The private key file must have permissions `600` (owner read/write only).

#### Command-line flags

| Long flag | Short flag | Description |
|-----------|------------|-------------|
| `--client-cert` | `-C` | Path to client certificate (PEM or PKCS#12). Default: ~/.quicsc/servers/<hostname>.p12, then ~/.quicsc/client.p12, then PEM files |
| `--client-key` | `-K` | Path to client private key (PEM). Default: ~/.quicsc/private.key (must have 600 permissions). Ignored if PKCS#12 file is used |
| `--server-addr` | `-s` | Server address (default: localhost:4242) |
| `--ca-cert` | `-a` | CA certificate to verify server (optional). CA is automatically extracted from PKCS#12 file; use this flag to override or when using PEM certificates |
| `--upload` | `-u` | Local file to upload |
| `--download` | `-d` | Remote file to download |
| `--output` | `-o` | Output path for downloaded file |
| `--mode` | `-m` | Transfer mode: BIN or ASCII (default: BIN) |
| `--cmd` | `-c` | Remote command to execute |
| `--exec` | `-X` | Command to execute as the mapped local user |
| `--env` | `-e` | Environment variable in NAME=VALUE format (can be repeated) |
| `--interactive` | `-i` | Start interactive session (default: false) |
| `--insecure` | `-k` | Skip server certificate verification |
| `--max-idle-timeout` | `-t` | Maximum idle timeout in seconds (default: 120) |
| `--keep-alive-period` | `-p` | Keep-alive period in seconds (default: 15, -1 to disable) |

#### File upload
```bash
# Long form
./quicsc --client-cert certs/client.crt --client-key certs/client.key \
  --server-addr localhost:4242 --upload file.txt --mode BIN --insecure

# Short form (equivalent)
./quicsc -C certs/client.crt -K certs/client.key \
  -s localhost:4242 -u file.txt -m BIN -k
```

#### File download
```bash
# Long form
./quicsc --client-cert certs/client.crt --client-key certs/client.key \
  --server-addr localhost:4242 --download file.txt --output local.txt --insecure

# Short form (equivalent)
./quicsc -C certs/client.crt -K certs/client.key \
  -s localhost:4242 -d file.txt -o local.txt -k
```

#### Remote command execution
```bash
# Long form
./quicsc --client-cert certs/client.crt --client-key certs/client.key \
  --server-addr localhost:4242 --cmd "ls -l" --env "CUSTOM_VAR=value" --insecure

# Short form (equivalent)
./quicsc -C certs/client.crt -K certs/client.key \
  -s localhost:4242 -c "ls -l" -e "CUSTOM_VAR=value" -k
# Multiple environment variables can be set with repeated -e flags
```

#### Execute command as mapped user (Linux only)
```bash
# Long form
./quicsc --client-cert certs/client.crt --client-key certs/client.key \
  --server-addr localhost:4242 --exec "id" --insecure

# Short form (equivalent)
./quicsc -C certs/client.crt -K certs/client.key \
  -s localhost:4242 -X "id" -k
# The user is derived from the client certificate CN; requires root
# or CAP_SETUID/CAP_SETGID plus CAP_SYS_CHROOT on the server
```

#### Interactive mode
```bash
# Long form
./quicsc --client-cert certs/client.crt --client-key certs/client.key \
  --server-addr localhost:4242 --interactive --insecure

# Short form (equivalent)
./quicsc -C certs/client.crt -K certs/client.key \
  -s localhost:4242 -i -k
```

Interactive commands:
- `! <command>` - Execute local command
- `put <local> [remote] [ascii|bin]` - Upload file
- `get <remote> [local] [ascii|bin]` - Download file
- `exec <command>` - Execute command as mapped user (Linux only)
- `<remote command>` - Execute command on server
- `exit`, `quit` - Exit interactive mode
- `help` - Show help

Interactive features:
- Command history navigation with arrow keys
- Auto-completion for built-in commands with Tab
- Ctrl+C to cancel current line
- Ctrl+D to exit interactive mode

## Protocol

The application protocol operates over QUIC streams:

### Command format
```
COMMAND [ARGUMENTS...]\n
[DATA]
```

Supported commands:
- `UPLOAD <filename> <size> [BIN|ASCII] [sha256]`
- `DOWNLOAD <filename> [BIN|ASCII] [offset]`
- `GET`, `PUT` (aliases)
- `CMD <command> [args...]`
- `EXEC <command> [args...]` (user/group derived from session CN mapping, Linux only)
- `ENV <NAME=VALUE>`

### Response format
- Success: `OK <message>\n`
- Error: `ERROR <message>\n`

For command execution:
```
OK
<exit_code>
<stdout_size>
<stdout>
<stderr_size>
<stderr>
```

## Webhook Notifications

The server can send HTTP POST notifications to a configured URL when client actions are completed (successfully or with error). Notifications are sent asynchronously and include details about the action.

### Configuration

Add to `config/server.yaml`:

```yaml
webhook:
  url: "http://localhost:8080/webhook"
  timeout_seconds: 10
  retry_count: 2
  enabled: true
  # Authentication: none, basic, bearer, mtls
  auth_type: "none"
  username: ""           # for basic auth
  password: ""           # for basic auth
  bearer_token: ""       # for bearer auth
  client_cert: ""        # for mtls (certificate file)
  client_key: ""         # for mtls (private key file)
  insecure_skip_verify: false  # skip SSL certificate verification
```

Authentication options:
- `none`: No authentication (default)
- `basic`: HTTP Basic authentication with `username` and `password`
- `bearer`: Bearer token authentication with `bearer_token`
- `mtls`: Mutual TLS authentication with `client_cert` and `client_key` files

Set `insecure_skip_verify: true` to skip SSL certificate verification for HTTPS endpoints (e.g., self‑signed certificates).

### Notification Format

```json
{
  "action": "upload",
  "userid": "client-certificate-common-name",
  "timestamp": "2026-04-22T10:30:00Z",
  "success": true,
  "error": "",
  "details": {
    "filename": "test.txt",
    "size": 1234,
    "mode": "bin"
  }
}
```

Supported actions: `upload`, `download`, `command`, `exec`, `env`.

## Security Notes

- The server requires client certificate authentication
- **CN → local user mapping**: the client certificate CN determines the local system user for file access and command execution
- **Virtual root**: file operations are confined to the mapped user's home directory (or configured subdirectory)
- **`chroot` jail for remote commands**: `CMD` and `EXEC` run inside the session virtual root, not just with that directory as working directory
- Command whitelisting prevents arbitrary command execution
- Environment variable whitelisting controls variable passing
- The server needs `CAP_SYS_CHROOT` (or root) in addition to `CAP_SETUID`/`CAP_SETGID` to run remote commands inside the jail
- Use proper CA-signed certificates in production
- Never expose the server to untrusted networks without proper sandboxing

## Development

This project uses Go modules. Dependencies:
- `github.com/quic-go/quic-go` - QUIC implementation
- `gopkg.in/yaml.v3` - YAML configuration parsing

### Recent Improvements

Recent versions include several code quality and security improvements:
- Structured logging using Zap for better observability
- Extracted protocol utilities to reduce code duplication
- Improved error handling consistency and resource cleanup
- Added comprehensive unit tests for core logic (session handling, path resolution)
- Replaced magic numbers with named constants
- Implemented early and comprehensive configuration validation
- Enhanced security documentation and validation

## License

MIT
