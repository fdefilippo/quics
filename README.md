# QUICS - QUIC File Transfer and Remote Command Execution

A secure file transfer and remote command execution application built on the QUIC protocol using quic-go.

## Features

- Secure mutual authentication with X.509 certificates
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

storage:
  root_dir: "./files"

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

## Certificate Generation

Test certificates are included in `certs/`. You can regenerate them using the built‑in commands or the external OpenSSL script.

### Built‑in Certificate Management

The server includes two commands for creating a Certificate Authority and user certificates:

```bash
# Create a new ECDSA P‑256 CA (saved in certs_dir)
./bin/quicsd create-ca --userid ca --name "QUICS CA" --email "admin@example.com"

# Create a user certificate signed by the CA
./bin/quicsd create-cert --userid alice --name "Alice" --surname "Smith" --email "alice@example.com"
```

The CA certificate will be saved as `certs/ca.crt` and private key as `certs/ca.key`. User certificates are saved as `certs/<userid>.crt` and `certs/<userid>.key`. The private keys have permissions `600`.

### Using OpenSSL Script

Alternatively, you can use the OpenSSL script in `certs/`:

```bash
cd certs
./generate.sh  # or follow README.md in certs/
```

## Default Client Certificate Setup

For convenience, you can place client certificates in `~/.quicsc/`:

```bash
mkdir -p ~/.quicsc
# Generate or copy client certificate and key
cp certs/client.crt ~/.quicsc/public.crt
cp certs/client.key ~/.quicsc/private.key
chmod 600 ~/.quicsc/private.key
# Optional: copy CA certificate for server verification
cp certs/ca.crt ~/.quicsc/ca.crt
```

The private key must have permissions `600` (read/write for owner only). If permissions are incorrect, the client will report an error.

The client automatically loads `~/.quicsc/ca.crt` if present (no need to specify `--ca-cert`).

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

The client defaults to interactive mode (`--interactive=true`). Certificate and key paths default to `~/.quicsc/public.crt` and `~/.quicsc/private.key` respectively. The private key file must have permissions `600` (owner read/write only).

#### Command-line flags

| Long flag | Short flag | Description |
|-----------|------------|-------------|
| `--client-cert` | `-C` | Path to client certificate (PEM). Default: ~/.quicsc/public.crt |
| `--client-key` | `-K` | Path to client private key (PEM). Default: ~/.quicsc/private.key (must have 600 permissions) |
| `--server-addr` | `-s` | Server address (default: localhost:4242) |
| `--ca-cert` | `-a` | CA certificate to verify server (optional) |
| `--upload` | `-u` | Local file to upload |
| `--download` | `-d` | Remote file to download |
| `--output` | `-o` | Output path for downloaded file |
| `--mode` | `-m` | Transfer mode: BIN or ASCII (default: BIN) |
| `--cmd` | `-c` | Remote command to execute |
| `--exec-user` | `-U` | User to run command as (use '-' for current user) |
| `--exec-group` | `-G` | Group to run command as (use '-' for current group) |
| `--exec-cmd` | `-X` | Command to execute with specified user/group |
| `--env` | `-e` | Environment variable in NAME=VALUE format (can be repeated) |
| `--interactive` | `-i` | Start interactive session (default: true) |
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

#### Execute command as specific user/group (Linux only)
```bash
# Long form
./quicsc --client-cert certs/client.crt --client-key certs/client.key \
  --server-addr localhost:4242 --exec-user www-data --exec-group www-data \
  --exec-cmd "id" --insecure

# Short form (equivalent)
./quicsc -C certs/client.crt -K certs/client.key \
  -s localhost:4242 -U www-data -G www-data -X "id" -k
# Use '-' for current user/group: -U - -G -
# Requires root or CAP_SETUID/CAP_SETGID capabilities on server
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
- `exec <user> <group> <command>` - Execute command as user/group (Linux only)
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
- `UPLOAD <filename> <size> [BIN|ASCII]`
- `DOWNLOAD <filename> [BIN|ASCII]`
- `GET`, `PUT` (aliases)
- `CMD <command> [args...]`
- `EXEC <user> <group> <command> [args...]` (Linux only)
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
- Command whitelisting prevents arbitrary command execution
- Environment variable whitelisting controls variable passing
- Use proper CA-signed certificates in production
- Never expose the server to untrusted networks without proper sandboxing

## Development

This project uses Go modules. Dependencies:
- `github.com/quic-go/quic-go` - QUIC implementation
- `gopkg.in/yaml.v3` - YAML configuration parsing

## License

MIT