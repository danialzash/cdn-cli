# VergeCloud CDN CLI

A minimal, production-quality command-line interface for the [VergeCloud CDN API](https://api.vergecloud.dev/cdn/api-docs).

This is **v0.1.0** — a small, extensible foundation focused on read-only operations and authentication. It is designed to grow with additional resources (DNS, SSL, cache, analytics, WAF rule management) without restructuring.

## Features

- API key or bearer token authentication with local config storage
- Domain listing and details
- DNS record listing, creation, and live DNS verification
- WAF package catalog and domain-specific packages
- Firewall rule listing (read-only)
- Smart Check troubleshooting with human-friendly output
- Pretty tables (default), JSON output (`--json`), and verbose request logging (`--verbose`)

## Requirements

- A VergeCloud CDN API key or bearer token

For building from source: Go 1.22+

## Installation

### Install script (recommended)

No runtime dependencies — downloads a pre-built binary from GitHub Releases.

**Linux / macOS:**

```bash
curl -fsSL https://raw.githubusercontent.com/danialzash/cdn-cli/main/scripts/install.sh | sh
```

Install to a custom directory:

```bash
INSTALL_DIR=~/bin curl -fsSL https://raw.githubusercontent.com/danialzash/cdn-cli/main/scripts/install.sh | sh
```

Then authenticate with either method:

```bash
# API key (X-API-Key header)
verge auth login --api-key <your-api-key>

# Bearer token (Authorization: Bearer header)
verge auth login --token <your-jwt>
```

### Manual download

Download the archive for your platform from [GitHub Releases](https://github.com/danialzash/cdn-cli/releases):

| Platform | Archive |
|----------|---------|
| Linux (amd64) | `verge_linux_amd64.tar.gz` |
| Linux (arm64) | `verge_linux_arm64.tar.gz` |
| macOS (Apple Silicon) | `verge_darwin_arm64.tar.gz` |
| macOS (Intel) | `verge_darwin_amd64.tar.gz` |
| Windows (amd64) | `verge_windows_amd64.zip` |

```bash
# Linux example
curl -LO https://github.com/danialzash/cdn-cli/releases/latest/download/verge_linux_amd64.tar.gz
tar -xzf verge_linux_amd64.tar.gz
sudo mv verge /usr/local/bin/   # or mv verge ~/bin/
```

### From source (developers)

```bash
git clone https://github.com/danialzash/cdn-cli.git
cd cdn-cli
make build
./bin/verge version
```

Install globally:

```bash
make install
```

### Manual build

```bash
go build -o verge ./cmd/verge
```

### Install to `~/bin`

```bash
make build
mkdir -p ~/bin
cp bin/verge ~/bin/verge
```

Ensure `~/bin` is on your `PATH` (for example, `export PATH="$HOME/bin:$PATH"` in `~/.bashrc`).

## Publishing a release (maintainers)

1. Commit your changes and push to `main`.
2. Tag a version:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. GitHub Actions runs GoReleaser and publishes binaries to [GitHub Releases](https://github.com/danialzash/cdn-cli/releases).

**You do not need GoReleaser installed locally.** Pushing the tag is enough — CI builds and publishes everything.

Check progress at: `https://github.com/danialzash/cdn-cli/actions`

### Optional: test release build locally

Local GoReleaser is only for maintainers who want to preview `dist/` before tagging. It is **not required** to publish.

```bash
make release-snapshot
ls dist/
```

If `go install github.com/goreleaser/goreleaser/v2@latest` fails on your machine, that is fine — common causes:

- **Go version too old:** latest GoReleaser requires Go 1.26+, while this project uses Go 1.22. GitHub Actions uses its own Go toolchain, so releases still work.
- **`403 Forbidden` from `proxy.golang.org`:** a network/proxy issue on your machine. Skip local install and publish via git tag instead.

## Shell completion

The CLI includes tab completion via Cobra's built-in `completion` command. It completes commands, subcommands, and flags (not dynamic values like domain names).

**Requirements:** the `bash-completion` package (Ubuntu/Debian: `sudo apt install bash-completion`).

### Bash (recommended)

Create the completions directory first, then install the script:

```bash
mkdir -p ~/.local/share/bash-completion/completions
verge completion bash > ~/.local/share/bash-completion/completions/verge
```

Open a new terminal, then test:

```bash
verge <Tab>
verge domains <Tab>
verge auth login --<Tab>
```

To load completion in the **current session only**:

```bash
source <(verge completion bash)
```

### Zsh

```bash
verge completion zsh > "${fpath[1]}/_verge"
```

### Fish

```bash
verge completion fish > ~/.config/fish/completions/verge.fish
```

### Troubleshooting

- **"No such file or directory"** when redirecting output: run `mkdir -p` on the target directory first (the `>` redirect does not create parent folders).
- **Permission denied** writing to `/etc/bash_completion.d/`: use the user-local path above instead of a system path.
- **Wrong command runs on Tab**: ensure `verge` resolves to the CLI binary (`type verge` should show `/home/you/bin/verge`, not a shell alias).

## Manual pages (`man verge`)

Man pages are auto-generated from the Cobra command tree and included in release archives.

### After install script or release download

The install script copies man pages to `~/.local/share/man/man1` (or `/usr/local/share/man/man1` with permissions). Then:

```bash
export MANPATH="$HOME/.local/share/man:$MANPATH"   # add to ~/.bashrc or ~/.zshrc
man verge
man verge-dns-list
man verge-auth-login
```

### From source (developers)

```bash
make manpages      # generates man/*.1 from commands
make install-man   # installs to ~/.local/share/man/man1
export MANPATH="$HOME/.local/share/man:$MANPATH"
man verge
```

### System-wide install (Linux)

```bash
make manpages
sudo cp man/*.1 /usr/local/share/man/man1/
sudo mandb
man verge
```

## Quick start

### 1. Authenticate

Use an API key or bearer token (not both):

```bash
verge auth login --api-key <your-api-key>
# or
verge auth login --token <your-jwt>
```

Credentials are stored at `~/.config/vergecloud/config.yaml` with `0600` permissions.

### 2. Verify authentication

```bash
verge auth status
```

### 3. List domains

```bash
verge domains list
verge domains list --status active
verge domains list --status inactive
verge domains list --sort-by name --order asc
verge domains list --sort-by status --order desc
```

The list includes plan name (for example `enterprise`), organization ID, and created date.

### 4. Get domain details

```bash
verge domains get example.com
# or by UUID
verge domains get 11111111-1111-1111-1111-111111111111
```

### 5. Domain overview (parallel inspect)

Fetch comprehensive domain details from all major API sections at once:

```bash
verge domains inspect example.com
verge domains inspect example.com --json
```

Includes domain info, DNS, firewall, WAF, DDoS, page rules, SSL, caching, load balancing, rate limiting, acceleration, and smart-check status. All API calls run in parallel.

### 6. List WAF packages

Global catalog:

```bash
verge waf packages
```

Domain-specific packages (with mode and status):

```bash
verge waf packages --domain example.com
```

### 7. List firewall rules

```bash
verge firewall list example.com
```

### 8. Manage DNS records

List all records with full values:

```bash
verge dns list example.com
verge dns list example.com --type a
```

Get a single record:

```bash
verge dns get example.com <record-id>
```

Add a record:

```bash
verge dns add example.com --type a --name www --value 198.51.100.42 --ttl 300
verge dns add example.com --type cname --name blog --value target.example.com
verge dns add example.com --type txt --name _dmarc --value "v=DMARC1; p=none"
verge dns add example.com --type mx --name @ --value mail.example.com --priority 10
```

Verify records against live DNS (like `dig`):

```bash
verge dns verify example.com
verge dns verify example.com --workers 20
verge dns verify example.com --record-id <record-id>
```

### 9. Run smart check

```bash
verge troubleshoot smartcheck example.com
```

## Global flags

| Flag | Description |
|------|-------------|
| `--json` | Output raw JSON |
| `--verbose` | Log HTTP requests to stderr |
| `--api-url` | Override API base URL (default: `https://api.vergecloud.dev/cdn`) |
| `--api-key` | Override stored API key for a single command |
| `--token` | Override stored bearer token for a single command |

## Configuration

Example config (`~/.config/vergecloud/config.yaml`):

```yaml
auth_method: api_key
api_key: "vc_your_api_key_here"
api_url: "https://api.vergecloud.dev/cdn"
```

Or with a bearer token:

```yaml
auth_method: bearer
bearer_token: "eyJhbGciOi..."
api_url: "https://api.vergecloud.dev/cdn"
```

See [examples/config.yaml](examples/config.yaml).

## Commands

```
verge auth login --api-key <key>
verge auth login --token <jwt>
verge auth status
verge auth logout

verge domains list [--status active|inactive] [--sort-by name|status|updated_at] [--order asc|desc]
verge domains get <domain-id-or-name>
verge domains inspect <domain>

verge waf packages [--domain <domain>]

verge firewall list <domain-id>

verge dns list <domain>
verge dns get <domain> <record-id>
verge dns add <domain> --type <type> --name <name> --value <value>
verge dns verify <domain> [--record-id <id>] [--workers 10]

verge troubleshoot smartcheck <domain-id>
```

## Architecture

```
cmd/verge/           CLI entrypoint
internal/cmd/        Cobra commands (thin handlers)
internal/client/     Stable API wrapper used by commands
internal/sdk/        Low-level HTTP SDK + OpenAPI spec
internal/config/     Viper-backed config management
internal/output/     Table/JSON rendering (lipgloss + tablewriter)
internal/transport/  HTTP client with timeout, retries, User-Agent
```

- Commands never import generated SDK types directly.
- The OpenAPI spec is stored at `internal/sdk/openapi.yaml` for future code generation (`make generate`).
- All API calls use `context.Context`.
- List endpoints automatically paginate when the API returns page metadata.

## Development

```bash
make build            # Build binary to bin/verge
make test             # Run tests
make lint             # Run golangci-lint (if installed)
make generate         # Generate SDK from OpenAPI spec (optional)
make manpages         # Generate man pages to man/
make install-man      # Install man pages to ~/.local/share/man/man1
make release-snapshot # Test GoReleaser build locally (outputs to dist/)
```

## Extending

To add a new resource:

1. Add minimal SDK methods in `internal/sdk/`.
2. Expose stable types and logic in `internal/client/`.
3. Add a Cobra command under `internal/cmd/`.
4. Add table/JSON rendering in `internal/output/`.

## License

MIT
