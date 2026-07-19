# User guide

Install, authenticate, and use the VergeCloud CDN CLI.

For command flags and subcommands, use `verge --help`, `verge <command> --help`, or `man verge`.

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

Pin a specific release:

```bash
VERSION=v0.3.0 curl -fsSL https://raw.githubusercontent.com/danialzash/cdn-cli/main/scripts/install.sh | sh
```

The install script verifies SHA256 checksums and installs man pages when available.

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

## Getting started

```bash
verge getting-started    # install, update, auth, and first commands
verge auth api-key       # how to create an API key in the panel
```

Create an API key at [panel.vergecloud.dev](https://panel.vergecloud.dev) → **Organization** → **API Keys**.

## Authentication

Use an API key or bearer token (not both):

```bash
verge auth login --api-key <your-api-key>
# or
verge auth login --token <your-jwt>
```

Or export credentials for the current shell (useful in CI):

```bash
export VERGECLOUD_API_KEY="vc_your_api_key_here"
# or
export VERGECLOUD_TOKEN="eyJ..."
```

Verify authentication:

```bash
verge auth status
```

Log out:

```bash
verge auth logout
```

Credentials from `verge auth login` are stored at `~/.config/vergecloud/config.yaml` with `0600` permissions.

## Updating

```bash
verge version --check    # check for a newer release
verge update             # download, verify, and install latest
```

Re-running the install script also works and verifies checksums.

## Configuration

### Config file

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

See [examples/config.yaml](../examples/config.yaml).

### Environment variables

| Variable | Description |
|----------|-------------|
| `VERGECLOUD_API_KEY` | API key (`X-API-Key` header) |
| `VERGECLOUD_TOKEN` | Bearer JWT (`Authorization: Bearer` header) |
| `VERGECLOUD_API_URL` | API base URL (default: `https://api.vergecloud.dev/cdn`) |

Set only one of `VERGECLOUD_API_KEY` or `VERGECLOUD_TOKEN`.

Credential precedence (highest wins): **flags** → **environment variables** → **config file**.

```bash
export VERGECLOUD_API_KEY="vc_your_api_key_here"
verge auth status
verge domains list
```

### API keys from the panel

```bash
verge auth api-key
```

Or manually: sign in at [panel.vergecloud.dev](https://panel.vergecloud.dev) → **Organization** → **API Keys** → create and copy the key (shown once).

## Global flags

| Flag | Description |
|------|-------------|
| `--json` | Output raw JSON |
| `--verbose` | Log HTTP requests to stderr |
| `--api-url` | Override API base URL (default: `https://api.vergecloud.dev/cdn`) |
| `--api-key` | Override stored API key for a single command |
| `--token` | Override stored bearer token for a single command |

## Common workflows

### Domains

```bash
verge domains list
verge domains list --status active --sort-by name --order asc
verge domains get example.com
verge domains inspect example.com
verge domains checkup example.com
```

**inspect** shows the current VergeCloud configuration (parallel API fetch).

**smartcheck** shows the latest server-side VergeCloud Smart Checker result.

**checkup** combines VergeCloud configuration with live DNS, HTTP, TLS, cache, CDN, and optional origin tests, then explains what is wrong and how to resolve it.

```bash
verge domains checkup example.com

verge domains checkup example.com --only activation,dns,tls

verge domains checkup example.com --path /healthz

verge domains checkup example.com \
  --origin 203.0.113.10 \
  --origin-scheme https

verge domains checkup example.com --strict

verge domains checkup example.com --json

verge domains checkup example.com --fix

verge domains checkup example.com --fix --dry-run

verge domains checkup example.com --fix --yes
```

Aliases: `verge domains doctor`, `verge domains diagnose`.

#### Checkup categories

`activation`, `dns`, `cdn`, `http`, `tls`, `origin`, `cache`, `security`, `configuration`, `smartcheck`

Use `--only` or `--skip` to limit checks (not both together).

#### Checkup exit codes

| Code | Meaning |
|------|---------|
| 0 | Checks completed with no failures (warnings alone are OK unless `--strict`) |
| 1 | CLI usage, authentication, API, or unexpected execution error |
| 2 | One or more domain checks failed (or warnings with `--strict`) |
| 3 | One or more required diagnostic probes could not run |
| 4 | One or more approved fixes failed |

Checkup is **read-only by default**. Pass `--fix` to review safe fixes; `--fix --yes` for automation; `--json --fix` requires `--yes` or `--dry-run`.

#### CI example

```bash
verge domains checkup example.com \
  --only activation,dns,http,tls \
  --strict \
  --json > checkup.json

status=$?

case "$status" in
  0) echo "Domain is healthy" ;;
  2) echo "Domain checks failed" ;;
  3) echo "One or more probes could not run" ;;
  *) echo "Checkup command failed" ;;
esac

exit "$status"
```

Boolean remediation commands use explicit values, for example:

```bash
verge dns update example.com <record-id> --cloud=false
verge cache update example.com --developer-mode=false
verge ssl update example.com --https-redirect=true
```

`inspect` fetches DNS, firewall, WAF, SSL, cache, and other settings in parallel.

### DNS

```bash
verge dns list example.com
verge dns add example.com --type a --name www --value 198.51.100.42 --ttl 300
verge dns update example.com <record-id> --value 198.51.100.50
verge dns delete example.com <record-id>
verge dns verify example.com
```

### Cache

```bash
verge cache example.com
verge cache update example.com --max-age 1h
verge cache purge example.com --purge all
```

### SSL/TLS

```bash
verge ssl example.com
verge ssl update example.com --certificate managed --https-redirect
verge ssl certificates list example.com
verge ssl issue example.com
```

### WAF

```bash
verge waf packages
verge waf example.com
verge waf update example.com --mode protect
```

Run `verge waf --help` for all subcommands.

### Reports

```bash
verge reports list
verge reports traffic example.com --period 24h
verge reports status example.com --period 7d
verge reports traffic-saved example.com
```

Run `verge reports --help` for all report types. Use `--json` for raw API output.

### Firewall, page rules, acceleration, lists

```bash
verge firewall list example.com
verge page-rules list example.com
verge acceleration example.com
verge lists list
```

### Smart check

```bash
verge smartcheck example.com
```

Server-side Smart Checker only. For live DNS/HTTP/TLS diagnosis and remediation hints, use `verge domains checkup`.

## Shell completion

The CLI includes tab completion via Cobra's built-in `completion` command.

**Requirements:** the `bash-completion` package (Ubuntu/Debian: `sudo apt install bash-completion`).

### Bash

```bash
mkdir -p ~/.local/share/bash-completion/completions
verge completion bash > ~/.local/share/bash-completion/completions/verge
```

Load in the current session only:

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

- **"No such file or directory"** when redirecting output: run `mkdir -p` on the target directory first.
- **Permission denied** writing to `/etc/bash_completion.d/`: use the user-local path above.
- **Wrong command runs on Tab**: ensure `verge` resolves to the CLI binary (`type verge`).

## Manual pages

Man pages are auto-generated from the Cobra command tree and included in release archives.

After install:

```bash
export MANPATH="$HOME/.local/share/man:$MANPATH"   # add to ~/.bashrc or ~/.zshrc
man verge
man verge-dns-list
man verge-auth-login
```
