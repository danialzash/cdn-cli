# VergeCloud CDN CLI

A minimal, production-quality command-line interface for the [VergeCloud CDN API](https://api.vergecloud.dev/cdn/api-docs).

This is **v0.1.0** — a small, extensible foundation focused on read-only operations and authentication. It is designed to grow with additional resources (DNS, SSL, cache, analytics, WAF rule management) without restructuring.

## Features

- Bearer token authentication with local config storage
- Domain listing and details
- WAF package catalog and domain-specific packages
- Firewall rule listing (read-only)
- Smart Check troubleshooting with human-friendly output
- Pretty tables (default), JSON output (`--json`), and verbose request logging (`--verbose`)

## Requirements

- Go 1.22+
- A VergeCloud CDN API key

## Installation

### From source

```bash
git clone <repository-url>
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

## Quick start

### 1. Authenticate

```bash
verge auth login --api-key <your-api-key>
```

Credentials are stored at `~/.config/vergecloud/config.yaml` with `0600` permissions.

### 2. Verify authentication

```bash
verge auth status
```

### 3. List domains

```bash
verge domains list
```

### 4. Get domain details

```bash
verge domains get example.com
# or by UUID
verge domains get 11111111-1111-1111-1111-111111111111
```

### 5. List WAF packages

Global catalog:

```bash
verge waf packages
```

Domain-specific packages (with mode and status):

```bash
verge waf packages --domain example.com
```

### 6. List firewall rules

```bash
verge firewall list example.com
```

### 7. Run smart check

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

## Configuration

Example config (`~/.config/vergecloud/config.yaml`):

```yaml
api_key: "vc_your_api_key_here"
api_url: "https://api.vergecloud.dev/cdn"
```

See [examples/config.yaml](examples/config.yaml).

## Commands

```
verge auth login --api-key <key>
verge auth status
verge auth logout

verge domains list
verge domains get <domain-id-or-name>

verge waf packages [--domain <domain>]

verge firewall list <domain-id>

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
make build    # Build binary to bin/verge
make test     # Run tests
make lint     # Run golangci-lint (if installed)
make generate # Generate SDK from OpenAPI spec (optional)
```

## Extending

To add a new resource:

1. Add minimal SDK methods in `internal/sdk/`.
2. Expose stable types and logic in `internal/client/`.
3. Add a Cobra command under `internal/cmd/`.
4. Add table/JSON rendering in `internal/output/`.

## License

MIT
