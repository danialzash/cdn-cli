# VergeCloud CDN CLI

A command-line interface for the [VergeCloud CDN API](https://api.vergecloud.dev/cdn/api-docs).

Manage domains, DNS, SSL, cache, firewall, WAF, analytics, and more from your terminal.

**Current version:** v0.3.0

## Features

- One-line install from GitHub Releases (Linux / macOS) with checksum verification
- Self-update: `verge update`
- API key or bearer token auth (config file, environment variables, or flags)
- Built-in help for API keys at [panel.vergecloud.dev](https://panel.vergecloud.dev)
- Pretty tables, JSON output (`--json`), and terminal charts for reports

## Requirements

- A VergeCloud CDN API key or bearer token

## Quick install

**Linux / macOS:**

```bash
curl -fsSL https://raw.githubusercontent.com/danialzash/cdn-cli/main/scripts/install.sh | sh
```

Manual download: [GitHub Releases](https://github.com/danialzash/cdn-cli/releases)

## Quick start

```bash
verge getting-started
verge auth api-key
verge auth login --api-key <your-api-key>
verge auth status
verge domains list
```

Or use environment variables (no config file):

```bash
export VERGECLOUD_API_KEY="vc_your_api_key_here"
verge domains list
```

## Update

```bash
verge version --check
verge update
```

## Documentation

| Guide | Description |
|-------|-------------|
| [User guide](docs/user-guide.md) | Install, auth, config, workflows, completion, man pages |
| [Development guide](docs/development.md) | Build, architecture, extending, releases |

Command reference:

```bash
verge --help
verge dns --help
verge reports --help
man verge
```

## Command groups

`auth` · `domains` · `dns` · `firewall` · `page-rules` · `cache` · `acceleration` · `lists` · `ssl` · `reports` · `waf` · `smartcheck` · `update` · `version`

## License

MIT
