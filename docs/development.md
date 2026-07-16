# Development guide

Build, test, extend, and release the VergeCloud CDN CLI.

## Prerequisites

- Go 1.22+

## Build from source

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

Install to `~/bin`:

```bash
make build
mkdir -p ~/bin
cp bin/verge ~/bin/verge
export PATH="$HOME/bin:$PATH"
```

Manual build:

```bash
go build -o verge ./cmd/verge
```

## Development commands

```bash
make build            # Build binary to bin/verge
make test             # Run tests
make lint             # Run golangci-lint (if installed)
make generate         # Generate SDK from OpenAPI spec (optional)
make manpages         # Generate man pages to man/
make install-man      # Install man pages to ~/.local/share/man/man1
make release-snapshot # Test GoReleaser build locally (outputs to dist/)
```

## Architecture

```
cmd/verge/           CLI entrypoint
cmd/gendocs/         Man page generator
internal/cmd/        Cobra commands (thin handlers)
internal/client/     Stable API wrapper used by commands
internal/sdk/        Low-level HTTP SDK + OpenAPI spec
internal/config/     Viper-backed config management
internal/output/     Table/JSON rendering (lipgloss + tablewriter)
internal/transport/  HTTP client with timeout, retries, User-Agent
internal/update/     Self-update from GitHub Releases
internal/help/       Onboarding text for CLI help commands
```

Design rules:

- Commands never import generated SDK types directly.
- The OpenAPI spec is stored at `internal/sdk/openapi.yaml` for code generation (`make generate`).
- All API calls use `context.Context`.
- List endpoints automatically paginate when the API returns page metadata.

## Extending the CLI

To add a new resource:

1. Add minimal SDK methods in `internal/sdk/`.
2. Expose stable types and logic in `internal/client/`.
3. Add a Cobra command under `internal/cmd/`.
4. Add table/JSON rendering in `internal/output/`.
5. Regenerate man pages: `make manpages`.

Keep command handlers thin — validation and HTTP logic belong in `internal/client/` and `internal/sdk/`.

## Man pages

Man pages are generated from the Cobra command tree:

```bash
make manpages      # generates man/*.1
make install-man   # installs to ~/.local/share/man/man1
export MANPATH="$HOME/.local/share/man:$MANPATH"
man verge
```

System-wide install (Linux):

```bash
make manpages
sudo cp man/*.1 /usr/local/share/man/man1/
sudo mandb
```

GoReleaser runs `go run ./cmd/gendocs` before each release build, so published archives include up-to-date man pages.

## Publishing a release

1. Commit your changes and push to `main`.
2. Tag a version:
   ```bash
   git tag v0.3.0
   git push origin v0.3.0
   ```
3. GitHub Actions runs GoReleaser and publishes binaries to [GitHub Releases](https://github.com/danialzash/cdn-cli/releases).

**You do not need GoReleaser installed locally.** Pushing the tag is enough — CI builds and publishes everything.

Check progress at: `https://github.com/danialzash/cdn-cli/actions`

### Optional: test release build locally

Local GoReleaser is only for maintainers who want to preview `dist/` before tagging:

```bash
make release-snapshot
ls dist/
```

If `go install github.com/goreleaser/goreleaser/v2@latest` fails on your machine:

- **Go version too old:** latest GoReleaser may require a newer Go than this project. GitHub Actions uses its own toolchain, so releases still work.
- **`403 Forbidden` from `proxy.golang.org`:** skip local install and publish via git tag instead.

## Go package documentation

Go API docs for packages under `internal/` are available via godoc when browsing the module source. End-user CLI documentation lives in this repo (`docs/user-guide.md`) and in `verge --help` / man pages — not on pkg.go.dev for CLI users.
