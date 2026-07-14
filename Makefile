BINARY := verge
VERSION := 0.2.0
LDFLAGS := -ldflags "-s -w -X github.com/vergecloud/cdn-cli/internal/version.Version=$(VERSION) -X github.com/vergecloud/cdn-cli/internal/version.UserAgent=vergecloud-cli/$(VERSION)"

.PHONY: build test lint clean generate manpages install-man release-snapshot

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/verge

install:
	go install $(LDFLAGS) ./cmd/verge

test:
	go test ./...

lint:
	@which golangci-lint >/dev/null 2>&1 || (echo "golangci-lint not installed; run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	golangci-lint run ./...

generate:
	@which oapi-codegen >/dev/null 2>&1 || (echo "oapi-codegen not installed; run: go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest" && exit 1)
	oapi-codegen -generate types,client -package sdk -o internal/sdk/client.gen.go internal/sdk/openapi.yaml

manpages:
	go run ./cmd/gendocs

install-man: manpages
	@mkdir -p "$(HOME)/.local/share/man/man1"
	@cp man/*.1 "$(HOME)/.local/share/man/man1/"
	@echo "Installed man pages to $(HOME)/.local/share/man/man1"
	@echo "Add to ~/.bashrc or ~/.zshrc if needed:"
	@echo '  export MANPATH="$$HOME/.local/share/man:$$MANPATH"'

release-snapshot:
	@which goreleaser >/dev/null 2>&1 || (echo "goreleaser not found. Local install is optional — push a v* tag and GitHub Actions will publish releases." && exit 1)
	goreleaser release --snapshot --clean --skip=publish

clean:
	rm -rf bin/ dist/
