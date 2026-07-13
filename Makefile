BINARY := verge
VERSION := 0.1.0
LDFLAGS := -ldflags "-s -w -X github.com/vergecloud/cdn-cli/internal/version.Version=$(VERSION) -X github.com/vergecloud/cdn-cli/internal/version.UserAgent=vergecloud-cli/$(VERSION)"

.PHONY: build test lint clean generate install release-snapshot

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

release-snapshot:
	@which goreleaser >/dev/null 2>&1 || (echo "goreleaser not installed; run: go install github.com/goreleaser/goreleaser/v2@latest" && exit 1)
	goreleaser release --snapshot --clean --skip=publish

clean:
	rm -rf bin/ dist/
