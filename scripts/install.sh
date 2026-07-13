#!/usr/bin/env sh
# Install verge CLI from GitHub Releases.
# Usage: curl -fsSL https://raw.githubusercontent.com/danialzash/cdn-cli/main/scripts/install.sh | sh

set -e

REPO="danialzash/cdn-cli"
BINARY="verge"
INSTALL_DIR="${INSTALL_DIR:-}"

main() {
  need_cmd uname
  need_cmd mktemp
  need_cmd tar

  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo "error: unsupported architecture: $arch" >&2
      exit 1
      ;;
  esac

  case "$os" in
    linux) ;;
    darwin) ;;
    *)
      echo "error: unsupported OS: $os" >&2
      exit 1
      ;;
  esac

  if [ -z "$INSTALL_DIR" ]; then
    if [ -w "/usr/local/bin" ]; then
      INSTALL_DIR="/usr/local/bin"
    else
      INSTALL_DIR="${HOME}/.local/bin"
      mkdir -p "$INSTALL_DIR"
    fi
  else
    mkdir -p "$INSTALL_DIR"
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  archive="${BINARY}_${os}_${arch}.tar.gz"
  url="https://github.com/${REPO}/releases/latest/download/${archive}"

  echo "Downloading ${url} ..."
  if ! curl -fsSL "$url" -o "${tmpdir}/${archive}"; then
    echo "error: failed to download release asset" >&2
    echo "hint: check that a release exists at https://github.com/${REPO}/releases" >&2
    exit 1
  fi

  tar -xzf "${tmpdir}/${archive}" -C "$tmpdir"
  install -m 0755 "${tmpdir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"

  echo ""
  echo "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"
  echo ""
  echo "Next steps:"
  echo "  ${BINARY} version"
  echo "  ${BINARY} auth login --api-key <your-api-key>"
  echo ""
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      echo "Add ${INSTALL_DIR} to your PATH, for example:"
      echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
      ;;
  esac
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

main "$@"
