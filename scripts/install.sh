#!/usr/bin/env sh
# Install verge CLI from GitHub Releases.
# Usage: curl -fsSL https://raw.githubusercontent.com/danialzash/cdn-cli/main/scripts/install.sh | sh

set -e

REPO="danialzash/cdn-cli"
BINARY="verge"
INSTALL_DIR="${INSTALL_DIR:-}"
MAN_DIR="${MAN_DIR:-}"

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

  if [ -z "$MAN_DIR" ]; then
    if [ -w "/usr/local/share/man/man1" ]; then
      MAN_DIR="/usr/local/share/man/man1"
    else
      MAN_DIR="${HOME}/.local/share/man/man1"
    fi
  fi
  mkdir -p "$MAN_DIR"

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

  man_count=0
  for page in "${tmpdir}"/*.1; do
    if [ -f "$page" ]; then
      install -m 0644 "$page" "${MAN_DIR}/"
      man_count=$((man_count + 1))
    fi
  done

  if command -v mandb >/dev/null 2>&1; then
    mandb -q "${MAN_DIR}" 2>/dev/null || true
  fi

  echo ""
  echo "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"
  if [ "$man_count" -gt 0 ]; then
    echo "Installed ${man_count} man pages to ${MAN_DIR}"
  fi
  echo ""
  echo "Next steps:"
  echo "  ${BINARY} version"
  echo "  ${BINARY} auth login --api-key <your-api-key>"
  if [ "$man_count" -gt 0 ]; then
    echo "  man ${BINARY}"
  fi
  echo ""
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      echo "Add ${INSTALL_DIR} to your PATH, for example:"
      echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
      ;;
  esac
  case ":${MANPATH:-}:" in
    *":${MAN_DIR}:"*) ;;
    *)
      if [ "$man_count" -gt 0 ]; then
        echo "Add ${MAN_DIR} to your MANPATH, for example:"
        echo "  export MANPATH=\"${MAN_DIR}:\$MANPATH\""
      fi
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
