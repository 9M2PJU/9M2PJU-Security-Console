#!/bin/sh
set -eu

REPO="9M2PJU/9M2PJU-Security-Console"
BIN_PATH="/usr/local/bin/crowdsec-ui"
VERSION="latest"
NO_SERVICE=0
UNINSTALL=0

usage() {
    cat << 'EOF'
9M2PJU Security Console Installer (Linux & FreeBSD)

Usage:
  curl -fsSL https://raw.githubusercontent.com/9M2PJU/9M2PJU-Security-Console/main/install.sh | sudo sh
  sudo sh install.sh [--version v1.0.0] [--no-service] [--uninstall]
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="${2:-latest}"
            shift 2
            ;;
        --no-service)
            NO_SERVICE=1
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root (or with sudo)." >&2
    exit 1
fi

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_RAW="$(uname -m)"
case "$OS" in
    linux|freebsd) ;;
    *)
        echo "Unsupported OS: $OS (supported: linux, freebsd)" >&2
        exit 1
        ;;
esac

case "$ARCH_RAW" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
        echo "Unsupported architecture: $ARCH_RAW (supported: amd64, arm64)" >&2
        exit 1
        ;;
esac

if [ "$OS" = "freebsd" ]; then
    CFG_DIR="/usr/local/etc/crowdsec-ui"
    DB_DEFAULT="/var/db/crowdsec/data/crowdsec.db"
else
    CFG_DIR="/etc/crowdsec-ui"
    DB_DEFAULT="/var/lib/crowdsec/data/crowdsec.db"
fi
CFG_PATH="$CFG_DIR/config.json"

if [ "$UNINSTALL" -eq 1 ]; then
    echo "Uninstalling 9M2PJU Security Console..."
    if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now crowdsec-ui >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/crowdsec-ui.service
        systemctl daemon-reload >/dev/null 2>&1 || true
    elif [ "$OS" = "freebsd" ]; then
        service crowdsec_ui stop >/dev/null 2>&1 || true
        rm -f /usr/local/etc/rc.d/crowdsec_ui
    fi
    rm -f "$BIN_PATH"
    echo "Removed binary and service. Config preserved at $CFG_PATH (delete manually if desired)."
    exit 0
fi

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v fetch >/dev/null 2>&1; then
        fetch -qo "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        echo "Need curl, fetch, or wget to download release artifacts." >&2
        exit 1
    fi
}

if [ "$VERSION" = "latest" ]; then
    API_TMP="$(mktemp)"
    fetch "https://api.github.com/repos/$REPO/releases/latest" "$API_TMP"
    VERSION="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$API_TMP" | head -n 1)"
    rm -f "$API_TMP"
    if [ -z "$VERSION" ]; then
        echo "Could not resolve latest release tag from GitHub." >&2
        exit 1
    fi
fi

TARBALL="9M2PJU-Security-Console-${VERSION}-${OS}-${ARCH}.tar.gz"
BASE_URL="https://github.com/$REPO/releases/download/${VERSION}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${TARBALL}..."
fetch "${BASE_URL}/${TARBALL}" "${TMPDIR}/${TARBALL}"
fetch "${BASE_URL}/SHA256SUMS.txt" "${TMPDIR}/SHA256SUMS.txt"

echo "Verifying SHA-256 checksum..."
EXPECTED_SUM="$(grep " ${TARBALL}\$" "${TMPDIR}/SHA256SUMS.txt" | awk '{print $1}')"
if [ -z "$EXPECTED_SUM" ]; then
    echo "Checksum entry for ${TARBALL} not found in SHA256SUMS.txt" >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SUM="$(sha256sum "${TMPDIR}/${TARBALL}" | awk '{print $1}')"
elif command -v sha256 >/dev/null 2>&1; then
    ACTUAL_SUM="$(sha256 -q "${TMPDIR}/${TARBALL}")"
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SUM="$(shasum -a 256 "${TMPDIR}/${TARBALL}" | awk '{print $1}')"
else
    echo "No SHA-256 tool found." >&2
    exit 1
fi

if [ "$ACTUAL_SUM" != "$EXPECTED_SUM" ]; then
    echo "Checksum mismatch! Expected $EXPECTED_SUM, got $ACTUAL_SUM" >&2
    exit 1
fi

tar -xzf "${TMPDIR}/${TARBALL}" -C "${TMPDIR}"
install -m 0755 "${TMPDIR}/crowdsec-ui" "$BIN_PATH"
echo "Installed binary to $BIN_PATH"

mkdir -p "$CFG_DIR"
chmod 0700 "$CFG_DIR"

if [ ! -f "$CFG_PATH" ]; then
    "$BIN_PATH" -c "$CFG_PATH" -init-config -init-user admin -init-db "$DB_DEFAULT"
else
    echo "Existing config preserved at $CFG_PATH"
fi

if [ "$NO_SERVICE" -eq 0 ]; then
    if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
        install -m 0644 "${TMPDIR}/contrib/crowdsec-ui.service" /etc/systemd/system/crowdsec-ui.service
        systemctl daemon-reload
        systemctl enable --now crowdsec-ui
        echo "Service started via systemd (crowdsec-ui)."
    elif [ "$OS" = "freebsd" ]; then
        install -m 0755 "${TMPDIR}/contrib/crowdsec_ui.rc" /usr/local/etc/rc.d/crowdsec_ui
        mkdir -p /var/run/crowdsec-ui /var/log/crowdsec-ui
        if ! grep -q '^crowdsec_ui_enable=' /etc/rc.conf 2>/dev/null; then
            printf '\ncrowdsec_ui_enable="YES"\n' >> /etc/rc.conf
        fi
        service crowdsec_ui restart
        echo "Service started via rc.d (crowdsec_ui)."
    fi
fi

echo ""
echo "Installation complete!"
echo "Local URL: http://127.0.0.1:8082/ (place behind Nginx HTTPS for remote access)"
