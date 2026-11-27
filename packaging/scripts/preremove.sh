#!/bin/sh
set -eu

# Skip stopping on package upgrades (deb passes "upgrade", rpm passes $1 >= 1).
case "${1:-}" in
    upgrade|1|2)
        exit 0
        ;;
esac

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now crowdsec-ui >/dev/null 2>&1 || true
fi
