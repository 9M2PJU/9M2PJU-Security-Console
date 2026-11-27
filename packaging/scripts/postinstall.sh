#!/bin/sh
set -eu

BIN="/usr/bin/crowdsec-ui"
CFG_DIR="/etc/crowdsec-ui"
CFG_PATH="${CFG_DIR}/config.json"
DB_DEFAULT="/var/lib/crowdsec/data/crowdsec.db"

mkdir -p "${CFG_DIR}"
chmod 0700 "${CFG_DIR}"

if [ ! -f "${CFG_PATH}" ] && [ -x "${BIN}" ]; then
    "${BIN}" -c "${CFG_PATH}" -init-config -init-user admin -init-db "${DB_DEFAULT}"
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if systemctl is-active --quiet crowdsec-ui >/dev/null 2>&1; then
        systemctl restart crowdsec-ui >/dev/null 2>&1 || true
    elif [ -f "${DB_DEFAULT}" ]; then
        systemctl enable --now crowdsec-ui >/dev/null 2>&1 || true
    else
        echo "9M2PJU Security Console installed. Edit ${CFG_PATH} and run: sudo systemctl enable --now crowdsec-ui"
    fi
fi
