#!/bin/sh
set -eu

CFG="${CROWDSEC_UI_CONFIG:-/config/config.json}"
DB="${CROWDSEC_UI_DB:-/crowdsec-data/crowdsec.db}"
LISTEN="${CROWDSEC_UI_LISTEN:-0.0.0.0:8082}"
METRICS="${CROWDSEC_UI_METRICS:-http://127.0.0.1:6060/metrics}"
TZNAME="${CROWDSEC_UI_TIMEZONE:-UTC}"
ADMIN_USER="${UI_ADMIN_USER:-admin}"

if [ ! -f "$CFG" ]; then
    mkdir -p "$(dirname "$CFG")"
    echo "Initializing $CFG on first boot..."
    /usr/local/bin/crowdsec-ui \
        -c "$CFG" \
        -init-config \
        -init-user "$ADMIN_USER" \
        -init-listen "$LISTEN" \
        -init-db "$DB" \
        -init-tz "$TZNAME"
fi

exec /usr/local/bin/crowdsec-ui -c "$CFG"
