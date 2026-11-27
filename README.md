# 9M2PJU Security Console

A lightweight, single-binary web security console written in Go for monitoring CrowdSec detections, active decisions, multi-vhost targets, and acquisition health directly from your local host - with no cloud alert quota and no heavy SIEM stack.

Developed by **9M2PJU** (`https://hamradio.my`).

## Why This Exists

- **No 500-alert monthly limit:** Reads your local `crowdsec.db` (SQLite, strictly read-only) and scrapes your local CrowdSec Prometheus endpoint (`127.0.0.1:6060/metrics`) directly.
- **Minimal footprint:** Single static Go binary (`CGO_ENABLED=0`, pure-Go `modernc.org/sqlite`), ~45 MB RSS, zero external JavaScript/CSS CDNs, and no OpenSearch/Elasticsearch/Loki dependency.
- **Multi-vhost visibility:** Maps per-vhost log paths (via configurable `site_map` in `config.json` or CrowdSec `site` metadata) so every HTTP alert shows the full target URL (`https://<site><target_uri>`) instead of only a relative path.
- **Live enforcement clarity:** Automatically inspects the `bouncers` table and clearly displays **Monitor Only (Not Blocking)** with `would-ban` badges when `0` bouncers are active, switching to **Enforcing** when a bouncer is connected.

## Features

- **Real-Time Overview & Charts:** 24h and total alert counts, unique attacker IPs, local vs CAPI blocklist breakdown, clickable **Top Attacked Sites**, clickable **Top Scenarios**, **24h Hourly Timeline**, and **Top Source Countries** with flag icons.
- **Searchable Alerts Feed:** Filter by free-text (`IP`, `ASN`, `country`, `site`, `target_uri`, `user_agent`), `Site`, `Scenario`, time window (`1h`, `24h`, `7d`, `All`), active bans only, or hide noisy `postscreen-rbl` entries. Click any alert row to inspect every underlying event.
- **Active Decisions & Acquisition Health:** Inspect active local decisions with remaining TTL and live Prometheus reader/parser metrics per log file.
- **Multi-User Auth & RBAC:**
  - Built-in login screen with salted PBKDF2-SHA256 password hashing (`100,000` iterations), HMAC-SHA256 `HttpOnly` session cookies, and IP login rate limiting.
  - **Change Password** modal for every signed-in user.
  - **User Management** tab (`admin` role only) to create `viewer` (read-only) or `admin` accounts, reset passwords, and delete accounts (immediately invalidating deleted user sessions).
- **Self-Contained Assets:** Custom SVG shield/radar emblem and embedded `/favicon.ico`, `/favicon.svg`, and `/apple-touch-icon.png` routes.

## Quick Start

### 1. Build

Requires Go 1.24+ (no C compiler needed because `CGO_ENABLED=0` uses pure-Go SQLite):

```bash
git clone https://github.com/9M2PJU/9M2PJU-Security-Console.git
cd 9M2PJU-Security-Console

# Linux amd64
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o crowdsec-ui .

# Cross-compile for FreeBSD amd64 (e.g., from Linux)
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o crowdsec-ui .
```

### 2. Initialize Configuration

Generate a secure `config.json` (mode `0600`) with a random 20-character admin password and 32-byte session secret:

```bash
./crowdsec-ui -c /etc/crowdsec-ui/config.json -init-config -init-user admin
```

Edit `/etc/crowdsec-ui/config.json` to adjust:
- `db_path`: `/var/lib/crowdsec/data/crowdsec.db` (Linux) or `/var/db/crowdsec/data/crowdsec.db` (FreeBSD)
- `timezone`: IANA timezone such as `UTC` or `Asia/Kuala_Lumpur`
- `site_map`: Optional substring-to-domain mapping for Nginx/Apache log filenames (for example `"/site-a_": "site-a.example.com"`)

Other CLI helpers:

```bash
./crowdsec-ui -hash-password "YourStrongPassword"
./crowdsec-ui -gen-secret
```

### 3. Run as a Service

- **Linux (systemd):** Copy `contrib/crowdsec-ui.service` to `/etc/systemd/system/crowdsec-ui.service`, then run `systemctl enable --now crowdsec-ui`.
- **FreeBSD (rc.d):** Copy `contrib/crowdsec_ui.rc` to `/usr/local/etc/rc.d/crowdsec_ui` (`chmod 0755`), add `crowdsec_ui_enable="YES"` to `/etc/rc.conf`, and run `service crowdsec_ui start`.

### 4. Put Behind Nginx HTTPS (Recommended)

The service binds to `127.0.0.1:8082` by default. Use `contrib/nginx-mtls.conf.example` to expose it over HTTPS (optionally enforcing Cloudflare Authenticated Origin Pulls mTLS so direct origin IP access is blocked).

## Optional: Enriching CrowdSec Events With `site`

If your Nginx vhosts log to separate files without `$host` in `access_log`, you can either:
1. Map log path substrings in `config.json` under `site_map`, or
2. Add CrowdSec's `s02-enrich` parser and context templates from `contrib/crowdsec-site-enrich.yaml.example` and `contrib/crowdsec-site.yaml.example`.

## Security Design

- Opens `crowdsec.db` strictly read-only (`mode=ro&_busy_timeout=5000&_query_only=on`).
- Config file written atomically with `0600` permissions.
- Enforces `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and a restrictive `Content-Security-Policy`.
- Escapes all untrusted log fields (`target_uri`, `user_agent`, `source_as_name`, etc.) before rendering.

## License

GNU Affero General Public License v3.0 (AGPL-3.0) - Copyright (c) 2026 9M2PJU. See [LICENSE](LICENSE).
