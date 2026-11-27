# 9M2PJU Security Console

A lightweight, single-binary web security console written in Go for monitoring CrowdSec detections, active decisions, multi-vhost targets, and acquisition health directly from your local host - with no cloud alert quota and no heavy SIEM stack.

Developed by **9M2PJU** (`https://hamradio.my`).

![Dashboard Overview](docs/screenshots/dashboard-overview.png)

## Screenshots

| Alert Detail Inspection | User Management & RBAC |
| :---: | :---: |
| ![Alert Detail Modal](docs/screenshots/alert-detail-modal.png) | ![User Management](docs/screenshots/user-management.png) |

<details>
<summary>Login Screen (TLS + mTLS Protected)</summary>

![Login Screen](docs/screenshots/login-screen.png)

</details>

## Why This Exists

- **No 500-alert monthly limit:** Reads your local `crowdsec.db` (SQLite, strictly read-only) and scrapes your local CrowdSec Prometheus endpoint (`127.0.0.1:6060/metrics`) directly.
- **Minimal footprint:** Single static Go binary (`CGO_ENABLED=0`, pure-Go `modernc.org/sqlite`), ~45 MB RSS (~25 MB Docker image), zero external JavaScript/CSS CDNs, and no OpenSearch/Elasticsearch/Loki dependency.
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

## Installation

### Option 1: One-Line Installer (Linux & FreeBSD, Prebuilt Releases)

Downloads the verified release binary from [GitHub Releases](https://github.com/9M2PJU/9M2PJU-Security-Console/releases), verifies `SHA256SUMS.txt`, initializes `config.json` with a random admin password, and sets up the `systemd` (Linux) or `rc.d` (FreeBSD) service:

```bash
curl -fsSL https://raw.githubusercontent.com/9M2PJU/9M2PJU-Security-Console/main/install.sh | sudo sh
```

Useful installer flags:
```bash
# Install a specific tag without touching systemd/rc.d
sudo sh install.sh --version v1.0.0 --no-service

# Uninstall binary and service (preserves config.json)
sudo sh install.sh --uninstall
```

### Option 2: Docker & Docker Compose

Run the ~25 MB Alpine image with CrowdSec's data directory mounted read-only:

```bash
git clone https://github.com/9M2PJU/9M2PJU-Security-Console.git
cd 9M2PJU-Security-Console
docker compose up -d
docker compose logs security-console   # Prints the generated first-boot admin password
```

On FreeBSD or custom paths, edit the read-only volume in `docker-compose.yml` (for example `/var/db/crowdsec/data:/crowdsec-data:ro`). Supported environment overrides: `CROWDSEC_UI_LISTEN`, `CROWDSEC_UI_DB`, `CROWDSEC_UI_METRICS`, `CROWDSEC_UI_TIMEZONE`, `CROWDSEC_UI_HOSTNAME`, and `UI_ADMIN_USER`.

### Option 3: Build From Source

Requires Go 1.26+ (no C compiler needed because `CGO_ENABLED=0` uses pure-Go SQLite):

```bash
git clone https://github.com/9M2PJU/9M2PJU-Security-Console.git
cd 9M2PJU-Security-Console

# Linux amd64
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o crowdsec-ui .

# Cross-compile for FreeBSD amd64 (e.g., from Linux)
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o crowdsec-ui .
```

Initialize a fresh `config.json` (mode `0600`):

```bash
./crowdsec-ui -c /etc/crowdsec-ui/config.json -init-config -init-user admin
```

Edit `config.json` to set `site_map` (substring-to-domain mapping for log filenames) or `timezone` (`UTC`, `Asia/Kuala_Lumpur`, etc.):

```bash
./crowdsec-ui -hash-password "YourStrongPassword"
./crowdsec-ui -gen-secret
```

## Reverse Proxy Setup (Recommended)

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
