# audown.cubus.sh

yt-dlp web proxy server to download YouTube audio clips (`cubus.sh`), protected by invite-only Passkey (WebAuthn) authentication.

## Features

- Invite-only Passkey (WebAuthn discoverable credential) enrollment and one-tap biometric login with zero passwords or usernames.
- Web UI (`GET /`) with YouTube Data API v3 preview and interactive time-range trimming.
- Server-side audio extraction (`POST /download`) via `yt-dlp` + `ffmpeg`.
- PostgreSQL persistence (`DB_BROKER_URL` in `cubus.sh`, `DATABASE_URL` fallback for standalone local dev) with automatic embedded SQL migrations.
- **Optional Internal Admin API (`:9090`):** Disabled unless `ADMIN_API_TOKEN` is set; binds strictly to the `ADMIN_BIND_CIDR` interface IP (or `127.0.0.1` locally) for `admin.cubus.sh` integration (`settings`, `users`, `invites`).

## Environment Variables

Copy `.env.example` to `.env` before building or running:

```sh
cp .env.example .env
```

| Variable | Required | Description |
| :--- | :--- | :--- |
| `YOUTUBE_API_KEY` | Build time | YouTube Data API v3 key embedded into static `config.js` at Docker build time. |
| `PUBLIC_BASE_URL` | No | Public origin (default `http://localhost:8080`; set to `https://audown.cubus.sh` in prod). Must use a domain name (not an IP literal) per WebAuthn RPID rules. Derives WebAuthn `RPID`, `RPOrigins`, session cookie prefix (`__Host-audown_session` on HTTPS), CSRF `Origin`, and invite URLs. |
| `DB_BROKER_URL` | Prod (`cubus.sh`) | Injected by root `cubus.sh/docker-compose.yml` to fetch isolated `svc_audown` PostgreSQL credentials. Takes precedence over `DATABASE_URL`. |
| `DATABASE_URL` | Local dev | PostgreSQL DSN used when `DB_BROKER_URL` is unset (wired to local `postgres:18.7-alpine3.24` in standalone `docker-compose.yml`). |
| `ADMIN_API_TOKEN` | No | Optional Bearer token (`>= 16` bytes, non-placeholder, no whitespace) enabling `:9090` Admin API. Leave unset to keep `:9090` disabled. |

Additional runtime variables:

- `PUBLIC_DIR_NAME` — path to static `public` assets (default `public`; set to `/app/public` in `Dockerfile`).
- `LISTEN_ADDR` — public HTTP listen address (default `:8080`).
- `ADMIN_PORT` — Admin API port (default `9090`, must differ from `LISTEN_ADDR` port).
- `ADMIN_BIND_CIDR` — optional CIDR (`172.31.0.0/24` in `cubus.sh`) selecting the interface IP that `:9090` binds to (`127.0.0.1` when unset).
- `ADMIN_ALLOW_CIDR` — optional peer allowlist CIDR (`172.31.0.2/32` in `cubus.sh`) restricting which source IP(s) can call `:9090` (defaults to `ADMIN_BIND_CIDR`, or loopback when unset).

## Internal Admin API (`:9090`)

When `ADMIN_API_TOKEN` is configured, `audown` exposes:

- `GET /admin/v1/manifest` — service metadata, `capabilities` (`settings`, `users`, `invites`), `user_capabilities`, `user_columns`, and `settings_schema`.
- `GET /admin/v1/settings` & `PATCH /admin/v1/settings` — persisted runtime updates:
  - `require_auth` (`bool`, default `true`) — require Passkey session on `GET /`, `POST /download`, `GET /auth/me`, and `POST /auth/logout`.
  - `accept_downloads` (`bool`, default `true`) — returns `503` on `POST /download` when disabled while keeping the web UI and `/healthz` healthy.
  - `ytdlp_timeout_seconds` (`int`, `10..600`, default `110`) — per-job `yt-dlp` timeout.
  - `max_concurrent_downloads` (`int`, `1..32`, default `4`) — concurrent `yt-dlp` cap (returns `429` when saturated).
  - `audio_format` (`string`, `mp3|m4a|opus|flac|wav`, default `mp3`) — target `yt-dlp --audio-format`.
- `GET /admin/v1/users`, `PATCH /admin/v1/users/{id}`, `DELETE /admin/v1/users/{id}`, `DELETE /admin/v1/users/{id}/sessions` — manage Passkey users and revoke sessions.
- `GET /admin/v1/invites`, `POST /admin/v1/invites`, `DELETE /admin/v1/invites/{id}` — issue and revoke single-use Enrollment Invites.

### Root `cubus.sh` Wiring Prerequisites

To run `audown` inside `cubus.sh`, root `cubus.sh/docker-compose.yml` wires `audown` to `web`, `web-external`, `db`, and `admin` networks, injects `PUBLIC_BASE_URL=https://audown.cubus.sh`, `DB_BROKER_URL=http://db-broker:8080/v1/database`, `ADMIN_BIND_CIDR=172.31.0.0/24`, `ADMIN_ALLOW_CIDR=172.31.0.2/32`, labels `cubus.admin.port: "9090"` and `cubus.admin.name: "audown"`, and sets matching `ADMIN_TOKEN_AUDOWN` in `sites/admin/.env`.

## Development & Verification

```sh
go vet ./...
go test -v -count=1 -race ./...
CGO_ENABLED=0 go build ./src
```
