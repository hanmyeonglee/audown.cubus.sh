# audown.cubus.sh

yt-dlp web proxy server to download YouTube audio clips (`cubus.sh`).

## Features

- Web UI (`GET /`) with YouTube Data API v3 preview and interactive time-range trimming.
- Server-side audio extraction (`POST /download`) via `yt-dlp` + `ffmpeg`.
- **Optional Internal Admin API (`:9090`):** Disabled unless `ADMIN_API_TOKEN` is set; binds strictly to the `ADMIN_BIND_CIDR` interface IP (or `127.0.0.1` locally) for `admin.cubus.sh` integration.

## Environment Variables

Copy `.env.example` to `.env` before building or running:

```sh
cp .env.example .env
```

| Variable | Required | Description |
| :--- | :--- | :--- |
| `YOUTUBE_API_KEY` | Build time | YouTube Data API v3 key embedded into static `config.js` at Docker build time. |
| `ADMIN_API_TOKEN` | No | Optional Bearer token (`>= 16` bytes, non-placeholder, no whitespace) enabling `:9090` Admin API. Leave unset to keep `:9090` disabled. |

Additional runtime variables:

- `PUBLIC_DIR_NAME` — path to static `public` assets (default `public`; set to `/app/public` in `Dockerfile`).
- `LISTEN_ADDR` — public HTTP listen address (default `:8080`).
- `ADMIN_PORT` — Admin API port (default `9090`, must differ from `LISTEN_ADDR` port).
- `ADMIN_BIND_CIDR` — optional CIDR (`172.31.0.0/24` in `cubus.sh`) selecting the interface IP that `:9090` binds to (`127.0.0.1` when unset).
- `ADMIN_ALLOW_CIDR` — optional peer allowlist CIDR (`172.31.0.2/32` in `cubus.sh`) restricting which source IP(s) can call `:9090` (defaults to `ADMIN_BIND_CIDR`, or loopback when unset).

## Internal Admin API (`:9090`)

When `ADMIN_API_TOKEN` is configured, `audown` exposes:

- `GET /admin/v1/manifest` — service metadata and `settings_schema`.
- `GET /admin/v1/settings` — current runtime settings.
- `PATCH /admin/v1/settings` — atomic runtime updates:
  - `accept_downloads` (`bool`, default `true`) — returns `503` on `POST /download` when disabled while keeping `GET /` and `GET /healthz` healthy.
  - `ytdlp_timeout_seconds` (`int`, `10..600`, default `110`) — per-job `yt-dlp` timeout (note: root `cubus.sh/config/vhost.d/audown.cubus.sh_location` enforces `proxy_read_timeout 120s;` unless raised).
  - `max_concurrent_downloads` (`int`, `1..32`, default `4`) — concurrent `yt-dlp` cap (returns `429` when saturated).
  - `audio_format` (`string`, `mp3|m4a|opus|flac|wav`, default `mp3`) — target `yt-dlp --audio-format`.

### Root `cubus.sh` Wiring Prerequisites

To expose `audown` in `admin.cubus.sh`, root `cubus.sh/docker-compose.yml` wires `audown` to the `admin` network with `ADMIN_BIND_CIDR=172.31.0.0/24`, `ADMIN_ALLOW_CIDR=172.31.0.2/32`, labels `cubus.admin.port: "9090"` and `cubus.admin.name: "audown"`, and sets matching `ADMIN_TOKEN_AUDOWN` in `sites/admin/.env`.

## Development & Verification

```sh
go vet ./...
go test -v -count=1 -race ./...
CGO_ENABLED=0 go build ./src
```
