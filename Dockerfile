FROM golang:1.27-trixie AS builder

COPY src /src
RUN go build -o /src/main /src/main.go

FROM node:24-trixie-slim AS runtime

ARG YT_DLP_VERSION=2026.08.19

RUN apt update && apt install -y curl ffmpeg

RUN set -eux; \
    release_url="https://github.com/yt-dlp/yt-dlp/releases/download/${YT_DLP_VERSION}"; \
    curl -fsSL "$release_url/yt-dlp_linux" -o /tmp/yt-dlp_linux; \
    curl -fsSL "$release_url/SHA2-256SUMS" -o /tmp/SHA2-256SUMS; \
    grep "  yt-dlp_linux$" /tmp/SHA2-256SUMS > /tmp/yt-dlp.sha256; \
    test -s /tmp/yt-dlp.sha256; \
    (cd /tmp && sha256sum --check /tmp/yt-dlp.sha256); \
    chmod +x /tmp/yt-dlp_linux; \
    mv /tmp/yt-dlp_linux /usr/local/bin/yt-dlp; \
    rm /tmp/SHA2-256SUMS /tmp/yt-dlp.sha256

RUN mkdir /app
COPY --from=builder /src/main /app/main

COPY public /app/public

RUN --mount=type=bind,source=.env,target=/tmp/audown.env,ro \
    . /tmp/audown.env \
    && test -n "$YOUTUBE_API_KEY" \
    && case "$YOUTUBE_API_KEY" in \
      *[!A-Za-z0-9_-]*) echo "YOUTUBE_API_KEY contains unsupported characters" >&2; exit 1 ;; \
    esac \
    && printf 'export const YOUTUBE_API_KEY = "%s";\n' "$YOUTUBE_API_KEY" \
      > /app/public/static/js/config.js

ENV PUBLIC_DIR_NAME=/app/public

WORKDIR /app
CMD ["./main"]
