FROM golang:1.27.3-trixie AS builder

WORKDIR /build
COPY go.mod ./
COPY src ./src
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/main ./src

FROM node:24-trixie-slim AS runtime

ARG YT_DLP_VERSION=2026.08.19

RUN apt-get update && apt-get install -y --no-install-recommends curl ffmpeg && rm -rf /var/lib/apt/lists/*

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
COPY --from=builder /out/main /app/main

COPY public /app/public

RUN --mount=type=bind,source=.env,target=/tmp/audown.env,ro \
    node -e ' \
      const fs = require("fs"); \
      const lines = fs.readFileSync("/tmp/audown.env", "utf8").split(/\r?\n/); \
      let val = ""; \
      for (const raw of lines) { \
        const m = /^\s*YOUTUBE_API_KEY\s*=\s*(.*)$/.exec(raw); \
        if (!m) continue; \
        let v = m[1].trim(); \
        if ((v.startsWith("\x22") && v.endsWith("\x22")) || (v.startsWith("\x27") && v.endsWith("\x27"))) { \
          v = v.slice(1, -1); \
        } \
        val = v; \
      } \
      if (!/^[A-Za-z0-9_-]+$/.test(val)) { \
        console.error("YOUTUBE_API_KEY missing or contains unsupported characters"); \
        process.exit(1); \
      } \
      fs.writeFileSync("/app/public/static/js/config.js", `export const YOUTUBE_API_KEY = ${JSON.stringify(val)};\n`); \
    '

ENV PUBLIC_DIR_NAME=/app/public

WORKDIR /app
EXPOSE 80 9090
CMD ["./main"]
