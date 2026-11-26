FROM golang:1.27.3-trixie AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY src ./src
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/main ./src

FROM node:24.22.3-trixie-slim AS runtime

ARG YT_DLP_VERSION=2026.08.19
ARG YT_DLP_SHA256=58162f9bfdc27458ea47bfcb311cf47028f17d8154a8bf7d689861d46399230a

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl ffmpeg && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    release_url="https://github.com/yt-dlp/yt-dlp/releases/download/${YT_DLP_VERSION}"; \
    curl -fsSL "$release_url/yt-dlp_linux" -o /tmp/yt-dlp_linux; \
    echo "${YT_DLP_SHA256}  /tmp/yt-dlp_linux" | sha256sum --check -; \
    chmod 0755 /tmp/yt-dlp_linux; \
    mv /tmp/yt-dlp_linux /usr/local/bin/yt-dlp

RUN mkdir -p /app
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

RUN chmod 0755 /app /app/main && chmod -R a+rX /app/public

ENV PUBLIC_DIR_NAME=/app/public

WORKDIR /app
USER node
EXPOSE 8080 9090
CMD ["./main"]
