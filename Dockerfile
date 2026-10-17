FROM golang:1.27-trixie AS builder

COPY src /src
RUN go build -o /src/main /src/main.go

FROM node:24-trixie-slim AS runtime

ARG YOUTUBE_API_KEY

RUN apt update && apt install -y curl ffmpeg
RUN curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local/bin sh
RUN chmod +x /usr/local/bin/uv

RUN mkdir /app
COPY --from=builder /src/main /app/main

COPY public /app/public

RUN case "$YOUTUBE_API_KEY" in \
      *[!A-Za-z0-9_-]*) echo "YOUTUBE_API_KEY contains unsupported characters" >&2; exit 1 ;; \
    esac \
    && printf 'export const YOUTUBE_API_KEY = "%s";\n' "$YOUTUBE_API_KEY" \
      > /app/public/static/js/config.js

ENV PUBLIC_DIR_NAME=/app/public

WORKDIR /app
CMD ["./main"]
