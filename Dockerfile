FROM golang:1.27-trixie

RUN apt update && apt install -y curl ffmpeg
RUN curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local/bin sh
RUN chmod +x /usr/local/bin/uv

COPY src /tmp/src
RUN go build -o /tmp/src/main /tmp/src/main.go

RUN mkdir /app
RUN mv /tmp/src/main /app/main
RUN rm -rf /tmp/src

COPY public /app/public

ENV PUBLIC_DIR_NAME=/app/public

WORKDIR /app
CMD ["./main"]
