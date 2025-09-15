FROM node:20-bookworm AS frontend-builder

WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install

COPY src/ ./src/
COPY tsconfig.json ./
RUN pnpm run build

FROM golang:1.23.5-bookworm AS go-builder

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential pkg-config && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=frontend-builder /app/public ./public
RUN CGO_ENABLED=1 go build -o mkbox .

FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates gosu && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY --from=go-builder /app/mkbox .
COPY --from=go-builder /app/public ./public

RUN useradd -m -s /usr/sbin/nologin mkbox && \
    mkdir -p /var/lib/mkbox/files /var/run && \
    chown -R mkbox:mkbox /var/lib/mkbox /var/run && \
    chmod 700 /var/lib/mkbox && \
    chmod 755 /var/run

COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

USER root

ENV MBOX_SOCKET_PATH=/var/run/mkbox/mkbox.sock
ENV MBOX_DATA_DIR=/var/lib/mkbox

ENTRYPOINT ["./entrypoint.sh"]
CMD ["-daemon"]
