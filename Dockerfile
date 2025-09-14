FROM node:20-alpine AS frontend-builder

WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install

COPY src/ ./src/
COPY tsconfig.json ./
RUN pnpm run build

FROM golang:1.23.5-alpine AS go-builder

RUN apk --no-cache add gcc musl-dev sqlite-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=frontend-builder /app/public ./public
RUN CGO_ENABLED=1 go build -o mkbox .

FROM alpine:3.19

RUN apk --no-cache add ca-certificates sqlite
WORKDIR /app

COPY --from=go-builder /app/mkbox .
COPY --from=go-builder /app/public ./public

RUN adduser -D -s /bin/sh mkbox && \
    mkdir -p /var/lib/mkbox/files /var/run && \
    chown -R mkbox:mkbox /var/lib/mkbox /var/run && \
    chmod 700 /var/lib/mkbox && \
    chmod 755 /var/run

USER mkbox

EXPOSE 8080

ENV MBOX_SOCKET_PATH=/var/run/mkbox/mkbox.sock
ENV MBOX_DATA_DIR=/var/lib/mkbox

CMD ["./mkbox", "-daemon"]
