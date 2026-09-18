# ---------------------------------------------------------------
# MosWAF control plane: the API and the admin dashboard.
# The build context is the project root (see docker-compose.yml).
#
# Three stages: build the Vue dashboard -> build the Go binary with the dashboard
#               embedded -> a runtime image holding a single executable.
# ---------------------------------------------------------------

FROM node:22-alpine AS web
WORKDIR /src
COPY web/package.json web/package-lock.json* ./web/
RUN cd web && (npm ci --no-audit --no-fund || npm install --no-audit --no-fund)
COPY web ./web
# Vite writes its output to ../control/internal/web/dist (see web/vite.config.js)
RUN mkdir -p control/internal/web/dist && cd web && npm run build


FROM golang:1.23-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY control/go.mod control/go.sum ./control/
RUN cd control && go mod download
COPY control ./control
COPY --from=web /src/control/internal/web/dist ./control/internal/web/dist
RUN cd control && CGO_ENABLED=0 GOOS=linux go build \
        -trimpath -ldflags="-s -w" -o /moswafd ./cmd/moswafd


FROM alpine:3.20

# su-exec drops privileges without the signal and process handling that su brings
# with it - the control plane stays PID 1 and keeps receiving SIGTERM from Docker.
RUN apk add --no-cache ca-certificates tzdata su-exec \
    && addgroup -S -g 10001 moswaf \
    && adduser  -S -u 10001 -G moswaf -H -s /sbin/nologin moswaf \
    && mkdir -p /etc/moswaf/sites /etc/moswaf/certs /etc/moswaf/admin-tls \
    && chown -R moswaf:moswaf /etc/moswaf

COPY --from=build /moswafd /moswafd
COPY control/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 9443

# Runs as the moswaf user, so the healthcheck exercises the same identity the
# service does rather than a more privileged one.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/moswafd", "-healthcheck"]

ENTRYPOINT ["/entrypoint.sh"]
