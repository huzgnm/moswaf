# ---------------------------------------------------------------
# MosWAF control plane: API + dashboard admin
# Build context la thu muc goc cua du an (xem docker-compose.yml).
#
# Ba tang: build giao dien Vue -> build binary Go (nhung san giao dien)
#          -> image chay chi co dung mot file thuc thi.
# ---------------------------------------------------------------

FROM node:22-alpine AS web
WORKDIR /src
COPY web/package.json web/package-lock.json* ./web/
RUN cd web && (npm ci --no-audit --no-fund || npm install --no-audit --no-fund)
COPY web ./web
# Vite ghi ket qua sang ../control/internal/web/dist (xem web/vite.config.js)
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
RUN apk add --no-cache ca-certificates tzdata \
    && mkdir -p /etc/moswaf/sites /etc/moswaf/certs /etc/moswaf/admin-tls

COPY --from=build /moswafd /moswafd

EXPOSE 9443

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/moswafd", "-healthcheck"]

ENTRYPOINT ["/moswafd"]
