#!/usr/bin/env bash
#
# Data plane entrypoint:
#   1. Generate the default certificate (for HTTPS requests to unknown domains)
#   2. Apply the log level from the environment
#   3. Run a watcher: when /etc/moswaf/sites changes -> openresty -s reload
#   4. Run OpenResty in the foreground
#
set -euo pipefail

SSL_DIR=/usr/local/moswaf/ssl
SITES_DIR=/etc/moswaf/sites
CONF=/usr/local/openresty/nginx/conf/nginx.conf
LOG_LEVEL="${MOSWAF_LOG_LEVEL:-warn}"

mkdir -p "$SITES_DIR" /etc/moswaf/certs /var/log/moswaf "$SSL_DIR"

# --- 1. default self-signed certificate ---
if [[ ! -f "$SSL_DIR/default.crt" ]]; then
  echo "[moswaf] generating the default self-signed certificate..."
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout "$SSL_DIR/default.key" -out "$SSL_DIR/default.crt" \
    -subj "/C=VN/O=MosWAF/CN=moswaf.local" >/dev/null 2>&1
fi

# --- 2. nginx.conf ---
install -m 0644 /usr/local/moswaf/conf/nginx.conf "$CONF"
sed -i "s|__LOG_LEVEL__|${LOG_LEVEL}|g" "$CONF"

# --- 3. site configuration watcher ---
sites_hash() { cat "$SITES_DIR"/*.conf /etc/moswaf/certs/* 2>/dev/null | md5sum | cut -d' ' -f1; }

watch_sites() {
  local last; last="$(sites_hash)"
  while sleep 3; do
    local cur; cur="$(sites_hash)"
    if [[ "$cur" != "$last" ]]; then
      last="$cur"
      if openresty -t >/dev/null 2>&1; then
        echo "[moswaf] site configuration changed -> reload"
        openresty -s reload
      else
        echo "[moswaf] SITE CONFIGURATION IS INVALID, skipping reload:" >&2
        openresty -t 2>&1 | sed 's/^/[moswaf]   /' >&2
      fi
    fi
  done
}

# --- 4. run ---
openresty -t
watch_sites &
echo "[moswaf] data plane starting (log=${LOG_LEVEL})"
exec openresty -g 'daemon off;'
