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
#
# An empty sites directory is the normal state of a fresh install, and it is the
# state that used to break this: with no files to match, the globs stay literal,
# cat fails, and `set -o pipefail` hands that failure to the whole pipeline. The
# grouping below swallows it so the hash of "no sites at all" is simply the hash
# of nothing - a real value the watcher can compare against.
sites_hash() {
  { cat "$SITES_DIR"/*.conf /etc/moswaf/certs/* 2>/dev/null || true; } | md5sum | cut -d' ' -f1
}

watch_sites() {
  # errexit off on purpose. This loop is the only thing that turns a site written
  # to disk into a site nginx is actually serving, and it runs in the background
  # where its death is invisible: openresty keeps answering, the dashboard keeps
  # reporting success, and every site added from then on is silently never loaded.
  # A transient failure must cost one cycle, not the watcher.
  set +e

  local last cur
  last="$(sites_hash)"
  echo "[moswaf] watching $SITES_DIR for changes"

  while sleep 3; do
    cur="$(sites_hash)"
    [[ -n "$cur" && "$cur" != "$last" ]] || continue
    last="$cur"
    if openresty -t >/dev/null 2>&1; then
      echo "[moswaf] site configuration changed -> reload"
      openresty -s reload
    else
      echo "[moswaf] SITE CONFIGURATION IS INVALID, skipping reload:" >&2
      openresty -t 2>&1 | sed 's/^/[moswaf]   /' >&2
    fi
  done

  echo "[moswaf] WARNING: the site watcher stopped; new sites will not be loaded" >&2
}

# --- 4. run ---
openresty -t
watch_sites &
echo "[moswaf] data plane starting (log=${LOG_LEVEL})"
exec openresty -g 'daemon off;'
