#!/usr/bin/env bash
#
# Regression tests for the data plane's site watcher (finding #26).
#
# The watcher is the only thing that turns a site file written by the control
# plane into a site nginx is actually serving. It runs in the background, so when
# it dies nothing notices: openresty keeps answering on the default certificate,
# the dashboard keeps reporting success, and every site added from then on is
# written to disk and never loaded.
#
# That is exactly what happened on a fresh install. With no site files yet the
# globs in sites_hash stayed literal, cat failed, `set -o pipefail` handed the
# failure to the pipeline, and `last="$(sites_hash)"` on the watcher's first line
# tripped errexit - so the watcher was dead before the first site ever existed.
#
# These tests drive the real functions out of entrypoint.sh with a stub openresty.
#
#   bash dataplane/test/entrypoint.sh

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENTRYPOINT="$ROOT/dataplane/entrypoint.sh"

failures=0
pass() { echo "  ok   - $1"; }
fail() { echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; failures=$((failures + 1)); }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ------------------------------------------------------------------ 1. sites_hash
#
# The unit of the bug: hashing an empty sites directory must succeed under the
# same shell options entrypoint.sh sets, because that is a fresh install.

echo "sites_hash on an empty directory"

hash_out="$(
  set -euo pipefail
  SITES_DIR="$WORK/empty-sites"
  mkdir -p "$SITES_DIR" /etc/moswaf/certs 2>/dev/null || true
  eval "$(sed -n '/^sites_hash()/,/^}/p' "$ENTRYPOINT")"
  last="$(sites_hash)"          # the exact line that used to kill the watcher
  echo "$last"
)" && rc=0 || rc=$?

if [[ "$rc" != "0" ]]; then
  fail "sites_hash succeeds with no site files" \
       "exited $rc under 'set -euo pipefail' - the watcher dies here on a fresh install"
elif [[ -z "$hash_out" ]]; then
  fail "sites_hash returns a value with no site files" "got an empty string"
else
  pass "sites_hash succeeds and returns a hash with no site files"
fi

# ------------------------------------------------------------------ 2. the watcher
#
# The behaviour that matters: start the watcher with zero sites, as a fresh
# install does, then add one. It has to reload. Before the fix it was already
# dead and the site stayed invisible until the container was restarted by hand.

echo "the watcher reloads a site added after it started with no sites"

SITES_DIR="$WORK/sites"
CERTS_DIR="$WORK/certs"
mkdir -p "$SITES_DIR" "$CERTS_DIR"
RELOADS="$WORK/reloads"
: > "$RELOADS"

# Stand in for openresty: -t always validates, -s reload records the call.
openresty() {
  case "${1:-}" in
    -t) return 0 ;;
    -s) echo "reload" >> "$RELOADS" ;;
  esac
}

# The watcher reads /etc/moswaf/certs directly; point the copy under test at the
# temp directory so the test needs no root and no container.
eval "$(sed -n '/^sites_hash()/,/^}/p' "$ENTRYPOINT" | sed "s#/etc/moswaf/certs#$CERTS_DIR#")"
eval "$(sed -n '/^watch_sites()/,/^}/p' "$ENTRYPOINT")"

# entrypoint.sh sets `set -euo pipefail` at the top of the file and launches the
# watcher with `&`, so the background job inherits those options. The subshell
# here reproduces that: without it the watcher cannot die the way it died in
# production, and this test would pass against the broken code.
( set -euo pipefail; watch_sites ) > "$WORK/watcher.log" 2>&1 &
watcher=$!
sleep 1

if ! kill -0 "$watcher" 2>/dev/null; then
  fail "the watcher is still alive after starting with zero sites" \
       "it exited immediately; log: $(cat "$WORK/watcher.log")"
else
  pass "the watcher is still alive after starting with zero sites"

  # The control plane writes a site file and its certificate.
  printf 'server { listen 80; server_name example.test; }\n' > "$SITES_DIR/1.conf"
  printf 'cert-material\n' > "$CERTS_DIR/1.crt"

  for _ in $(seq 1 10); do
    [[ -s "$RELOADS" ]] && break
    sleep 1
  done

  if [[ -s "$RELOADS" ]]; then
    pass "adding a site triggered a reload"
  else
    fail "adding a site triggered a reload" \
         "no reload within 10s - the site is on disk but nginx never loaded it"
  fi

  # Removing the last site empties the directory again, which puts sites_hash back
  # in the state that used to be fatal. The watcher has to survive it.
  rm -f "$SITES_DIR/1.conf" "$CERTS_DIR/1.crt"
  sleep 5
  if kill -0 "$watcher" 2>/dev/null; then
    pass "the watcher survives the last site being deleted"
  else
    fail "the watcher survives the last site being deleted" \
         "it died when the directory emptied; the next site added would never load"
  fi

  kill "$watcher" 2>/dev/null || true
  wait "$watcher" 2>/dev/null || true
fi

# ------------------------------------------------------------------ report

echo
if [[ "$failures" == "0" ]]; then
  echo "entrypoint: all checks passed"
  exit 0
fi
echo "entrypoint: $failures check(s) FAILED"
exit 1
