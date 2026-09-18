#!/usr/bin/env bash
#
#  MosWAF - take everything out of SafeLine before anything is touched
#
#  Run this ON THE SAFELINE HOST. It only reads: it starts nothing, stops
#  nothing and deletes nothing. What it writes goes to one directory outside
#  any repository, because it contains real domains, addresses and private keys.
#
#  Usage:
#    ./safeline-export.sh                      # config + certificates
#    ./safeline-export.sh --full               # also a tarball of /data/safeline
#    ./safeline-export.sh --out ~/somewhere    # default ~/moswaf-migration
#
#  The output feeds scripts/safeline-import.py, which turns it into MosWAF sites.
#
set -uo pipefail

OUT="$HOME/moswaf-migration"
FULL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)  OUT="$2"; shift 2 ;;
    --full) FULL=1; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

STAMP="$(date +%F-%H%M)"
DIR="$OUT/safeline-$STAMP"
mkdir -p "$DIR/certs" || { echo "Cannot write to $DIR" >&2; exit 1; }
chmod 700 "$OUT" "$DIR" 2>/dev/null || true

say()  { printf '  %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*" >&2; }

echo
echo "SafeLine export -> $DIR"
echo

# ---------------------------------------------------------------- containers
docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' > "$DIR/containers.txt" 2>/dev/null \
  || { warn "docker is not usable here. Run this as root on the SafeLine host."; exit 1; }
say "containers.txt"

# The proxy container has been called different things across SafeLine versions.
TENGINE=""
for c in safeline-tengine safeline-nginx safeline_tengine; do
  docker ps --format '{{.Names}}' | grep -qx "$c" && { TENGINE="$c"; break; }
done
if [[ -z "$TENGINE" ]]; then
  TENGINE="$(docker ps --format '{{.Names}}' | grep -i -m1 'tengine\|nginx' || true)"
fi
[[ -n "$TENGINE" ]] || { warn "No SafeLine proxy container is running - nothing to read the config from."; exit 1; }
say "proxy container: $TENGINE"

# ------------------------------------------------------------- the real config
#  nginx -T is the ground truth: every server_name with the proxy_pass behind it,
#  includes already expanded. The UI shows listening ports and truncates domain
#  lists, which is how a site gets forgotten until it is down.
if ! docker exec "$TENGINE" nginx -T > "$DIR/nginx-T.conf" 2> "$DIR/nginx-T.stderr"; then
  warn "nginx -T returned an error; see nginx-T.stderr. Keeping what it did print."
fi
if [[ ! -s "$DIR/nginx-T.conf" ]]; then
  warn "The config dump is empty. Without it no site can be migrated - stop here and find out why."
  exit 1
fi
say "nginx-T.conf  ($(grep -c '^\s*server_name' "$DIR/nginx-T.conf" || echo 0) server_name lines)"

# ------------------------------------------------------------------- certificates
#  Copied straight out of the container, at the paths the config actually names.
#  A site that must not lose HTTPS for a minute reuses its existing certificate:
#  ordering a new one needs the domain already pointing here, which only happens
#  after cutover.
mapfile -t CERTPATHS < <(
  grep -hE '^\s*ssl_certificate(_key)?\s' "$DIR/nginx-T.conf" \
    | awk '{print $2}' | tr -d ';"' | sort -u
)
copied=0
for p in "${CERTPATHS[@]:-}"; do
  [[ -n "$p" && "$p" == /* ]] || continue
  if docker cp "$TENGINE:$p" "$DIR/certs/$(basename "$p")" 2>/dev/null; then
    copied=$((copied + 1))
  else
    warn "could not copy $p"
  fi
done
chmod 600 "$DIR"/certs/* 2>/dev/null || true
say "certs/  ($copied files)"

# --------------------------------------------------------------- a second copy
#  The database is the other place the applications are written down. If the two
#  disagree, the difference is worth knowing before the move, not after.
PG="$(docker ps --format '{{.Names}}' | grep -i -m1 'safeline.*pg\|safeline.*postgres' || true)"
if [[ -n "$PG" ]]; then
  if docker exec "$PG" sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > "$DIR/safeline-db.sql" 2>/dev/null; then
    say "safeline-db.sql"
  else
    rm -f "$DIR/safeline-db.sql"
    warn "pg_dump failed on $PG (not fatal - nginx -T is the config that matters)"
  fi
fi

# ------------------------------------------------------------------- full backup
if [[ "$FULL" == "1" ]]; then
  SLDIR="/data/safeline"
  [[ -d "$SLDIR" ]] || SLDIR="$(docker inspect "$TENGINE" --format '{{range .Mounts}}{{.Source}}{{println}}{{end}}' 2>/dev/null | grep -m1 safeline || true)"
  if [[ -n "$SLDIR" && -d "$SLDIR" ]]; then
    tar czf "$DIR/safeline-data.tgz" "$SLDIR" 2>/dev/null \
      && say "safeline-data.tgz  ($(du -h "$DIR/safeline-data.tgz" | cut -f1))" \
      || warn "tar of $SLDIR failed"
  else
    warn "Could not find the SafeLine data directory; skipping the full backup."
  fi
fi

# ------------------------------------------------------------------ what we saw
echo
SERVERS=$(grep -cE '^\s*server\s*\{' "$DIR/nginx-T.conf" || echo 0)
NAMES=$(grep -hE '^\s*server_name\s' "$DIR/nginx-T.conf" | sed 's/server_name//; s/;//' | tr ' ' '\n' \
        | grep -vE '^\s*$|^_$' | sort -u | wc -l | tr -d ' ')
UPSTREAMS=$(grep -cE '^\s*proxy_pass\s' "$DIR/nginx-T.conf" || echo 0)
echo "  server blocks : $SERVERS"
echo "  distinct names: $NAMES"
echo "  proxy_pass    : $UPSTREAMS"
echo
echo "  Count the applications SafeLine's own dashboard reports and compare with"
echo "  the names above. If they differ, the missing ones are the sites nobody"
echo "  will remember until they are down."
echo
echo "  Next:  python3 scripts/safeline-import.py $DIR/nginx-T.conf --certs-from $DIR/certs"
echo
