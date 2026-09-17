#!/usr/bin/env bash
#
#  MosWAF - chay toan bo stack tren may dev, khong can Docker
#
#  Dung khi muon thu nhanh hoac khi may khong cai duoc Docker. Moi thu chay
#  bang tai khoan thuong, du lieu nam gon trong .local/ va xoa di la sach.
#
#    ./scripts/dev-local.sh start     dung stack + tao san mot site demo
#    ./scripts/dev-local.sh stop      dung tat ca
#    ./scripts/dev-local.sh status    xem con song khong
#    ./scripts/dev-local.sh logs      theo doi log
#    ./scripts/dev-local.sh reset     dung + xoa sach du lieu
#
#  Can: postgresql@16, redis, openresty, go, node
#    brew install postgresql@16 redis go node
#    brew trust openresty/brew && brew install openresty/brew/openresty
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/.local"

# Cong mac dinh tranh cac cong hay bi chiem tren may dev
HTTP_PORT="${MOSWAF_DEV_HTTP_PORT:-8088}"
HTTPS_PORT="${MOSWAF_DEV_HTTPS_PORT:-8543}"
ADMIN_PORT="${MOSWAF_DEV_ADMIN_PORT:-9443}"
INTERNAL_PORT="${MOSWAF_DEV_INTERNAL_PORT:-8081}"
PG_PORT="${MOSWAF_DEV_PG_PORT:-5433}"
REDIS_PORT="${MOSWAF_DEV_REDIS_PORT:-6399}"
DEMO_PORT="${MOSWAF_DEV_DEMO_PORT:-8090}"

ADMIN_USER="admin"
ADMIN_PASS="${MOSWAF_DEV_ADMIN_PASSWORD:-moswaf-dev-12345}"
REDIS_PASS="moswaf-dev-redis"

GRN=$'\033[0;32m'; RED=$'\033[0;31m'; YLW=$'\033[0;33m'; BLU=$'\033[0;36m'; BLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'
info() { echo "${BLU}[*]${NC} $*"; }
ok()   { echo "${GRN}[+]${NC} $*"; }
warn() { echo "${YLW}[!]${NC} $*"; }
die()  { echo "${RED}[x]${NC} $*" >&2; exit 1; }

BREW_PREFIX="$(brew --prefix 2>/dev/null || echo /usr/local)"
PG_BIN="$BREW_PREFIX/opt/postgresql@16/bin"
OPENRESTY_BIN="$BREW_PREFIX/opt/openresty/bin/openresty"
[[ -x "$OPENRESTY_BIN" ]] || OPENRESTY_BIN="$(command -v openresty || true)"

DSN="postgres://$(whoami)@127.0.0.1:${PG_PORT}/moswaf?sslmode=disable"

# ------------------------------------------------------------------ kiem tra

SKIP_PROXY=0

check_deps() {
  [[ -x "$PG_BIN/pg_ctl" ]] || die "Thieu postgresql@16: brew install postgresql@16"
  command -v redis-server >/dev/null || die "Thieu redis: brew install redis"
  command -v go >/dev/null || die "Thieu go: brew install go"
  command -v node >/dev/null || die "Thieu node: brew install node"

  # Thieu OpenResty thi van chay duoc control plane + dashboard de xem giao dien
  # va thu API; chi khong co lop loc traffic that.
  if [[ -z "$OPENRESTY_BIN" || ! -x "$OPENRESTY_BIN" ]]; then
    SKIP_PROXY=1
    warn "Chua co OpenResty - se chay thieu data plane (khong loc duoc traffic)."
    warn "Cai bang: brew trust openresty/brew && brew install openresty/brew/openresty"
  fi
}

port_busy() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

# ------------------------------------------------------------------ postgres

start_postgres() {
  if port_busy "$PG_PORT"; then
    ok "Postgres da chay san o cong $PG_PORT"
    return
  fi
  # Tren macOS, thieu LC_ALL hop le thi postmaster bao
  # "became multithreaded during startup" roi chet ngay.
  export LC_ALL="${LC_ALL:-en_US.UTF-8}"

  if [[ ! -d "$RUN/pgdata/base" ]]; then
    info "Khoi tao cum du lieu Postgres..."
    "$PG_BIN/initdb" -D "$RUN/pgdata" -U "$(whoami)" -E UTF8 --locale=C >/dev/null
  fi
  info "Khoi dong Postgres (cong $PG_PORT)..."
  "$PG_BIN/pg_ctl" -D "$RUN/pgdata" -l "$RUN/logs/postgres.log" \
    -o "-p $PG_PORT -k $RUN/run -h 127.0.0.1" -w start >/dev/null

  "$PG_BIN/psql" -h 127.0.0.1 -p "$PG_PORT" -d postgres -tAc \
    "SELECT 1 FROM pg_database WHERE datname='moswaf'" | grep -q 1 \
    || "$PG_BIN/createdb" -h 127.0.0.1 -p "$PG_PORT" moswaf
  ok "Postgres san sang"
}

# ------------------------------------------------------------------ redis

start_redis() {
  if port_busy "$REDIS_PORT"; then
    ok "Redis da chay san o cong $REDIS_PORT"
    return
  fi
  info "Khoi dong Redis (cong $REDIS_PORT)..."
  redis-server --port "$REDIS_PORT" --requirepass "$REDIS_PASS" \
    --bind 127.0.0.1 --save '' --appendonly no --daemonize yes \
    --dir "$RUN/run" --pidfile "$RUN/run/redis.pid" \
    --logfile "$RUN/logs/redis.log"
  sleep 0.5
  ok "Redis san sang"
}

# ------------------------------------------------------------------ site demo

start_demo_upstream() {
  mkdir -p "$RUN/demo-site/san-pham"
  cat > "$RUN/demo-site/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>Demo upstream</title>
<body style="font-family:system-ui;background:#0b0e14;color:#c9d1d9;padding:48px">
<h2>Trang web demo</h2>
<p>Day la upstream gia dung de thu MosWAF. Neu ban thay trang nay nghia la
request da di qua tuong lua va duoc cho phep.</p>
</body>
HTML
  cp "$RUN/demo-site/index.html" "$RUN/demo-site/san-pham/index.html"

  if port_busy "$DEMO_PORT"; then
    ok "Upstream demo da chay o cong $DEMO_PORT"
    return
  fi
  info "Khoi dong upstream demo (cong $DEMO_PORT)..."
  (cd "$RUN/demo-site" && nohup python3 -m http.server "$DEMO_PORT" --bind 127.0.0.1 \
    >"$RUN/logs/demo.log" 2>&1 & echo $! > "$RUN/run/demo.pid")
  sleep 0.5
  ok "Upstream demo san sang"
}

# ------------------------------------------------------------------ openresty

write_nginx_conf() {
  mkdir -p "$RUN/nginx/conf" "$RUN/nginx/logs" "$RUN/ssl" "$RUN/acme"

  if [[ ! -f "$RUN/ssl/default.crt" ]]; then
    info "Sinh chung chi mac dinh cho data plane..."
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -keyout "$RUN/ssl/default.key" -out "$RUN/ssl/default.crt" \
      -subj "/C=VN/O=MosWAF/CN=moswaf.local" >/dev/null 2>&1
  fi

  # Lay dung file cau hinh that cua data plane roi chi doi duong dan + cong,
  # de thu nghiem o day sat voi ban chay trong container nhat co the.
  sed \
    -e '/^user  *root;/d' \
    -e "s|__LOG_LEVEL__|notice|g" \
    -e "s|/var/log/moswaf|$RUN/logs|g" \
    -e "s|/run/nginx.pid|$RUN/run/nginx.pid|g" \
    -e "s|/usr/local/moswaf/lua|$ROOT/dataplane/lua|g" \
    -e "s|/usr/local/moswaf/conf/default.conf|$RUN/nginx/conf/default.conf|g" \
    -e "s|/etc/moswaf/sites|$RUN/sites|g" \
    -e "s|^ *resolver .*|    resolver 1.1.1.1 ipv6=off valid=30s;|" \
    "$ROOT/dataplane/conf/nginx.conf" > "$RUN/nginx/conf/nginx.conf"

  sed \
    -e "s|listen      80  default_server;|listen      $HTTP_PORT  default_server;|" \
    -e "s|listen      443 ssl default_server;|listen      $HTTPS_PORT ssl default_server;|" \
    -e "s|listen 8081;|listen $INTERNAL_PORT;|" \
    -e "s|/usr/local/moswaf/ssl|$RUN/ssl|g" \
    -e "s|/var/www/acme|$RUN/acme|g" \
    "$ROOT/dataplane/conf/default.conf" > "$RUN/nginx/conf/default.conf"

  # mime.types nam khac cho tuy ban cai (brew de o etc/openresty)
  local mime
  for mime in "$BREW_PREFIX/etc/openresty/mime.types" \
              "$BREW_PREFIX/opt/openresty/nginx/conf/mime.types" \
              "$BREW_PREFIX/etc/nginx/mime.types"; do
    if [[ -f "$mime" ]]; then
      cp "$mime" "$RUN/nginx/conf/"
      return
    fi
  done
  die "Khong tim thay mime.types cua OpenResty"
}

start_openresty() {
  write_nginx_conf

  # Engine Lua doc ba bien nay qua os.getenv (khai bao `env` trong nginx.conf).
  # Thieu chung thi worker se di tim host "redis" cua Docker va rot het
  # su kien lan cau hinh.
  export MOSWAF_REDIS_HOST="127.0.0.1"
  export MOSWAF_REDIS_PORT="$REDIS_PORT"
  export MOSWAF_REDIS_PASSWORD="$REDIS_PASS"
  export MOSWAF_CHALLENGE_SECRET="moswaf-dev-challenge-secret"
  export MOSWAF_CONF_DIR="$ROOT/dataplane/conf"

  if [[ -f "$RUN/run/nginx.pid" ]] && kill -0 "$(cat "$RUN/run/nginx.pid")" 2>/dev/null; then
    info "Nap lai cau hinh OpenResty..."
    "$OPENRESTY_BIN" -p "$RUN/nginx" -c conf/nginx.conf -s reload
    return
  fi
  info "Kiem tra cu phap nginx..."
  "$OPENRESTY_BIN" -p "$RUN/nginx" -c conf/nginx.conf -t
  info "Khoi dong OpenResty (HTTP $HTTP_PORT, HTTPS $HTTPS_PORT)..."
  "$OPENRESTY_BIN" -p "$RUN/nginx" -c conf/nginx.conf
  sleep 0.5
  ok "Data plane san sang"
}

# ------------------------------------------------------------------ control plane

build_all() {
  if [[ ! -f "$ROOT/control/internal/web/dist/index.html" ]]; then
    info "Build dashboard..."
    (cd "$ROOT/web" && npm install --silent --no-audit --no-fund && npm run build >/dev/null)
  fi
  info "Build control plane..."
  (cd "$ROOT/control" && go build -o "$RUN/moswafd" ./cmd/moswafd)
}

start_control() {
  if port_busy "$ADMIN_PORT"; then
    ok "Control plane da chay o cong $ADMIN_PORT"
    return
  fi
  info "Khoi dong control plane (dashboard cong $ADMIN_PORT)..."
  MOSWAF_LISTEN=":$ADMIN_PORT" \
  MOSWAF_DB_DSN="$DSN" \
  MOSWAF_REDIS_ADDR="127.0.0.1:$REDIS_PORT" \
  MOSWAF_REDIS_PASSWORD="$REDIS_PASS" \
  MOSWAF_JWT_SECRET="moswaf-dev-jwt-secret" \
  MOSWAF_CHALLENGE_SECRET="moswaf-dev-challenge-secret" \
  MOSWAF_ADMIN_USER="$ADMIN_USER" \
  MOSWAF_ADMIN_PASSWORD="$ADMIN_PASS" \
  MOSWAF_SITES_DIR="$RUN/sites" \
  MOSWAF_CERTS_DIR="$RUN/certs" \
  MOSWAF_ADMIN_TLS_DIR="$RUN/admin-tls" \
  MOSWAF_PROXY_SYNC_URL="http://127.0.0.1:$INTERNAL_PORT/sync" \
  MOSWAF_SITE_HTTP_PORT="$HTTP_PORT" \
  MOSWAF_SITE_HTTPS_PORT="$HTTPS_PORT" \
    nohup "$RUN/moswafd" >"$RUN/logs/mgmt.log" 2>&1 &
  echo $! > "$RUN/run/mgmt.pid"

  for _ in $(seq 1 40); do
    if curl -sk "https://127.0.0.1:$ADMIN_PORT/api/health" >/dev/null 2>&1; then
      ok "Control plane san sang"
      return
    fi
    sleep 0.5
  done
  die "Control plane khong len duoc, xem $RUN/logs/mgmt.log"
}

# ------------------------------------------------------------------ site demo trong MosWAF

seed_site() {
  local token
  token="$(curl -sk "https://127.0.0.1:$ADMIN_PORT/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  [[ -n "$token" ]] || die "Khong dang nhap duoc de tao site demo"

  local count
  count="$(curl -sk "https://127.0.0.1:$ADMIN_PORT/api/sites" \
    -H "Authorization: Bearer $token" | grep -o '"id"' | wc -l | tr -d ' ')"

  if [[ "$count" == "0" ]]; then
    info "Tao site demo tro ve upstream 127.0.0.1:$DEMO_PORT..."
    curl -sk "https://127.0.0.1:$ADMIN_PORT/api/sites" \
      -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
      -d "{\"name\":\"Site demo\",\"domains\":[\"localhost\",\"127.0.0.1\",\"demo.moswaf.local\"],
           \"upstream_scheme\":\"http\",\"upstream_host\":\"127.0.0.1\",\"upstream_port\":$DEMO_PORT,
           \"mode\":\"protect\",\"challenge\":\"auto\"}" >/dev/null
    if [[ "$SKIP_PROXY" != "1" ]]; then
      sleep 2   # cho control plane ghi xong file cau hinh site
      "$OPENRESTY_BIN" -p "$RUN/nginx" -c conf/nginx.conf -s reload 2>/dev/null || true
    fi
    ok "Da tao site demo"
  else
    ok "Da co $count site, khong tao them"
  fi
}

# ------------------------------------------------------------------ lenh

cmd_start() {
  check_deps
  mkdir -p "$RUN"/{logs,run,sites,certs,admin-tls}
  start_postgres
  start_redis
  start_demo_upstream
  build_all
  [[ "$SKIP_PROXY" == "1" ]] || start_openresty
  start_control
  seed_site
  echo
  echo "${GRN}${BLD}============================================================${NC}"
  echo "${GRN}${BLD}  MosWAF dang chay tren may nay${NC}"
  echo "${GRN}${BLD}============================================================${NC}"
  echo "  Dashboard      : ${BLD}https://127.0.0.1:${ADMIN_PORT}${NC} ${DIM}(TLS tu ky, bo qua canh bao)${NC}"
  echo "  Tai khoan      : ${BLD}${ADMIN_USER} / ${ADMIN_PASS}${NC}"
  echo
  if [[ "$SKIP_PROXY" == "1" ]]; then
    echo "  ${YLW}Data plane   : chua chay (thieu OpenResty) - chua loc duoc traffic${NC}"
    echo "  Upstream goc   : http://127.0.0.1:${DEMO_PORT}/"
    echo
  else
    echo "  Site qua WAF   : ${BLD}http://127.0.0.1:${HTTP_PORT}/${NC}"
    echo "  Upstream goc   : http://127.0.0.1:${DEMO_PORT}/ ${DIM}(khong qua WAF, de doi chieu)${NC}"
    echo
    echo "  Thu tan cong   : ./scripts/attack-sim.sh http://127.0.0.1:${HTTP_PORT}"
  fi
  echo "  Log            : ./scripts/dev-local.sh logs"
  echo "  Dung           : ./scripts/dev-local.sh stop"
  echo "${GRN}${BLD}============================================================${NC}"
  echo
}

stop_pid() {
  local file="$1" name="$2"
  if [[ -f "$file" ]] && kill -0 "$(cat "$file")" 2>/dev/null; then
    kill "$(cat "$file")" 2>/dev/null || true
    ok "Da dung $name"
  fi
  rm -f "$file"
}

cmd_stop() {
  stop_pid "$RUN/run/mgmt.pid" "control plane"
  stop_pid "$RUN/run/demo.pid" "upstream demo"
  if [[ -f "$RUN/run/nginx.pid" ]]; then
    "$OPENRESTY_BIN" -p "$RUN/nginx" -c conf/nginx.conf -s quit 2>/dev/null || \
      kill "$(cat "$RUN/run/nginx.pid")" 2>/dev/null || true
    ok "Da dung OpenResty"
  fi
  if [[ -f "$RUN/run/redis.pid" ]]; then
    redis-cli -p "$REDIS_PORT" -a "$REDIS_PASS" --no-auth-warning shutdown nosave 2>/dev/null || true
    ok "Da dung Redis"
  fi
  if [[ -d "$RUN/pgdata" ]]; then
    "$PG_BIN/pg_ctl" -D "$RUN/pgdata" stop -m fast >/dev/null 2>&1 && ok "Da dung Postgres" || true
  fi
}

cmd_status() {
  printf "%-18s %s\n" "Postgres"      "$(port_busy "$PG_PORT"       && echo "${GRN}dang chay${NC} :$PG_PORT"       || echo "${RED}tat${NC}")"
  printf "%-18s %s\n" "Redis"         "$(port_busy "$REDIS_PORT"    && echo "${GRN}dang chay${NC} :$REDIS_PORT"    || echo "${RED}tat${NC}")"
  printf "%-18s %s\n" "Upstream demo" "$(port_busy "$DEMO_PORT"     && echo "${GRN}dang chay${NC} :$DEMO_PORT"     || echo "${RED}tat${NC}")"
  printf "%-18s %s\n" "Data plane"    "$(port_busy "$HTTP_PORT"     && echo "${GRN}dang chay${NC} :$HTTP_PORT"     || echo "${RED}tat${NC}")"
  printf "%-18s %s\n" "Control plane" "$(port_busy "$ADMIN_PORT"    && echo "${GRN}dang chay${NC} :$ADMIN_PORT"    || echo "${RED}tat${NC}")"
}

cmd_logs() { tail -f "$RUN/logs/mgmt.log" "$RUN/logs/error.log" 2>/dev/null; }

cmd_reset() {
  cmd_stop
  read -r -p "Xoa sach .local/ (database, log, chung chi)? [y/N] " a
  [[ "${a:-N}" =~ ^[Yy]$ ]] && rm -rf "$RUN" && ok "Da xoa $RUN"
}

case "${1:-start}" in
  start)  cmd_start ;;
  stop)   cmd_stop ;;
  status) cmd_status ;;
  logs)   cmd_logs ;;
  reset)  cmd_reset ;;
  *) sed -n '2,16p' "$0"; exit 1 ;;
esac
