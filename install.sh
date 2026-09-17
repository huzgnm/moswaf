#!/usr/bin/env bash
#
#  MosWAF - trinh cai dat one-command
#
#    curl -fsSL https://raw.githubusercontent.com/huzgnm/moswaf/main/install.sh | bash
#  hoac chay truc tiep trong thu muc source:
#    sudo bash install.sh
#
#  Tuy chon:
#    --admin-port <port>   cong dashboard admin (mac dinh 9443)
#    --admin-bind <ip>     IP bind dashboard (mac dinh 0.0.0.0, dung 127.0.0.1 de chi vao qua SSH tunnel)
#    --http-port <port>    cong HTTP data plane (mac dinh 80)
#    --https-port <port>   cong HTTPS data plane (mac dinh 443)
#    --dir <path>          thu muc cai dat (mac dinh /opt/moswaf)
#    --upgrade             keo code moi + build lai, giu nguyen du lieu
#    --uninstall           go MosWAF (hoi truoc khi xoa du lieu)
#    --reset-password      sinh mat khau admin moi
#
set -euo pipefail

MOSWAF_REPO="${MOSWAF_REPO:-https://github.com/huzgnm/moswaf.git}"
MOSWAF_BRANCH="${MOSWAF_BRANCH:-main}"
INSTALL_DIR="${MOSWAF_DIR:-/opt/moswaf}"

ADMIN_PORT="9443"
ADMIN_BIND="0.0.0.0"
HTTP_PORT="80"
HTTPS_PORT="443"
ACTION="install"

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[0;33m'; BLU=$'\033[0;36m'; BLD=$'\033[1m'; NC=$'\033[0m'
info()  { echo "${BLU}[*]${NC} $*"; }
ok()    { echo "${GRN}[+]${NC} $*"; }
warn()  { echo "${YLW}[!]${NC} $*"; }
die()   { echo "${RED}[x]${NC} $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-port)     ADMIN_PORT="$2"; shift 2 ;;
    --admin-bind)     ADMIN_BIND="$2"; shift 2 ;;
    --http-port)      HTTP_PORT="$2";  shift 2 ;;
    --https-port)     HTTPS_PORT="$2"; shift 2 ;;
    --dir)            INSTALL_DIR="$2"; shift 2 ;;
    --upgrade)        ACTION="upgrade"; shift ;;
    --uninstall)      ACTION="uninstall"; shift ;;
    --reset-password) ACTION="reset-password"; shift ;;
    -h|--help)        sed -n '2,25p' "$0"; exit 0 ;;
    *) die "Tham so khong hop le: $1" ;;
  esac
done

banner() {
cat <<'EOF'

   __  __            _       _____ ____
  |  \/  | ___  ___ | |     / /   |  _ \    Layer-7 WAF / Anti-DDoS
  | |\/| |/ _ \/ __|| | /| / / /| | |_) |
  | |  | | (_) \__ \| |/ |/ / ___ |  __/
  |_|  |_|\___/|___/|__/|__/_/  |_|_|

EOF
}

need_root() {
  [[ "$(id -u)" == "0" ]] || die "Can chay bang root. Dung: sudo bash $0"
}

rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-32}"; }

detect_os() {
  [[ "$(uname -s)" == "Linux" ]] || die "MosWAF chi cai dat tren Linux server (phat hien: $(uname -s))."
  if [[ -f /etc/os-release ]]; then . /etc/os-release; OS_ID="${ID:-unknown}"; else OS_ID="unknown"; fi
}

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "Docker + Compose plugin da san sang"
    return
  fi
  warn "Chua co Docker, dang cai dat..."
  curl -fsSL https://get.docker.com | sh || die "Cai Docker that bai"
  systemctl enable --now docker >/dev/null 2>&1 || true
  docker compose version >/dev/null 2>&1 || die "Thieu docker compose plugin, cai thu cong roi chay lai."
  ok "Da cai Docker"
}

check_port() {
  local port="$1" label="$2"
  if command -v ss >/dev/null 2>&1 && ss -lntH "sport = :$port" 2>/dev/null | grep -q .; then
    warn "Cong $port ($label) dang bi tien trinh khac chiem. Dung tien trinh do hoac doi cong."
    return 1
  fi
  return 0
}

fetch_source() {
  if [[ -f "$(dirname "$0")/docker-compose.yml" && -d "$(dirname "$0")/dataplane" ]]; then
    SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [[ "$SRC_DIR" != "$INSTALL_DIR" ]]; then
      info "Copy source tu $SRC_DIR -> $INSTALL_DIR"
      mkdir -p "$INSTALL_DIR"
      tar -C "$SRC_DIR" --exclude='.git' --exclude='data' --exclude='node_modules' -cf - . | tar -C "$INSTALL_DIR" -xf -
    fi
  elif [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Cap nhat source san co tai $INSTALL_DIR"
    git -C "$INSTALL_DIR" fetch --depth 1 origin "$MOSWAF_BRANCH"
    git -C "$INSTALL_DIR" reset --hard "origin/$MOSWAF_BRANCH"
  else
    command -v git >/dev/null 2>&1 || die "Thieu git. Cai git roi chay lai."
    info "Tai source tu $MOSWAF_REPO"
    git clone --depth 1 -b "$MOSWAF_BRANCH" "$MOSWAF_REPO" "$INSTALL_DIR"
  fi
  cd "$INSTALL_DIR"
}

write_env() {
  if [[ -f "$INSTALL_DIR/.env" ]]; then
    ok "Giu nguyen .env hien co"
    return
  fi
  info "Sinh .env voi bi mat ngau nhien"
  ADMIN_PASSWORD="$(rand 16)"
  cat > "$INSTALL_DIR/.env" <<EOF
MOSWAF_VERSION=0.1.0

MOSWAF_HTTP_PORT=${HTTP_PORT}
MOSWAF_HTTPS_PORT=${HTTPS_PORT}
MOSWAF_ADMIN_PORT=${ADMIN_PORT}
MOSWAF_ADMIN_BIND=${ADMIN_BIND}

MOSWAF_ADMIN_USER=admin
MOSWAF_ADMIN_PASSWORD=${ADMIN_PASSWORD}

POSTGRES_USER=moswaf
POSTGRES_PASSWORD=$(rand 32)
POSTGRES_DB=moswaf

REDIS_PASSWORD=$(rand 32)

MOSWAF_JWT_SECRET=$(rand 48)
MOSWAF_CHALLENGE_SECRET=$(rand 48)

MOSWAF_DATA_DIR=${INSTALL_DIR}/data
MOSWAF_LOG_LEVEL=warn
TZ=$(cat /etc/timezone 2>/dev/null || echo Asia/Ho_Chi_Minh)
EOF
  chmod 600 "$INSTALL_DIR/.env"
  NEW_INSTALL=1
}

compose() { docker compose --env-file "$INSTALL_DIR/.env" -f "$INSTALL_DIR/docker-compose.yml" "$@"; }

public_ip() {
  curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null \
    || ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' \
    || echo "<IP-SERVER>"
}

print_result() {
  local ip; ip="$(public_ip)"
  local port user pass
  port="$(grep -E '^MOSWAF_ADMIN_PORT=' "$INSTALL_DIR/.env" | cut -d= -f2)"
  user="$(grep -E '^MOSWAF_ADMIN_USER=' "$INSTALL_DIR/.env" | cut -d= -f2)"
  pass="$(grep -E '^MOSWAF_ADMIN_PASSWORD=' "$INSTALL_DIR/.env" | cut -d= -f2)"
  echo
  echo "${GRN}${BLD}============================================================${NC}"
  echo "${GRN}${BLD}  MosWAF da chay${NC}"
  echo "${GRN}${BLD}============================================================${NC}"
  echo "  Dashboard : ${BLD}https://${ip}:${port}${NC}   ${YLW}(cong rieng, TLS tu ky)${NC}"
  echo "  Tai khoan : ${BLD}${user}${NC}"
  echo "  Mat khau  : ${BLD}${pass}${NC}"
  echo
  echo "  Traffic   : HTTP ${HTTP_PORT} / HTTPS ${HTTPS_PORT} (tro domain ve IP nay)"
  echo "  Thu muc   : ${INSTALL_DIR}"
  echo "  Lenh      : cd ${INSTALL_DIR} && docker compose ps | logs -f | restart"
  echo
  echo "  ${YLW}Doi mat khau ngay sau khi dang nhap lan dau.${NC}"
  echo "  ${YLW}Mo firewall cho cong ${port} hoac dung SSH tunnel:${NC}"
  echo "    ssh -L ${port}:127.0.0.1:${port} root@${ip}"
  echo "${GRN}${BLD}============================================================${NC}"
  echo
}

do_install() {
  banner
  need_root
  detect_os
  install_docker
  check_port "$HTTP_PORT"  "data plane HTTP"  || true
  check_port "$HTTPS_PORT" "data plane HTTPS" || true
  check_port "$ADMIN_PORT" "dashboard admin"  || true
  fetch_source
  write_env
  mkdir -p "$INSTALL_DIR/data"/{postgres,proxy-logs,admin-tls}
  info "Build image (lan dau mat vai phut)..."
  compose build
  info "Khoi dong dich vu..."
  compose up -d
  info "Cho control plane san sang..."
  for _ in $(seq 1 60); do
    if compose exec -T mgmt /moswafd -healthcheck >/dev/null 2>&1; then break; fi
    sleep 2
  done
  ok "Hoan tat"
  print_result
}

do_upgrade() {
  need_root
  [[ -f "$INSTALL_DIR/.env" ]] || die "Chua cai MosWAF tai $INSTALL_DIR"
  fetch_source
  info "Build lai image..."
  compose build --pull
  compose up -d
  ok "Da nang cap. Du lieu va cau hinh duoc giu nguyen."
  compose ps
}

do_uninstall() {
  need_root
  [[ -d "$INSTALL_DIR" ]] || die "Khong thay $INSTALL_DIR"
  warn "Se dung va xoa toan bo container MosWAF."
  compose down --remove-orphans || true
  read -r -p "Xoa luon DU LIEU (database, log, chung chi) tai $INSTALL_DIR/data? [y/N] " a
  if [[ "${a:-N}" =~ ^[Yy]$ ]]; then
    compose down -v --remove-orphans || true
    rm -rf "${INSTALL_DIR:?}/data"
    ok "Da xoa du lieu."
  else
    ok "Giu lai du lieu tai $INSTALL_DIR/data"
  fi
  ok "Da go MosWAF."
}

do_reset_password() {
  need_root
  [[ -f "$INSTALL_DIR/.env" ]] || die "Chua cai MosWAF tai $INSTALL_DIR"
  local newpass; newpass="$(rand 16)"
  compose exec -T mgmt /moswafd -reset-password "$newpass" \
    || die "Doi mat khau that bai (container mgmt dang chay chua?)"
  sed -i "s|^MOSWAF_ADMIN_PASSWORD=.*|MOSWAF_ADMIN_PASSWORD=${newpass}|" "$INSTALL_DIR/.env"
  ok "Mat khau admin moi: ${BLD}${newpass}${NC}"
}

case "$ACTION" in
  install)        do_install ;;
  upgrade)        do_upgrade ;;
  uninstall)      do_uninstall ;;
  reset-password) do_reset_password ;;
esac
