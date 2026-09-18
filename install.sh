#!/usr/bin/env bash
#
#  MosWAF installer
#
#    curl -fsSL https://raw.githubusercontent.com/huzgnm/moswaf/main/install.sh | bash
#  or, from a source checkout:
#    sudo bash install.sh
#
#  Run without arguments for the menu:
#
#    1) INSTALL     fresh install
#    2) UPDATE      pull the latest code, rebuild, keep all data
#    3) REPAIR      diagnose and fix a broken install
#    4) UNINSTALL   remove MosWAF
#
#  Non-interactive flags (for scripts and CI):
#    --install | --update | --repair | --uninstall
#    --admin-port <port>   admin dashboard port (default 9443)
#    --admin-bind <ip>     address the dashboard binds to (default 0.0.0.0,
#                          use 127.0.0.1 to reach it only through an SSH tunnel)
#    --http-port <port>    data plane HTTP port (default 80)
#    --https-port <port>   data plane HTTPS port (default 443)
#    --dir <path>          install directory (default /opt/moswaf)
#    --yes                 never prompt, assume yes
#
set -euo pipefail

MOSWAF_REPO="${MOSWAF_REPO:-https://github.com/huzgnm/moswaf.git}"
MOSWAF_BRANCH="${MOSWAF_BRANCH:-main}"
INSTALL_DIR="${MOSWAF_DIR:-/opt/moswaf}"

ADMIN_PORT="9443"
ADMIN_BIND="0.0.0.0"
HTTP_PORT="80"
HTTPS_PORT="443"
ACTION=""
ASSUME_YES=0

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[0;33m'; BLU=$'\033[0;36m'
BLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'
info() { echo "${BLU}[*]${NC} $*"; }
ok()   { echo "${GRN}[+]${NC} $*"; }
warn() { echo "${YLW}[!]${NC} $*"; }
die()  { echo "${RED}[x]${NC} $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install)     ACTION="install"; shift ;;
    --update)      ACTION="update"; shift ;;
    --repair)      ACTION="repair"; shift ;;
    --uninstall)   ACTION="uninstall"; shift ;;
    --admin-port)  ADMIN_PORT="$2"; shift 2 ;;
    --admin-bind)  ADMIN_BIND="$2"; shift 2 ;;
    --http-port)   HTTP_PORT="$2";  shift 2 ;;
    --https-port)  HTTPS_PORT="$2"; shift 2 ;;
    --dir)         INSTALL_DIR="$2"; shift 2 ;;
    --yes|-y)      ASSUME_YES=1; shift ;;
    -h|--help)     sed -n '2,28p' "$0"; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

banner() {
cat <<'BANNER'

   __  __               __        __    _     _____
  |  \/  |  ___    ___  \ \      / /   / \   |  ___|
  | |\/| | / _ \  / __|  \ \ /\ / /   / _ \  | |_
  | |  | || (_) | \__ \   \ V  V /   / ___ \ |  _|
  |_|  |_| \___/  |___/    \_/\_/   /_/   \_\|_|

  Layer-7 WAF / Anti-DDoS

BANNER
}

# ------------------------------------------------------------------ helpers

need_root() { [[ "$(id -u)" == "0" ]] || die "Must run as root. Try: sudo bash $0"; }
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-32}"; }
installed() { [[ -f "$INSTALL_DIR/.env" && -f "$INSTALL_DIR/docker-compose.yml" ]]; }
compose() { docker compose --env-file "$INSTALL_DIR/.env" -f "$INSTALL_DIR/docker-compose.yml" "$@"; }

# Read a value out of .env without sourcing the file
env_get() { grep -E "^$1=" "$INSTALL_DIR/.env" 2>/dev/null | head -1 | cut -d= -f2-; }

confirm() {
  [[ "$ASSUME_YES" == "1" ]] && return 0
  local answer
  read -r -p "$1 [y/N] " answer </dev/tty || return 1
  [[ "$answer" =~ ^[Yy]$ ]]
}

detect_os() {
  [[ "$(uname -s)" == "Linux" ]] || die "MosWAF installs on Linux servers only (found: $(uname -s))."
}

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "Docker and the Compose plugin are ready"
    return
  fi
  warn "Docker is missing, installing it..."
  curl -fsSL https://get.docker.com | sh || die "Docker installation failed"
  systemctl enable --now docker >/dev/null 2>&1 || true
  docker compose version >/dev/null 2>&1 || die "The docker compose plugin is missing; install it and run this again."
  ok "Docker installed"
}

port_taken() {
  command -v ss >/dev/null 2>&1 && ss -lntH "sport = :$1" 2>/dev/null | grep -q .
}

check_ports() {
  local p
  for p in "$HTTP_PORT:data plane HTTP" "$HTTPS_PORT:data plane HTTPS" "$ADMIN_PORT:admin dashboard"; do
    if port_taken "${p%%:*}"; then
      warn "Port ${p%%:*} (${p#*:}) is already in use. Stop that process or pick another port."
    fi
  done
}

fetch_source() {
  local here; here="$(cd "$(dirname "$0")" && pwd)"
  if [[ -f "$here/docker-compose.yml" && -d "$here/dataplane" ]]; then
    if [[ "$here" != "$INSTALL_DIR" ]]; then
      info "Copying the source from $here to $INSTALL_DIR"
      mkdir -p "$INSTALL_DIR"
      tar -C "$here" --exclude='.git' --exclude='data' --exclude='.local' \
          --exclude='node_modules' -cf - . | tar -C "$INSTALL_DIR" -xf -
    fi
  elif [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Updating the existing checkout in $INSTALL_DIR"
    git -C "$INSTALL_DIR" fetch --depth 1 origin "$MOSWAF_BRANCH"
    git -C "$INSTALL_DIR" reset --hard "origin/$MOSWAF_BRANCH"
  else
    command -v git >/dev/null 2>&1 || die "git is missing. Install it and run this again."
    info "Cloning $MOSWAF_REPO"
    git clone --depth 1 -b "$MOSWAF_BRANCH" "$MOSWAF_REPO" "$INSTALL_DIR"
  fi
  cd "$INSTALL_DIR"
}

write_env() {
  if [[ -f "$INSTALL_DIR/.env" ]]; then
    ok "Keeping the existing .env"
    return
  fi
  info "Generating .env with fresh random secrets"
  cat > "$INSTALL_DIR/.env" <<ENVFILE
MOSWAF_VERSION=0.1.0

MOSWAF_HTTP_PORT=${HTTP_PORT}
MOSWAF_HTTPS_PORT=${HTTPS_PORT}
MOSWAF_ADMIN_PORT=${ADMIN_PORT}
MOSWAF_ADMIN_BIND=${ADMIN_BIND}

MOSWAF_ADMIN_USER=admin
MOSWAF_ADMIN_PASSWORD=$(rand 16)

POSTGRES_USER=moswaf
POSTGRES_PASSWORD=$(rand 32)
POSTGRES_DB=moswaf

REDIS_PASSWORD=$(rand 32)

MOSWAF_JWT_SECRET=$(rand 48)
MOSWAF_CHALLENGE_SECRET=$(rand 48)
MOSWAF_INTERNAL_TOKEN=$(rand 48)

# Certificate authority for automatic certificates. Empty means Let's Encrypt
# production. Test against staging first - production rate limits are strict and a
# handful of failed attempts can lock a domain out for a week:
#   MOSWAF_ACME_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory
MOSWAF_ACME_DIRECTORY=

MOSWAF_DATA_DIR=${INSTALL_DIR}/data
MOSWAF_LOG_LEVEL=warn
TZ=$(cat /etc/timezone 2>/dev/null || echo UTC)
ENVFILE
  chmod 600 "$INSTALL_DIR/.env"
}

public_ip() {
  curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null \
    || ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' \
    || echo "<SERVER-IP>"
}

wait_healthy() {
  info "Waiting for the control plane..."
  local i
  for i in $(seq 1 60); do
    if compose exec -T mgmt /moswafd -healthcheck >/dev/null 2>&1; then
      ok "Control plane is up"
      return 0
    fi
    sleep 2
  done
  warn "The control plane did not come up in time. Check: docker compose logs mgmt"
  return 1
}

print_result() {
  local ip port user pass
  ip="$(public_ip)"
  port="$(env_get MOSWAF_ADMIN_PORT)"
  user="$(env_get MOSWAF_ADMIN_USER)"
  pass="$(env_get MOSWAF_ADMIN_PASSWORD)"
  echo
  echo "${GRN}${BLD}============================================================${NC}"
  echo "${GRN}${BLD}  MosWAF is running${NC}"
  echo "${GRN}${BLD}============================================================${NC}"
  echo "  Dashboard : ${BLD}https://${ip}:${port}${NC}   ${YLW}(own port, self-signed TLS)${NC}"
  echo "  Username  : ${BLD}${user}${NC}"
  echo "  Password  : ${BLD}${pass}${NC}"
  echo
  echo "  Traffic   : HTTP $(env_get MOSWAF_HTTP_PORT) / HTTPS $(env_get MOSWAF_HTTPS_PORT)"
  echo "  Directory : ${INSTALL_DIR}"
  echo
  echo "  ${YLW}Change the password right after your first sign-in.${NC}"
  echo "  ${YLW}Open the firewall for port ${port}, or use an SSH tunnel:${NC}"
  echo "    ssh -L ${port}:127.0.0.1:${port} root@${ip}"
  echo "${GRN}${BLD}============================================================${NC}"
  echo
}

# ------------------------------------------------------------------ actions

do_install() {
  need_root; detect_os
  if installed; then
    warn "MosWAF is already installed in $INSTALL_DIR."
    confirm "Reinstall over it? Data is kept." || { info "Cancelled."; return 0; }
  fi
  install_docker
  check_ports
  fetch_source
  write_env
  mkdir -p "$INSTALL_DIR/data"/{postgres,proxy-logs,admin-tls}
  info "Building images (the first build takes a few minutes)..."
  compose build
  info "Starting services..."
  compose up -d
  wait_healthy || true
  print_result
}

do_update() {
  need_root
  installed || die "MosWAF is not installed in $INSTALL_DIR. Run INSTALL first."
  fetch_source
  info "Rebuilding images..."
  compose build --pull
  info "Recreating containers..."
  compose up -d
  wait_healthy || true
  ok "Updated. All data and configuration were kept."
  compose ps
}

# REPAIR is for the usual breakages: a container stuck in a restart loop, a
# .env that lost a key, missing data directories, or an image that no longer
# matches the source. It never touches the database.
do_repair() {
  need_root
  installed || die "MosWAF is not installed in $INSTALL_DIR. Run INSTALL first."

  echo
  info "Diagnosing..."
  local problems=0

  if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    warn "Docker or the Compose plugin is missing"; problems=$((problems+1))
    install_docker
  else
    ok "Docker is available"
  fi

  # Any secret missing from .env leaves a service unable to start
  local key missing=0
  for key in POSTGRES_PASSWORD REDIS_PASSWORD MOSWAF_JWT_SECRET MOSWAF_CHALLENGE_SECRET \
             MOSWAF_INTERNAL_TOKEN; do
    if [[ -z "$(env_get "$key")" ]]; then
      warn "$key is missing from .env, generating a new value"
      echo "$key=$(rand 32)" >> "$INSTALL_DIR/.env"
      missing=$((missing+1))
    fi
  done
  if [[ "$missing" == "0" ]]; then
    ok ".env has every required secret"
  else
    problems=$((problems+missing))
  fi

  local d
  for d in postgres proxy-logs admin-tls; do
    if [[ ! -d "$INSTALL_DIR/data/$d" ]]; then
      warn "Data directory data/$d is missing, creating it"
      mkdir -p "$INSTALL_DIR/data/$d"; problems=$((problems+1))
    fi
  done

  local down
  down="$(compose ps --services --filter status=stopped 2>/dev/null | tr '\n' ' ')"
  if [[ -n "${down// /}" ]]; then
    warn "Stopped services: $down"; problems=$((problems+1))
  fi

  echo
  info "Rebuilding images and recreating containers (the database is untouched)..."
  compose build --pull
  compose up -d --force-recreate
  wait_healthy || true

  echo
  info "Resyncing the configuration to the data plane..."
  if compose exec -T proxy curl -fsS http://127.0.0.1:8081/sync >/dev/null 2>&1; then
    ok "Data plane reloaded its configuration"
  else
    warn "Could not reach the data plane /sync endpoint"
  fi

  echo
  compose ps
  echo
  if [[ "$problems" == "0" ]]; then
    ok "No configuration problems found; everything was rebuilt and restarted."
  else
    ok "Fixed $problems problem(s) and restarted the stack."
  fi
  echo "  ${DIM}If a service still fails, read its log: docker compose logs <service>${NC}"
  echo
}

do_uninstall() {
  need_root
  [[ -d "$INSTALL_DIR" ]] || die "$INSTALL_DIR does not exist"
  warn "This stops and removes every MosWAF container."
  confirm "Continue?" || { info "Cancelled."; return 0; }

  compose down --remove-orphans || true
  ok "Containers removed."

  if confirm "Also delete ALL DATA (database, logs, certificates) in $INSTALL_DIR/data?"; then
    compose down -v --remove-orphans || true
    rm -rf "${INSTALL_DIR:?}/data"
    ok "Data deleted."
  else
    ok "Data kept in $INSTALL_DIR/data"
  fi
  ok "MosWAF uninstalled."
}

# ------------------------------------------------------------------ menu

menu() {
  banner
  if installed; then
    local running total
    running="$(compose ps --services --filter status=running 2>/dev/null | wc -l | tr -d ' ')"
    total="$(compose config --services 2>/dev/null | wc -l | tr -d ' ')"
    echo "  Installed in ${BLD}${INSTALL_DIR}${NC}"
    echo "  Services running: ${BLD}${running}/${total}${NC}"
    echo "  Dashboard: ${BLD}https://$(public_ip):$(env_get MOSWAF_ADMIN_PORT)${NC}"
  else
    echo "  ${DIM}Not installed yet.${NC}"
  fi
  echo
  echo "  ${BLD}1)${NC} INSTALL     ${DIM}fresh install${NC}"
  echo "  ${BLD}2)${NC} UPDATE      ${DIM}pull the latest code, rebuild, keep all data${NC}"
  echo "  ${BLD}3)${NC} REPAIR      ${DIM}diagnose and fix a broken install${NC}"
  echo "  ${BLD}4)${NC} UNINSTALL   ${DIM}remove MosWAF${NC}"
  echo "  ${BLD}0)${NC} Exit"
  echo

  local choice
  read -r -p "  Choose [0-4]: " choice </dev/tty || choice=0
  echo
  case "$choice" in
    1) do_install ;;
    2) do_update ;;
    3) do_repair ;;
    4) do_uninstall ;;
    0) info "Nothing to do." ;;
    *) die "Invalid choice: $choice" ;;
  esac
}

# A flag was given -> run that action. Otherwise show the menu when a terminal
# is attached. Piped through `curl | bash` there is no terminal to read from,
# so fall back to a plain install.
if [[ -n "$ACTION" ]]; then
  case "$ACTION" in
    install)   do_install ;;
    update)    do_update ;;
    repair)    do_repair ;;
    uninstall) do_uninstall ;;
  esac
elif [[ -r /dev/tty ]]; then
  menu
else
  banner
  info "No terminal attached, running a plain install. Use --update, --repair or"
  info "--uninstall for the other actions."
  do_install
fi
