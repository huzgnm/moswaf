#!/usr/bin/env bash
#
#  MosWAF installer
#
#    curl -fsSL https://raw.githubusercontent.com/huzgnm/moswaf/main/install.sh | sudo bash
#  or, from a source checkout:
#    sudo bash install.sh
#
#  The same command updates an existing installation - there is nothing else to
#  remember. Run without arguments for the menu:
#
#    1) INSTALL     fresh install
#    2) UPDATE      pull the latest code, rebuild, keep all data
#    3) REPAIR      diagnose and fix a broken install
#    4) UNINSTALL   remove MosWAF
#
#  Enter picks UPDATE when MosWAF is already installed, INSTALL when it is not.
#  With no terminal at all - a provisioning script, CI - the same rule decides
#  the action without asking.
#
#  Non-interactive flags (for scripts and CI):
#    --install | --update | --repair | --uninstall
#    --kernel-ban          install the host agent that drops persistent
#                          attackers in the kernel (OFF unless asked for)
#    --no-kernel-ban       stop and remove that agent
#    --admin-addr <ip|cidr>  with --kernel-ban: the address you administer this
#                          machine from, which the agent must never drop
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

# The one command that installs, updates, repairs and removes. Printed after an
# install so nobody has to go looking for it when an update is due.
ONE_LINER="https://raw.githubusercontent.com/huzgnm/moswaf/${MOSWAF_BRANCH}/install.sh"

ADMIN_PORT="9443"
ADMIN_BIND="0.0.0.0"
HTTP_PORT="80"
HTTPS_PORT="443"
ACTION=""
ASSUME_YES=0

# The address or range this machine is administered from, for the kernel ban
# agent. Empty by default and never guessed silently: see do_kernel_ban.
ADMIN_ADDR=""

# Where the kernel ban agent lives. Up here with the other paths rather than
# beside the functions that install it, because the menu and the uninstaller
# read KBANS_UNIT to decide what to offer and what to clean up - and under
# `set -u` a path that is only defined further down is a path that works until
# somebody reorders the file.
KBANS_BIN="/usr/local/bin/moswaf-kbans"
KBANS_ENV="/etc/moswaf/kbans.env"
KBANS_UNIT="/etc/systemd/system/moswaf-kbans.service"

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[0;33m'; BLU=$'\033[0;36m'
BLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'
info() { echo "${BLU}[*]${NC} $*"; }
ok()   { echo "${GRN}[+]${NC} $*"; }
warn() { echo "${YLW}[!]${NC} $*"; }
die()  { echo "${RED}[x]${NC} $*" >&2; exit 1; }

# ------------------------------------------------------------------ self copy
#
# UPDATE rewrites install.sh in place - fetch_source runs `git reset --hard`, and
# on an install made from a git clone that file is this one. bash does not read a
# script into memory up front; it reads it in chunks as it goes, so replacing the
# file underneath a running shell makes it resume at a byte offset inside
# different contents. Run from a private copy instead, which also gives UPDATE a
# fixed thing to compare the newly fetched installer against.
#
# Skipped when there is no file to copy, which is the `curl | bash` case - there
# the script is already the newest one and nothing can overwrite it.
#
# MOSWAF_SELF_ORIG carries the path the operator actually invoked. The copy lives
# in a temporary directory, so without it fetch_source would look for the source
# tree next to the copy and never find it - installing from a checkout would
# silently turn into cloning from GitHub instead.
if [[ -z "${MOSWAF_SELF_COPY:-}" && -f "$0" ]]; then
  _self="$(mktemp "${TMPDIR:-/tmp}/moswaf-install.XXXXXX")" || die "Cannot create a temporary file"
  cat "$0" >"$_self"
  MOSWAF_SELF_COPY="$_self" MOSWAF_SELF_ORIG="$0" bash "$_self" "$@"
  _rc=$?
  rm -f "$_self"
  exit "$_rc"
fi

# Where the operator ran this from, whatever shell is executing it now.
SELF_PATH="${MOSWAF_SELF_ORIG:-$0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install)     ACTION="install"; shift ;;
    --update)      ACTION="update"; shift ;;
    --repair)      ACTION="repair"; shift ;;
    --uninstall)   ACTION="uninstall"; shift ;;
    --kernel-ban)     ACTION="kernel_ban"; shift ;;
    --no-kernel-ban)  ACTION="kernel_ban_off"; shift ;;
    --admin-addr)  ADMIN_ADDR="$2"; shift 2 ;;
    --admin-port)  ADMIN_PORT="$2"; shift 2 ;;
    --admin-bind)  ADMIN_BIND="$2"; shift 2 ;;
    --http-port)   HTTP_PORT="$2";  shift 2 ;;
    --https-port)  HTTPS_PORT="$2"; shift 2 ;;
    --dir)         INSTALL_DIR="$2"; shift 2 ;;
    --yes|-y)      ASSUME_YES=1; shift ;;
    # Print the header block itself rather than a fixed line range, which silently
    # started truncating the moment the header grew a line.
    -h|--help)     awk 'NR > 1 { if ($0 !~ /^#/) exit; print }' "$0"; exit 0 ;;
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

need_root() { [[ "$(id -u)" == "0" ]] || die "Must run as root. Try: sudo bash $SELF_PATH"; }
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-32}"; }
installed() { [[ -f "$INSTALL_DIR/.env" && -f "$INSTALL_DIR/docker-compose.yml" ]]; }
compose() { docker compose --env-file "$INSTALL_DIR/.env" -f "$INSTALL_DIR/docker-compose.yml" "$@"; }

# Read a value out of .env without sourcing the file
env_get() { grep -E "^$1=" "$INSTALL_DIR/.env" 2>/dev/null | head -1 | cut -d= -f2-; }

# Whether a question can actually be asked.
#
# `[[ -r /dev/tty ]]` is not enough. The device node can exist and test as
# readable while opening it fails - "Device not configured" - which is what
# happens when the script is piped in with no controlling terminal. The menu
# then printed itself, could not read a choice, and the whole run ended with
# "Nothing to do": the operator pasted the command, watched it print something,
# and nothing was installed or updated. Open the device to find out.
#
# The open runs in a subshell so that both the failure message and the file
# descriptor stay inside it: `exec 3</dev/tty 2>/dev/null` in this shell applies
# its redirections left to right, so the open fails - and prints - before the
# error is silenced.
has_tty() { (exec 3</dev/tty) 2>/dev/null; }

confirm() {
  [[ "$ASSUME_YES" == "1" ]] && return 0
  if ! has_tty; then
    warn "No terminal to ask on, so taking this as no. Pass --yes to answer in advance."
    return 1
  fi
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
  local here; here="$(cd "$(dirname "$SELF_PATH")" && pwd)"

  # The order of these branches matters. Running the installer from inside the
  # install directory - `cd /opt/moswaf && bash install.sh --update`, the obvious
  # thing to type - used to match the first branch, find nothing to copy (source
  # and destination are the same directory) and return without fetching anything.
  # UPDATE then rebuilt the code already on disk and reported success, so it
  # looked like an update that changed nothing. Requiring the source to be
  # somewhere else sends that case to the git branch below, where it belongs.
  if [[ -f "$here/docker-compose.yml" && -d "$here/dataplane" && "$here" != "$INSTALL_DIR" ]]; then
    info "Copying the source from $here to $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    # .env is deliberately excluded. Copying it in would install the source
    # checkout's secrets, admin password and ports into production - write_env
    # then sees a file and generates nothing - and on an UPDATE it would
    # overwrite the live configuration with whatever the checkout happened to
    # carry. .env.example is not matched by this pattern and still ships.
    tar -C "$here" --exclude='.git' --exclude='data' --exclude='.local' \
        --exclude='node_modules' --exclude='.env' -cf - . | tar -C "$INSTALL_DIR" -xf -

  elif [[ -d "$INSTALL_DIR/.git" ]]; then
    command -v git >/dev/null 2>&1 || die "git is missing. Install it and run this again."
    info "Fetching the latest code into $INSTALL_DIR"
    git -C "$INSTALL_DIR" fetch --depth 1 origin "$MOSWAF_BRANCH"
    git -C "$INSTALL_DIR" reset --hard "origin/$MOSWAF_BRANCH"
    ok "Now on $(git -C "$INSTALL_DIR" log -1 --format='%h %s')"

  elif [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
    # Installed by copying a source tree in, so there is no history to pull from.
    # Saying so is the point: an UPDATE that cannot fetch has to admit it rather
    # than rebuild the same code and report success.
    warn "$INSTALL_DIR is not a git checkout, so there is no new code to fetch."
    warn "The files already there will be rebuilt as they are."
    warn "To take new code, run the installer from an updated source checkout"
    warn "outside $INSTALL_DIR, or reinstall from $MOSWAF_REPO."

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
  echo
  echo "  ${DIM}To update later, run the same one-line command again:${NC}"
  echo "    curl -fsSL ${ONE_LINER} | sudo bash"
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

  # The credentials are printed either way - they are real and the operator needs
  # them - but an install that never came up must not look like one that did.
  if wait_healthy; then
    print_result
  else
    print_result
    warn "The control plane did not become healthy, so the dashboard above is not"
    warn "answering yet. Check the log, then run: bash $SELF_PATH --repair"
    echo "  ${DIM}docker compose --env-file $INSTALL_DIR/.env -f $INSTALL_DIR/docker-compose.yml logs mgmt${NC}"
    echo
    exit 1
  fi
}

do_update() {
  need_root
  installed || die "MosWAF is not installed in $INSTALL_DIR. Run INSTALL first."
  fetch_source

  # The installer updates itself along with everything else. Without this a fix
  # to install.sh would only take effect the *next* time somebody updated, and a
  # bug that stops UPDATE from working - there has been one - could never repair
  # itself from the machine it is installed on.
  #
  # Only when this run started from a file we copied, so there is something real
  # to compare; piped from curl the running script is already the newest.
  local fresh="$INSTALL_DIR/install.sh"
  if [[ -z "${MOSWAF_UPDATED_SELF:-}" && -n "${MOSWAF_SELF_COPY:-}" && -f "$fresh" ]] \
     && ! cmp -s "$fresh" "$MOSWAF_SELF_COPY"; then
    ok "The installer itself was updated; continuing with the new one"
    local args=(--update --dir "$INSTALL_DIR")
    [[ "$ASSUME_YES" == "1" ]] && args+=(--yes)
    MOSWAF_UPDATED_SELF=1 exec bash "$fresh" "${args[@]}"
  fi

  # An installation made before a secret existed does not have it. Fill those in
  # here rather than leaving the feature that needs it quietly switched off until
  # somebody runs a repair.
  add_missing_secrets
  if [[ "$SECRETS_ADDED" -gt 0 ]]; then
    ok "Added $SECRETS_ADDED secret(s) this installation did not have yet"
  fi

  info "Rebuilding images..."
  compose build --pull
  info "Recreating containers..."
  compose up -d

  # An update that leaves the control plane down is a failed update, whatever
  # was rebuilt on the way. Say so instead of printing a success line over it.
  local healthy=0
  wait_healthy && healthy=1
  compose ps
  echo
  if [[ "$healthy" != "1" ]]; then
    warn "The rebuild finished but the control plane is not healthy."
    echo "  ${DIM}Read its log:  docker compose --env-file $INSTALL_DIR/.env -f $INSTALL_DIR/docker-compose.yml logs mgmt${NC}"
    echo "  ${DIM}Then try:      bash $SELF_PATH --repair${NC}"
    echo
    die "UPDATE did not finish cleanly."
  fi
  ok "Updated. All data and configuration were kept."
}

# REPAIR is for the usual breakages: a container stuck in a restart loop, a
# .env that lost a key, missing data directories, or an image that no longer
# matches the source. It never touches the database.
# Generate a new POSTGRES_PASSWORD and make the database agree with it. On a
# database that has never been initialised the value in .env is all there is, so
# writing it is enough. On an existing one the password lives in the database and
# has to be changed there with ALTER USER - the official image trusts connections
# over the local unix socket, which is what makes that possible without knowing
# the old password. .env is only written once the change has actually landed, so
# a failure here leaves a working installation alone.
repair_db_password() {
  local pw user data i
  pw="$(rand 32)"
  user="$(env_get POSTGRES_USER)"; user="${user:-moswaf}"
  data="$(env_get MOSWAF_DATA_DIR)"; data="${data:-$INSTALL_DIR/data}"

  if [[ -f "$data/postgres/PG_VERSION" ]]; then
    info "The database already exists; changing its password to the new value"
    compose up -d postgres >/dev/null 2>&1 || return 1
    for i in $(seq 1 30); do
      compose exec -T postgres pg_isready -U "$user" >/dev/null 2>&1 && break
      sleep 2
    done
    compose exec -T postgres psql -v ON_ERROR_STOP=1 -U "$user" -d postgres \
        -c "ALTER USER \"$user\" WITH PASSWORD '$pw';" >/dev/null 2>&1 || return 1
    ok "The database accepted the new password"
  fi

  echo "POSTGRES_PASSWORD=$pw" >> "$INSTALL_DIR/.env"
}

# Write any stateless secret that .env is missing, and report how many.
#
# Called on UPDATE as well as REPAIR. A secret introduced after an installation
# was made does not exist in its .env, and an update that only replaces code
# leaves it missing - so the feature that needs it silently does not work until
# somebody happens to run a repair. MOSWAF_INTERNAL_TOKEN is exactly that case:
# without it the data plane now refuses internal API calls, which would turn a
# hardening change into a permanent error on every save.
#
# Every secret here is read fresh on each boot, so writing a new value is enough.
# POSTGRES_PASSWORD is not in this list, deliberately: it is baked into the
# database at initialisation and needs the separate handling below.
# Sets SECRETS_ADDED rather than returning the count: an exit status is a single
# byte and is read by `set -e` as success or failure, so a function that returned
# "3 secrets written" would be a function that failed.
SECRETS_ADDED=0

add_missing_secrets() {
  local key
  SECRETS_ADDED=0
  for key in REDIS_PASSWORD MOSWAF_JWT_SECRET MOSWAF_CHALLENGE_SECRET \
             MOSWAF_INTERNAL_TOKEN; do
    if [[ -z "$(env_get "$key")" ]]; then
      warn "$key is missing from .env, generating a new value"
      echo "$key=$(rand 48)" >> "$INSTALL_DIR/.env"
      SECRETS_ADDED=$((SECRETS_ADDED + 1))
    fi
  done
}

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

  add_missing_secrets
  local missing=$SECRETS_ADDED

  # POSTGRES_PASSWORD is the exception: postgres reads it only while it
  # initialises its data directory and ignores it on every boot after that.
  # Writing a fresh value into .env therefore authenticates against nothing -
  # the control plane dies with "password authentication failed (28P01)" - so
  # the database has to be changed to match.
  if [[ -z "$(env_get POSTGRES_PASSWORD)" ]]; then
    warn "POSTGRES_PASSWORD is missing from .env, generating a new value"
    repair_db_password \
      || die "Could not reset the database password. The database is still up with its old password; restore POSTGRES_PASSWORD in $INSTALL_DIR/.env from a backup, or read: docker compose logs postgres"
    missing=$((missing+1))
  fi
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
  local healthy=0
  wait_healthy && healthy=1

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

  # Reporting success while the control plane is down is worse than reporting
  # nothing: the operator walks away from a broken install. Whatever was fixed
  # along the way, a repair has only succeeded if mgmt actually answers.
  if [[ "$healthy" != "1" ]]; then
    warn "$problems problem(s) were addressed, but the control plane is still not healthy."
    echo "  ${DIM}Read its log:  docker compose --env-file $INSTALL_DIR/.env -f $INSTALL_DIR/docker-compose.yml logs mgmt${NC}"
    echo
    die "REPAIR did not restore a working installation."
  fi

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

  # The kernel agent is the one piece that does not live in a container, so
  # "remove every MosWAF container" would leave it behind: a root service still
  # programming nftables for a WAF that no longer exists, with no dashboard left
  # to explain why an address cannot reach the machine.
  if [[ -f "$KBANS_UNIT" ]]; then
    info "Removing the kernel ban agent as well..."
    do_kernel_ban_off
  fi

  if confirm "Also delete ALL DATA (database, logs, certificates) in $INSTALL_DIR/data?"; then
    compose down -v --remove-orphans || true
    rm -rf "${INSTALL_DIR:?}/data"
    ok "Data deleted."
  else
    ok "Data kept in $INSTALL_DIR/data"
  fi
  ok "MosWAF uninstalled."
}

# ------------------------------------------------------- kernel ban agent
#
# The only part of MosWAF that runs outside Docker, and the only part that can
# make a server unreachable. Everything below is shaped by that.
#
# It is OFF unless somebody asks for it. A WAF that refuses bad requests is
# something you can install on a machine you care about without thinking hard; a
# program that tells the kernel to discard packets is not, and turning the second
# on by default because somebody wanted the first would be answering a question
# they were never asked.
#
# The install refuses rather than guesses at every point where a wrong answer
# costs the machine: no nft, no address, an address that turns out not to be
# protected - each of those stops the install with the service not enabled,
# which leaves the WAF exactly where it was.

# Where this SSH session came from, if it is one.
#
# Offered as a suggestion and never used without being shown. It is right almost
# every time and wrong in the two cases that matter - a console login, or sudo
# that scrubbed the environment - and in those it is empty rather than wrong,
# which is why it can be offered at all.
ssh_client_addr() {
  local c="${SSH_CONNECTION:-}"
  [[ -n "$c" ]] && { echo "$c" | awk '{print $1}'; return; }
  c="${SSH_CLIENT:-}"
  [[ -n "$c" ]] && { echo "$c" | awk '{print $1}'; return; }
  echo ""
}

# The subnets the containers talk to each other over, read from Docker rather
# than assumed. Dropping one of these would cut the WAF off from its own
# database instead of cutting off an attacker.
docker_subnets() {
  local out
  out="$(docker network inspect $(docker network ls -q) \
        --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null \
        | tr ' ' '\n' | grep -E '^[0-9]' | sort -u | paste -sd, -)"
  echo "${out:-172.17.0.0/16,172.18.0.0/16}"
}

do_kernel_ban() {
  need_root
  installed || die "MosWAF is not installed in $INSTALL_DIR. Run INSTALL first."

  command -v nft >/dev/null 2>&1 || die \
    "nftables is not installed on this host. The agent programs kernel drops
   through nft and there is nothing useful it can do without it.
   Install it first:  apt install nftables   (or)   dnf install nftables"

  command -v systemctl >/dev/null 2>&1 || die \
    "This host does not use systemd, so there is nowhere to install the agent as
   a service. The WAF keeps working; only kernel escalation is unavailable."

  echo
  echo "  ${BLD}Kernel ban agent${NC}"
  echo "  ${DIM}Addresses that keep knocking after being banned get dropped by the"
  echo "  kernel instead of being answered. Cheaper under a flood - and it is the"
  echo "  one piece of MosWAF that could lock you out of this server.${NC}"
  echo

  # ---- the address that must never be dropped
  local suggested addr
  suggested="$(ssh_client_addr)"
  addr="$ADMIN_ADDR"

  if [[ -z "$addr" ]]; then
    if ! has_tty; then
      die "--kernel-ban needs --admin-addr <ip-or-cidr>: the address you reach
   this server from, which the agent must never drop. There is no terminal to
   ask on, and guessing it is the one mistake that cannot be undone from here."
    fi
    echo "  Which address do you administer this server from?"
    echo "  ${DIM}The agent will never drop it. A range is fine: 59.153.224.0/20${NC}"
    [[ -n "$suggested" ]] && \
      echo "  ${DIM}This SSH session comes from ${BLD}${suggested}${NC}${DIM} - press Enter to use it.${NC}"
    echo
    read -r -p "  Address or range: " addr </dev/tty || addr=""
    addr="${addr:-$suggested}"
  fi

  [[ -n "$addr" ]] || die \
    "No address given. The agent will not be installed.
   Without knowing which addresses administer this machine it could be asked to
   discard yours, and you would find out by losing the connection you were about
   to fix it over."

  # ---- build the binary, using the toolchain the stack already has
  info "Building the agent..."
  local built="$INSTALL_DIR/data/moswaf-kbans"
  ( cd "$INSTALL_DIR/control" && \
    docker run --rm -v "$PWD":/src -w /src golang:1.23-alpine \
      go build -trimpath -o /src/moswaf-kbans ./cmd/moswaf-kbans ) \
    || die "The agent did not build. Nothing was installed or changed."
  mv "$INSTALL_DIR/control/moswaf-kbans" "$built"

  # ---- write the configuration
  mkdir -p /etc/moswaf
  local redis_pw token proxy_port
  redis_pw="$(env_get REDIS_PASSWORD)"
  token="$(env_get MOSWAF_INTERNAL_TOKEN)"
  proxy_port="$(env_get MOSWAF_PROXY_API_PORT)"; proxy_port="${proxy_port:-8081}"

  # This file holds the Redis password and the internal token, so it is created
  # unreadable rather than created and then chmod'ed - there is no window.
  local prev_umask
  prev_umask="$(umask)"
  umask 077
  cat > "$KBANS_ENV" <<EOF
# MosWAF kernel ban agent. Written by install.sh; safe to edit.
#
# MOSWAF_KBANS_ALLOW is the list this agent will never drop, whatever it is
# told. It is the reason you can still reach this machine. Add to it; think
# twice before taking anything out.
MOSWAF_KBANS_ALLOW=$addr
MOSWAF_KBANS_DOCKER_SUBNETS=$(docker_subnets)
MOSWAF_KBANS_REDIS=127.0.0.1:6379
MOSWAF_KBANS_REDIS_PASSWORD=$redis_pw
MOSWAF_KBANS_BANS_URL=http://127.0.0.1:${proxy_port}/bans?limit=0
MOSWAF_INTERNAL_TOKEN=$token
MOSWAF_KBANS_RESYNC=60s

# Set to 1 to have the agent log what it would do and touch nothing.
MOSWAF_KBANS_DRY_RUN=0
EOF
  chmod 600 "$KBANS_ENV"
  umask "$prev_umask"

  # ---- prove it before enabling it
  #
  # The binary checks its own configuration and reports whether the address
  # would be protected. Running this before the service is enabled is the whole
  # safety story: a failure here means nothing was started, rather than
  # something was started and we find out later.
  info "Checking the agent would never drop ${BLD}${addr}${NC}..."
  local check_from="${suggested:-$addr}"
  # A range cannot be checked against itself, so when the operator gave a CIDR
  # and there is no SSH address to test, take the first address in it.
  [[ "$check_from" == */* ]] && check_from="${check_from%%/*}"

  if ! ( set -a; . "$KBANS_ENV"; set +a; "$built" -check -check-from "$check_from" ); then
    rm -f "$KBANS_ENV"
    die "The agent refused its own configuration, so it was not installed and
   nothing on this machine was changed. Fix the address and run again:
     bash $SELF_PATH --kernel-ban --admin-addr <your-ip-or-range>"
  fi

  # ---- only now does anything get installed
  install -m 0755 "$built" "$KBANS_BIN"
  rm -f "$built"
  if [[ -f "$INSTALL_DIR/scripts/moswaf-kbans.service" ]]; then
    install -m 0644 "$INSTALL_DIR/scripts/moswaf-kbans.service" "$KBANS_UNIT"
  else
    die "scripts/moswaf-kbans.service is missing from the checkout."
  fi

  systemctl daemon-reload
  systemctl enable --now moswaf-kbans >/dev/null 2>&1 || true
  sleep 2

  if systemctl is-active --quiet moswaf-kbans; then
    ok "The kernel ban agent is running."
    echo "  ${DIM}Never dropped: ${addr}, this machine's own addresses, and the"
    echo "  container subnets.${NC}"
    echo "  ${DIM}Log:      journalctl -u moswaf-kbans -f${NC}"
    echo "  ${DIM}Turn off: bash $SELF_PATH --no-kernel-ban${NC}"
    echo
    echo "  ${DIM}Nothing is dropped until an address is banned AND keeps sending"
    echo "  requests afterwards. Every kernel entry expires when its ban does.${NC}"
  else
    warn "The agent was installed but is not running."
    echo "  ${DIM}journalctl -u moswaf-kbans -n 50${NC}"
    echo "  ${DIM}The WAF is unaffected - it refuses these addresses in userspace,"
    echo "  which is what it was doing before.${NC}"
  fi
  echo
}

do_kernel_ban_off() {
  need_root
  if ! [[ -f "$KBANS_UNIT" ]]; then
    info "The kernel ban agent is not installed."
    return 0
  fi

  systemctl disable --now moswaf-kbans >/dev/null 2>&1 || true

  # Remove the table as well as the service. Stopping the agent alone would
  # leave whatever it last programmed in the kernel, draining on its own
  # timeouts - correct, but not what somebody who just asked for it to be off
  # expects to be true.
  if command -v nft >/dev/null 2>&1; then
    nft delete table inet moswaf >/dev/null 2>&1 || true
  fi

  rm -f "$KBANS_UNIT" "$KBANS_BIN"
  systemctl daemon-reload
  ok "The kernel ban agent is removed and its nftables table is gone."
  echo "  ${DIM}${KBANS_ENV} was kept, so turning it back on will not ask again.${NC}"
  echo "  ${DIM}Bans still work; they are refused in userspace as before.${NC}"
  echo
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
  if [[ -f "$KBANS_UNIT" ]]; then
    echo "  ${BLD}5)${NC} KERNEL BAN  ${DIM}installed - choose to turn it off${NC}"
  else
    echo "  ${BLD}5)${NC} KERNEL BAN  ${DIM}drop persistent attackers in the kernel (off)${NC}"
  fi
  echo "  ${BLD}0)${NC} Exit"
  echo

  # Enter picks the action that run is almost certainly for: UPDATE on a machine
  # that already has MosWAF, INSTALL on one that does not.
  local choice fallback
  if installed; then fallback=2; else fallback=1; fi
  read -r -p "  Choose [0-5] (Enter = $fallback): " choice </dev/tty || choice=""
  choice="${choice:-$fallback}"
  echo
  case "$choice" in
    1) do_install ;;
    2) do_update ;;
    3) do_repair ;;
    4) do_uninstall ;;
    # Picking 5 when it is already on means turning it off - there is nothing
    # else somebody could want from that entry, and a second menu to say so
    # would be a menu whose only purpose is to be answered.
    5) if [[ -f "$KBANS_UNIT" ]]; then do_kernel_ban_off; else do_kernel_ban; fi ;;
    0) info "Nothing to do." ;;
    *) die "Invalid choice: $choice" ;;
  esac
}

# A flag was given -> run that action. Otherwise show the menu when a terminal
# is attached.
#
# With no terminal - piped into a provisioning script, or a CI job - there is
# nothing to read a choice from, so the action is decided by what is on the
# machine: an existing installation is updated, a bare machine is installed. It
# used to always install, which on an existing installation stopped at a
# "Reinstall over it?" prompt that had no terminal to answer it, so the run did
# nothing at all and said so in a way that looked like success.
if [[ -n "$ACTION" ]]; then
  case "$ACTION" in
    install)        do_install ;;
    update)         do_update ;;
    repair)         do_repair ;;
    uninstall)      do_uninstall ;;
    kernel_ban)     do_kernel_ban ;;
    kernel_ban_off) do_kernel_ban_off ;;
  esac
elif has_tty; then
  menu
elif installed; then
  banner
  info "No terminal attached and MosWAF is already installed in $INSTALL_DIR."
  info "Updating. Pass --install, --repair or --uninstall to do something else."
  echo
  do_update
else
  banner
  info "No terminal attached, running a plain install. Use --update, --repair or"
  info "--uninstall for the other actions."
  do_install
fi
