#!/usr/bin/env bash
#
#  MosWAF - check that the firewall actually blocks
#
#  Fires a batch of common attacks at your own site and compares the status
#  codes. Run it after adding a site or editing rules: a dashboard reading
#  "0 blocked" does not tell you whether nobody attacked you or your
#  configuration is simply wrong.
#
#  ONLY RUN THIS AGAINST SYSTEMS YOU OWN.
#
#  Usage:
#    ./scripts/attack-sim.sh https://example.com
#    ./scripts/attack-sim.sh http://127.0.0.1 --host example.com   # test on the server itself
#    ./scripts/attack-sim.sh https://example.com --flood 300       # also exercise rate limiting
#
#  --flood sends requests in parallel (25 at a time, override with CONCURRENCY=50).
#  The count has to exceed the rate limit configured in Settings.
#
set -uo pipefail

TARGET="${1:-}"
HOST_HEADER=""
FLOOD=0
CONCURRENCY="${CONCURRENCY:-25}"
shift || true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)  HOST_HEADER="$2"; shift 2 ;;
    --flood) FLOOD="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  sed -n '2,19p' "$0"
  exit 1
fi

GRN=$'\033[0;32m'; RED=$'\033[0;31m'; YLW=$'\033[0;33m'; DIM=$'\033[2m'; NC=$'\033[0m'

# The trailing newline matters: the flood step writes each result to its own file
# and counts them together, and without it hundreds of codes glue into one line.
curl_args=(-s -o /dev/null -k --max-time 10 -w '%{http_code}\n')
[[ -n "$HOST_HEADER" ]] && curl_args+=(-H "Host: $HOST_HEADER")

pass=0; fail=0

# probe <description> <expect: block|allow> <curl args...>
probe() {
  local desc="$1" expect="$2"; shift 2
  local code; code="$(curl "${curl_args[@]}" "$@")"

  local blocked=0
  case "$code" in
    403|406|429|444|503) blocked=1 ;;
  esac

  local ok=0
  [[ "$expect" == "block" && $blocked == 1 ]] && ok=1
  [[ "$expect" == "allow" && $blocked == 0 ]] && ok=1

  if [[ $ok == 1 ]]; then
    pass=$((pass + 1))
    printf "  ${GRN}✓${NC} %-38s ${DIM}%s${NC}\n" "$desc" "HTTP $code"
  else
    fail=$((fail + 1))
    printf "  ${RED}✗${NC} %-38s ${RED}HTTP %s${NC} ${DIM}(expected: %s)${NC}\n" "$desc" "$code" \
      "$([[ "$expect" == block ]] && echo "blocked" || echo "allowed")"
  fi
}

echo
echo "MosWAF - blocking check against ${TARGET}${HOST_HEADER:+ (Host: $HOST_HEADER)}"
echo

echo "Normal traffic (must not be blocked):"
probe "Home page"                 allow "$TARGET/"
probe "Ordinary path with query"  allow "$TARGET/products?id=42&sort=price"

echo
echo "SQL injection:"
probe "UNION SELECT"        block "$TARGET/?id=1%20UNION%20ALL%20SELECT%20NULL,NULL"
probe "Blind / time based"  block "$TARGET/?id=1%20AND%20SLEEP(5)"
probe "Metadata probing"    block "$TARGET/?id=1%20AND%201=(SELECT%20COUNT(*)%20FROM%20information_schema.tables)"

echo
echo "Encoding evasion (the payload is the same UNION SELECT, wrapped in layers):"
probe "Double encoded"  block "$TARGET/?id=1%2520UNION%2520ALL%2520SELECT%2520NULL"
probe "Triple encoded"  block "$TARGET/?id=1%252520UNION%252520ALL%252520SELECT%252520NULL"

echo
echo "XSS:"
probe "Script tag"      block "$TARGET/?q=%3Cscript%3Ealert(1)%3C/script%3E"
probe "Event handler"   block "$TARGET/?q=%3Cimg%20src=x%20onerror=alert(1)%3E"

echo
echo "File read and directory traversal:"
probe "Path traversal"   block "$TARGET/../../../../etc/passwd"
probe "Read /etc/passwd" block "$TARGET/?file=/etc/passwd"
probe "PHP wrapper"      block "$TARGET/?file=php://input"

echo
echo "Remote command execution:"
probe "Shell injection"        block "$TARGET/?cmd=;cat%20/etc/passwd"
probe "Dangerous PHP function" block "$TARGET/?x=system(%27id%27)"

echo
echo "Secret files and SSRF:"
probe "Fetch .env"          block "$TARGET/.env"
probe "The .git directory"  block "$TARGET/.git/config"
probe "Cloud metadata"      block "$TARGET/?url=http://169.254.169.254/latest/meta-data/"

echo
echo "Bots and scanners:"
probe "User-Agent sqlmap"   block "$TARGET/" -A "sqlmap/1.7.2#stable"
probe "User-Agent nikto"    block "$TARGET/" -A "Mozilla/5.00 (Nikto/2.5.0)"

echo
echo "Where a payload can hide (body, multipart, upgrade, unusual methods):"
SQLI='1 UNION ALL SELECT password FROM users'
# A multipart form is scanned as raw body, so a payload in any field is visible.
probe "SQLi in a multipart field"    block "$TARGET/" -F "q=$SQLI"
probe "SQLi in a multipart filename" block "$TARGET/" -F "f=@/dev/null;filename=$SQLI"
# Declaring a WebSocket upgrade must not exempt the request from scanning.
probe "SQLi in a WS-upgrade URL"     block "$TARGET/?id=1%20UNION%20ALL%20SELECT%20NULL" \
  -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13"
# A body on a non-standard method is still a body.
probe "SQLi in a PATCH body"         block "$TARGET/" -X PATCH -H "Content-Type: text/plain" --data "$SQLI"
# Control: an ordinary multipart form must not be blocked.
probe "Clean multipart form"         allow "$TARGET/" -F "name=alice" -F "qty=3"

if [[ "$FLOOD" -gt 0 ]]; then
  echo
  echo "Rate limiting - $FLOOD requests in parallel ($CONCURRENCY at a time):"

  # Requests have to go out in parallel to look like a real flood. Sequential curl
  # only manages a few dozen per second, usually under the threshold, which reads
  # as "nothing blocked" even though rate limiting works fine.
  tmpdir="$(mktemp -d)"
  running=0
  for i in $(seq 1 "$FLOOD"); do
    curl "${curl_args[@]}" "$TARGET/" > "$tmpdir/$i" 2>/dev/null &
    running=$((running + 1))
    if [[ $running -ge $CONCURRENCY ]]; then
      wait -n 2>/dev/null || wait
      running=$((running - 1))
    fi
  done
  wait

  # 429 = over the threshold, 503 = sent to the challenge, 403 = the IP is banned
  limited="$(cat "$tmpdir"/* 2>/dev/null | grep -c -E '^(403|429|503)$' || true)"
  rm -rf "$tmpdir"

  if [[ "$limited" -gt 0 ]]; then
    pass=$((pass + 1))
    printf "  ${GRN}✓${NC} %-38s ${DIM}%s/%s requests blocked or challenged${NC}\n" \
      "Rate limiting works" "$limited" "$FLOOD"
  else
    fail=$((fail + 1))
    printf "  ${RED}✗${NC} %-38s ${RED}nothing was blocked${NC}\n" "Rate limiting"
    echo "     ${YLW}Check that the request count exceeds the limits in Settings${NC}"
    echo "     ${YLW}(60 requests/second and 120 requests/10 seconds per IP by default),${NC}"
    echo "     ${YLW}and that your IP is not on the allowlist.${NC}"
  fi
fi

echo
echo "-----------------------------------------------------------"
printf "  Passed: ${GRN}%d${NC}   Failed: ${RED}%d${NC}\n" "$pass" "$fail"
echo "-----------------------------------------------------------"
echo
echo "${DIM}Note: a site in \"Monitor only\" mode lets everything through - that is"
echo "correct. Open the Attack log in the dashboard to see what was recorded.${NC}"
echo

[[ $fail -eq 0 ]]
