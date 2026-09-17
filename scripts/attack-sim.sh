#!/usr/bin/env bash
#
#  MosWAF - kiem tra nhanh xem tuong lua co that su chan khong
#
#  Ban gui mot loat request kieu tan cong pho bien vao chinh site cua minh
#  roi doi chieu ma tra ve. Dung sau moi lan them site hoac sua luat: nhin
#  dashboard thay "da chan 0" thi khong biet la khong ai tan cong hay la
#  minh cau hinh sai.
#
#  CHI CHAY VOI HE THONG CUA CHINH BAN.
#
#  Dung:
#    ./scripts/attack-sim.sh https://example.com
#    ./scripts/attack-sim.sh http://127.0.0.1 --host example.com   # test truc tiep tren may chu
#    ./scripts/attack-sim.sh https://example.com --flood 300       # thu ca rate limit
#
#  --flood ban song song (mac dinh 25 luong, doi bang CONCURRENCY=50).
#  So request phai vuot nguong rate limit dang dat trong Cai dat.
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
    *) echo "Tham so la: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  sed -n '2,18p' "$0"
  exit 1
fi

GRN=$'\033[0;32m'; RED=$'\033[0;31m'; YLW=$'\033[0;33m'; DIM=$'\033[2m'; NC=$'\033[0m'

# Co xuong dong o cuoi: phan flood ghi moi ket qua ra mot file roi gop lai dem,
# thieu \n thi ca tram ma se dinh thanh mot dong va dem sai.
curl_args=(-s -o /dev/null -k --max-time 10 -w '%{http_code}\n')
[[ -n "$HOST_HEADER" ]] && curl_args+=(-H "Host: $HOST_HEADER")

pass=0; fail=0

# probe <mo ta> <ky vong: block|allow> <curl args...>
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
    printf "  ${RED}✗${NC} %-38s ${RED}HTTP %s${NC} ${DIM}(ky vong: %s)${NC}\n" "$desc" "$code" \
      "$([[ "$expect" == block ]] && echo "bi chan" || echo "cho qua")"
  fi
}

echo
echo "MosWAF - kiem tra kha nang chan tren ${TARGET}${HOST_HEADER:+ (Host: $HOST_HEADER)}"
echo

echo "Luu luong binh thuong (khong duoc chan):"
probe "Trang chu"                    allow "$TARGET/"
probe "Duong dan thuong co tham so"  allow "$TARGET/san-pham?id=42&sort=gia"

echo
echo "SQL injection:"
probe "UNION SELECT"        block "$TARGET/?id=1%20UNION%20ALL%20SELECT%20NULL,NULL"
probe "Blind / time based"  block "$TARGET/?id=1%20AND%20SLEEP(5)"
probe "Do metadata"         block "$TARGET/?id=1%20AND%201=(SELECT%20COUNT(*)%20FROM%20information_schema.tables)"

echo
echo "XSS:"
probe "The script"      block "$TARGET/?q=%3Cscript%3Ealert(1)%3C/script%3E"
probe "Event handler"   block "$TARGET/?q=%3Cimg%20src=x%20onerror=alert(1)%3E"

echo
echo "Doc file / duyet thu muc:"
probe "Path traversal"   block "$TARGET/../../../../etc/passwd"
probe "Doc /etc/passwd"  block "$TARGET/?file=/etc/passwd"
probe "PHP wrapper"      block "$TARGET/?file=php://input"

echo
echo "Chay lenh tu xa:"
probe "Chen lenh shell"  block "$TARGET/?cmd=;cat%20/etc/passwd"
probe "Ham PHP nguy hiem" block "$TARGET/?x=system(%27id%27)"

echo
echo "Do file bi mat va SSRF:"
probe "Tai .env"            block "$TARGET/.env"
probe "Thu muc .git"        block "$TARGET/.git/config"
probe "Metadata cloud"      block "$TARGET/?url=http://169.254.169.254/latest/meta-data/"

echo
echo "Bot va cong cu quet:"
probe "User-Agent sqlmap"   block "$TARGET/" -A "sqlmap/1.7.2#stable"
probe "User-Agent nikto"    block "$TARGET/" -A "Mozilla/5.00 (Nikto/2.5.0)"

if [[ "$FLOOD" -gt 0 ]]; then
  echo
  echo "Rate limit - ban $FLOOD request song song ($CONCURRENCY luong):"

  # Phai ban song song moi giong flood that. Ban tuan tu bang curl chi dat
  # vai chuc request/giay, thuong khong cham noi nguong nen bao "khong chan"
  # trong khi rate limit van dang hoat dong binh thuong.
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

  # 429 = vuot nguong, 503 = bi day sang challenge, 403 = IP da bi ban tam thoi
  limited="$(cat "$tmpdir"/* 2>/dev/null | grep -c -E '^(403|429|503)$' || true)"
  rm -rf "$tmpdir"

  if [[ "$limited" -gt 0 ]]; then
    pass=$((pass + 1))
    printf "  ${GRN}✓${NC} %-38s ${DIM}%s/%s request bi chan hoac bi challenge${NC}\n" \
      "Rate limit co hoat dong" "$limited" "$FLOOD"
  else
    fail=$((fail + 1))
    printf "  ${RED}✗${NC} %-38s ${RED}khong request nao bi chan${NC}\n" "Rate limit"
    echo "     ${YLW}Kiem tra: so request phai vuot nguong trong Cai dat${NC}"
    echo "     ${YLW}(mac dinh 60 request/giay va 120 request/10 giay cho moi IP),${NC}"
    echo "     ${YLW}va IP cua ban khong nam trong danh sach trang.${NC}"
  fi
fi

echo
echo "-----------------------------------------------------------"
printf "  Dat: ${GRN}%d${NC}   Khong dat: ${RED}%d${NC}\n" "$pass" "$fail"
echo "-----------------------------------------------------------"
echo
echo "${DIM}Luu y: site dang o che do \"Chi theo doi\" thi moi thu deu cho qua -"
echo "day la dung, vao dashboard xem Nhat ky tan cong de doi chieu.${NC}"
echo

[[ $fail -eq 0 ]]
