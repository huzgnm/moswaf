# MosWAF

[![CI](https://github.com/huzgnm/moswaf/actions/workflows/ci.yml/badge.svg)](https://github.com/huzgnm/moswaf/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](control/go.mod)
[![OpenResty](https://img.shields.io/badge/OpenResty-1.27-009639?logo=nginx&logoColor=white)](dataplane/Dockerfile)
[![Vue 3](https://img.shields.io/badge/Vue-3-4FC08D?logo=vuedotjs&logoColor=white)](web/package.json)
[![Docker](https://img.shields.io/badge/deploy-one--command-2496ED?logo=docker&logoColor=white)](install.sh)

Tuong lua ung dung web (WAF) kiem chong DDoS lop 7, trien khai bang mot lenh,
co bang dieu khien admin chay tren **cong rieng** tach khoi luu luong that.

---

## Cai dat one-command

Tren may chu Linux (Ubuntu/Debian/CentOS/Alma...), chay bang root:

```bash
curl -fsSL https://raw.githubusercontent.com/huzgnm/moswaf/main/install.sh | bash
```

Hoac khi da co san source:

```bash
sudo bash install.sh
```

Script se: kiem tra/cai Docker → sinh `.env` voi toan bo bi mat ngau nhien →
build image → khoi dong stack → in ra URL dashboard kem mat khau admin.

Tuy chon hay dung:

```bash
sudo bash install.sh --admin-port 9443 --admin-bind 127.0.0.1   # chi vao qua SSH tunnel
sudo bash install.sh --upgrade                                   # nang cap, giu du lieu
sudo bash install.sh --reset-password                            # sinh mat khau admin moi
sudo bash install.sh --uninstall                                 # go
```

## Cac cong

| Cong | Dich vu | Ghi chu |
|------|---------|---------|
| `80` | Data plane (HTTP) | luu luong that cua khach |
| `443` | Data plane (HTTPS) | luu luong that cua khach |
| **`9443`** | **Dashboard admin** | **cong rieng, HTTPS chung chi tu ky, doi duoc qua `.env`** |
| `8081` | API noi bo data plane | chi mo trong mang Docker, khong publish |

Dashboard khong bao gio dung chung cong voi traffic: ke tan cong dap cong 80/443
cung khong cham duoc trang quan tri. Neu muon kin hon nua, dat
`MOSWAF_ADMIN_BIND=127.0.0.1` roi vao bang tunnel:

```bash
ssh -L 9443:127.0.0.1:9443 root@IP_SERVER
```

## Kien truc

```
                      Internet
                         │
              ┌──────────▼───────────┐   cong 80/443
              │   proxy (OpenResty)  │   ← data plane, engine Lua
              │  rate limit ▸ IP set │
              │  JS challenge ▸ rule │
              └─────┬──────────┬─────┘
       config (3s)  │          │  su kien + bo dem
              ┌─────▼──────────▼─────┐
              │        Redis         │
              └─────┬──────────┬─────┘
                    │          │
              ┌─────▼──────────▼─────┐   cong 9443 (rieng)
              │   mgmt (Go + Vue)    │   ← control plane + dashboard
              └──────────┬───────────┘
                         │
                   ┌─────▼─────┐
                   │ Postgres  │  site, luat, nhat ky tan cong
                   └───────────┘
```

Vi sao tach doi:

- **Data plane** chi lo loc goi tin. Khong dung DB, khong cho I/O. Moi quyet
  dinh doc tu `lua_shared_dict` trong bo nho, nen chi phi moi request la vai
  chuc micro giay.
- **Control plane** giu nguon su that trong Postgres, day chinh sach sang Redis
  va sinh file cau hinh nginx. Control plane chet thi WAF **van chan binh thuong**
  bang ban config cuoi cung.

## Cac lop phong ve (theo dung thu tu chay)

| # | Lop | Xu ly |
|---|-----|-------|
| 1 | `limit_conn` / `limit_req` cua nginx | cat song flood tho truoc khi ton CPU cho Lua |
| 2 | Whitelist IP | bo qua toan bo kiem tra con lai |
| 3 | Blacklist + ban tam thoi | chan ngay, doc tu shared dict |
| 4 | Rate limit 2 cua so (1s + 10s) | bat ca burst tuc thoi lan flood rai deu |
| 5 | JS challenge (proof-of-work SHA-256) | loc bot khong chay duoc JavaScript |
| 6 | Engine chu ky | SQLi, XSS, LFI/traversal, RCE, SSRF, scanner, CRLF |

Vuot nguong 3 lan trong 1 phut thi IP bi **ban tam thoi** thay vi chan tung
request - re hon nhieu khi dang bi botnet dap.

### JS challenge hoat dong the nao

Khach chua co cookie hop le se nhan trang challenge. Trinh duyet phai tim `nonce`
sao cho `SHA-256(salt + nonce)` co N bit 0 dau (mac dinh 16 bit ≈ 0,1-0,3 giay).
Giai xong thi duoc cap cookie ky HMAC, song 30 phut.

Bot dung `curl`/`python-requests` khong chay JavaScript nen rot ngay. Botnet muon
duy tri flood se phai tra chi phi CPU gap hang nghin lan phia may chu.

Khi bi tan cong nang, bat **che do dang bi tan cong** o goc phai dashboard:
moi khach la deu phai giai challenge truoc khi vao site.

## Su dung

1. Vao `https://IP:9443`, dang nhap bang tai khoan installer in ra.
2. **Doi mat khau ngay** trong muc Cai dat.
3. Vao **Trang web → Them site**: khai ten mien va upstream that
   (vi du `10.0.0.5:8080`, hoac `host.docker.internal:8080` neu web chay tren chinh may nay).
4. Tro ban ghi A cua ten mien ve IP may chay MosWAF.
5. Theo doi o **Tong quan** va **Nhat ky tan cong**.

Nen bat che do **Chi theo doi** vai ngay dau de xem co luat nao chan nham
luu luong that khong, roi moi chuyen sang **Bao ve**.

## Kiem tra WAF co that su chan khong

Sau khi them site, ban mot loat request kieu tan cong vao chinh site cua minh
roi doi chieu ket qua:

```bash
./scripts/attack-sim.sh https://example.com
./scripts/attack-sim.sh https://example.com --flood 150   # thu ca rate limit
```

Script thu SQLi, XSS, path traversal, RCE, do file bi mat, SSRF metadata va
User-Agent cua cong cu quet, dong thoi kiem tra hai request binh thuong **khong**
bi chan nham. Nhin dashboard thay "da chan 0" thi khong biet la chua ai tan cong
hay la minh cau hinh sai - chay script nay se ro ngay.

## Lenh thuong dung

```bash
cd /opt/moswaf
docker compose ps                 # trang thai
docker compose logs -f proxy      # log data plane
docker compose logs -f mgmt       # log control plane
docker compose restart proxy
```

Trong thu muc source con co `make`:

```bash
make up          # build + chay
make logs        # xem log
make nginx-test  # kiem tra cu phap nginx dang chay
make down        # dung
```

## Phat trien

Can Go >= 1.22 va Node >= 20.

```bash
make web-build   # build dashboard vao control/internal/web/dist
make go-build    # build binary control plane
make go-test     # go vet + go test
make web-dev     # Vite dev server, proxy API sang https://127.0.0.1:9443
```

Sua engine Lua trong `dataplane/lua/moswaf/` thi chi can:

```bash
docker compose restart proxy
```

## Cau truc thu muc

```
moswaf/
├── install.sh              trinh cai one-command
├── docker-compose.yml
├── dataplane/              OpenResty - lop chan
│   ├── conf/               nginx.conf, server mac dinh, trang challenge/blocked
│   └── lua/moswaf/
│       ├── access.lua      pha quyet dinh cho qua / chan / challenge
│       ├── rules.lua       engine chu ky + bo luat goc
│       ├── ratelimit.lua   bo dem 2 cua so
│       ├── ipset.lua       danh sach den/trang + ban tam thoi
│       ├── challenge.lua   JS challenge proof-of-work
│       ├── config.lua      dong bo cau hinh tu Redis
│       └── log.lua         day su kien + thong ke
├── control/                Go - API, dashboard, dong bo
│   ├── cmd/moswafd/
│   └── internal/{api,store,engine,config,web}
└── web/                    Vue 3 + Vite - giao dien dashboard
```

## Gioi han hien tai

Nhung phan **chua** co, can biet truoc khi dua ra san xuat:

- Chua tu xin chung chi Let's Encrypt (da chua san duong `/.well-known/acme-challenge/`,
  chung chi hien phai dan tay vao form site).
- Chua co cum nhieu node - moi ban cai la mot may doc lap.
- Chua co fingerprint TLS (JA3/JA4) va chua co hoc may; phat hien hien dua tren
  chu ky + tan suat.
- Chua co xac thuc hai lop cho dashboard.
- Chua co canh bao qua Telegram/email khi bi tan cong.

## Tai lieu

- [Tai lieu REST API](docs/API.md) - toan bo endpoint cua control plane, kem vi du curl.
