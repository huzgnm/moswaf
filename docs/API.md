# MosWAF REST API

Toan bo API nam duoi `https://<IP>:<MOSWAF_ADMIN_PORT>/api/`, mac dinh cong `9443`,
chung chi tu ky (dung `curl -k` khi test).

Tru `POST /api/auth/login` va `GET /api/health`, moi endpoint deu can header:

```
Authorization: Bearer <token>
```

Loi luon tra ve dang `{"error": "mo ta bang tieng Viet"}` kem ma HTTP tuong ung.

---

## Xac thuc

### `POST /api/auth/login`

```bash
curl -sk https://127.0.0.1:9443/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}'
```

```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_at": "2026-09-18T05:12:00Z",
  "user": { "id": 1, "username": "admin", "created_at": "..." }
}
```

Sai mat khau 5 lan tu mot IP se bi khoa 5 phut, 10 lan thi khoa 30 phut
(dem trong bo nho cua tien trinh, reset khi restart).

### `GET /api/auth/me`

Tra ve tai khoan dang dang nhap.

### `POST /api/auth/password`

```json
{ "current": "mat-khau-cu", "new": "mat-khau-moi-it-nhat-8-ky-tu" }
```

---

## Site

### `GET /api/sites`

Mang cac site. Khoa rieng TLS **khong bao gio** duoc tra ve; truong `has_tls`
cho biet site da co chung chi hay chua.

### `POST /api/sites`

```json
{
  "name": "Website ban hang",
  "domains": ["example.com", "www.example.com"],
  "upstream_scheme": "http",
  "upstream_host": "10.0.0.5",
  "upstream_port": 8080,
  "mode": "protect",
  "challenge": "auto",
  "rate_rps": 0,
  "rate_burst": 0,
  "force_https": false,
  "tls_cert": "-----BEGIN CERTIFICATE-----\n...",
  "tls_key": "-----BEGIN PRIVATE KEY-----\n..."
}
```

| Truong | Gia tri | Y nghia |
|--------|---------|---------|
| `mode` | `protect` / `monitor` / `off` | chan that / chi ghi log / cho qua het |
| `challenge` | `auto` / `always` / `off` | khi nao bat JS challenge |
| `rate_rps` | so nguyen, `0` = theo muc toan cuc | request/giay/IP |
| `rate_burst` | so nguyen, `0` = theo muc toan cuc | nguong trong cua so 10 giay |

Moi thay doi site deu lam control plane sinh lai file nginx va day cau hinh
sang Redis ngay; container proxy phat hien file doi va tu `reload`.

### `PUT /api/sites/{id}`

Giong `POST`. De trong `tls_cert` va `tls_key` thi giu nguyen chung chi dang dung.

### `DELETE /api/sites/{id}`

---

## Luat phat hien

### `GET /api/rules`

Bao gom ca luat goc (`builtin: true`) lan luat tu tao.

### `POST /api/rules`

```json
{
  "name": "Chan truy cap /internal tu ben ngoai",
  "category": "custom",
  "target": "uri",
  "pattern": "(?i)^/internal/",
  "action": "deny",
  "severity": "high"
}
```

| Truong | Gia tri |
|--------|---------|
| `target` | `any`, `uri`, `args`, `body`, `ua`, `header`, `cookie` |
| `action` | `deny`, `challenge`, `ban`, `log` |
| `severity` | `low`, `medium`, `high`, `critical` |

Ma luat tu tao luon duoc them tien to `custom-`. Bieu thuc duoc kiem tra cu phap
truoc khi luu.

### `PUT /api/rules/{id}` · `POST /api/rules/{id}/toggle` · `DELETE /api/rules/{id}`

```json
{ "enabled": false }
```

Luat goc chi duoc **tat**, khong xoa duoc - de lan nang cap sau con doi chieu.

---

## Danh sach IP

### `GET /api/ips?kind=black`

`kind` nhan `black` hoac `white`. Bo trong thi tra ve ca hai.

### `POST /api/ips`

```json
{ "cidr": "45.83.122.0/24", "kind": "black", "reason": "Flood tang 7", "minutes": 60 }
```

`minutes: 0` nghia la vinh vien. Dia chi duoc chuan hoa truoc khi luu
(`1.2.3.4/24` thanh `1.2.3.0/24`).

### `DELETE /api/ips/{id}`

---

## Nhat ky tan cong

### `GET /api/events`

| Tham so | Vi du | Y nghia |
|---------|-------|---------|
| `hours` | `24` | khoang thoi gian |
| `site` | `s1a2b3c4d5` | loc theo site |
| `ip` | `45.83.122.9` | loc theo IP |
| `action` | `deny` | `deny`, `challenge`, `monitor`, `log` |
| `severity` | `high` | muc do |
| `q` | `union` | tim trong URI, User-Agent, ten luat |
| `limit` / `offset` | `50` / `0` | phan trang, toi da 500 |

```json
{ "items": [ { "id": 1, "ts": "...", "ip": "...", "action": "deny", "rule_name": "SQLi - UNION SELECT" } ],
  "total": 1284, "limit": 50, "offset": 0 }
```

Chi request bi chan / bi challenge / khop luat moi duoc ghi. Muon ghi ca luu luong
binh thuong thi bat `log_allowed` trong cai dat (rat ton dung luong).

---

## Thong ke

### `GET /api/stats/overview?hours=24`

```json
{
  "requests": 83768, "blocked": 18206, "challenged": 5615,
  "sites_total": 3, "sites_active": 2, "under_attack": true,
  "top_attackers": [ { "key": "45.83.122.9", "count": 3184 } ],
  "top_rules":     [ { "key": "sqli-union", "label": "SQLi - UNION SELECT", "count": 2890 } ],
  "config_version": 1737000000000
}
```

### `GET /api/stats/timeseries?hours=6`

Mang diem theo phut: `{ "minute": "...", "total": 0, "blocked": 0, "challenged": 0, "monitored": 0 }`.

Phut khong co du lieu se khong xuat hien trong mang - phia hien thi tu dien 0.

---

## Cai dat

### `GET /api/settings` · `PUT /api/settings`

Chi can gui nhung truong muon doi; phan con lai giu nguyen.

| Truong | Mac dinh | Y nghia |
|--------|----------|---------|
| `under_attack` | `false` | ep moi khach la giai JS challenge |
| `default_mode` | `protect` | che do cho site khong dat rieng |
| `global_rate_rps` | `60` | request/giay/IP |
| `global_rate_burst` | `120` | nguong cua so 10 giay |
| `ban_seconds` | `600` | thoi gian ban tam thoi |
| `challenge_difficulty` | `16` | so bit 0 dau cua SHA-256, toi da 24 |
| `challenge_ttl` | `1800` | cookie challenge song bao lau |
| `block_status` | `403` | ma tra ve khi chan |
| `real_ip_header` | `""` | `X-Forwarded-For`, `CF-Connecting-IP`... |
| `trusted_proxies` | `[]` | chi tin header IP that tu cac dai nay |
| `scan_body` | `true` | co quet noi dung POST khong |
| `max_body_scan` | `65536` | so byte body toi da duoc quet |
| `log_retain_days` | `7` | so ngay giu nhat ky |

> Chi bat `real_ip_header` khi that su co CDN/proxy dung truoc MosWAF va da khai
> `trusted_proxies`. Neu khong, ke tan cong chi can tu them header la gia mao duoc IP.

### `POST /api/settings/under-attack`

```json
{ "enabled": true }
```

Tach rieng de bam mot nut la xong khi dang bi tan cong.

---

## He thong

### `GET /api/health`

Khong can dang nhap. `200` khi Postgres con song.

### `GET /api/system/status`

```json
{ "config_version": 1737000000000, "database": "ok", "redis": "ok",
  "dataplane": { "status": "ok", "version": 17 }, "event_queue": 0 }
```

### `POST /api/system/publish`

Day lai toan bo cau hinh xuong data plane khi nghi bi lech.

---

## Endpoint noi bo cua data plane

Chay tren cong `8081`, chi mo trong mang Docker (`allow` cac dai IP noi bo).

| Duong dan | Cong dung |
|-----------|-----------|
| `GET /healthz` | trang thai + phien ban cau hinh dang chay |
| `GET /metrics` | dinh dang Prometheus |
| `GET /sync` | ep nap lai cau hinh ngay, khong doi chu ky 3 giay |

```
moswaf_config_version 1737000000000
moswaf_requests_total 1284
moswaf_blocked_total 96
moswaf_challenged_total 12
moswaf_rules_active 18
moswaf_banned_ips 3
moswaf_event_queue 0
```
