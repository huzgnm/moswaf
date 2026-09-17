# MosWAF — Báo cáo kiểm thử #1

**Ngày:** 2026-09-17
**Phạm vi:** data plane (`dataplane/lua/`, `dataplane/conf/`), control plane (`control/`), cấu hình triển khai (`install.sh`, `docker-compose.yml`, `.env.example`)
**Phương pháp:** đọc mã nguồn + test tái hiện chạy được bằng Go. Chưa kiểm thử hộp đen trên stack đang chạy (xem phần *Chưa kiểm được*).
**Commit:** `cd6ce7d`

---

## Tóm tắt

Kiến trúc tách data plane / control plane là đúng, lớp xác thực JWT sạch, và nhiều chỗ trong mã cho thấy tác giả đã nghĩ kỹ (comment giải thích bẫy `tonumber(x) or default` với giá trị 0, tách `pcall` từng phần trong `init_worker`, ghi file tạm rồi `rename`). Vấn đề không nằm ở sự cẩu thả mà nằm ở **các tương tác giữa hai lớp**: thứ tự rule do SQL quyết định nhưng ngữ nghĩa "first match wins" nằm ở Lua; kiểm tra regex bằng RE2 nhưng thực thi bằng PCRE; validate site ở Go nhưng render ra nginx cũng ở Go mà không ai escape.

Kết quả: **một header `User-Agent` duy nhất vô hiệu hoá toàn bộ engine chữ ký.**

| # | Mức | Vấn đề | Test |
|---|-----|--------|------|
| 1 | **Nghiêm trọng** | Rule `log` chắn trước rule `deny` → bypass WAF bằng 1 header | `TestLoggingRuleDoesNotShadowBlockingRule` |
| 2 | **Nghiêm trọng** | `make up` triển khai với bí mật `changeme`, không có chốt chặn | — |
| 3 | **Cao** | `Site.Name` không validate → inject chỉ thị nginx (worker chạy `root`) | `TestRenderSiteDoesNotEmitInjectedDirectives` |
| 4 | **Cao** | Header và User-Agent nằm ngoài tầm quét của mọi rule `any` | `TestAttackInHeaderIsDetected` |
| 5 | **Cao** | Body > 64KB hoặc `Transfer-Encoding: chunked` không bị quét | — |
| 6 | **Cao** | `real_ip_header` không bắt buộc `trusted_proxies` → giả mạo IP | `TestValidateSettingsRequiresTrustedProxiesWithRealIPHeader` |
| 7 | Trung bình | Rate limit fail-open khi shared dict đầy | — |
| 8 | Trung bình | Cửa sổ đếm cố định → cho phép gấp đôi ngưỡng ở ranh giới | — |
| 9 | Trung bình | Validate regex bằng RE2, chạy bằng PCRE; lỗi PCRE bị nuốt | `TestValidateRuleAcceptsPCRELookahead` |
| 10 | Trung bình | `/__moswaf/verify` đứng trước mọi kiểm tra ban/rate limit | — |
| 11 | Trung bình | `loginGuard` rò bộ nhớ vĩnh viễn | `TestLoginGuardReleasesInertEntries` |
| 12 | Thấp | Open redirect qua `/\` trong tham số `r` của verify | — |
| 13 | Thấp | Đổi mật khẩu không thu hồi JWT đang có | — |

---

## 1. Bypass toàn bộ engine chữ ký bằng một header — NGHIÊM TRỌNG

**Tái hiện:**

```bash
curl -A 'python-requests/2.31.0' \
     'https://site-cua-ban/products?id=1%20UNION%20ALL%20SELECT%20password%20FROM%20users'
```

Request đi lọt lên upstream. Đổi `-A` thành `curl/8.4` thì bị chặn.

**Nguyên nhân — chuỗi ba mắt xích ở ba file khác nhau:**

1. `store/rules.go:101` — `ListRules` sắp xếp `ORDER BY builtin DESC, category, id`.
2. `engine/publisher.go:116` — `Publish` đẩy rule vào Redis đúng theo thứ tự đó.
3. `dataplane/lua/moswaf/rules.lua:137` — `scan` duyệt tuần tự và **`return` ngay ở rule khớp đầu tiên**, bất kể `action` là gì.

Category `bot` đứng trước `lfi`, `rce`, `sqli`, `xss` theo thứ tự chữ cái. Trong `bot`, id sắp thành `ua-empty`, `ua-lib`, `ua-scanner`. Rule **`ua-lib` mang `action = "log"`**, mà `access.lua:198` xử lý `log` là *cho qua và ghi nhận*:

```lua
if action == "log" then
    ctx.action = "log"
    ...
    return          -- request đi tiếp lên upstream
```

Nên chỉ cần `User-Agent` khớp `ua-lib`, vòng lặp dừng lại và **không rule sqli/xss/rce/lfi nào được chạy**.

Các UA kích hoạt: `python-requests`, `python-urllib`, `go-http-client`, `java/`, `okhttp`, `libwww-perl`, `axios/`, `scrapy`, `node-fetch`.

Trớ trêu: đây là danh sách "client tự động đáng ngờ" — **đánh dấu mình là bot thì được miễn kiểm tra.**

Lỗi tương tự trong category `recon`: `path-admin` (`log`) đứng trước `path-secret` (`deny`), nên `GET /pma/.env` lọt qua.

**Vì sao `scripts/attack-sim.sh` không bắt được:** script dùng UA mặc định của curl, không nằm trong `ua-lib`. Dashboard vẫn báo "đã chặn" cho mọi ca test, trong khi lỗ hổng thật vẫn mở.

**Hướng sửa (chọn một):**
- Trong `rules.lua:scan`, đừng dừng ở rule `log`: ghi nhận rồi tiếp tục duyệt, chỉ dừng khi gặp `deny`/`ban`/`challenge`.
- Hoặc duyệt hết và chọn rule có `action` nặng nhất, thay vì rule đầu tiên.
- Đồng thời cho `ListRules` sắp theo mức độ chặn (`deny` → `ban` → `challenge` → `log`) thay vì theo `category`, để thứ tự đánh giá không còn phụ thuộc vào tên category.

---

## 2. `make up` triển khai với bí mật `changeme` — NGHIÊM TRỌNG

`install.sh` sinh bí mật ngẫu nhiên đàng hoàng (`rand 48`). Nhưng `Makefile` có:

```make
.env: ; @test -f .env || cp .env.example .env
up: .env
	$(COMPOSE) up -d --build
```

Và `.env.example` chứa:

```
MOSWAF_ADMIN_PASSWORD=changeme
POSTGRES_PASSWORD=changeme
REDIS_PASSWORD=changeme
MOSWAF_JWT_SECRET=changeme
MOSWAF_CHALLENGE_SECRET=changeme
```

**Không có chỗ nào từ chối khởi động với các giá trị này.** Hậu quả nếu ai đó triển khai bằng `make up` (README mục *Development* dạy đúng đường này):

- `MOSWAF_JWT_SECRET=changeme` → ký JWT giả → **chiếm toàn quyền dashboard** không cần mật khẩu.
- `MOSWAF_CHALLENGE_SECRET=changeme` → giả cookie `__moswaf` → **vô hiệu hoá JS challenge và chế độ under-attack**, tức là tính năng chống DDoS chính.
- `admin` / `changeme`.

Ngoài ra `control/internal/config/config.go:78` đặt mặc định `ChallengeSecret = "moswaf-insecure-default"`, trùng khớp với `challenge.lua:23`. Nếu biến môi trường thiếu, hai bên vẫn "đồng thuận" trên một khoá công khai nằm trong repo — hệ thống chạy bình thường, không cảnh báo, và cookie challenge giả được chấp nhận.

**Hướng sửa:** control plane từ chối khởi động nếu `MOSWAF_JWT_SECRET` hoặc `MOSWAF_CHALLENGE_SECRET` rỗng, bằng `changeme`, hay bằng `moswaf-insecure-default`. Bỏ giá trị mặc định trong `config.go` và `challenge.lua`. Đổi `.env.example` sang để trống kèm chú thích.

---

## 3. Inject chỉ thị nginx qua tên site — CAO

`ValidateSite` (`store/sites.go:66`) kiểm tra ký tự cho `Domains` và `UpstreamHost`, nhưng **`Name` chỉ bị `TrimSpace` và kiểm tra khác rỗng**. `renderSite` ghi thẳng vào một dòng chú thích:

```go
w("# MosWAF - %s (%s)", s.Name, s.ID)
```

Một ký tự xuống dòng là thoát khỏi chú thích. Đặt tên site thành:

```
acme
}
server { listen 8888; location / { root /; } }
#
```

Output thực tế do test sinh ra:

```nginx
# MosWAF - acme
}
server { listen 8888; location / { root /; } }
# (acme)
```

File này được `include` trong `http{}`, và `nginx.conf:7` đặt `user root`. Nên đây không dừng ở "phục vụ toàn bộ filesystem của container qua cổng 8888" — chỉ thị `content_by_lua_block` cũng hợp lệ ở vị trí đó, tức là **thực thi mã tuỳ ý với quyền root** trong container proxy.

Cần quyền admin đã đăng nhập, nên mức độ phụ thuộc vào việc bạn coi admin dashboard là ranh giới tin cậy hay không. Nhưng đây là phòng thủ theo chiều sâu cơ bản: kết hợp với bất kỳ lỗi XSS/CSRF nào trên dashboard là thành chiếm quyền máy chủ.

`Domains` và `UpstreamHost` **không** inject được (`;`, `{`, `}`, khoảng trắng đều bị chặn nên không kết thúc được chỉ thị), nhưng vẫn cho lọt ký tự xuống dòng, sinh ra config nginx không parse được → proxy không reload được nữa → mọi thay đổi cấu hình sau đó âm thầm không có hiệu lực.

**Hướng sửa:** từ chối `\r` và `\n` trong cả ba trường; escape `Name` khi render, hoặc đơn giản là không in `Name` vào file config.

---

## 4. Header và User-Agent nằm ngoài tầm quét — CAO

`access.lua:174` thu thập cẩn thận `ngx.req.get_headers(64)` và truyền vào `scan.headers`. Nhưng `rules.lua:125`:

```lua
ctx._any = concat({ ctx.uri, ctx.args, ctx.body, ctx.cookie, ctx.referer }, "\n")
```

Target `any` **không bao gồm `ua` và không bao gồm `headers`**. Và trong bộ rule mặc định **không có rule nào target `header`**. Nên:

- SQLi/RCE/XSS đặt trong header bất kỳ (`X-Api-Version`, `X-Forwarded-Host`, ...) → hoàn toàn vô hình.
- Payload đặt trong `User-Agent` chỉ gặp 3 rule `ua` (tên scanner, UA rỗng, thư viện HTTP) → `User-Agent: 1' UNION ALL SELECT ...` đi lọt.

Đây là bề mặt tấn công rất thực tế: header là nơi Log4Shell sống, và là nơi payload SQLi đi vào các hệ thống ghi log request.

Rule `hdr-inject` (phát hiện CRLF injection) cũng để `target = "any"` — tức là **rule chống tiêm header không bao giờ nhìn thấy header**.

**Hướng sửa:** thêm `ua` và `_hdr` vào subject `any`, hoặc đổi các rule chính sang một target mới bao trùm tất cả. Đồng thời xử lý việc `get_headers(64)` cắt bớt khi request có >64 header (gửi 70 header, giấu payload ở header thứ 65).

---

## 5. Body lớn và chunked không bị quét — CAO

`access.lua:186`:

```lua
local len = tonumber(ngx.var.http_content_length) or 0
local max = tonumber(st.max_body_scan) or 65536
if len > 0 and len <= max then
    ngx.req.read_body()
    scan.body = expand(ngx.req.get_body_data() or "")
end
```

Hai lối thoát:

1. **`Transfer-Encoding: chunked`** — không có `Content-Length`, nên `len = 0`, điều kiện `len > 0` sai, **body không bao giờ được quét**.
2. **Body > 64KB** — `nginx.conf:49` cho `client_max_body_size 64m`, còn `max_body_scan` mặc định 65536. Đệm payload bằng 64KB rác là qua. Lưu ý điều kiện là `len <= max` chứ không phải "quét 64KB đầu", nên vượt ngưỡng là bỏ qua **toàn bộ**, không phải cắt bớt.

Ngoài ra `ngx.req.get_body_data()` trả `nil` khi nginx đã ghi body ra file tạm (`client_body_buffer_size 256k`) — nhưng trường hợp đó đã bị chặn bởi giới hạn 64KB, nên hiện chưa lộ.

**Hướng sửa:** quét `min(len, max)` byte đầu thay vì bỏ qua; xử lý chunked bằng cách đọc body rồi đo độ dài thực tế; cân nhắc chặn thẳng request vượt `max_body_scan` khi ở chế độ protect (fail-closed) thay vì cho qua.

---

## 6. Giả mạo IP khi bật `real_ip_header` — CAO

`util.lua:99`:

```lua
local trusted = settings.trusted_proxies
if trusted and #trusted > 0 and not _M.ip_in_list(peer, trusted) then
    return peer
end
```

Nếu `trusted_proxies` rỗng, điều kiện sai → **không kiểm tra gì cả** → đọc thẳng header. `ValidateSettings` không hề bắt buộc khai báo proxy tin cậy khi đã đặt `real_ip_header`.

Kịch bản: admin đặt sau Cloudflare, điền "Real IP header = X-Forwarded-For", để trống danh sách proxy tin cậy (rất tự nhiên). Từ đó **mọi client tự khai IP của mình**:

- Ban tạm thời vô dụng — đổi header là có IP mới.
- Blacklist vô dụng.
- Rate limit vô dụng — mỗi request một IP là mỗi request một bộ đếm mới (`ratelimit.lua:31` khoá theo chuỗi IP).
- Nhật ký tấn công bị đầu độc, chỉ về nạn nhân vô can.

**Lỗi thứ hai, tồn tại ngay cả khi đã cấu hình đúng:** `util.lua:108` lấy phần tử **trái nhất** hợp lệ của `X-Forwarded-For`. Nhưng CDN *nối thêm* vào cuối, nên phần tử trái nhất chính là phần kẻ tấn công tự điền. Gửi `X-Forwarded-For: 1.2.3.4`, Cloudflare biến thành `1.2.3.4, <IP thật>`, MosWAF lấy `1.2.3.4`. **Rate limit và ban vẫn bị vô hiệu dù cấu hình chuẩn.** Đúng quy tắc là bóc các proxy tin cậy từ *phải* sang và lấy phần tử không tin cậy đầu tiên.

Phụ: `ipv4_to_int` chấp nhận số 0 ở đầu (`010.0.0.1`), và lệnh ban lưu theo *chuỗi* IP. Nên `1.2.3.4`, `01.2.3.4`, `001.2.3.4`… là các khoá ban khác nhau nhưng khớp cùng một dải blacklist — thêm một đường lách ban.

---

## 7. Rate limit tự tắt khi bị tấn công nặng — TRUNG BÌNH

`ratelimit.lua:14`:

```lua
local newval, err = cnt:incr(key, 1, 0, ttl)
if not newval then
    ngx.log(ngx.WARN, ...)
    return 0                 -- "khong chan nham, chi ghi log"
end
```

Trả `0` nghĩa là không bao giờ vượt ngưỡng → **rate limit ngừng hoạt động**. Khoá đếm là `scope:s:<ip>:<giây>` — một khoá mỗi IP mỗi giây. Khi botnet từ hàng chục nghìn IP tràn vào, `moswaf_cnt` (64MB) đầy hoặc bị đẩy LRU liên tục, và bộ chống flood tự vô hiệu hoá **đúng lúc cần nhất**.

Với sản phẩm chống DDoS, đây là chế độ hỏng tệ nhất. Quyết định "thà cho qua còn hơn chặn nhầm" là có chủ ý (comment nói rõ) nhưng đặt sai chỗ.

**Hướng sửa:** khi `incr` lỗi, chuyển sang challenge thay vì cho qua; theo dõi `cnt:free_space()` và cảnh báo lên dashboard; cân nhắc khoá đếm theo `/24` thay vì IP đơn để giảm số khoá.

## 8. Cửa sổ đếm cố định — TRUNG BÌNH

`floor(now)` và `floor(now/10)` là cửa sổ cố định, không trượt. Với `rps = 60`: gửi 60 request ở `t = 0.999` và 60 request ở `t = 1.001` → **120 request trong 2ms, không có gì bị chặn**. Tương tự ở cửa sổ 10 giây. Thực tế ngưỡng thật cao gấp đôi ngưỡng cấu hình.

`mark_violation` cũng dùng cửa sổ cố định 60 giây, nên bộ đếm vi phạm reset đều đặn và ngưỡng leo thang sang ban (`>= 3`) khó đạt hơn dự kiến.

## 9. Validate bằng RE2, thực thi bằng PCRE — TRUNG BÌNH

`ValidateRule` (`store/rules.go:137`) dùng `regexp.Compile` của Go (RE2); data plane chạy bằng PCRE qua `ngx.re.find`. Lệch cả hai chiều:

- **RE2 từ chối lookahead/backreference** → không lưu được các mẫu WAF thông dụng như `(?=.*union)(?=.*select)`.
- **RE2 không có backtracking thảm hoạ nên chấp nhận mẫu sẽ treo PCRE.** `nginx.conf` không đặt `lua_regex_match_limit`, nên một mẫu kiểu `^(a+)+$` chạy trên mọi request là đủ làm nghẽn data plane.
- `rules.lua:148` **bỏ qua giá trị lỗi** của `ngx.re.find`. Mẫu hợp lệ với RE2 nhưng PCRE từ chối sẽ **âm thầm không bao giờ khớp**, trong khi dashboard vẫn hiển thị rule đang bật. Admin tin là mình được bảo vệ.

**Hướng sửa:** validate bằng chính PCRE (gọi xuống data plane qua endpoint `/validate` mới, hoặc dùng thư viện PCRE trong Go); đặt `lua_regex_match_limit`; ghi log và báo lên dashboard khi `ngx.re.find` trả lỗi.

## 10. `/__moswaf/verify` đứng trước mọi kiểm tra — TRUNG BÌNH

`access.lua:114` xử lý endpoint verify **trước** kiểm tra ban, blacklist và rate limit. Nên endpoint này không chịu bất kỳ giới hạn nào của lớp Lua: IP đang bị ban vẫn gọi được, và có thể gọi ở tốc độ tuỳ ý (chỉ còn `limit_req` mức nginx với ngưỡng 200r/s). Mỗi lượt gọi tốn một HMAC và một SHA-256.

Thêm nữa, bộ ba `(salt, sig, nonce)` đã giải dùng lại được suốt 120 giây (`SALT_TTL`) vì không có theo dõi nonce đã dùng — tác động hạn chế do cookie gắn với IP, nhưng vẫn nên vá.

## 11. `loginGuard` rò bộ nhớ — TRUNG BÌNH

`auth.go:39` `cleanup()` chỉ xoá entry có `fails == 0`. Nhưng `fail()` luôn tăng `fails`, còn `success()` xoá hẳn entry. **Không entry nào từng thoả điều kiện xoá** — goroutine dọn dẹp là mã chết, và map giữ một `*attempt` cho mỗi IP từng đăng nhập sai, vĩnh viễn.

`/api/auth/login` không cần xác thực, nên đây là đường làm cạn bộ nhớ control plane từ xa.

## 12. Open redirect — THẤP

`challenge.lua:147` chặn `//evil.com` nhưng không chặn `/\evil.com`. Trình duyệt chuẩn hoá `\` thành `/`, nên `/\evil.com` được xử lý như `//evil.com` → chuyển hướng ra ngoài. Tham số `r` là base64url do client gửi.

## 13. Đổi mật khẩu không thu hồi JWT — THẤP

`parseToken` chỉ kiểm chữ ký và `exp`. Đổi mật khẩu, xoá tài khoản, hay `install.sh --reset-password` đều **không** làm mất hiệu lực token đang lưu hành (TTL mặc định 12 giờ). `requireAuth` cũng không kiểm tra tài khoản còn tồn tại (chỉ `handleMe` kiểm).

---

## Điểm đã kiểm và ĐẠT

Không phải mọi thứ đều hỏng — các mục sau đã được kiểm và chắc chắn:

- **JWT**: từ chối `alg=none`, từ chối sai khoá, từ chối hết hạn. `jwt.WithValidMethods` dùng đúng.
- **`requireAuth`**: chặn thiếu header, sai scheme, token rác.
- **Khoá đăng nhập sai**: 5 lần sai → khoá 5 phút, 10 lần → 30 phút; đăng nhập đúng xoá khoá. Khoá theo `r.RemoteAddr`, **không** tin `X-Forwarded-For` — đúng.
- **Header bảo mật**: `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, CSP `default-src 'self'` đều có.
- **Token gửi qua `Authorization: Bearer`** chứ không qua cookie → không có bề mặt CSRF.
- **`renderSite`**: áp `limit_conn`, `limit_req`, `access_by_lua_block`, `log_by_lua_block` đúng chỗ; kết quả tất định; từ chối site id sai định dạng.
- **Bộ rule mặc định** chặn đúng SQLi/traversal/RCE/XSS/scanner ở đường đi thông thường (khi không bị lỗi #1 chắn).
- **`expand()`** giải mã URL hai lớp đúng như thiết kế; `%2e%2e%2f` bị bắt.
- **`const_eq`** so sánh chữ ký không phụ thuộc thời gian — đúng.
- **`ValidateSettings`** kẹp biên hợp lý cho độ khó challenge, TTL, thời gian ban, mã trạng thái.

---

## Chưa kiểm được

- **Kiểm thử hộp đen trên stack thật** — chưa dựng được; đang cài colima. Ưu tiên khi có: xác nhận #1 và #5 bằng request thật, đo tác động #8 bằng tải thực.
- **`lua-check`** — máy chưa có `luajit`, chưa kiểm cú pháp Lua.
- **Dashboard Vue** — chưa soi XSS (`v-html`), chưa kiểm nơi lưu token.
- **`log.lua`, `api.lua`, `consumer.go`, `events.go`** — chưa đọc. Riêng `/unban` và `/sync` trên cổng 8081 không có xác thực, chỉ lọc bằng `allow` cho toàn bộ dải RFC1918 — cần soi kỹ.
- **`install.sh`** — mới đọc phần sinh bí mật.
- **Tấn công tải thật** (slowloris, bypass PoW bằng headless browser) — cần hạ tầng riêng.

---

## Đề xuất thứ tự sửa

1. **#1** — một dòng trong `rules.lua` và một `ORDER BY`. Sửa xong là bịt lỗ hổng lớn nhất.
2. **#2** — thêm chốt chặn khởi động. Nhanh, và ngăn được thảm hoạ triển khai.
3. **#4**, **#5** — mở rộng bề mặt quét. Vừa phải, giá trị cao.
4. **#6** — sửa cả hai phần (bắt buộc `trusted_proxies`, và lấy IP từ phải sang).
5. **#3** — chặn `\r\n` ở ba trường.
6. Còn lại theo mức độ.

Sau mỗi mục, bổ sung ca tương ứng vào `scripts/attack-sim.sh` để lần sau bắt được bằng kiểm thử hộp đen, không phải bằng đọc mã.

---

## Cách chạy bộ test

```bash
cd control && go test ./...
```

Các test tái hiện nằm ở:

- `internal/store/rules_scan_test.go` — mô phỏng trung thực thứ tự đánh giá rule của data plane (bao gồm `expand()`), dùng để săn bypass mà không cần dựng stack.
- `internal/store/validate_test.go` — validate site, settings, rule.
- `internal/engine/nginxconf_test.go` — kết quả render nginx.
- `internal/api/auth_test.go` — JWT, `requireAuth`, chống dò mật khẩu.

**Các test đang đỏ là cố ý** — mỗi test đỏ tương ứng một mục trong báo cáo này và sẽ tự chuyển xanh khi lỗi được vá. Trước đó repo có 0 file test, nên `go test ./...` trong CI luôn xanh mà không kiểm chứng điều gì.
