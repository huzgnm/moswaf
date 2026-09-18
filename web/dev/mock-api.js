// A fake control plane for laying out the dashboard.
//
// DEVELOPMENT ONLY. It is a Vite dev-server middleware, it is off unless
// MOSWAF_MOCK=1 is set, and nothing in this file is reachable from a build:
// `vite build` never touches it, so the binary Go embeds cannot serve it.
//
//   MOSWAF_MOCK=1 npm run dev
//
// Why it exists: a fresh install has no sites and no attack log, so the states
// that are hardest to get right - a full table, a chart with a spike in it, a
// long Russian label in a narrow column - are exactly the ones a real local
// database cannot show. Every field below is one the real API documents in
// docs/API.md; if a shape here disagrees with the server, this file is wrong.

const now = () => Date.now()

const SITES = [
  {
    id: 's1a2b3c4d5', name: 'Cửa hàng online', domains: ['shop.example.com', 'www.shop.example.com'],
    upstream_scheme: 'http', upstream_host: '10.0.0.5', upstream_port: 8080,
    mode: 'protect', challenge: 'auto', rate_rps: 0, rate_burst: 0, flood_rps: 0,
    force_https: true, has_tls: true, acme_enabled: true, acme_email: 'ops@example.com',
    cert_expires_at: new Date(now() + 41 * 864e5).toISOString(), acme_last_error: '',
    auth_enabled: false, auth_paths: [], enabled: true, geo_mode: '', geo_countries: [],
  },
  {
    id: 's6e7f8a9b0', name: 'Trang quản trị nội bộ', domains: ['admin.example.com'],
    upstream_scheme: 'https', upstream_host: '10.0.0.9', upstream_port: 443,
    mode: 'protect', challenge: 'always', rate_rps: 20, rate_burst: 60, flood_rps: 0,
    force_https: true, has_tls: true, acme_enabled: false,
    cert_expires_at: new Date(now() + 9 * 864e5).toISOString(), acme_last_error: '',
    auth_enabled: true, auth_paths: ['/'], enabled: true, geo_mode: 'allow', geo_countries: ['VN'],
  },
  {
    id: 'sc1d2e3f45', name: 'Blog', domains: ['blog.example.com'],
    upstream_scheme: 'http', upstream_host: 'host.docker.internal', upstream_port: 3000,
    mode: 'monitor', challenge: 'off', rate_rps: 0, rate_burst: 0, flood_rps: 0,
    force_https: false, has_tls: false, acme_enabled: true, acme_email: 'ops@example.com',
    cert_expires_at: null, acme_last_error: 'DNS problem: NXDOMAIN looking up A for blog.example.com',
    auth_enabled: false, auth_paths: [], enabled: true, geo_mode: 'off', geo_countries: [],
  },
]

const RULE_SEED = [
  ['sqli-union', 'SQLi - UNION SELECT', 'sqli', 'args', 'deny', 'critical'],
  ['sqli-or1', 'SQLi - OR 1=1', 'sqli', 'args', 'deny', 'critical'],
  ['xss-script', 'XSS - thẻ script', 'xss', 'args', 'deny', 'high'],
  ['lfi-traversal', 'LFI - ../ traversal', 'lfi', 'uri', 'deny', 'high'],
  ['rce-shell', 'RCE - lệnh shell', 'rce', 'body', 'ban', 'critical'],
  ['ssrf-meta', 'SSRF - metadata nội bộ', 'ssrf', 'args', 'deny', 'high'],
  ['scanner-ua', 'Scanner - sqlmap / nikto', 'scanner', 'ua', 'challenge', 'medium'],
  ['crlf-header', 'CRLF injection', 'crlf', 'header', 'deny', 'medium'],
  ['wp-probe', 'Dò /wp-admin', 'scanner', 'uri', 'log', 'low'],
]
const RULES = RULE_SEED.map(([id, name, category, target, action, severity], i) => ({
  id, name, category, target, action, severity, pattern: '(?i)…', builtin: true, enabled: i !== 8,
})).concat([{
  id: 'custom-1', name: 'Chặn truy cập /internal từ bên ngoài', category: 'custom',
  target: 'uri', pattern: '(?i)^/internal/', action: 'deny', severity: 'high', builtin: false, enabled: true,
}])

const IPS = [
  { id: 1, cidr: '45.83.122.0/24', kind: 'black', reason: 'Layer 7 flood', expires_at: null, created_at: new Date(now() - 3 * 864e5).toISOString() },
  { id: 2, cidr: '103.21.244.9/32', kind: 'black', reason: 'Chặn từ nhật ký tấn công', expires_at: new Date(now() + 36e5).toISOString(), created_at: new Date(now() - 36e5).toISOString() },
  { id: 3, cidr: '14.161.0.0/16', kind: 'white', reason: 'Văn phòng Hà Nội', expires_at: null, created_at: new Date(now() - 20 * 864e5).toISOString() },
]

const ATTACKERS = ['45.83.122.9', '103.21.244.9', '185.220.101.44', '2001:db8:ac10:fe01::9', '92.63.197.153', '141.98.10.62']
const PATHS = ['/index.php?id=1%20UNION%20SELECT', '/wp-admin/setup-config.php', '/../../etc/passwd', '/api/v1/orders?q=<script>', '/actuator/env', '/?s=/Index/think/app/invokefunction']
const UAS = ['sqlmap/1.7.2#stable (https://sqlmap.org)', 'Mozilla/5.0 (X11; Linux x86_64) python-requests/2.31', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', '']

function events(n, hours) {
  const out = []
  for (let i = 0; i < n; i++) {
    const action = ['deny', 'deny', 'deny', 'challenge', 'monitor', 'log'][i % 6]
    const rule = RULES[i % RULES.length]
    out.push({
      id: 100000 - i,
      ts: new Date(now() - i * ((hours * 36e5) / Math.max(n, 1)) - 4000).toISOString(),
      ray: (0xa1b2c3 + i).toString(16).padStart(12, '0'),
      site: SITES[i % SITES.length].id,
      ip: ATTACKERS[i % ATTACKERS.length],
      method: i % 5 === 0 ? 'POST' : 'GET',
      host: SITES[i % SITES.length].domains[0],
      uri: PATHS[i % PATHS.length],
      ua: UAS[i % UAS.length],
      referer: '',
      action,
      reason: action === 'challenge' ? 'flood:rate_rps' : rule.id,
      rule_id: action === 'challenge' ? '' : rule.id,
      rule_name: action === 'challenge' ? '' : rule.name,
      severity: rule.severity,
      status: action === 'deny' ? 403 : action === 'challenge' ? 429 : 200,
      rt: 0.004,
      country: ['CN', 'RU', 'NL', '', 'VN', 'US'][i % 6],
    })
  }
  return out
}

// A shape with a plateau and one spike, so the axis and the tooltip get tested
// against both a quiet stretch and a jump.
function series(hours) {
  const out = []
  const minutes = hours * 60
  const end = Math.floor(now() / 60000) * 60000
  for (let m = minutes; m >= 0; m--) {
    const ts = end - m * 60000
    const wave = Math.sin(m / 37) * 40 + Math.sin(m / 11) * 12
    const spike = m > minutes * 0.32 && m < minutes * 0.38 ? 900 : 0
    const total = Math.max(0, Math.round(180 + wave + spike + (m % 7) * 3))
    const blocked = Math.round(total * (spike ? 0.62 : 0.14))
    const challenged = Math.round(total * (spike ? 0.2 : 0.05))
    if (m % 3 === 0 && !spike) continue   // real data skips minutes with no traffic
    out.push({ minute: new Date(ts).toISOString(), total, blocked, challenged, monitored: Math.round(total * 0.03) })
  }
  return out
}

const SETTINGS = {
  under_attack: false, default_mode: 'protect', real_ip_header: '', trusted_proxies: [],
  global_rate_rps: 60, global_rate_burst: 120, ban_seconds: 600,
  challenge_difficulty: 16, challenge_ttl: 1800, block_status: 403,
  max_body_scan: 65536, scan_body: true, log_allowed: false, log_retain_days: 7,
  flood_rps: 300, flood_error_rate: 30, flood_hold: 120,
  geo_mode: 'block', geo_countries: ['CN', 'RU'],
}

const COUNTRY_CODES = ['AD', 'AE', 'AR', 'AT', 'AU', 'BD', 'BE', 'BR', 'CA', 'CH', 'CL', 'CN', 'CZ', 'DE', 'DK', 'EG', 'ES', 'FI', 'FR', 'GB', 'HK', 'ID', 'IE', 'IL', 'IN', 'IR', 'IT', 'JP', 'KR', 'MY', 'NL', 'NO', 'NZ', 'PH', 'PL', 'PT', 'RO', 'RU', 'SE', 'SG', 'TH', 'TR', 'TW', 'UA', 'US', 'VN', 'ZA']

// The signed-in account. MOSWAF_MOCK_COUNTRY drives the language guess: a
// two-letter code, or "-" for an address the dataset cannot place - a tunnel or
// a private network, which is what most installations will actually look like.
function account(username = 'admin') {
  const c = (process.env.MOSWAF_MOCK_COUNTRY || 'VN').toUpperCase()
  const resolved = c !== '-'
  return {
    id: 1, username, created_at: new Date(now() - 30 * 864e5).toISOString(),
    country: resolved ? c : '', country_resolved: resolved,
  }
}

function body(req) {
  return new Promise((resolve) => {
    let raw = ''
    req.on('data', (c) => { raw += c })
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}) } catch { resolve({}) } })
  })
}

export function mockApi() {
  if (process.env.MOSWAF_MOCK !== '1') return { name: 'moswaf-mock-api-disabled' }

  const state = { settings: { ...SETTINGS }, ips: [...IPS], rules: RULES.map((r) => ({ ...r })), sites: SITES.map((s) => ({ ...s })) }

  return {
    name: 'moswaf-mock-api',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const url = new URL(req.url, 'http://localhost')
        if (!url.pathname.startsWith('/api/')) return next()

        const send = (data, status = 200) => {
          res.statusCode = status
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify(data))
        }
        const hours = Math.min(168, Math.max(1, Number(url.searchParams.get('hours')) || 24))
        const p = url.pathname

        if (p === '/api/auth/login') {
          const b = await body(req)
          if (!b.password) return send({ error: 'Sai tên đăng nhập hoặc mật khẩu' }, 401)
          return send({ token: 'mock-token', expires_at: new Date(now() + 864e5).toISOString(), user: account(b.username) })
        }
        if (p === '/api/auth/me') return send(account())
        if (p === '/api/health') return send({ status: 'ok' })

        if (p === '/api/settings' && req.method === 'PUT') {
          const b = await body(req)
          state.settings = { ...state.settings, ...b }
          if (state.settings.geo_mode === 'allow' && !state.settings.geo_countries.length) state.settings.geo_mode = 'off'
          return send(state.settings)
        }
        if (p === '/api/settings') return send(state.settings)
        if (p === '/api/settings/under-attack') {
          const b = await body(req)
          state.settings.under_attack = !!b.enabled
          return send({ under_attack: state.settings.under_attack })
        }

        if (p === '/api/stats/overview') {
          const pts = series(hours)
          const sum = (k) => pts.reduce((a, x) => a + x[k], 0)
          const requests = sum('total'), blocked = sum('blocked')
          const rate = (a, b2) => (b2 ? Math.round((a / b2) * 1000) / 10 : 0)
          return send({
            hours, requests, blocked, challenged: sum('challenged'), monitored: sum('monitored'),
            page_views: Math.round(requests * 0.42), visitors: Math.round(requests * 0.09), unique_ips: Math.round(requests * 0.06),
            errors_4xx: Math.round(requests * 0.19), blocked_4xx: blocked, errors_5xx: Math.round(requests * 0.004),
            blocked_rate: rate(blocked, requests), rate_4xx: rate(Math.round(requests * 0.19), requests), rate_5xx: rate(Math.round(requests * 0.004), requests),
            qps: Math.round((requests / (hours * 3600)) * 100) / 100,
            events: { deny: Math.round(blocked * 0.8), challenge: sum('challenged'), monitor: 143, log: 51 },
            top_attackers: ATTACKERS.map((ip, i) => ({ key: ip, label: ip, count: 3184 - i * 420 })),
            top_rules: RULES.slice(0, 6).map((r, i) => ({ key: r.id, label: r.name, count: 2890 - i * 380 })),
            top_countries: ['CN', 'RU', 'US', 'NL', 'VN', 'BR'].map((c, i) => ({ key: c, label: c, count: 2410 - i * 330 })),
            sites_total: state.sites.length, sites_active: state.sites.filter((s) => s.mode !== 'off').length,
            under_attack: state.settings.under_attack, config_version: 1737000000000,
          })
        }
        if (p === '/api/stats/timeseries') return send(series(hours))

        if (p === '/api/events') {
          const limit = Math.min(500, Number(url.searchParams.get('limit')) || 50)
          const offset = Number(url.searchParams.get('offset')) || 0
          let items = events(160, hours)
          const q = url.searchParams
          if (q.get('ip')) items = items.filter((e) => e.ip.includes(q.get('ip')))
          if (q.get('action')) items = items.filter((e) => e.action === q.get('action'))
          if (q.get('severity')) items = items.filter((e) => e.severity === q.get('severity'))
          if (q.get('q')) {
            const needle = q.get('q').toLowerCase()
            items = items.filter((e) => (e.uri + e.ua + e.rule_name).toLowerCase().includes(needle))
          }
          return send({ items: items.slice(offset, offset + limit), total: items.length, limit, offset })
        }

        if (p === '/api/sites') return send(state.sites)
        if (p.startsWith('/api/sites/') && p.endsWith('/users')) return send([{ id: 1, username: 'ketoan', created_at: new Date(now() - 12 * 864e5).toISOString() }])
        if (p.startsWith('/api/sites/')) return send(state.sites[0])

        if (p === '/api/rules') return send(state.rules)
        if (p.includes('/api/rules/')) return send({ ok: true })

        if (p === '/api/ips') {
          if (req.method === 'POST') { const b = await body(req); state.ips.push({ id: state.ips.length + 1, ...b, created_at: new Date().toISOString(), expires_at: b.minutes ? new Date(now() + b.minutes * 60000).toISOString() : null }); return send({ ok: true }) }
          const kind = url.searchParams.get('kind')
          return send(kind ? state.ips.filter((i) => i.kind === kind) : state.ips)
        }
        if (p.startsWith('/api/ips/')) { state.ips = state.ips.filter((i) => String(i.id) !== p.split('/').pop()); return send({ ok: true }) }

        if (p === '/api/bans') {
          return send({ items: [
            { ip: '45.83.122.9', reason: 'rate_rps', ttl: 463.8 },
            { ip: '185.220.101.44', reason: 'rate_burst', ttl: 128.2 },
            { ip: '2001:db8:ac10:fe01::9', reason: 'rate_rps', ttl: 41.5 },
          ], total: 3 })
        }
        if (p.startsWith('/api/bans/')) return send({ ok: true })

        if (p === '/api/geo/countries') {
          return send({
            ready: true,
            countries: COUNTRY_CODES.map((code, i) => ({ code, ranges: 12 + ((i * 977) % 41000) })),
            dataset: { ranges: 700123, month: '2026-09', loaded_at: new Date(now() - 36e5).toISOString(), last_error: '' },
          })
        }

        if (p === '/api/system/status') {
          return send({
            config_version: 1737000000000, database: 'ok', redis: 'ok',
            dataplane: { status: 'ok', version: 17 }, event_queue: 0,
            geoip: { ranges: 700123, month: '2026-09' },
          })
        }
        if (p === '/api/system/publish') return send({ status: 'published', version: 1737000000001 })

        return send({ error: 'mock: ' + p }, 404)
      })
    },
  }
}
