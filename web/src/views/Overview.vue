<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, fmtNumber, notify } from '../api'
import TrafficChart from '../components/TrafficChart.vue'

const router = useRouter()
const hours = ref(6)
const overview = ref(null)
const series = ref([])
const status = ref(null)
const loading = ref(true)
let timer = null

const RANGES = [
  { h: 1, label: '1 gio' },
  { h: 6, label: '6 gio' },
  { h: 24, label: '24 gio' },
  { h: 72, label: '3 ngay' },
]

// Phut khong co du lieu nghia la khong co request nao -> dien 0 de duong
// bieu dien dung theo thoi gian thuc, khong bi co lai.
function densify(points, rangeHours) {
  const step = 60_000
  const end = Math.floor(Date.now() / step) * step
  const start = end - rangeHours * 3600_000
  const map = new Map()
  for (const p of points) {
    map.set(Math.floor(new Date(p.minute).getTime() / step) * step, p)
  }
  // Voi khoang dai, gop nhieu phut vao mot diem cho bieu do do nang
  const bucket = rangeHours > 24 ? 15 : rangeHours > 6 ? 5 : 1
  const out = []
  for (let t = start; t <= end; t += step * bucket) {
    let total = 0, blocked = 0, challenged = 0
    for (let k = 0; k < bucket; k++) {
      const p = map.get(t + k * step)
      if (p) {
        total += p.total
        blocked += p.blocked
        challenged += p.challenged
      }
    }
    out.push({ minute: t, total, blocked, challenged })
  }
  return out
}

const tiles = computed(() => {
  const o = overview.value
  if (!o) return []
  const blockRate = o.requests > 0 ? ((o.blocked / o.requests) * 100).toFixed(1) : '0.0'
  return [
    { label: 'Request da xu ly', value: fmtNumber(o.requests), sub: `trong ${o.hours} gio qua` },
    { label: 'Da chan', value: fmtNumber(o.blocked), sub: `${blockRate}% tong luu luong`, tone: 'serious' },
    { label: 'Buoc challenge', value: fmtNumber(o.challenged), sub: 'khach nghi van phai giai PoW', tone: 'good' },
    { label: 'Site dang bao ve', value: `${o.sites_active}/${o.sites_total}`, sub: 'so site bat che do loc' },
  ]
})

async function load(showSpinner = false) {
  if (showSpinner) loading.value = true
  try {
    const [o, ts, st] = await Promise.all([
      api.get(`/api/stats/overview?hours=${hours.value}`),
      api.get(`/api/stats/timeseries?hours=${hours.value}`),
      api.get('/api/system/status'),
    ])
    overview.value = o
    series.value = densify(ts, hours.value)
    status.value = st
  } catch (e) {
    notify(e.message, true)
  } finally {
    loading.value = false
  }
}

function setRange(h) {
  hours.value = h
  load(true)
}

onMounted(() => {
  load(true)
  timer = setInterval(() => load(false), 15000)
})
onUnmounted(() => clearInterval(timer))

const dataplaneOk = computed(() => {
  const d = status.value?.dataplane
  return d && typeof d === 'object' && d.status === 'ok'
})

// Thanh ngang so sanh do lon trong cung mot bang xep hang
function barWidth(b, list) {
  const max = Math.max(...list.map((x) => x.count), 1)
  return `${Math.max(3, (b.count / max) * 100)}%`
}
</script>

<template>
  <div v-if="overview?.under_attack" class="alert">
    Che do <b>dang bi tan cong</b> dang bat. Moi khach truy cap chua co cookie hop le
    deu phai giai JS challenge truoc khi vao site.
  </div>

  <div class="grid grid-4">
    <div v-for="t in tiles" :key="t.label" class="card tile">
      <div class="tile-label">{{ t.label }}</div>
      <div class="tile-value" :class="t.tone">{{ t.value }}</div>
      <div class="tile-sub">{{ t.sub }}</div>
    </div>
  </div>

  <div class="card" style="margin-top:16px">
    <div class="card-head">
      <div>
        <div class="card-title">Luu luong theo thoi gian</div>
        <div class="card-sub">Tong request, so bi chan va so phai giai challenge</div>
      </div>
      <div class="row">
        <button
          v-for="r in RANGES" :key="r.h"
          class="btn btn-sm"
          :style="hours === r.h ? 'border-color: var(--series-1); color: var(--text-primary)' : ''"
          @click="setRange(r.h)"
        >{{ r.label }}</button>
      </div>
    </div>
    <TrafficChart :points="series" :loading="loading" />
  </div>

  <div class="grid grid-2" style="margin-top:16px">
    <div class="card">
      <div class="card-head">
        <div class="card-title">IP tan cong nhieu nhat</div>
        <button class="btn btn-sm" @click="router.push('/ips')">Quan ly danh sach IP</button>
      </div>
      <div v-if="!overview?.top_attackers?.length" class="empty">Chua ghi nhan IP nao</div>
      <div v-else>
        <div v-for="b in overview.top_attackers" :key="b.key" class="bar-row">
          <span class="mono bar-label">{{ b.key }}</span>
          <span class="bar-track">
            <span class="bar-fill" :style="{ width: barWidth(b, overview.top_attackers) }"></span>
          </span>
          <span class="bar-val">{{ fmtNumber(b.count) }}</span>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="card-title">Luat khop nhieu nhat</div>
        <button class="btn btn-sm" @click="router.push('/rules')">Xem luat</button>
      </div>
      <div v-if="!overview?.top_rules?.length" class="empty">Chua co luat nao khop</div>
      <div v-else>
        <div v-for="b in overview.top_rules" :key="b.key" class="bar-row">
          <span class="bar-label">{{ b.label }}</span>
          <span class="bar-track">
            <span class="bar-fill" :style="{ width: barWidth(b, overview.top_rules) }"></span>
          </span>
          <span class="bar-val">{{ fmtNumber(b.count) }}</span>
        </div>
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:16px">
    <div class="card-head">
      <div class="card-title">Trang thai he thong</div>
      <div class="card-sub">Phien ban cau hinh: {{ status?.config_version ?? '-' }}</div>
    </div>
    <div class="row" style="gap:26px">
      <span class="tag" :class="status?.database === 'ok' ? 'tag-ok' : 'tag-deny'">
        <span class="dot"></span>Postgres
      </span>
      <span class="tag" :class="status?.redis === 'ok' ? 'tag-ok' : 'tag-deny'">
        <span class="dot"></span>Redis
      </span>
      <span class="tag" :class="dataplaneOk ? 'tag-ok' : 'tag-deny'">
        <span class="dot"></span>Data plane (OpenResty)
      </span>
      <span class="card-sub">Hang doi su kien: {{ fmtNumber(status?.event_queue ?? 0) }}</span>
    </div>
  </div>
</template>

<style scoped>
.alert {
  background: #2a1616; border: 1px solid #5a2a2a; color: #f3b9b9;
  padding: 11px 15px; border-radius: 10px; font-size: 13px; margin-bottom: 16px;
}
.tile-label { font-size: 12px; color: var(--text-secondary); }
.tile-value {
  font-size: 28px; font-weight: 600; margin: 6px 0 2px;
  font-variant-numeric: tabular-nums; letter-spacing: -.02em;
}
.tile-value.serious { color: var(--serious); }
.tile-value.good { color: var(--good); }
.tile-sub { font-size: 11.5px; color: var(--text-muted); }

.bar-row { display: flex; align-items: center; gap: 12px; padding: 6px 0; font-size: 12.5px; }
.bar-label { width: 150px; flex: 0 0 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-secondary); }
.bar-track { flex: 1; height: 8px; background: var(--surface-2); border-radius: 4px; overflow: hidden; }
.bar-fill { display: block; height: 100%; background: var(--series-1); border-radius: 4px; }
.bar-val { width: 62px; text-align: right; font-variant-numeric: tabular-nums; color: var(--text-secondary); }
</style>
