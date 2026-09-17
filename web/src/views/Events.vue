<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { api, notify, fmtTime, fmtNumber, ACTION_LABELS } from '../api'

const items = ref([])
const total = ref(0)
const loading = ref(true)
const auto = ref(true)
const expanded = ref(null)
let timer = null

const filters = ref({ q: '', ip: '', action: '', severity: '', hours: 24 })
const page = ref(0)
const LIMIT = 50

async function load(spinner = false) {
  if (spinner) loading.value = true
  const params = new URLSearchParams({
    limit: String(LIMIT),
    offset: String(page.value * LIMIT),
    hours: String(filters.value.hours),
  })
  for (const k of ['q', 'ip', 'action', 'severity']) {
    if (filters.value[k]) params.set(k, filters.value[k])
  }
  try {
    const res = await api.get(`/api/events?${params}`)
    items.value = res.items || []
    total.value = res.total || 0
  } catch (e) {
    notify(e.message, true)
  } finally {
    loading.value = false
  }
}

function applyFilters() {
  page.value = 0
  load(true)
}

async function banIP(ip) {
  if (!confirm(`Chan vinh vien IP ${ip}?`)) return
  try {
    await api.post('/api/ips', { cidr: ip, kind: 'black', reason: 'Chan tu nhat ky tan cong' })
    notify(`Da them ${ip} vao danh sach den`)
  } catch (e) {
    notify(e.message, true)
  }
}

onMounted(() => {
  load(true)
  timer = setInterval(() => { if (auto.value && page.value === 0) load(false) }, 10000)
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="card">
    <div class="card-head">
      <div>
        <div class="card-title">Nhat ky tan cong</div>
        <div class="card-sub">
          Chi ghi nhung request bi chan, bi challenge hoac khop luat - khong ghi luu luong binh thuong
        </div>
      </div>
      <label class="switch">
        <input v-model="auto" type="checkbox" />
        <span class="track"></span>
        <span class="card-sub">Tu lam moi</span>
      </label>
    </div>

    <div class="row" style="margin-bottom:14px">
      <input v-model="filters.q" class="input grow" placeholder="Tim trong duong dan, User-Agent, ten luat" @keyup.enter="applyFilters" />
      <input v-model="filters.ip" class="input mono" style="width:150px" placeholder="IP" @keyup.enter="applyFilters" />
      <select v-model="filters.action" class="select" style="width:140px">
        <option value="">Moi hanh dong</option>
        <option value="deny">Chan</option>
        <option value="challenge">Challenge</option>
        <option value="monitor">Ghi nhan</option>
        <option value="log">Ghi log</option>
      </select>
      <select v-model="filters.severity" class="select" style="width:140px">
        <option value="">Moi muc do</option>
        <option value="critical">Nghiem trong</option>
        <option value="high">Cao</option>
        <option value="medium">Trung binh</option>
        <option value="low">Thap</option>
      </select>
      <select v-model="filters.hours" class="select" style="width:130px">
        <option :value="1">1 gio</option>
        <option :value="24">24 gio</option>
        <option :value="72">3 ngay</option>
        <option :value="168">7 ngay</option>
      </select>
      <button class="btn btn-primary" @click="applyFilters">Loc</button>
    </div>

    <div v-if="loading" class="empty">Dang tai...</div>
    <div v-else-if="!items.length" class="empty">Khong co su kien nao khop dieu kien loc</div>

    <table v-else class="table">
      <thead>
        <tr>
          <th style="width:150px">Thoi diem</th>
          <th style="width:130px">IP</th>
          <th style="width:110px">Hanh dong</th>
          <th>Yeu cau</th>
          <th>Luat / ly do</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <template v-for="e in items" :key="e.id">
          <tr @click="expanded = expanded === e.id ? null : e.id" style="cursor:pointer">
            <td class="card-sub">{{ fmtTime(e.ts) }}</td>
            <td class="mono">{{ e.ip }}</td>
            <td>
              <span class="tag" :class="`tag-${e.action}`">
                <span class="dot"></span>{{ ACTION_LABELS[e.action] || e.action }}
              </span>
            </td>
            <td class="mono truncate">{{ e.method }} {{ e.uri }}</td>
            <td class="truncate">{{ e.rule_name || e.reason }}</td>
            <td style="text-align:right">
              <button class="btn btn-sm btn-danger" @click.stop="banIP(e.ip)">Chan IP</button>
            </td>
          </tr>
          <tr v-if="expanded === e.id">
            <td colspan="6" style="background:var(--surface-2)">
              <div class="detail">
                <div><span>Ma su kien</span><b class="mono">{{ e.ray || '-' }}</b></div>
                <div><span>Ten mien</span><b class="mono">{{ e.host }}</b></div>
                <div><span>Duong dan day du</span><b class="mono">{{ e.uri }}</b></div>
                <div><span>User-Agent</span><b class="mono">{{ e.ua || '(trong)' }}</b></div>
                <div><span>Referer</span><b class="mono">{{ e.referer || '-' }}</b></div>
                <div><span>Ly do</span><b>{{ e.reason || '-' }}</b></div>
                <div><span>Ma luat</span><b class="mono">{{ e.rule_id || '-' }}</b></div>
                <div><span>Muc do</span><b>{{ e.severity || '-' }}</b></div>
                <div><span>Ma tra ve</span><b class="mono">{{ e.status }}</b></div>
              </div>
            </td>
          </tr>
        </template>
      </tbody>
    </table>

    <div class="row" style="margin-top:14px">
      <span class="card-sub">Tong cong {{ fmtNumber(total) }} su kien</span>
      <div class="spacer"></div>
      <button class="btn btn-sm" :disabled="page === 0" @click="page--; load(true)">Truoc</button>
      <span class="card-sub">Trang {{ page + 1 }}</span>
      <button class="btn btn-sm" :disabled="(page + 1) * 50 >= total" @click="page++; load(true)">Sau</button>
    </div>
  </div>
</template>

<style scoped>
.detail { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 24px; padding: 6px 0; }
.detail > div { display: flex; gap: 10px; font-size: 12.5px; min-width: 0; }
.detail span { color: var(--text-muted); width: 130px; flex: 0 0 130px; }
.detail b { font-weight: 500; word-break: break-all; }
</style>
