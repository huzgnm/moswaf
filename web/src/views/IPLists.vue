<script setup>
import { ref, onMounted } from 'vue'
import { api, notify, fmtTime } from '../api'

const kind = ref('black')
const items = ref([])
const loading = ref(true)
const busy = ref(false)
const form = ref({ cidr: '', reason: '', minutes: 0 })

const bans = ref([])

async function load() {
  loading.value = true
  try {
    if (kind.value === 'ban') {
      const res = await api.get('/api/bans')
      bans.value = res.items || []
    } else {
      items.value = await api.list(`/api/ips?kind=${kind.value}`)
    }
  } catch (e) {
    notify(e.message, true)
  } finally {
    loading.value = false
  }
}

// Ban tam thoi do engine tu sinh khi phat hien flood, nam trong bo nho
// data plane chu khong phai DB - nen go ban di qua duong rieng.
async function unban(ip) {
  try {
    await api.del(`/api/bans/${encodeURIComponent(ip)}`)
    notify(ip === '*' ? 'Da go toan bo ban tam thoi' : `Da go ban cho ${ip}`)
    await load()
  } catch (e) {
    notify(e.message, true)
  }
}

function fmtTTL(sec) {
  if (sec <= 0) return 'sap het'
  const m = Math.floor(sec / 60)
  return m > 0 ? `con ${m} phut ${sec % 60} giay` : `con ${sec} giay`
}

function switchKind(k) {
  kind.value = k
  load()
}

async function add() {
  if (!form.value.cidr.trim()) return
  busy.value = true
  try {
    await api.post('/api/ips', {
      cidr: form.value.cidr.trim(),
      kind: kind.value,
      reason: form.value.reason,
      minutes: Number(form.value.minutes) || 0,
    })
    notify(kind.value === 'black' ? 'Da them vao danh sach den' : 'Da them vao danh sach trang')
    form.value = { cidr: '', reason: '', minutes: 0 }
    await load()
  } catch (e) {
    notify(e.message, true)
  } finally {
    busy.value = false
  }
}

async function remove(entry) {
  try {
    await api.del(`/api/ips/${entry.id}`)
    notify('Da xoa')
    await load()
  } catch (e) {
    notify(e.message, true)
  }
}

onMounted(load)
</script>

<template>
  <div class="card">
    <div class="card-head">
      <div>
        <div class="card-title">Danh sach IP</div>
        <div class="card-sub">
          Danh sach trang duoc kiem tra truoc va bo qua moi buoc loc.
          Danh sach den chan thang truoc khi ton CPU quet luat.
        </div>
      </div>
      <div class="row">
        <button class="btn btn-sm" :style="kind === 'black' ? 'border-color: var(--series-1)' : ''" @click="switchKind('black')">
          Danh sach den
        </button>
        <button class="btn btn-sm" :style="kind === 'white' ? 'border-color: var(--series-1)' : ''" @click="switchKind('white')">
          Danh sach trang
        </button>
        <button class="btn btn-sm" :style="kind === 'ban' ? 'border-color: var(--series-1)' : ''" @click="switchKind('ban')">
          Dang bi ban tam
        </button>
      </div>
    </div>

    <div v-if="kind !== 'ban'" class="row" style="margin-bottom:16px">
      <input v-model="form.cidr" class="input mono" style="width:220px" placeholder="1.2.3.4 hoac 10.0.0.0/8" @keyup.enter="add" />
      <input v-model="form.reason" class="input grow" placeholder="Ly do (tuy chon)" @keyup.enter="add" />
      <input v-model="form.minutes" type="number" class="input mono" style="width:150px" placeholder="Phut" />
      <button class="btn btn-primary" :disabled="busy" @click="add">Them</button>
    </div>
    <div v-if="kind !== 'ban'" class="hint" style="margin:-10px 0 16px">
      De o phut la <code class="mono">0</code> nghia la vinh vien. Nhap so phut de dong nay tu het han.
    </div>

    <div v-else class="row" style="margin-bottom:16px">
      <span class="card-sub grow">
        Day la cac IP bi engine tu dong ban sau khi vuot nguong nhieu lan.
        Chung nam trong bo nho cua data plane va tu het han, khong luu vao database.
      </span>
      <button class="btn btn-danger" :disabled="!bans.length" @click="unban('*')">Go tat ca</button>
    </div>

    <div v-if="loading" class="empty">Dang tai...</div>

    <template v-else-if="kind === 'ban'">
      <div v-if="!bans.length" class="empty">Khong co IP nao dang bi ban tam thoi</div>
      <table v-else class="table">
        <thead>
          <tr><th>Dia chi IP</th><th>Ly do</th><th>Thoi gian con lai</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="b in bans" :key="b.ip">
            <td class="mono">{{ b.ip }}</td>
            <td><span class="tag tag-deny"><span class="dot"></span>{{ b.reason }}</span></td>
            <td class="card-sub">{{ fmtTTL(b.ttl) }}</td>
            <td style="text-align:right">
              <button class="btn btn-sm" @click="unban(b.ip)">Go ban</button>
            </td>
          </tr>
        </tbody>
      </table>
    </template>

    <div v-else-if="!items.length" class="empty">
      {{ kind === 'black' ? 'Danh sach den dang trong' : 'Danh sach trang dang trong' }}
    </div>

    <table v-else class="table">
      <thead>
        <tr>
          <th>Dia chi</th>
          <th>Ly do</th>
          <th>Het han</th>
          <th>Them luc</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="e in items" :key="e.id">
          <td class="mono">{{ e.cidr }}</td>
          <td>{{ e.reason || '-' }}</td>
          <td class="card-sub">{{ e.expires_at ? fmtTime(e.expires_at) : 'Vinh vien' }}</td>
          <td class="card-sub">{{ fmtTime(e.created_at) }}</td>
          <td style="text-align:right">
            <button class="btn btn-sm btn-danger" @click="remove(e)">Xoa</button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
