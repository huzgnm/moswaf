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

// Temporary bans are created by the engine when it detects a flood. They live
// in the data plane's shared memory, not the database - hence a separate path.
async function unban(ip) {
  try {
    await api.del(`/api/bans/${encodeURIComponent(ip)}`)
    notify(ip === '*' ? 'All temporary bans lifted' : `Ban lifted for ${ip}`)
    await load()
  } catch (e) {
    notify(e.message, true)
  }
}

function fmtTTL(sec) {
  if (sec <= 0) return 'expiring'
  const m = Math.floor(sec / 60)
  return m > 0 ? `${m}m ${sec % 60}s left` : `${sec}s left`
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
    notify(kind.value === 'black' ? 'Added to the blocklist' : 'Added to the allowlist')
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
    notify('Removed')
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
        <div class="card-title">IP lists</div>
        <div class="card-sub">
          The allowlist is checked first and skips every other filter.
          The blocklist rejects immediately, before any CPU is spent on rule scanning.
        </div>
      </div>
      <div class="row">
        <button class="btn btn-sm" :style="kind === 'black' ? 'border-color: var(--series-1)' : ''" @click="switchKind('black')">
          Blocklist
        </button>
        <button class="btn btn-sm" :style="kind === 'white' ? 'border-color: var(--series-1)' : ''" @click="switchKind('white')">
          Allowlist
        </button>
        <button class="btn btn-sm" :style="kind === 'ban' ? 'border-color: var(--series-1)' : ''" @click="switchKind('ban')">
          Temporary bans
        </button>
      </div>
    </div>

    <div v-if="kind !== 'ban'" class="row" style="margin-bottom:16px">
      <input v-model="form.cidr" class="input mono" style="width:220px" placeholder="1.2.3.4 or 10.0.0.0/8" @keyup.enter="add" />
      <input v-model="form.reason" class="input grow" placeholder="Reason (optional)" @keyup.enter="add" />
      <input v-model="form.minutes" type="number" class="input mono" style="width:150px" placeholder="Minutes" />
      <button class="btn btn-primary" :disabled="busy" @click="add">Add</button>
    </div>
    <div v-if="kind !== 'ban'" class="hint" style="margin:-10px 0 16px">
      Leave minutes at <code class="mono">0</code> for permanent. Enter a number to make the entry expire on its own.
    </div>

    <div v-else class="row" style="margin-bottom:16px">
      <span class="card-sub grow">
        These IPs were banned automatically by the engine after repeatedly crossing the
        threshold. They live in the data plane's memory and expire on their own; nothing is stored in the database.
      </span>
      <button class="btn btn-danger" :disabled="!bans.length" @click="unban('*')">Lift all</button>
    </div>

    <div v-if="loading" class="empty">Loading...</div>

    <template v-else-if="kind === 'ban'">
      <div v-if="!bans.length" class="empty">No IP is currently under a temporary ban</div>
      <table v-else class="table">
        <thead>
          <tr><th>IP address</th><th>Reason</th><th>Time left</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="b in bans" :key="b.ip">
            <td class="mono">{{ b.ip }}</td>
            <td><span class="tag tag-deny"><span class="dot"></span>{{ b.reason }}</span></td>
            <td class="card-sub">{{ fmtTTL(b.ttl) }}</td>
            <td style="text-align:right">
              <button class="btn btn-sm" @click="unban(b.ip)">Lift ban</button>
            </td>
          </tr>
        </tbody>
      </table>
    </template>

    <div v-else-if="!items.length" class="empty">
      {{ kind === 'black' ? 'The blocklist is empty' : 'The allowlist is empty' }}
    </div>

    <table v-else class="table">
      <thead>
        <tr>
          <th>Address</th>
          <th>Reason</th>
          <th>Expires</th>
          <th>Added</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="e in items" :key="e.id">
          <td class="mono">{{ e.cidr }}</td>
          <td>{{ e.reason || '-' }}</td>
          <td class="card-sub">{{ e.expires_at ? fmtTime(e.expires_at) : 'Never' }}</td>
          <td class="card-sub">{{ fmtTime(e.created_at) }}</td>
          <td style="text-align:right">
            <button class="btn btn-sm btn-danger" @click="remove(e)">Remove</button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
