<script setup>
import { ref, onMounted } from 'vue'
import { api, notify, fmtTime } from '../api'
import { t } from '../i18n'

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
    notify(ip === '*' ? t('ips.allLifted') : t('ips.lifted', { ip }))
    await load()
  } catch (e) {
    notify(e.message, true)
  }
}

function fmtTTL(sec) {
  if (sec <= 0) return t('ips.ttl.expiring')
  const m = Math.floor(sec / 60)
  return m > 0
    ? t('ips.ttl.minutes', { m, s: sec % 60 })
    : t('ips.ttl.seconds', { s: sec })
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
    notify(t(kind.value === 'black' ? 'ips.addedBlock' : 'ips.addedAllow'))
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
    notify(t('ips.removed'))
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
        <div class="card-title">{{ t('ips.title') }}</div>
        <div class="card-sub">{{ t('ips.sub') }}</div>
      </div>
      <div class="row">
        <button class="btn btn-sm" :style="kind === 'black' ? 'border-color: var(--series-1)' : ''" @click="switchKind('black')">
          {{ t('ips.blocklist') }}
        </button>
        <button class="btn btn-sm" :style="kind === 'white' ? 'border-color: var(--series-1)' : ''" @click="switchKind('white')">
          {{ t('ips.allowlist') }}
        </button>
        <button class="btn btn-sm" :style="kind === 'ban' ? 'border-color: var(--series-1)' : ''" @click="switchKind('ban')">
          {{ t('ips.bans') }}
        </button>
      </div>
    </div>

    <div v-if="kind !== 'ban'" class="row" style="margin-bottom:16px">
      <input v-model="form.cidr" class="input mono" style="width:220px" :placeholder="t('ips.cidrPlaceholder')" @keyup.enter="add" />
      <input v-model="form.reason" class="input grow" :placeholder="t('ips.reasonPlaceholder')" @keyup.enter="add" />
      <input v-model="form.minutes" type="number" class="input mono" style="width:150px" :placeholder="t('ips.minutesPlaceholder')" />
      <button class="btn btn-primary" :disabled="busy" @click="add">{{ t('common.add') }}</button>
    </div>
    <div v-if="kind !== 'ban'" class="hint" style="margin:-10px 0 16px">
      {{ t('ips.minutesHint', { code: '0' }) }}
    </div>

    <div v-else class="row" style="margin-bottom:16px">
      <span class="card-sub grow">{{ t('ips.bansNote') }}</span>
      <button class="btn btn-danger" :disabled="!bans.length" @click="unban('*')">{{ t('ips.liftAll') }}</button>
    </div>

    <div v-if="loading" class="empty">{{ t('common.loading') }}</div>

    <template v-else-if="kind === 'ban'">
      <div v-if="!bans.length" class="empty">{{ t('ips.noBans') }}</div>
      <div v-else class="table-wrap">
        <table class="table">
          <thead>
            <tr><th>{{ t('ips.col.ip') }}</th><th>{{ t('ips.col.reason') }}</th><th>{{ t('ips.col.timeLeft') }}</th><th></th></tr>
          </thead>
          <tbody>
            <tr v-for="b in bans" :key="b.ip">
              <td class="mono">{{ b.ip }}</td>
              <td><span class="tag tag-deny"><span class="dot"></span>{{ b.reason }}</span></td>
              <td class="card-sub">{{ fmtTTL(b.ttl) }}</td>
              <td style="text-align:right">
                <button class="btn btn-sm" @click="unban(b.ip)">{{ t('ips.liftBan') }}</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <div v-else-if="!items.length" class="empty">
      {{ t(kind === 'black' ? 'ips.emptyBlock' : 'ips.emptyAllow') }}
    </div>

    <div v-else class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>{{ t('ips.col.address') }}</th>
            <th>{{ t('ips.col.reason') }}</th>
            <th>{{ t('ips.col.expires') }}</th>
            <th>{{ t('ips.col.added') }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in items" :key="e.id">
            <td class="mono">{{ e.cidr }}</td>
            <td>{{ e.reason || '-' }}</td>
            <td class="card-sub">{{ e.expires_at ? fmtTime(e.expires_at) : t('common.never') }}</td>
            <td class="card-sub">{{ fmtTime(e.created_at) }}</td>
            <td style="text-align:right">
              <button class="btn btn-sm btn-danger" @click="remove(e)">{{ t('common.remove') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
