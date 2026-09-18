<script setup>
import { ref, computed, onMounted } from 'vue'
import { api, notify, fmtTime } from '../api'
import { t } from '../i18n'
import Segmented from '../components/Segmented.vue'
import Icon from '../components/Icon.vue'

const kind = ref('black')
const items = ref([])
const loading = ref(true)
const busy = ref(false)
const form = ref({ cidr: '', reason: '', minutes: 0 })

const bans = ref([])

const kinds = computed(() => [
  { value: 'black', label: t('ips.blocklist') },
  { value: 'white', label: t('ips.allowlist') },
  { value: 'ban',   label: t('ips.bans') },
])

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
    ? t('ips.ttl.minutes', { m, s: Math.floor(sec % 60) })
    : t('ips.ttl.seconds', { s: Math.floor(sec) })
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
  <div class="page-head">
    <div>
      <h2>{{ t('ips.title') }}</h2>
      <p class="page-sub">{{ t('ips.sub') }}</p>
    </div>
    <div class="page-actions">
      <Segmented :model-value="kind" :options="kinds" :aria-label="t('ips.title')" @update:model-value="switchKind" />
    </div>
  </div>

  <form v-if="kind !== 'ban'" class="filter-bar" @submit.prevent="add">
    <input v-model="form.cidr" class="input mono" style="width:220px" :placeholder="t('ips.cidrPlaceholder')" :aria-label="t('ips.col.address')" />
    <input v-model="form.reason" class="input grow" :placeholder="t('ips.reasonPlaceholder')" :aria-label="t('ips.col.reason')" />
    <input v-model="form.minutes" type="number" min="0" class="input mono" style="width:130px" :placeholder="t('ips.minutesPlaceholder')" :aria-label="t('ips.minutesPlaceholder')" />
    <button type="submit" class="btn btn-primary" :disabled="busy || !form.cidr.trim()"><Icon name="plus" />{{ kind === 'black' ? t('ips.addBlock') : t('ips.addAllow') }}</button>
    <span class="hint" style="margin:0; flex-basis:100%">{{ t('ips.minutesHint', { code: '0' }) }}</span>
  </form>

  <div v-else class="alert alert-info">
    <Icon name="info" />
    <div class="alert-body">{{ t('ips.bansNote') }} <router-link to="/ratelimit">{{ t('nav.ratelimit') }}</router-link></div>
  </div>

  <div class="card">
    <div v-if="kind === 'ban'" class="card-head">
      <div class="card-title">{{ t('ips.bans') }}</div>
      <button type="button" class="btn btn-sm btn-danger" :disabled="!bans.length" @click="unban('*')">{{ t('ips.liftAll') }}</button>
    </div>

    <div v-if="loading" class="skel-rows"><div v-for="i in 5" :key="i" class="skel skel-line"></div></div>

    <template v-else-if="kind === 'ban'">
      <div v-if="!bans.length" class="empty"><Icon name="shieldOk" /><b>{{ t('ips.noBans') }}</b></div>
      <div v-else class="table-wrap">
        <table class="table">
          <thead>
            <tr><th>{{ t('ips.col.ip') }}</th><th>{{ t('ips.col.reason') }}</th><th>{{ t('ips.col.timeLeft') }}</th><th></th></tr>
          </thead>
          <tbody>
            <tr v-for="b in bans" :key="b.ip">
              <td class="mono">{{ b.ip }}</td>
              <td><span class="tag tag-deny"><span class="dot"></span>{{ b.reason }}</span></td>
              <td class="sub">{{ fmtTTL(b.ttl) }}</td>
              <td class="actions">
                <button type="button" class="btn btn-sm" @click="unban(b.ip)">{{ t('ips.liftBan') }}</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <div v-else-if="!items.length" class="empty">
      <Icon :name="kind === 'black' ? 'ban' : 'check'" />
      <b>{{ t(kind === 'black' ? 'ips.emptyBlock' : 'ips.emptyAllow') }}</b>
      <span class="empty-hint">{{ t(kind === 'black' ? 'ips.emptyBlockHint' : 'ips.emptyAllowHint') }}</span>
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
            <td class="sub">{{ e.expires_at ? fmtTime(e.expires_at) : t('common.never') }}</td>
            <td class="sub">{{ fmtTime(e.created_at) }}</td>
            <td class="actions">
              <button type="button" class="btn btn-sm btn-danger" @click="remove(e)">{{ t('common.remove') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.skel-rows { display: flex; flex-direction: column; gap: 14px; padding: 8px 0; }
</style>
