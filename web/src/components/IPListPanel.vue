<script setup>
import { ref, onMounted, watch } from 'vue'
import { api, notify, fmtTime } from '../api'
import { t } from '../i18n'
import Icon from './Icon.vue'

// One list of addresses - the blocklist or the allowlist, chosen by the tab
// above. Temporary bans are not here: the engine creates those from rate
// limiting, so they are shown on the page that sets the thresholds.
const props = defineProps({ kind: { type: String, required: true } })

const items = ref([])
const loading = ref(true)
const busy = ref(false)
const form = ref({ cidr: '', reason: '', minutes: 0 })

async function load() {
  loading.value = true
  try {
    items.value = await api.list(`/api/ips?kind=${props.kind}`)
  } catch (e) {
    notify(e.message, true)
  } finally {
    loading.value = false
  }
}

async function add() {
  if (!form.value.cidr.trim()) return
  busy.value = true
  try {
    await api.post('/api/ips', {
      cidr: form.value.cidr.trim(),
      kind: props.kind,
      reason: form.value.reason,
      minutes: Number(form.value.minutes) || 0,
    })
    notify(t(props.kind === 'black' ? 'ips.addedBlock' : 'ips.addedAllow'))
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
watch(() => props.kind, load)
</script>

<template>
  <form class="filter-bar" @submit.prevent="add">
    <input v-model="form.cidr" class="input mono" style="width:220px" :placeholder="t('ips.cidrPlaceholder')" :aria-label="t('ips.col.address')" />
    <input v-model="form.reason" class="input grow" :placeholder="t('ips.reasonPlaceholder')" :aria-label="t('ips.col.reason')" />
    <input v-model="form.minutes" type="number" min="0" class="input mono" style="width:130px" :placeholder="t('ips.minutesPlaceholder')" :aria-label="t('ips.minutesPlaceholder')" />
    <button type="submit" class="btn btn-primary" :disabled="busy || !form.cidr.trim()">
      <Icon name="plus" />{{ kind === 'black' ? t('ips.addBlock') : t('ips.addAllow') }}
    </button>
    <span class="hint" style="margin:0; flex-basis:100%">{{ t('ips.minutesHint', { code: '0' }) }}</span>
  </form>

  <div class="card">
    <div v-if="loading" class="skel-rows"><div v-for="i in 5" :key="i" class="skel skel-line"></div></div>

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
