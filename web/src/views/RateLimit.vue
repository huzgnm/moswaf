<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { api, notify, fmtNumber } from '../api'
import { t } from '../i18n'
import Modal from '../components/Modal.vue'
import Icon from '../components/Icon.vue'

// Rate limiting, the way an operator thinks about it: three rules, each a
// switch and one sentence saying what it does with the current numbers, and
// underneath the addresses those rules are holding back right now.
//
// The numbers live in /api/settings (same fields as before, nothing new); the
// live list is /api/bans, which the control plane proxies from the data plane's
// shared memory. A rule is "off" when its threshold is 0 - that is what the
// engine checks (ratelimit.lua: `rps > 0`, flood.lua: `flood_rps ... or 0`).

const settings = ref(null)
const bans = ref([])

// What the ban list said about itself. The data plane will not walk the whole
// dict to count - doing so holds the same lock every request needs to ask "am I
// banned", and the only time the number is large enough to care about is a
// flood, which is the worst possible moment to slow that question down. So it
// answers "is there more" for the price of one extra key, and leaves the exact
// total out rather than filling in a figure that would read as an answer.
const bansTruncated = ref(false)
const bansTotal = ref(null)

// What is actually enforcing each ban, and whether the thing that would know is
// running. Absent on a control plane without the kernel agent, which is most of
// them - see kernelAgent below.
const kernelAgent = ref(null)
const kernelOrphans = ref([])
const unbanError = ref(null)   // { ip, message } from a refusal, kept on screen
let refreshTimer = null
const loading = ref(true)
const busy = ref(false)
const editing = ref('')     // 'access' | 'flood' | 'error'
const form = ref({})
let timer = null

// Values to restore when a rule is switched back on after being zeroed
const DEFAULTS = { global_rate_rps: 60, global_rate_burst: 120, flood_rps: 300, flood_error_rate: 30 }
const remembered = {}

async function load(first = false) {
  if (first) loading.value = true
  try {
    // Never ask for limit=0 here, however tempting it looks next to the "showing
    // the first 1,000" notice below. That path makes the data plane walk every
    // key in the ban dict while holding the lock every request needs to ask
    // whether it is banned - so opening this page would slow down the thing the
    // page is here to watch, and hardest exactly when the list is long enough to
    // want it, which is during a flood. The uncapped read belongs to the host
    // agent: a different process, once a minute, and it genuinely needs all of
    // them.
    const [st, b] = await Promise.all([api.get('/api/settings'), api.get('/api/bans')])
    settings.value = st
    bans.value = b.items || []
    bansTruncated.value = !!b.truncated
    // present:false means "not installed", which is the ordinary case, not a
    // fault. Everything kernel-shaped hides itself rather than reporting a
    // machine as unprotected when nobody asked it to be.
    kernelAgent.value = b.kernel_agent?.present ? b.kernel_agent : null
    kernelOrphans.value = b.kernel_orphans || []
    // Absent on a control plane older than this field, and absent by design
    // when the list was cut - either way there is no total to show.
    bansTotal.value = typeof b.total === 'number' ? b.total : null
  } catch (e) {
    notify(e.message, true)
  } finally {
    loading.value = false
  }
}

async function save(patch) {
  busy.value = true
  try {
    settings.value = await api.put('/api/settings', { ...settings.value, ...patch })
    notify(t('settings.saved'))
    editing.value = ''
  } catch (e) {
    notify(e.message, true)
  } finally {
    busy.value = false
  }
}

const accessOn = computed(() => settings.value && settings.value.global_rate_rps > 0)
const floodOn = computed(() => settings.value && settings.value.flood_rps > 0)
const errorOn = computed(() => settings.value && settings.value.flood_error_rate > 0)

function toggleAccess(on) {
  if (!on) {
    remembered.global_rate_rps = settings.value.global_rate_rps
    remembered.global_rate_burst = settings.value.global_rate_burst
    return save({ global_rate_rps: 0, global_rate_burst: 0 })
  }
  return save({
    global_rate_rps: remembered.global_rate_rps || DEFAULTS.global_rate_rps,
    global_rate_burst: remembered.global_rate_burst || DEFAULTS.global_rate_burst,
  })
}
function toggleFlood(on) {
  if (!on) { remembered.flood_rps = settings.value.flood_rps; return save({ flood_rps: 0 }) }
  return save({ flood_rps: remembered.flood_rps || DEFAULTS.flood_rps })
}
function toggleError(on) {
  if (!on) { remembered.flood_error_rate = settings.value.flood_error_rate; return save({ flood_error_rate: 0 }) }
  return save({ flood_error_rate: remembered.flood_error_rate || DEFAULTS.flood_error_rate })
}

function openEdit(which) {
  const s = settings.value
  editing.value = which
  form.value = which === 'access'
    ? { global_rate_rps: s.global_rate_rps || DEFAULTS.global_rate_rps, global_rate_burst: s.global_rate_burst || DEFAULTS.global_rate_burst, ban_seconds: s.ban_seconds }
    : which === 'flood'
      ? { flood_rps: s.flood_rps || DEFAULTS.flood_rps, flood_hold: s.flood_hold }
      : { flood_error_rate: s.flood_error_rate || DEFAULTS.flood_error_rate, flood_hold: s.flood_hold }
}

function submitEdit() {
  const f = form.value
  const patch = {}
  for (const k of Object.keys(f)) patch[k] = Number(f[k]) || 0
  return save(patch)
}

// The sentence for each rule, built from the live numbers
const accessSentence = computed(() => {
  const s = settings.value
  if (!s) return ''
  return accessOn.value
    ? t('ratelimit.access.on', { rps: s.global_rate_rps, burst: s.global_rate_burst, ban: fmtNumber(s.ban_seconds) })
    : t('ratelimit.access.off')
})
const floodSentence = computed(() => {
  const s = settings.value
  if (!s) return ''
  return floodOn.value ? t('ratelimit.flood.on', { rps: fmtNumber(s.flood_rps), hold: fmtNumber(s.flood_hold) }) : t('ratelimit.flood.off')
})
const errorSentence = computed(() => {
  const s = settings.value
  if (!s) return ''
  return errorOn.value ? t('ratelimit.error.on', { percent: s.flood_error_rate, hold: fmtNumber(s.flood_hold) }) : t('ratelimit.error.off')
})

// ---------------------------------------------------------------- bans

async function unban(ip) {
  unbanError.value = null
  try {
    const res = await api.del(`/api/bans/${encodeURIComponent(ip)}`)
    notify(ip === '*' ? t('ips.allLifted') : t('ips.lifted', { ip }))
    await load()
    // "queued" is the kernel release being handed to the agent, not the agent
    // having done it. The row is correct now and will be correct again shortly;
    // one late refresh is what makes the two agree without claiming the second
    // state before it exists.
    if (res?.kernel_release === 'queued') {
      clearTimeout(refreshTimer)
      refreshTimer = setTimeout(() => load(), 2500)
    }
  } catch (e) {
    // A refusal is not half a release. The ban is intact, the address is still
    // being dropped, and the row stays exactly where it was - no optimistic
    // removal, nothing struck through, nothing that reads as "done, with a
    // warning". still_blocked is the server saying so in as many words.
    if (e.code === 'kernel_unban_failed') {
      unbanError.value = { ip: e.ip || ip, message: e.error || e.message }
      return
    }
    notify(e.message, true)
  }
}

function fmtTTL(sec) {
  if (sec <= 0) return t('ips.ttl.expiring')
  const m = Math.floor(sec / 60)
  return m > 0 ? t('ips.ttl.minutes', { m, s: Math.floor(sec % 60) }) : t('ips.ttl.seconds', { s: Math.floor(sec) })
}

// A ban with no enforcement field is one this control plane does not describe -
// an older build, or the uncapped read the agent uses. Unknown and absent are
// treated alike: say nothing rather than guess, which is also what an unknown
// future value gets.
const KNOWN_ENFORCEMENT = ['lua', 'kernel_pending', 'kernel', 'kernel_refused']

function enforcementOf(b) {
  return KNOWN_ENFORCEMENT.includes(b.enforcement) ? b.enforcement : 'lua'
}

// stuck is its own field and only means anything while a request is pending;
// the server reports false for every other state, and this does not read it as
// a fifth kind of enforcement.
function isStuck(b) {
  return b.stuck === true && enforcementOf(b) === 'kernel_pending'
}

function enforcementTone(b) {
  if (isStuck(b)) return 'tag-monitor'
  switch (enforcementOf(b)) {
    case 'kernel': return 'tag-ok'
    case 'kernel_pending': return 'tag-off'
    // Deliberately not a warning colour. A refusal is almost always the agent
    // declining to drop an administrator's own address at the kernel, which is
    // it doing its job; painting it red sends somebody hunting a bug that is a
    // feature.
    case 'kernel_refused': return 'tag-verify'
    default: return 'tag-off'
  }
}

function enforcementLabel(b) {
  if (isStuck(b)) return t('kban.stuck')
  return t(`kban.${enforcementOf(b)}`)
}

// The detail under the badge: how long it has been in this state, or why it was
// refused. Nothing for a plain Lua ban, which is the majority and needs no note.
function enforcementNote(b) {
  const e = enforcementOf(b)
  if (e === 'kernel_refused') return b.refused_reason || ''
  if (!b.enforcement_since) return ''
  const secs = Math.max(0, Math.floor(Date.now() / 1000 - b.enforcement_since))
  return e === 'kernel'
    ? t('kban.sinceKernel', { d: fmtDuration(secs) })
    : t('kban.sincePending', { d: fmtDuration(secs) })
}

function fmtDuration(sec) {
  if (sec < 60) return t('kban.secs', { s: sec })
  const m = Math.floor(sec / 60)
  return m < 60 ? t('kban.mins', { m }) : t('kban.hours', { h: Math.floor(m / 60) })
}

function reasonLabel(reason) {
  const key = `ratelimit.reason.${reason}`
  const label = t(key)
  return label === key ? reason : label
}

onMounted(() => {
  load(true)
  timer = setInterval(() => load(false), 10000)
})
onUnmounted(() => { clearInterval(timer); clearTimeout(refreshTimer) })
</script>

<template>
  <div class="page-head">
    <div>
      <h2>{{ t('ratelimit.title') }}</h2>
      <p class="page-sub">{{ t('ratelimit.sub') }}</p>
    </div>
  </div>

  <div class="grid grid-3 rules">
    <!-- per-IP -->
    <div class="card rule-card" :class="{ on: accessOn }">
      <div class="rule-head">
        <div class="rule-title"><Icon name="clock" />{{ t('ratelimit.access.title') }}</div>
        <label class="switch" :class="{ 'is-disabled': !settings || busy }">
          <input type="checkbox" :checked="accessOn" :disabled="!settings || busy" @change="toggleAccess($event.target.checked)" />
          <span class="track"></span>
          <span class="sr-only">{{ t('ratelimit.access.title') }}</span>
        </label>
      </div>
      <p class="rule-text" :class="{ skel: loading }">{{ accessSentence }}</p>
      <div class="rule-foot">
        <span class="tag" :class="accessOn ? 'tag-ok' : 'tag-off'"><span class="dot"></span>{{ accessOn ? t('ratelimit.enabled') : t('ratelimit.disabled') }}</span>
        <button type="button" class="btn btn-sm" :disabled="!settings" @click="openEdit('access')"><Icon name="edit" />{{ t('common.edit') }}</button>
      </div>
    </div>

    <!-- flood -->
    <div class="card rule-card" :class="{ on: floodOn }">
      <div class="rule-head">
        <div class="rule-title"><Icon name="zap" />{{ t('ratelimit.flood.title') }}</div>
        <label class="switch" :class="{ 'is-disabled': !settings || busy }">
          <input type="checkbox" :checked="floodOn" :disabled="!settings || busy" @change="toggleFlood($event.target.checked)" />
          <span class="track"></span>
          <span class="sr-only">{{ t('ratelimit.flood.title') }}</span>
        </label>
      </div>
      <p class="rule-text" :class="{ skel: loading }">{{ floodSentence }}</p>
      <div class="rule-foot">
        <span class="tag" :class="floodOn ? 'tag-ok' : 'tag-off'"><span class="dot"></span>{{ floodOn ? t('ratelimit.enabled') : t('ratelimit.disabled') }}</span>
        <button type="button" class="btn btn-sm" :disabled="!settings" @click="openEdit('flood')"><Icon name="edit" />{{ t('common.edit') }}</button>
      </div>
    </div>

    <!-- origin errors -->
    <div class="card rule-card" :class="{ on: errorOn }">
      <div class="rule-head">
        <div class="rule-title"><Icon name="alert" />{{ t('ratelimit.error.title') }}</div>
        <label class="switch" :class="{ 'is-disabled': !settings || busy }">
          <input type="checkbox" :checked="errorOn" :disabled="!settings || busy" @change="toggleError($event.target.checked)" />
          <span class="track"></span>
          <span class="sr-only">{{ t('ratelimit.error.title') }}</span>
        </label>
      </div>
      <p class="rule-text" :class="{ skel: loading }">{{ errorSentence }}</p>
      <div class="rule-foot">
        <span class="tag" :class="errorOn ? 'tag-ok' : 'tag-off'"><span class="dot"></span>{{ errorOn ? t('ratelimit.enabled') : t('ratelimit.disabled') }}</span>
        <button type="button" class="btn btn-sm" :disabled="!settings" @click="openEdit('error')"><Icon name="edit" />{{ t('common.edit') }}</button>
      </div>
    </div>
  </div>

  <div class="alert alert-info">
    <Icon name="info" />
    <div class="alert-body">{{ t('ratelimit.perSiteNote') }} <router-link to="/sites">{{ t('nav.sites') }}</router-link></div>
  </div>

  <!-- currently limited -->
  <div class="card">
    <div class="card-head">
      <div>
        <div class="card-title">{{ t('ratelimit.bans.title') }}</div>
        <div class="card-sub">{{ t('ratelimit.bans.sub') }}</div>
      </div>
      <button type="button" class="btn btn-sm btn-danger" :disabled="!bans.length" @click="unban('*')">{{ t('ips.liftAll') }}</button>
    </div>

    <!-- Addresses the kernel is still dropping with no ban behind them. Normally
         this list does not exist. When it does, the people on it cannot reach
         the site and appear in no table, so it gets a band of its own rather
         than a column nobody would look at. -->
    <div v-if="kernelOrphans.length" class="alert alert-warn" style="margin-bottom:14px">
      <Icon name="alert" />
      <div class="alert-body">
        <b>{{ t('kban.orphans', { n: kernelOrphans.length }) }}</b> {{ t('kban.orphansHint') }}
        <div class="mono orphan-list">{{ kernelOrphans.join(', ') }}</div>
      </div>
    </div>

    <!-- The agent's own state. Only ever rendered when there is an agent: on a
         machine without one this whole feature is silent, because "not
         installed" is the ordinary case and a warning would report every
         normal installation as broken. -->
    <div v-if="kernelAgent?.failing" class="alert alert-warn" style="margin-bottom:14px">
      <Icon name="alert" />
      <div class="alert-body"><b>{{ t('kban.failing') }}</b> {{ t('kban.failingHint') }}</div>
    </div>
    <div v-else-if="kernelAgent?.stale" class="alert alert-warn" style="margin-bottom:14px">
      <Icon name="clock" />
      <div class="alert-body"><b>{{ t('kban.stale') }}</b> {{ t('kban.staleHint', { every: kernelAgent.resync_every }) }}</div>
    </div>

    <div v-if="unbanError" class="alert alert-critical" style="margin-bottom:14px">
      <Icon name="alert" />
      <div class="alert-body">
        <b>{{ t('kban.unbanFailed', { ip: unbanError.ip }) }}</b> {{ t('kban.unbanFailedHint') }}
        <div class="dim" style="margin-top:4px">{{ unbanError.message }}</div>
      </div>
    </div>

    <div v-if="loading" class="skel-list"><div v-for="i in 3" :key="i" class="skel skel-line"></div></div>
    <div v-else-if="!bans.length" class="empty">
      <Icon name="shieldOk" />
      <b>{{ t('ips.noBans') }}</b>
      <span class="empty-hint">{{ t('ratelimit.bans.emptyHint') }}</span>
    </div>
    <div v-else class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>{{ t('ips.col.ip') }}</th>
            <th>{{ t('ips.col.reason') }}</th>
            <th>{{ t('ratelimit.bans.action') }}</th>
            <th v-if="kernelAgent">{{ t('kban.col') }}</th>
            <th>{{ t('ips.col.timeLeft') }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in bans" :key="b.ip">
            <td class="mono">{{ b.ip }}</td>
            <td><span class="tag tag-deny"><span class="dot"></span>{{ reasonLabel(b.reason) }}</span></td>
            <td class="sub">{{ t('ratelimit.bans.blockedFor', { seconds: fmtNumber(settings?.ban_seconds ?? 0) }) }}</td>
            <td v-if="kernelAgent">
              <span class="tag" :class="enforcementTone(b)">
                <span class="dot"></span>{{ enforcementLabel(b) }}
              </span>
              <div v-if="enforcementNote(b)" class="dim enforce-note">{{ enforcementNote(b) }}</div>
            </td>
            <td class="sub nowrap">{{ fmtTTL(b.ttl) }}</td>
            <td class="actions">
              <button type="button" class="btn btn-sm" @click="unban(b.ip)">{{ t('ips.liftBan') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="kernelAgent && !loading" class="card-foot">
      <Icon name="server" style="width:14px;height:14px" />
      <span>{{ kernelAgent.applied === undefined || kernelAgent.applied === null
        ? t('kban.agentNoCount')
        : t('kban.agent', { n: fmtNumber(kernelAgent.applied), every: kernelAgent.resync_every }) }}</span>
    </div>

    <div v-if="!loading && bans.length" class="card-foot">
      <Icon v-if="bansTruncated" name="info" style="width:14px;height:14px" />
      <span>{{ bansTruncated
        ? t('ratelimit.bans.partial', { shown: fmtNumber(bans.length) })
        : t('ratelimit.bans.count', { n: fmtNumber(bansTotal ?? bans.length) }) }}</span>
    </div>
  </div>

  <Modal
    v-if="editing"
    narrow
    :title="t(`ratelimit.${editing}.title`)"
    :busy="busy"
    @close="editing = ''"
    @submit="submitEdit"
  >
    <template v-if="editing === 'access'">
      <div class="field">
        <label class="label">{{ t('settings.rps') }}</label>
        <input v-model="form.global_rate_rps" type="number" min="1" class="input mono" />
      </div>
      <div class="field">
        <label class="label">{{ t('settings.burst') }}</label>
        <input v-model="form.global_rate_burst" type="number" min="1" class="input mono" />
        <div class="hint">{{ t('settings.burstHint') }}</div>
      </div>
      <div class="field">
        <label class="label">{{ t('settings.banSeconds') }}</label>
        <input v-model="form.ban_seconds" type="number" min="10" class="input mono" />
        <div class="hint">{{ t('settings.banSecondsHint') }}</div>
      </div>
    </template>
    <template v-else-if="editing === 'flood'">
      <div class="field">
        <label class="label">{{ t('settings.floodRPS') }}</label>
        <input v-model="form.flood_rps" type="number" min="1" class="input mono" />
        <div class="hint">{{ t('settings.floodRPSHint') }}</div>
      </div>
      <div class="field">
        <label class="label">{{ t('settings.floodHold') }}</label>
        <input v-model="form.flood_hold" type="number" min="10" class="input mono" />
        <div class="hint">{{ t('settings.floodHoldHint') }}</div>
      </div>
    </template>
    <template v-else>
      <div class="field">
        <label class="label">{{ t('settings.floodErrorRate') }}</label>
        <input v-model="form.flood_error_rate" type="number" min="1" max="100" class="input mono" />
        <div class="hint">{{ t('settings.floodErrorRateHint') }}</div>
      </div>
      <div class="field">
        <label class="label">{{ t('settings.floodHold') }}</label>
        <input v-model="form.flood_hold" type="number" min="10" class="input mono" />
        <div class="hint">{{ t('settings.floodHoldHint') }}</div>
      </div>
    </template>
  </Modal>
</template>

<style scoped>
.rules { align-items: stretch; }
.rule-card { display: flex; flex-direction: column; gap: 12px; border-top: 2px solid var(--line-2); }
.rule-card.on { border-top-color: var(--ink); }
.rule-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.rule-title { display: inline-flex; align-items: center; gap: 9px; font-weight: 600; font-size: 14px; }
.rule-title .ico { width: 17px; height: 17px; color: var(--ink-3); }
.rule-card.on .rule-title .ico { color: var(--ink); }
.rule-text { margin: 0; color: var(--ink-2); font-size: 13px; line-height: 1.6; flex: 1; min-height: 42px; }
.rule-foot { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding-top: 12px; border-top: 1px solid var(--line); }
.skel-list { display: flex; flex-direction: column; gap: 12px; padding: 6px 0; }
.enforce-note { font-size: 11px; margin-top: 3px; }
.orphan-list { font-size: 11.5px; margin-top: 6px; word-break: break-all; }
</style>
