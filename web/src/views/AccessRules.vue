<script setup>
import { ref, computed, onMounted } from 'vue'
import { api, notify, fmtNumber, fmtShortTime } from '../api'
import { t } from '../i18n'
import Modal from '../components/Modal.vue'
import Icon from '../components/Icon.vue'

// The operator's own ordered allow and deny rules. First match wins, so the
// order is the policy - which is why the list is ordered by hand, why a rule
// shows how often it actually fired, and why the panel on the right exists.

const rules = ref([])
const sites = ref([])
const loading = ref(true)
const busy = ref(false)
const siteFilter = ref('')

// Limits the control plane enforces. Shown before they are reached rather than
// reported as a 400 after the form is full.
const MAX_RULES = 200
const MAX_CONDITIONS = 10
const MAX_VALUES = 50
const MAX_VALUE_LEN = 256

// Field -> the operators it accepts. Taken from the control plane's own table;
// if these disagree, this is the copy that is wrong.
const FIELDS = {
  ip:      { ops: ['in_cidr'], allow: true },
  crawler: { ops: ['is'], allow: true, boolean: true },
  country: { ops: ['in'] },
  path:    { ops: ['prefix', 'equals', 'contains'] },
  host:    { ops: ['equals', 'suffix'] },
  ua:      { ops: ['contains', 'equals'] },
  method:  { ops: ['in'] },
}
const ACTIONS = ['deny', 'challenge', 'log', 'allow']

async function load() {
  loading.value = true
  try {
    const q = siteFilter.value ? `?site=${encodeURIComponent(siteFilter.value)}` : ''
    rules.value = await api.list(`/api/access-rules${q}`)
  } catch (e) {
    notify(e.message, true)
  } finally {
    loading.value = false
  }
}

async function loadSites() {
  try { sites.value = await api.list('/api/sites') } catch (e) { sites.value = [] }
}

function siteName(id) {
  if (!id) return t('access.allSites')
  return sites.value.find((s) => s.id === id)?.name || id
}

// ---------------------------------------------------------------- order

// The whole list goes back, in the new order, because that is what the endpoint
// takes: a policy half-reordered is a policy nobody has ever reviewed.
async function move(index, delta) {
  const next = index + delta
  if (next < 0 || next >= rules.value.length) return
  const reordered = [...rules.value]
  const [row] = reordered.splice(index, 1)
  reordered.splice(next, 0, row)
  const before = rules.value
  rules.value = reordered            // move it on screen first; it is one frame
  busy.value = true
  try {
    await api.post('/api/access-rules/reorder', { ids: reordered.map((r) => r.id) })
    await load()
  } catch (e) {
    rules.value = before             // put it back rather than leave a lie on screen
    notify(e.message, true)
  } finally {
    busy.value = false
  }
}

async function toggle(rule) {
  const next = !rule.enabled
  try {
    await api.put(`/api/access-rules/${rule.id}`, { ...rule, enabled: next })
    rule.enabled = next
    notify(t(next ? 'access.enabled' : 'access.disabled', { name: rule.name }))
  } catch (e) {
    notify(e.message, true)
  }
}

async function remove(rule) {
  if (!confirm(t('access.deleteConfirm', { name: rule.name }))) return
  try {
    await api.del(`/api/access-rules/${rule.id}`)
    notify(t('access.deleted'))
    await load()
  } catch (e) {
    notify(e.message, true)
  }
}

// ---------------------------------------------------------------- the form

const showForm = ref(false)
const editing = ref(null)
const form = ref(blank())

function blank() {
  return {
    name: '',
    action: 'deny',
    site_id: '',
    enabled: true,
    conditions: [{ field: 'ip', op: 'in_cidr', text: '' }],
  }
}

function openCreate() {
  editing.value = null
  form.value = blank()
  showForm.value = true
}

function openEdit(rule) {
  editing.value = rule
  form.value = {
    name: rule.name,
    action: rule.action,
    site_id: rule.site_id || '',
    enabled: rule.enabled,
    conditions: (rule.conditions || []).map((c) => ({
      field: c.field, op: c.op, text: (c.values || []).join(', '),
    })),
  }
  showForm.value = true
}

function addCondition() {
  if (form.value.conditions.length >= MAX_CONDITIONS) return
  form.value.conditions.push({ field: 'ip', op: 'in_cidr', text: '' })
}
function dropCondition(i) {
  form.value.conditions.splice(i, 1)
}
function onFieldChange(c) {
  // The operator list changes with the field, so an op left over from the last
  // field would be a rule the server refuses for a reason nobody can see.
  c.op = FIELDS[c.field].ops[0]
  c.text = FIELDS[c.field].boolean ? 'true' : ''
}

// Which fields may be picked for the action currently selected. "allow" means
// "stop checking", so it may only be triggered by who the request is from -
// never by a header or a path, which the caller chooses.
const fieldChoices = computed(() =>
  Object.keys(FIELDS).filter((f) => form.value.action !== 'allow' || FIELDS[f].allow)
)

function valuesOf(c) {
  return c.text.split(',').map((v) => v.trim()).filter(Boolean)
}

// Conditions the current action cannot use. They are marked rather than deleted:
// switching the action is not a request to throw away the work already typed.
const strandedConditions = computed(() => {
  if (form.value.action !== 'allow') return []
  return form.value.conditions
    .map((c, i) => ({ c, i }))
    .filter(({ c }) => !FIELDS[c.field]?.allow)
})

const COVERS_EVERYTHING = ['0.0.0.0/0', '::/0']

// The same refusals the control plane makes, stated here so they are read while
// the form is being filled instead of after it is submitted. The server is still
// the one that decides - this only explains earlier.
const formProblem = computed(() => {
  const f = form.value
  if (!f.name.trim()) return t('access.errNoName')
  if (!f.conditions.length) return t('access.errNoCondition')
  for (const c of f.conditions) {
    const values = valuesOf(c)
    if (!values.length) return t('access.errEmptyValues', { field: t(`access.field.${c.field}`) })
    if (values.length > MAX_VALUES) return t('access.errTooManyValues', { max: MAX_VALUES })
    if (values.some((v) => v.length > MAX_VALUE_LEN)) return t('access.errValueTooLong', { max: MAX_VALUE_LEN })
  }
  if (f.action === 'allow') {
    if (strandedConditions.value.length) return t('access.errAllowField')
    for (const c of f.conditions) {
      if (c.field === 'ip' && valuesOf(c).some((v) => COVERS_EVERYTHING.includes(v))) {
        return t('access.errAllowEverything')
      }
      if (c.field === 'crawler' && valuesOf(c).includes('false')) {
        return t('access.errAllowNotCrawler')
      }
    }
  }
  return ''
})

async function save() {
  if (formProblem.value) return
  const payload = {
    name: form.value.name.trim(),
    action: form.value.action,
    site_id: form.value.site_id,
    enabled: form.value.enabled,
    conditions: form.value.conditions.map((c) => ({
      field: c.field,
      op: c.op,
      values: c.field === 'country'
        ? valuesOf(c).map((v) => v.toUpperCase())
        : c.field === 'method'
          ? valuesOf(c).map((v) => v.toUpperCase())
          : valuesOf(c),
    })),
  }
  busy.value = true
  try {
    if (editing.value) {
      await api.put(`/api/access-rules/${editing.value.id}`, payload)
      notify(t('access.updated'))
    } else {
      await api.post('/api/access-rules', payload)
      notify(t('access.created'))
    }
    showForm.value = false
    await load()
  } catch (e) {
    notify(e.message, true)
  } finally {
    busy.value = false
  }
}

// ---------------------------------------------------------------- dry run

const probe = ref({ ip: '', path: '/', host: '', ua: '', method: 'GET', crawler: false, site_id: '' })
const probeResult = ref(null)     // { matched, id, name, action, site }
const probeError = ref('')
const probing = ref(false)

async function runProbe() {
  probing.value = true
  probeError.value = ''
  probeResult.value = null
  try {
    probeResult.value = await api.post('/api/access-rules/test', { ...probe.value })
  } catch (e) {
    // A request that could not be answered is not a request that matched
    // nothing. Saying "no rule matched" here would be a wrong answer dressed as
    // a real one, and the operator would act on it.
    probeError.value = e.message
  } finally {
    probing.value = false
  }
}

// Everything below the matched rule is unreachable for this request - the thing
// an ordered list cannot show on its own.
const shadowedCount = computed(() => {
  if (!probeResult.value?.matched) return 0
  const i = rules.value.findIndex((r) => r.id === probeResult.value.id)
  return i < 0 ? 0 : rules.value.length - i - 1
})

// The counter resets at midnight UTC, which in most of the world is not
// midnight. Naming the hour it actually resets is the difference between a
// number an operator can reconcile against the attack log and one they cannot.
const hitsLabel = computed(() => {
  const since = rules.value.find((r) => r.hits_since)?.hits_since
  return since
    ? t('access.col.hitsFrom', { time: fmtShortTime(since) })
    : t('access.col.hits')
})
const hitsHint = computed(() => {
  const since = rules.value.find((r) => r.hits_since)?.hits_since
  return since ? t('access.col.hitsHintFrom', { time: fmtShortTime(since) }) : t('access.col.hitsHint')
})

function summarise(rule) {
  return (rule.conditions || [])
    .map((c) => `${t(`access.field.${c.field}`)} ${t(`access.op.${c.op}`)} ${(c.values || []).join(' / ')}`)
    .join(t('access.andJoin'))
}

onMounted(() => { load(); loadSites() })
</script>

<template>
  <div class="page-head">
    <div>
      <h2>{{ t('access.title') }}</h2>
      <p class="page-sub">{{ t('access.sub') }}</p>
    </div>
    <div class="page-actions">
      <span v-if="!loading" class="sub">{{ t('access.count', { n: rules.length, max: MAX_RULES }) }}</span>
      <button type="button" class="btn btn-primary" :disabled="rules.length >= MAX_RULES" @click="openCreate">
        <Icon name="plus" />{{ t('access.addButton') }}
      </button>
    </div>
  </div>

  <div class="filter-bar">
    <span class="filter-label">{{ t('access.scope') }}</span>
    <select v-model="siteFilter" class="select" style="width:240px" :aria-label="t('access.scope')" @change="load">
      <option value="">{{ t('access.allSites') }}</option>
      <option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }}</option>
    </select>
  </div>

  <div class="rules-layout">
    <div class="card">
      <div v-if="loading" class="skel-rows"><div v-for="i in 6" :key="i" class="skel skel-line"></div></div>

      <div v-else-if="!rules.length" class="empty">
        <Icon name="filter" />
        <b>{{ t('access.emptyTitle') }}</b>
        <span class="empty-hint">{{ t('access.emptyHint') }}</span>
        <button type="button" class="btn btn-primary btn-sm" @click="openCreate"><Icon name="plus" />{{ t('access.addButton') }}</button>
      </div>

      <div v-else class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th style="width:74px">{{ t('access.col.order') }}</th>
              <th style="width:52px">{{ t('rules.col.on') }}</th>
              <th>{{ t('access.col.rule') }}</th>
              <th style="width:120px">{{ t('access.col.scopeCol') }}</th>
              <th style="width:110px">{{ t('events.col.action') }}</th>
              <th style="width:110px" class="num" :title="hitsHint">{{ hitsLabel }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(r, i) in rules" :key="r.id"
              :class="{ 'is-off': !r.enabled, 'is-hit': probeResult?.matched && probeResult.id === r.id, 'is-shadowed': probeResult?.matched && shadowedCount && i > rules.findIndex((x) => x.id === probeResult.id) }"
            >
              <td>
                <div class="order">
                  <span class="idx mono">{{ i + 1 }}</span>
                  <button type="button" class="btn btn-sm btn-ghost" :disabled="i === 0 || busy" :aria-label="t('access.moveUp')" @click="move(i, -1)">↑</button>
                  <button type="button" class="btn btn-sm btn-ghost" :disabled="i === rules.length - 1 || busy" :aria-label="t('access.moveDown')" @click="move(i, 1)">↓</button>
                </div>
              </td>
              <td>
                <label class="switch">
                  <input type="checkbox" :checked="r.enabled" @change="toggle(r)" />
                  <span class="track"></span>
                  <span class="sr-only">{{ r.name }}</span>
                </label>
              </td>
              <td>
                <div class="rule-name">{{ r.name }}</div>
                <div class="rule-cond mono dim">{{ summarise(r) }}</div>
              </td>
              <td class="sub">{{ siteName(r.site_id) }}</td>
              <td>
                <span class="tag" :class="r.action === 'allow' ? 'tag-ok' : `tag-${r.action}`">
                  <span class="dot"></span>{{ t(`access.action.${r.action}`) }}
                </span>
              </td>
              <td class="num">{{ fmtNumber(r.hits_today || 0) }}</td>
              <td class="actions">
                <button type="button" class="btn btn-sm" @click="openEdit(r)">{{ t('common.edit') }}</button>
                <button type="button" class="btn btn-sm btn-danger" @click="remove(r)">{{ t('common.delete') }}</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- The dry run. It asks the data plane, using the engine that is deciding
         right now, so it cannot drift from what actually happens. -->
    <div class="card probe">
      <div class="card-head">
        <div>
          <div class="card-title">{{ t('access.probe.title') }}</div>
          <div class="card-sub">{{ t('access.probe.sub') }}</div>
        </div>
      </div>

      <form @submit.prevent="runProbe">
        <div class="field">
          <label class="label">{{ t('access.probe.ip') }}</label>
          <input v-model="probe.ip" class="input mono" placeholder="203.0.113.9" />
        </div>
        <div class="field">
          <label class="label">{{ t('access.probe.host') }}</label>
          <input v-model="probe.host" class="input mono" placeholder="example.com" />
        </div>
        <div class="field">
          <label class="label">{{ t('access.probe.path') }}</label>
          <input v-model="probe.path" class="input mono" placeholder="/admin" />
        </div>
        <div class="field">
          <label class="label">{{ t('access.probe.ua') }}</label>
          <input v-model="probe.ua" class="input mono" placeholder="curl/8.4.0" />
        </div>
        <div class="row">
          <div class="field grow">
            <label class="label">{{ t('access.probe.method') }}</label>
            <select v-model="probe.method" class="select">
              <option v-for="m in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']" :key="m" :value="m">{{ m }}</option>
            </select>
          </div>
          <div class="field grow">
            <label class="label">{{ t('access.probe.site') }}</label>
            <select v-model="probe.site_id" class="select">
              <option value="">{{ t('access.allSites') }}</option>
              <option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }}</option>
            </select>
          </div>
        </div>
        <label class="switch" style="margin-bottom:14px">
          <input v-model="probe.crawler" type="checkbox" />
          <span class="track"></span>
          <span>{{ t('access.probe.crawler') }}</span>
        </label>

        <button type="submit" class="btn btn-primary" style="width:100%" :disabled="probing">
          <Icon name="radar" />{{ probing ? t('access.probe.running') : t('access.probe.run') }}
        </button>
      </form>

      <div v-if="probeError" class="alert alert-critical" style="margin-top:14px">
        <Icon name="alert" />
        <div class="alert-body"><b>{{ t('access.probe.failed') }}</b> {{ probeError }}</div>
      </div>

      <template v-else-if="probeResult">
        <div v-if="!probeResult.matched" class="alert alert-info" style="margin-top:14px">
          <Icon name="info" />
          <div class="alert-body">{{ t('access.probe.noMatch') }}</div>
        </div>
        <div v-else class="probe-hit" style="margin-top:14px">
          <div class="eyebrow">{{ t('access.probe.matched') }}</div>
          <div class="probe-rule">
            <span class="tag" :class="probeResult.action === 'allow' ? 'tag-ok' : `tag-${probeResult.action}`">
              <span class="dot"></span>{{ t(`access.action.${probeResult.action}`) }}
            </span>
            <b>{{ probeResult.name }}</b>
          </div>
          <p v-if="shadowedCount" class="probe-shadow">
            {{ t('access.probe.shadow', { n: shadowedCount }) }}
          </p>
        </div>
      </template>
    </div>
  </div>

  <Modal
    v-if="showForm"
    :title="editing ? t('access.form.editTitle', { name: editing.name }) : t('access.form.addTitle')"
    :busy="busy"
    :disabled="!!formProblem"
    @close="showForm = false"
    @submit="save"
  >
    <div class="field">
      <label class="label">{{ t('access.form.name') }}</label>
      <input v-model="form.name" class="input" :placeholder="t('access.form.namePlaceholder')" />
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">{{ t('access.form.action') }}</label>
        <select v-model="form.action" class="select">
          <option v-for="a in ACTIONS" :key="a" :value="a">{{ t(`access.action.${a}`) }}</option>
        </select>
      </div>
      <div class="field grow">
        <label class="label">{{ t('access.form.site') }}</label>
        <select v-model="form.site_id" class="select">
          <option value="">{{ t('access.allSites') }}</option>
          <option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }}</option>
        </select>
      </div>
    </div>

    <div v-if="form.action === 'allow'" class="alert alert-warn" style="margin-bottom:16px">
      <Icon name="info" />
      <div class="alert-body"><b>{{ t('access.allowTitle') }}</b> {{ t('access.allowHint') }}</div>
    </div>

    <div class="divider"></div>

    <div class="cond-head">
      <span class="label" style="margin:0">{{ t('access.form.conditions') }}</span>
      <span class="hint" style="margin:0">{{ t('access.form.conditionsHint') }}</span>
    </div>

    <div v-for="(c, i) in form.conditions" :key="i" class="cond" :class="{ bad: form.action === 'allow' && !FIELDS[c.field]?.allow }">
      <div class="cond-row">
        <select v-model="c.field" class="select" style="width:150px" :aria-label="t('access.form.field')" @change="onFieldChange(c)">
          <option v-for="f in fieldChoices" :key="f" :value="f">{{ t(`access.field.${f}`) }}</option>
          <!-- A field the action cannot use is kept selectable so the row still
               shows what it says, instead of silently becoming something else -->
          <option v-if="!fieldChoices.includes(c.field)" :value="c.field">{{ t(`access.field.${c.field}`) }}</option>
        </select>
        <select v-model="c.op" class="select" style="width:140px" :aria-label="t('access.form.op')">
          <option v-for="op in FIELDS[c.field].ops" :key="op" :value="op">{{ t(`access.op.${op}`) }}</option>
        </select>
        <select v-if="FIELDS[c.field].boolean" v-model="c.text" class="select grow" :aria-label="t('access.form.value')">
          <option value="true">{{ t('access.crawlerYes') }}</option>
          <option value="false">{{ t('access.crawlerNo') }}</option>
        </select>
        <input v-else v-model="c.text" class="input mono grow" :placeholder="t(`access.placeholder.${c.field}`)" :aria-label="t('access.form.value')" />
        <button
          type="button" class="btn btn-sm btn-ghost" :disabled="form.conditions.length === 1"
          :aria-label="t('access.form.removeCondition')" @click="dropCondition(i)"
        ><Icon name="x" /></button>
      </div>
      <div v-if="!FIELDS[c.field].boolean" class="hint">{{ t('access.form.valuesHint') }}</div>
    </div>

    <button
      type="button" class="btn btn-sm" style="margin-top:4px"
      :disabled="form.conditions.length >= MAX_CONDITIONS" @click="addCondition"
    ><Icon name="plus" />{{ t('access.form.addCondition') }}</button>
    <span v-if="form.conditions.length >= MAX_CONDITIONS" class="hint" style="margin-left:10px">
      {{ t('access.form.maxConditions', { max: MAX_CONDITIONS }) }}
    </span>

    <div v-if="formProblem" class="alert alert-critical" style="margin-top:16px">
      <Icon name="alert" />
      <div class="alert-body">{{ formProblem }}</div>
    </div>
    <div v-else-if="!editing" class="hint" style="margin-top:16px">{{ t('access.form.goesLast') }}</div>
  </Modal>
</template>

<style scoped>
.rules-layout { display: grid; grid-template-columns: minmax(0, 1fr) 296px; gap: 16px; align-items: start; }
@media (max-width: 1240px) { .rules-layout { grid-template-columns: minmax(0, 1fr); } }

.skel-rows { display: flex; flex-direction: column; gap: 14px; padding: 8px 0; }

.order { display: flex; align-items: center; gap: 2px; }
.order .idx { width: 18px; font-size: 11px; color: var(--ink-3); }
.order .btn { padding: 2px 5px; line-height: 1; }

.rule-name { font-weight: 500; }
.rule-name, .rule-cond { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 30ch; }
.rule-cond { font-size: 11.5px; margin-top: 2px; }

tr.is-off td:not(:first-child):not(:nth-child(2)) { opacity: .5; }
/* The rule the dry run landed on, and everything it stands in front of */
tr.is-hit td { background: var(--surface-3) !important; box-shadow: inset 2px 0 0 var(--ink); }
tr.is-shadowed td { opacity: .45; }

.probe .field { margin-bottom: 10px; }
.probe-hit { border-top: 1px solid var(--line); padding-top: 12px; }
.probe-rule { display: flex; align-items: center; gap: 8px; margin-top: 6px; flex-wrap: wrap; }
.probe-shadow { margin: 10px 0 0; font-size: 12px; color: var(--warning); line-height: 1.55; }

.cond-head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }
.cond { border: 1px solid var(--line); border-radius: var(--radius); padding: 10px; margin-bottom: 8px; background: var(--bg); }
.cond.bad { border-color: rgba(185, 28, 48, .4); background: var(--critical-bg); }
.cond-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.cond-row .grow { flex: 1; min-width: 160px; }
.cond .hint { margin-top: 6px; }
</style>
