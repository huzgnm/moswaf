import { reactive } from 'vue'
import { t, intlTag } from './i18n.js'

const TOKEN_KEY = 'moswaf.token'

export const session = reactive({
  token: localStorage.getItem(TOKEN_KEY) || '',
  user: null,
})

export const toast = reactive({ text: '', error: false, seq: 0 })

let toastTimer = null
export function notify(text, error = false) {
  toast.text = text
  toast.error = error
  toast.seq++
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => { toast.text = '' }, error ? 6000 : 3000)
}

export function setToken(token) {
  session.token = token || ''
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

export function logout() {
  setToken('')
  session.user = null
  if (location.hash !== '#/login') location.hash = '#/login'
}

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' }
  if (session.token) headers.Authorization = `Bearer ${session.token}`

  let res
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch (e) {
    throw new Error(t('api.unreachable'))
  }

  if (res.status === 401 && !path.endsWith('/auth/login')) {
    logout()
    throw new Error(t('api.sessionExpired'))
  }

  const text = await res.text()
  const data = text ? JSON.parse(text) : null

  if (!res.ok) {
    // The body travels with the error, not just its message. A refusal can carry
    // facts the caller has to act on rather than only show - a failed unban says
    // "still_blocked", and a caller that removed the row on the strength of the
    // status code alone would leave the operator believing an address was
    // released while the kernel is still dropping it.
    const err = new Error((data && data.error) || t('api.error', { status: res.status }))
    err.status = res.status
    // The body goes in its own property rather than being spread onto the error.
    // Spreading lets a response decide what "status" or "message" mean on an
    // Error object - and it would win, because it is assigned last. No endpoint
    // sends those today, which is exactly what makes it the kind of trap that
    // goes off later, in somebody else's change, far from this line.
    err.body = data
    throw err
  }
  return data
}

export const api = {
  get:  (p) => request('GET', p),
  // For list endpoints: never hand a view an undefined value
  list: async (p) => {
    const res = await request('GET', p)
    return Array.isArray(res) ? res : []
  },
  post: (p, b) => request('POST', p, b ?? {}),
  put:  (p, b) => request('PUT', p, b ?? {}),
  del:  (p) => request('DELETE', p),
}

// ---------------------------------------------------------------- formatting

export function fmtNumber(n) {
  if (n === null || n === undefined) return '0'
  return Number(n).toLocaleString(intlTag())
}

export function fmtTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts)
  return d.toLocaleString(intlTag(), {
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

export function fmtShortTime(ts) {
  return new Date(ts).toLocaleTimeString(intlTag(), { hour: '2-digit', minute: '2-digit' })
}

// The action recorded on an event. Unknown values are shown raw rather than
// swallowed - a new engine action should be visible, not invisible.
export function actionLabel(action) {
  const key = `action.${action}`
  const label = t(key)
  return label === key ? action : label
}
