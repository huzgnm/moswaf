// How a ban is being held, read from what the control plane reports.
//
// Out of the component so it can be tested without a DOM. The reading rules
// here are the ones that decide what an operator is told during a flood, and
// they were checked once by hand through a mock - which is exactly the kind of
// check that keeps passing after the thing it checks has changed.
//
// What still is not covered by a test: the column appearing and disappearing
// with the agent, and the row surviving a refused unban. Both live in the
// template, and pinning them needs a component mount this project has no
// dependency for. They are verified by hand and by review, and that is a weaker
// guarantee than the functions below have - said plainly rather than left to be
// assumed.

import { t } from './i18n.js'

// The four the server documents. Anything else - an older control plane sending
// nothing, a newer one sending a fifth - reads as "this one does not say", and
// the safe reading of that is the plain application ban: no badge, no promise.
export const KNOWN_ENFORCEMENT = ['lua', 'kernel_pending', 'kernel', 'kernel_refused']

export function enforcementOf(ban) {
  return KNOWN_ENFORCEMENT.includes(ban?.enforcement) ? ban.enforcement : 'lua'
}

// stuck is its own field, not a fifth kind of enforcement, and it only means
// anything while a request is waiting to be applied. The server reports it false
// everywhere else; this does not depend on that staying true.
export function isStuck(ban) {
  return ban?.stuck === true && enforcementOf(ban) === 'kernel_pending'
}

export function enforcementTone(ban) {
  if (isStuck(ban)) return 'tag-monitor'
  switch (enforcementOf(ban)) {
    case 'kernel': return 'tag-ok'
    case 'kernel_pending': return 'tag-off'
    // Not a warning colour. A refusal is almost always the agent declining to
    // drop an administrator's own address at the kernel, which is it doing its
    // job; painting it red sends somebody hunting a bug that is the feature.
    case 'kernel_refused': return 'tag-verify'
    default: return 'tag-off'
  }
}

export function enforcementLabel(ban) {
  return isStuck(ban) ? t('kban.stuck') : t(`kban.${enforcementOf(ban)}`)
}

export function fmtDuration(sec) {
  if (sec < 60) return t('kban.secs', { s: sec })
  const m = Math.floor(sec / 60)
  return m < 60 ? t('kban.mins', { m }) : t('kban.hours', { h: Math.floor(m / 60) })
}

// The line under the badge: how long it has been in this state, or why it was
// refused. Nothing for a plain application ban, which is most of them and needs
// no note. `now` is injected so the result does not depend on the clock.
export function enforcementNote(ban, now = Date.now() / 1000) {
  const e = enforcementOf(ban)
  if (e === 'kernel_refused') return ban?.refused_reason || ''
  if (!ban?.enforcement_since) return ''
  const secs = Math.max(0, Math.floor(now - ban.enforcement_since))
  return e === 'kernel'
    ? t('kban.sinceKernel', { d: fmtDuration(secs) })
    : t('kban.sincePending', { d: fmtDuration(secs) })
}
