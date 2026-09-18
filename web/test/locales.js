// Locale parity checks.
//
// A half-translated release does not crash - t() falls back to English - it just
// quietly shows an English sentence in the middle of a Russian page, which is the
// kind of thing nobody notices until a user reports it. These checks turn that
// into a build failure.
//
// Three things have to hold for every locale:
//
//   1. exactly the same key set as English - no missing keys, no stale ones left
//      behind after a key was renamed;
//   2. exactly the same {placeholders} in each value - a translation that drops
//      {days} renders "left" with no number, and one that invents {day} renders
//      the literal braces on screen;
//   3. no empty strings, which is how a missing translation usually arrives;
//   4. balanced braces, since an interpolation typo like "{days}}" survives the
//      placeholder check - the extra brace is not part of any {name} match - and
//      then renders as a stray brace on screen.
//
//   node test/locales.js

// i18n.js touches browser globals at import time, so stub the few it uses. The
// point is to check the picker's list and the default against the tables that
// actually exist: a locale file nobody lists is invisible, and a default nobody
// translated opens every dashboard on the fallback path.
globalThis.localStorage = { getItem: () => null, setItem: () => {} }
// vue/runtime-dom probes document on import; give it enough to load.
globalThis.document = { documentElement: {}, createElement: () => ({ content: {} }) }

const { LOCALES, DEFAULT_LOCALE } = await import('../src/i18n.js')

import en from '../src/locales/en.js'
import vi from '../src/locales/vi.js'
import ru from '../src/locales/ru.js'
import zh from '../src/locales/zh.js'

const locales = { vi, ru, zh }
const problems = []

function placeholders(value) {
  return [...value.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort()
}

function unbalancedBraces(value) {
  const open = (value.match(/\{/g) || []).length
  const close = (value.match(/\}/g) || []).length
  return open === close ? null : `${open} '{' vs ${close} '}'`
}

const enKeys = Object.keys(en).sort()
const codes = { en, ...locales }

// The picker's list and the tables have to be the same set, both ways round.
for (const { code } of LOCALES) {
  if (!Object.hasOwn(codes, code)) {
    problems.push(`LOCALES offers ${code}, but there is no message table for it`)
  }
}
for (const code of Object.keys(codes)) {
  if (!LOCALES.some((l) => l.code === code)) {
    problems.push(`${code} has a message table but is missing from LOCALES, so nobody can pick it`)
  }
}
for (const { code, label, english } of LOCALES) {
  if (!label || !english) problems.push(`LOCALES entry ${code} is missing a label`)
}
if (!Object.hasOwn(codes, DEFAULT_LOCALE)) {
  problems.push(`DEFAULT_LOCALE is ${DEFAULT_LOCALE}, which has no message table`)
}

// English is the reference, so check it for the one thing it can still get wrong.
for (const [key, value] of Object.entries(en)) {
  if (typeof value !== 'string' || value.trim() === '') {
    problems.push(`en: ${key} is empty`)
    continue
  }
  const braces = unbalancedBraces(value)
  if (braces) problems.push(`en: ${key} has unbalanced braces (${braces})`)
}

for (const [code, table] of Object.entries(locales)) {
  const keys = Object.keys(table).sort()

  // Object.hasOwn, not `in`: `in` walks the prototype chain, so a locale that was
  // missing a key named like an Object.prototype member - "constructor",
  // "toString" - would read as present and never be reported.
  for (const key of enKeys) {
    if (!Object.hasOwn(table, key)) problems.push(`${code}: missing key ${key}`)
  }
  for (const key of keys) {
    if (!Object.hasOwn(en, key)) problems.push(`${code}: stale key ${key} (not in en)`)
  }

  for (const key of enKeys) {
    if (!Object.hasOwn(table, key)) continue

    const value = table[key]
    if (typeof value !== 'string' || value.trim() === '') {
      problems.push(`${code}: ${key} is empty`)
      continue
    }

    const want = placeholders(en[key]).join(',')
    const got = placeholders(value).join(',')
    if (want !== got) {
      problems.push(
        `${code}: ${key} placeholders differ - en has {${want}}, ${code} has {${got}}`
      )
    }

    const braces = unbalancedBraces(value)
    if (braces) problems.push(`${code}: ${key} has unbalanced braces (${braces})`)
  }
}

if (problems.length) {
  console.error(`${problems.length} locale problem(s):\n`)
  for (const p of problems) console.error(`  - ${p}`)
  process.exit(1)
}

const counts = Object.entries({ en, ...locales })
  .map(([code, table]) => `${code}=${Object.keys(table).length}`)
  .join(' ')
console.log(`locales: all key sets and placeholders match (${counts})`)
