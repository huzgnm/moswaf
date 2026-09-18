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
//   3. no empty strings, which is how a missing translation usually arrives.
//
//   node test/locales.js

import en from '../src/locales/en.js'
import vi from '../src/locales/vi.js'
import ru from '../src/locales/ru.js'
import zh from '../src/locales/zh.js'

const locales = { vi, ru, zh }
const problems = []

function placeholders(value) {
  return [...value.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort()
}

const enKeys = Object.keys(en).sort()

// English is the reference, so check it for the one thing it can still get wrong.
for (const [key, value] of Object.entries(en)) {
  if (typeof value !== 'string' || value.trim() === '') {
    problems.push(`en: ${key} is empty`)
  }
}

for (const [code, table] of Object.entries(locales)) {
  const keys = Object.keys(table).sort()

  for (const key of enKeys) {
    if (!(key in table)) problems.push(`${code}: missing key ${key}`)
  }
  for (const key of keys) {
    if (!(key in en)) problems.push(`${code}: stale key ${key} (not in en)`)
  }

  for (const key of enKeys) {
    if (!(key in table)) continue

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
