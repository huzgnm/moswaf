// How a ban's enforcement state is read.
//
// These decide what an operator is told while being flooded: which addresses
// still cost CPU on every request, which are held in the kernel for free, and
// which the agent refused to drop - the last of those being, almost always, the
// administrator's own address.
//
// Checked here rather than through the screen because a check done through the
// screen is a check that keeps passing after the reading rules change. Two
// behaviours are deliberately NOT covered and are noted at the end.
//
//   node test/enforcement.js

globalThis.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} }
globalThis.document = { documentElement: {}, createElement: () => ({ content: {} }) }

const {
  enforcementOf, isStuck, enforcementTone, enforcementLabel, enforcementNote,
} = await import('../src/enforcement.js')

const problems = []
const check = (ok, why) => { if (!ok) problems.push(why) }

// ---------------------------------------------------------------- reading

for (const e of ['lua', 'kernel_pending', 'kernel', 'kernel_refused']) {
  check(enforcementOf({ enforcement: e }) === e, `${e} was not read back as itself`)
}

// Absent, null, and a value from a future server all mean "this one does not
// say", and all have to read as the plain application ban - the state that
// promises the reader nothing.
for (const ban of [{}, { enforcement: null }, { enforcement: 'kernel_quantum' }, undefined]) {
  check(enforcementOf(ban) === 'lua',
    `${JSON.stringify(ban)} did not read as "lua"; an unknown state would be shown as if it were understood`)
}

// ---------------------------------------------------------------- stuck

check(isStuck({ enforcement: 'kernel_pending', stuck: true }) === true,
  'a pending request past its deadline was not reported stuck')
check(isStuck({ enforcement: 'kernel_pending', stuck: false }) === false,
  'a pending request was reported stuck when the server said it was not')

// The server reports stuck:false outside pending. This must not depend on that:
// a server that sets it anyway must not produce a warning on a ban that is
// working, which is the shape of an alarm nobody can act on.
for (const e of ['kernel', 'kernel_refused', 'lua']) {
  check(isStuck({ enforcement: e, stuck: true }) === false,
    `stuck:true on "${e}" produced a warning; stuck only means anything while a request is pending`)
}

// ---------------------------------------------------------------- tone

check(enforcementTone({ enforcement: 'kernel' }) === 'tag-ok',
  'a ban held in the kernel was not shown as the good state')
check(enforcementTone({ enforcement: 'kernel_pending', stuck: true }) === 'tag-monitor',
  'a stuck request was not the warning tone; it is the one state here that is actually wrong')

// The one that matters most: a refusal is the agent protecting whoever is
// reading the page. A warning colour there sends somebody hunting a bug that is
// the feature working.
//
// Named as the tones that ARE allowed, not as the alarm tones that are not.
// A list of forbidden colours has to be remembered and extended - the app has
// twelve tag tones and half of them read as an alarm - so the first one left
// out, or the first one added later, passes silently. This way anything that is
// not one of the three calm tones fails, including a tone nobody has written
// yet.
const CALM_TONES = ['tag-ok', 'tag-off', 'tag-verify']
const refusedTone = enforcementTone({ enforcement: 'kernel_refused' })
check(CALM_TONES.includes(refusedTone),
  `a refused ban was shown in "${refusedTone}", which is not one of ${CALM_TONES.join(', ')}. ` +
  'It is usually the agent declining to drop the administrator own address, and an alarm colour ' +
  'there reads as a fault it is not.')

// ---------------------------------------------------------------- the note

check(enforcementNote({ enforcement: 'lua' }) === '',
  'a plain application ban carried a note; most bans are this and it would be noise on every row')
check(enforcementNote({ enforcement: 'kernel_refused', refused_reason: 'in the admin range' }) === 'in the admin range',
  'the reason for a refusal was not shown; without it the state is a badge nobody can act on')
check(enforcementNote({ enforcement: 'kernel_refused' }) === '',
  'a refusal with no reason produced something anyway')

// A clock going backwards, or a server a second ahead, must not print a
// negative age.
const ahead = enforcementNote({ enforcement: 'kernel', enforcement_since: 1000 }, 900)
check(!ahead.includes('-'), `a timestamp in the future printed a negative age: ${ahead}`)

check(enforcementNote({ enforcement: 'kernel', enforcement_since: 1000 }, 1000) !== '',
  'zero seconds in the kernel produced no note at all')

const labelled = enforcementLabel({ enforcement: 'kernel_pending', stuck: true })
check(labelled !== enforcementLabel({ enforcement: 'kernel_pending', stuck: false }),
  'a stuck request reads the same as one that is applying normally')

if (problems.length) {
  console.error('enforcement: FAILED\n - ' + problems.join('\n - '))
  process.exit(1)
}

// Said out loud so it is not mistaken for covered: the column appearing with
// the agent, and the row surviving a refused unban, are in the template. They
// hold today - both were driven through the running page - but nothing here
// would notice if they stopped.
console.log('enforcement: reading rules hold (template behaviour is not covered here)')
