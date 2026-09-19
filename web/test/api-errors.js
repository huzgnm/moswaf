// What a failed response is allowed to decide.
//
// The API helper attaches the response body to the Error it throws, so a caller
// can act on a refusal rather than only display it - the unban screen has to
// tell "the address is still blocked" apart from any other failure.
//
// The body is data from the network, and an Error is an object with meaning of
// its own. If the body were spread onto it, a response naming "status" would be
// choosing the HTTP code the dashboard believes, and one naming "message" would
// be choosing the text shown to the operator. Neither is the body's to decide.
//
// These checks exist because the safe version and the unsafe one differ by the
// order of two statements. A comment saying "keep these in this order" survives
// until the first tidy-up; a test does not care how the file is arranged, only
// that a body cannot name those two things.
//
//   node test/api-errors.js

globalThis.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} }
globalThis.document = { documentElement: {}, createElement: () => ({ content: {} }) }
globalThis.location = { hash: '' }

const { api } = await import('../src/api.js')

const problems = []

function reply(status, body) {
  globalThis.fetch = async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })
}

async function failed(call) {
  try {
    await call()
  } catch (e) {
    return e
  }
  throw new Error('the call resolved; it was supposed to throw')
}

// A refusal whose body happens to carry both of the names that matter.
reply(409, {
  code: 'kernel_unban_failed',
  still_blocked: true,
  ip: '203.0.113.9',
  error: 'nft: element still present after delete',
  status: 200,                 // the trap
  message: 'everything is fine', // the other one
})

let err = await failed(() => api.del('/api/bans/203.0.113.9'))

if (err.status !== 409) {
  problems.push(`a body naming "status" changed the HTTP code: expected 409, got ${err.status}. ` +
    'A caller branching on the status would take the success path on a refusal.')
}
if (err.message !== 'nft: element still present after delete') {
  problems.push(`a body naming "message" replaced the error text: got ${JSON.stringify(err.message)}. ` +
    'The operator would be told everything is fine about a request that failed.')
}
if (err.body?.code !== 'kernel_unban_failed' || err.body?.still_blocked !== true) {
  problems.push('the body did not survive on the error, so a caller cannot tell a refusal ' +
    'that leaves an address blocked from any other failure')
}

// No "error" field: the message is the helper's own, and a body "message" still
// does not get to be it.
reply(500, { message: 'everything is fine' })
err = await failed(() => api.get('/api/bans'))

if (err.message === 'everything is fine') {
  problems.push('with no "error" field, a body naming "message" became the error text')
}
if (err.status !== 500) {
  problems.push(`expected status 500, got ${err.status}`)
}

if (problems.length) {
  console.error('api errors: FAILED\n - ' + problems.join('\n - '))
  process.exit(1)
}
console.log('api errors: a failed response cannot name status or message on the error')
