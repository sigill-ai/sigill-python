// Generates runs/, expected/, findings/ and envelopes.json for vector 14 from cases.json and vector 13's
// control set. Guard: Agent Policy Control Set v2 §7. Facts: §8 (factsVersion 2). Findings: Agent Enforcement
// v1 §5. Results: the official Cedar core.
//   npm i --no-save @cedar-policy/cedar-wasm@4.14.0 && node _generate.mjs   (README: the Docker command)
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'

const here = dirname(fileURLToPath(import.meta.url))
const cedar = createRequire(import.meta.url)('@cedar-policy/cedar-wasm/nodejs')
const read = p => JSON.parse(readFileSync(join(here, p), 'utf8'))
const base = read('../13-policy-control-set-v2/control-set.json')
const schema = read('../../agent-policy-cedar-schema-v2.json')
const src = read('cases.json')
const rules = base.cedar.policies.staticPolicies
const entities = base.cedar.entities

// RFC 8785 for the value space used here (strings, safe integers, booleans, null): sorted keys, no whitespace.
const jcs = v => Array.isArray(v) ? `[${v.map(jcs).join(',')}]`
  : v && typeof v === 'object' ? `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${jcs(v[k])}`).join(',')}}`
  : JSON.stringify(v)
const sha256 = s => createHash('sha256').update(s, 'utf8').digest('hex')
const write = (p, v) => writeFileSync(join(here, p), JSON.stringify(v, null, 1) + '\n')

const AGENT = 'urn:example:agent:support'
const T0 = Date.parse('2026-11-02T10:00:00.000Z')
const ENGINE = `cedar-policy@${cedar.getCedarVersion()}`
const BASELINE = 'sigill:baseline-permit'
const uuid = n => '00000000-0000-4000-8000-' + n.toString(16).padStart(12, '0')
const stubSig = (corr, what) => sha256(`stub-signature:${corr}:${what}`)
const isRecord = e => e.step.type === 'authorization' && e.step.enforcer !== undefined

// ---- envelopes -------------------------------------------------------------------------------------------
function builder(idx, schemaVersion = '4') {
  const correlationId = 'urn:uuid:' + uuid(0x140000000000 + idx)
  const events = []
  function add(a, sealedBy) {
    const seq = events.length, ms = T0 + seq * 1000
    const step = { type: a.type, eventTime: new Date(ms).toISOString() }
    const objects = [], objectDigests = {}
    const obj = (role, bytes) => {
      const uri = 'objects/' + uuid(0x14b000000000 + idx * 0x100000 + seq * 16 + objects.length)
      objects.push({ uri, role, contentType: 'application/json' }); objectDigests[uri] = sha256(bytes)
    }
    if (a.consequential) step.consequential = true
    if (a.tool) step.tool = { name: a.tool, useId: a.useId }
    if (a.type === 'tool_call') {
      obj('tool-arguments', src.arguments[a.args])
      // A tool whose entity declares definitionSha256 gets its definition by default; `definition` overrides (null: none).
      const def = 'definition' in a ? a.definition : entities.some(e => e.uid.id === a.tool && e.attrs.definitionSha256) ? `${a.tool} definition` : null
      if (def !== null) obj('tool-definition', def)
    }
    if (a.type === 'tool_result') obj('tool-result', '{"ok":true}')
    if (a.type === 'human_approval') {
      Object.assign(step, { decision: a.decision, approver: 'urn:example:approver:1' })
      const { args, ...c } = a.covers
      step.covers = { ...c, argumentsSha256: sha256(src.arguments[args]) }
      obj('approval-receipt', `{"receipt":${seq}}`)
    }
    if (a.type === 'delegation') {
      step.delegation = { childCorrelationId: 'urn:uuid:' + uuid(0x14d000000000 + idx), childAgentId: a.childAgentId }
      obj('delegation-input', '{"task":"review"}')
    }
    if (a.type === 'delegation_result') step.delegation = { childCorrelationId: 'urn:uuid:' + uuid(0x14d000000000 + idx),
      childRunEndSignatureSha256: stubSig('urn:uuid:' + uuid(0x14d000000000 + idx), 'run_end'), childDisposition: 'completed' }
    if (a.type === 'authorization') {
      step.decision = 'denied'
      if (a.rules) step.rules = a.rules
      step.enforcer = { engine: ENGINE, factsVersion: '2', reason: a.reason }
    }
    if (a.type === 'run_end') Object.assign(step, { finalSeq: seq, finalPrevSignatureSha256: stubSig(correlationId, seq - 1), runDisposition: a.runDisposition ?? 'completed' })
    const envelope = {
      schemaName: 'AgentExecutionEvidence', schemaVersion, evidenceId: uuid(0x14a000000000 + idx * 0x10000 + seq),
      createdAt: new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z'), actor: { type: 'agent', id: AGENT },
      activity: { name: 'support-session', correlationId }, chain: seq ? { seq, prevSignatureSha256: stubSig(correlationId, seq - 1) } : { seq },
      step, ...(seq === 0 ? { binds: { controlArtifactSignatureSha256: stubSig(correlationId, 'control') } } : {}), objects,
    }
    events.push({ sealedBy, envelope, objectDigests })
    return events.length - 1
  }
  return { correlationId, events, add }
}

// ---- facts v2 (Control Set v2 §8) -------------------------------------------------------------------------
const digestOf = (ev, role) => {
  const a = ev.envelope.objects.filter(o => o.role === role)
  return a.length === 1 ? ev.objectDigests[a[0].uri] : undefined
}
// §8.1 for the tool_call at index j, given the approvals (indexes) earlier calls consumed.
function approvalOne(events, j, consumed) {
  const e = events[j].envelope, u = e.step.tool.useId, t = e.step.tool.name, a = digestOf(events[j], 'tool-arguments')
  const earlier = events.slice(0, j).map((x, k) => [k, x.envelope.step]).filter(([, s]) => s.type === 'human_approval')
  const args = c => a !== undefined && c.argumentsSha256 === a
  if (earlier.some(([, s]) => s.decision === 'rejected' && s.covers && ((s.covers.useId !== undefined && s.covers.useId === u) || (s.covers.tool === t && args(s.covers)))))
    return { approval: 'rejected' }
  const match = earlier.find(([k, s]) => s.decision === 'approved' && s.covers && s.covers.tool === t && args(s.covers)
    && (s.covers.useId === undefined || s.covers.useId === u)
    && (!s.covers.expiresAt || Date.parse(e.step.eventTime) < Date.parse(s.covers.expiresAt)) && !consumed.has(k))
  if (match) return { approval: 'bound', takes: match[0] }
  return { approval: earlier.length ? 'unbound' : 'none' }
}
// Walk the tool_calls in seq order: each bound call consumes the lowest-seq matching approval.
function approvalFor(events, i) {
  const consumed = new Set()
  for (let j = 0; j <= i; j++) {
    if (events[j].envelope.step.type !== 'tool_call') continue
    const r = approvalOne(events, j, consumed)
    if (r.takes !== undefined) consumed.add(r.takes)
    if (j === i) return r
  }
}
const principal = { type: 'Agent', id: AGENT }
function request(events, i) {
  const e = events[i].envelope, s = e.step, seq = e.chain.seq
  const upTo = events.slice(0, i + 1).map(x => x.envelope)
  const calls = upTo.filter(x => x.step.type === 'tool_call')
  const toolStep = s.type === 'tool_call' || s.type === 'tool_result'
  return {
    principal, action: { type: 'Action', id: s.type },
    resource: toolStep ? { type: 'Tool', id: s.tool.name } : { type: 'Step', id: String(seq) },
    context: {
      consequential: s.consequential === true, operation: s.tool?.operation ?? '', stepsSoFar: seq,
      approval: s.type === 'tool_call' ? approvalFor(events, i).approval : upTo.slice(0, -1).some(x => x.step.type === 'human_approval') ? 'unbound' : 'none',
      isChildRun: false, totalSteps: 0, consequentialCount: upTo.filter(x => x.step.consequential === true).length, unpairedConsequential: 0,
      toolCallsSoFar: calls.length, callsOfThisTool: toolStep ? calls.filter(c => c.step.tool.name === s.tool.name).length : 0,
      denialsSoFar: upTo.slice(0, -1).filter(isRecord).length,
    },
  }
}
function runLevel(events, correlationId) {
  const all = events.map(x => x.envelope), finalSeq = all.at(-1).step.finalSeq
  const calls = all.filter(x => x.step.type === 'tool_call'), uses = new Map()
  for (const c of calls) uses.set(c.step.tool.useId, (uses.get(c.step.tool.useId) ?? 0) + 1)
  const unpaired = calls.filter(c => c.step.consequential === true)
    .filter(c => !all.some(d => isRecord(d) && d.chain.seq > c.chain.seq && d.step.tool?.useId === c.step.tool.useId))
    .filter(c => uses.get(c.step.tool.useId) > 1 || !all.some(r => r.step.type === 'tool_result' && r.chain.seq > c.chain.seq && r.step.tool.useId === c.step.tool.useId))
  return {
    principal, action: { type: 'Action', id: 'run' }, resource: { type: 'Run', id: correlationId },
    context: { consequential: false, operation: '', stepsSoFar: finalSeq, approval: 'none', isChildRun: false, totalSteps: finalSeq,
      consequentialCount: all.filter(x => x.step.consequential === true).length, unpairedConsequential: unpaired.length,
      toolCallsSoFar: calls.length, callsOfThisTool: 0, denialsSoFar: all.filter(isRecord).length },
  }
}
const policies = { staticPolicies: { ...rules, [BASELINE]: { effect: 'permit', principal: { op: 'All' }, action: { op: 'All' }, resource: { op: 'All' }, conditions: [] } } }
function evaluate(r) {
  const a = cedar.isAuthorized({ ...r, schema, validateRequest: true, policies, entities })
  if (a.type !== 'success') throw new Error(JSON.stringify(a.errors))
  // The only rule errors in this vector are real Long overflows, as the Cedar core reports them.
  for (const e of a.response.diagnostics.errors) assert.match(e.error.message, /^integer overflow/)
  return { reason: a.response.diagnostics.reason.filter(id => id !== BASELINE).sort(), errors: a.response.diagnostics.errors.map(e => e.policyId).sort() }
}

// ---- findings (Agent Enforcement v1 §5), in the order of its table -----------------------------------------
function findings(envs, controlSet) {
  const f = [], at = s => envs.find(e => e.chain.seq === s)
  const results = envs.filter(x => x.step.type === 'tool_result'), records = envs.filter(isRecord), first = new Map()
  for (const e of results) if (!envs.some(c => c.step.type === 'tool_call' && c.chain.seq < e.chain.seq && c.step.tool.useId === e.step.tool.useId))
    f.push({ code: 'orphan_result', seqs: [e.chain.seq] })
  for (const e of results) { const u = e.step.tool.useId; if (first.has(u)) f.push({ code: 'conflicting_result', seqs: [first.get(u), e.chain.seq] }); else first.set(u, e.chain.seq) }
  for (const e of results) { const d = records.find(r => r.step.tool?.useId === e.step.tool.useId)
    if (d) f.push({ code: 'executed_after_denial', seqs: [d.chain.seq, e.chain.seq].sort((x, y) => x - y) }) }
  const byUse = new Map()
  for (const c of envs.filter(x => x.step.type === 'tool_call')) byUse.set(c.step.tool.useId, [...(byUse.get(c.step.tool.useId) ?? []), c.chain.seq])
  for (const seqs of byUse.values()) if (seqs.length > 1) f.push({ code: 'duplicate_use_id', seqs })
  for (const r of records) {
    const prev = at(r.chain.seq - 1)
    const ok = !(prev && isRecord(prev)) && (r.step.tool
      ? prev?.step.type === 'tool_call' && prev.step.tool.name === r.step.tool.name && prev.step.tool.useId === r.step.tool.useId
      : prev?.step.type !== 'tool_call')
    if (!ok) f.push({ code: 'misplaced_decision', seqs: [r.chain.seq] })
  }
  for (const e of envs.filter(x => x.step.type === 'run_end' && x.step.runDisposition === 'halted'))
    if (!(at(e.chain.seq - 1) && isRecord(at(e.chain.seq - 1)))) f.push({ code: 'unrecorded_halt', seqs: [e.chain.seq] })
  // Every record without tool is a halt, and so is every unavailable record.
  for (const r of records.filter(r => r.step.enforcer.reason === 'unavailable' || !r.step.tool)) {
    const next = at(r.chain.seq + 1)
    if (!(next?.step.type === 'run_end' && next.step.runDisposition === 'halted')) f.push({ code: 'continued_after_halt', seqs: [r.chain.seq] })
  }
  // controlSet: the run's control-set object, { contentType, document }, when the verifier is given its bytes.
  const notV4 = envs.filter(e => e.schemaVersion !== '4').map(e => e.chain.seq)
  if (controlSet?.contentType === 'application/vnd.sigill.control-set+json' && controlSet.document.schemaVersion === '2' && notV4.length)
    f.push({ code: 'evidence_version_mismatch', seqs: notV4 })
  return f
}

// ---- the guard (Control Set v2 §7) -------------------------------------------------------------------------
function runCase(c, idx) {
  const enforcement = { ...base.enforcement, ...c.enforcement }
  const { id, version, ...scope } = { ...base, enforcement }
  const approvalScopeDigest = sha256(jcs(scope))
  const configuration = Object.fromEntries(Object.entries({ 'instruction-set': 'instruction-set v1', 'tool-manifest': 'tool-manifest v1',
    'execution-policy': 'execution-policy v1', ...c.configuration }).map(([k, v]) => [k, sha256(v)]))

  const enforce = enforcement.mode === 'enforce'
  const effectOf = rid => enforce ? rules[rid].annotations.effect ?? enforcement.defaultEffect : 'observe'
  const blocking = ids => ids.filter(r => effectOf(r) !== 'observe')
  const run = builder(idx), out = [], denied = new Set(), notExecuted = []
  let halted = false
  const seal = (a, by) => {
    const i = run.add(a, by), r = request(run.events, i)
    out.push({ seq: i, sealedBy: by, type: a.type, request: r, diagnostics: evaluate(r) })
    if (a.type === 'tool_call') { const b = approvalFor(run.events, i); if (b.takes !== undefined) out[i].boundBy = b.takes }
    return i
  }
  // One enforcement record directly after event i; then the halt when due.
  function deny(i, reason, rid, call, halt) {
    Object.assign(out[i], { outcome: halt ? 'halted' : 'denied', reason }, rid ? { rules: rid } : {})
    if (call) denied.add(call.useId)
    seal({ type: 'authorization', reason, rules: rid, tool: call?.name, useId: call?.useId }, 'guard')
    if (halt) { seal({ type: 'run_end', runDisposition: 'halted' }, 'guard'); halted = true }
  }

  // Decide on the producer event just sealed at index i (engineFails: the Cedar core could not evaluate it).
  function decide(i, engineFails) {
    const s = run.events[i].envelope.step, d = out[i].diagnostics
    if (!enforce || s.type === 'run_end') return void (out[i].outcome = 'allowed')
    if (s.type === 'run_start') {
      if (Object.entries(enforcement.lockedConfiguration).some(([role, hex]) => configuration[role] !== hex)) return deny(i, 'configuration_locked', undefined, undefined, true)
      if (c.engineFailsAtStart) return deny(i, 'unavailable', undefined, undefined, true)
    }
    if (s.type !== 'tool_call') {
      if (engineFails) return deny(i, 'unavailable', undefined, undefined, true)
      const H = d.reason.filter(r => effectOf(r) === 'halt')
      return H.length ? deny(i, 'rule', H, undefined, true) : void (out[i].outcome = 'allowed')
    }
    const call = { name: s.tool.name, useId: s.tool.useId }
    if (engineFails) return deny(i, 'unavailable', undefined, call, true)
    const entity = entities.find(e => e.uid.type === 'Tool' && e.uid.id === call.name)
    const E = blocking(d.errors), R = blocking(d.reason)
    const denial = !entity && enforcement.unknownTools === 'deny' ? { reason: 'unknown_tool' }
      : entity?.attrs.definitionSha256 !== undefined && digestOf(run.events[i], 'tool-definition') !== entity.attrs.definitionSha256 ? { reason: 'tool_changed' }
      : E.length && enforcement.onRuleError === 'deny' ? { reason: 'rule_error', rules: E }
      : R.length ? { reason: 'rule', rules: R } : null
    if (!denial) return void (out[i].outcome = 'allowed')
    const count = run.events.filter(x => isRecord(x.envelope)).length + 1
    // A matching halt rule always halts, whatever reason won the record (Control Set v2 §7.2).
    const halt = d.reason.some(r => effectOf(r) === 'halt') || (enforcement.haltAfterDenials > 0 && count === enforcement.haltAfterDenials)
    deny(i, denial.reason, denial.rules, call, halt)
  }

  decide(seal({ type: 'run_start' }, 'producer'))
  for (const a of c.actions) {
    if (halted) break
    if (a.type === 'tool_result' && denied.has(a.useId)) { notExecuted.push(a.useId); continue }
    const { engineFails, ...action } = a
    decide(seal(action, 'producer'), engineFails === true)
  }
  const rl = { request: runLevel(run.events, run.correlationId) }
  rl.diagnostics = evaluate(rl.request)
  assert.deepEqual(findings(run.events.map(x => x.envelope), { contentType: 'application/vnd.sigill.control-set+json', document: base }), [],
    `${c.name}: a guard run has no findings`)

  // Per-rule results over every request, as Control Set v1 §6.
  const rank = { PASS: 0, INDETERMINATE: 1, FAIL: 2 }
  const res = Object.fromEntries(Object.keys(rules).sort().map(r => [r, { id: r, result: 'PASS', where: [] }]))
  for (const [where, d] of [...out.map(o => [String(o.seq), o.diagnostics]), ['run', rl.diagnostics]]) {
    const mark = (r, result) => { const x = res[r]; if (rank[result] > rank[x.result]) x.result = result; x.where.push(where) }
    for (const r of d.errors) mark(r, 'INDETERMINATE')
    for (const r of d.reason) mark(r, 'FAIL')
  }
  const controls = Object.values(res).map(x => x.result === 'PASS' ? { id: x.id, result: 'PASS' } : x)
  const overall = controls.reduce((o, x) => rank[x.result] > rank[o] ? x.result : o, 'PASS')

  write(`runs/${c.name}.json`, { agentId: AGENT, correlationId: run.correlationId, enforcement, configuration, events: run.events })
  // The facts document (Control Set v2 §8): Control Evaluation v2 §4.5's shape, factsVersion "2", plus entities.
  // Every run here is complete and gap-free, so the prefix is the whole run and the run-level request is present.
  const facts = { factsVersion: '2', throughSeq: run.events.length - 1, missingSeqs: [], runLevel: true, entities: base.cedar.entities ?? [],
    requests: [...out.map(o => ({ seq: o.seq, ...o.request })), { seq: 'run', ...rl.request }] }
  const factsBytes = jcs(facts)
  writeFileSync(join(here, `expected/${c.name}.facts.json`), factsBytes)
  const sealedActions = out.filter(o => o.sealedBy === 'producer').length - 1
  write(`expected/${c.name}.json`, { case: c.name, covers: c.covers, approvalScopeDigest, factsSha256: sha256(factsBytes), engine: ENGINE, events: out, runLevel: rl,
    notExecuted, discarded: c.actions.length - sealedActions - notExecuted.length, controls, overall })
  return { name: c.name, outcomes: out.map(o => o.outcome ? `${o.seq}:${o.outcome}${o.reason ? '/' + o.reason : ''}` : `${o.seq}:${o.type}`).join(' ') }
}

for (const dir of ['runs', 'expected', 'findings']) { rmSync(join(here, dir), { recursive: true, force: true }); mkdirSync(join(here, dir)) }
src.cases.forEach((c, k) => console.log(Object.values(runCase(c, k + 1)).join('  ')))
src.findings.forEach((c, k) => {
  const run = builder(100 + k, c.schemaVersion)
  run.add({ type: 'run_start' }, 'producer')
  for (const a of c.events) run.add(a, 'producer')
  // controlSetContentType: the verifier is given vector 13's control-set bytes under this object content type.
  const controlSet = c.controlSetContentType ? { contentType: c.controlSetContentType, document: base } : undefined
  assert.deepEqual(findings(run.events.map(x => x.envelope), controlSet), c.findings, c.name)
  write(`findings/${c.name}.json`, { agentId: AGENT, correlationId: run.correlationId,
    ...(c.controlSetContentType ? { controlSetContentType: c.controlSetContentType } : {}), events: run.events, findings: c.findings })
})

// ---- envelopes the v4 schema accepts and rejects -----------------------------------------------------------
const sample = read('runs/04-approval-laundering.json').events.map(x => x.envelope)
const byType = t => structuredClone(sample.find(e => e.step.type === t && (t !== 'authorization' || e.step.enforcer)))
const m = (name, t, f) => { const e = byType(t); f(e, e.step); return { name, envelope: e } }
const auth = (name, f) => m(name, 'authorization', f)
const hex = sha256('x'), ids = n => Array.from({ length: n }, (_, k) => `r${k}`)
const extraObj = (e, k, role) => e.objects.push({ uri: 'objects/' + uuid(0x14c000000000 + k), role, contentType: 'application/json' })
write('envelopes.json', {
  description: 'Each envelope is validated against the execution schema of its schemaVersion. `valid` must be accepted, `invalid` rejected.',
  valid: [
    m('tool-call', 'tool_call', () => {}),
    m('approval-with-expiry', 'human_approval', (e, s) => { s.covers.expiresAt = '2026-11-02T10:15:00.250Z' }),
    m('approval-without-covers', 'human_approval', (e, s) => { delete s.covers }),
    m('covers-without-use-id', 'human_approval', (e, s) => { delete s.covers.useId }),
    m('tool-call-with-definition', 'tool_call', e => { extraObj(e, 1, 'tool-definition') }),
    auth('enforcement-record', () => {}),
    auth('enforcement-consequential-false', (e, s) => { s.consequential = false }),
    auth('enforcement-rules-256', (e, s) => { s.rules = ids(256) }),
    auth('enforcement-tool-changed', (e, s) => { delete s.rules; s.enforcer.reason = 'tool_changed' }),
    auth('enforcement-halt-without-tool', (e, s) => { delete s.tool }),
    auth('enforcement-unavailable-with-tool', (e, s) => { delete s.rules; s.enforcer.reason = 'unavailable' }),
    auth('enforcement-unavailable-without-tool', (e, s) => { delete s.rules; delete s.tool; s.enforcer.reason = 'unavailable' }),
    auth('enforcement-configuration-locked', (e, s) => { delete s.rules; delete s.tool; s.enforcer.reason = 'configuration_locked' }),
    auth('producer-authorization-open-vocabulary', (e, s) => { delete s.enforcer; delete s.tool; s.decision = 'allow_with_human_approval'; s.rules = ['r1']; s.detail = 'policy engine of the producer' }),
    m('run-end-halted', 'run_end', (e, s) => { s.runDisposition = 'halted' }),
  ],
  invalid: [
    m('tool-call-without-use-id', 'tool_call', (e, s) => { delete s.tool.useId }),
    m('tool-call-use-id-too-long', 'tool_call', (e, s) => { s.tool.useId = 'u'.repeat(256) }),
    m('tool-call-name-too-long', 'tool_call', (e, s) => { s.tool.name = 't'.repeat(256) }),
    m('tool-result-without-tool', 'tool_result', (e, s) => { delete s.tool }),
    m('tool-result-without-use-id', 'tool_result', (e, s) => { delete s.tool.useId }),
    m('tool-result-status-not-in-v4', 'tool_result', (e, s) => { s.status = 'ok' }),
    m('covers-on-tool-call', 'tool_call', (e, s) => { s.covers = { tool: 'payments.refund', argumentsSha256: hex } }),
    m('covers-without-arguments', 'human_approval', (e, s) => { delete s.covers.argumentsSha256 }),
    m('covers-without-tool', 'human_approval', (e, s) => { delete s.covers.tool }),
    m('covers-tool-too-long', 'human_approval', (e, s) => { s.covers.tool = 't'.repeat(256) }),
    m('covers-use-id-too-long', 'human_approval', (e, s) => { s.covers.useId = 'u'.repeat(256) }),
    m('covers-arguments-uppercase', 'human_approval', (e, s) => { s.covers.argumentsSha256 = hex.toUpperCase() }),
    m('covers-unknown-member', 'human_approval', (e, s) => { s.covers.note = 'ok by phone' }),
    m('covers-expires-not-a-time', 'human_approval', (e, s) => { s.covers.expiresAt = 'tomorrow' }),
    m('covers-expires-not-utc', 'human_approval', (e, s) => { s.covers.expiresAt = '2026-11-02T11:15:00+01:00' }),
    m('covers-expires-microseconds', 'human_approval', (e, s) => { s.covers.expiresAt = '2026-11-02T10:15:00.123456Z' }),
    m('tool-definition-on-tool-result', 'tool_result', e => { extraObj(e, 2, 'tool-definition') }),
    m('two-tool-definitions', 'tool_call', e => { extraObj(e, 3, 'tool-definition'); extraObj(e, 4, 'tool-definition') }),
    m('enforcer-on-tool-call', 'tool_call', (e, s) => { s.enforcer = { engine: ENGINE, factsVersion: '2', reason: 'rule' } }),
    m('rules-on-tool-call', 'tool_call', (e, s) => { s.rules = ['r1'] }),
    m('run-start-with-directive', 'run_start', (e, s) => { s.directive = { serial: 7, signatureSha256: hex } }),
    auth('enforcer-allowed', (e, s) => { s.decision = 'allowed' }),
    auth('enforcer-open-decision', (e, s) => { s.decision = 'allow_with_human_approval' }),
    auth('enforcer-consequential-true', (e, s) => { s.consequential = true }),
    auth('enforcer-with-detail', (e, s) => { s.detail = 'denied by policy' }),
    auth('enforcer-with-policy-id', (e, s) => { s.policyId = 'p1' }),
    auth('enforcer-rule-without-rules', (e, s) => { delete s.rules }),
    auth('enforcer-rule-empty-rules', (e, s) => { s.rules = [] }),
    auth('enforcer-rule-error-without-rules', (e, s) => { delete s.rules; s.enforcer.reason = 'rule_error' }),
    auth('enforcer-rule-error-without-tool', (e, s) => { delete s.tool; s.enforcer.reason = 'rule_error' }),
    auth('enforcer-unknown-tool-with-rules', (e, s) => { s.enforcer.reason = 'unknown_tool' }),
    auth('enforcer-unknown-tool-without-tool', (e, s) => { delete s.rules; delete s.tool; s.enforcer.reason = 'unknown_tool' }),
    auth('enforcer-tool-changed-without-tool', (e, s) => { delete s.rules; delete s.tool; s.enforcer.reason = 'tool_changed' }),
    auth('enforcer-tool-changed-empty-rules', (e, s) => { s.rules = []; s.enforcer.reason = 'tool_changed' }),
    auth('enforcer-configuration-locked-with-tool', (e, s) => { delete s.rules; s.enforcer.reason = 'configuration_locked' }),
    auth('enforcer-unavailable-with-rules', (e, s) => { s.enforcer.reason = 'unavailable' }),
    auth('enforcer-tool-without-use-id', (e, s) => { delete s.tool.useId }),
    auth('enforcer-facts-version-1', (e, s) => { s.enforcer.factsVersion = '1' }),
    auth('enforcer-unknown-reason', (e, s) => { s.enforcer.reason = 'manual' }),
    auth('enforcer-reason-suspended-not-in-v4', (e, s) => { delete s.rules; s.enforcer.reason = 'suspended' }),
    auth('enforcer-reason-denial-limit-not-in-v4', (e, s) => { delete s.rules; delete s.tool; s.enforcer.reason = 'denial_limit' }),
    auth('enforcer-directive-not-in-v4', (e, s) => { s.enforcer.directive = { serial: 7, signatureSha256: hex } }),
    auth('enforcer-engine-free-text', (e, s) => { s.enforcer.engine = 'my policy engine' }),
    auth('rules-duplicate', (e, s) => { s.rules = ['a', 'a'] }),
    auth('rules-bad-id', (e, s) => { s.rules = ['no web search'] }),
    auth('rules-257', (e, s) => { s.rules = ids(257) }),
    m('run-end-unknown-disposition', 'run_end', (e, s) => { s.runDisposition = 'stopped' }),
    m('v4-member-in-v3', 'human_approval', e => { e.schemaVersion = '3' }),
    m('halted-in-v3', 'run_end', (e, s) => { e.schemaVersion = '3'; s.runDisposition = 'halted' }),
  ],
})
