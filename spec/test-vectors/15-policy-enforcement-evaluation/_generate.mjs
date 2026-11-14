// Generates runs/, expected/, invalid-evaluations/, envelopes.json and the control-set variants of vector 15 from
// cases.json, vector 13's control set and vector 14's runs. The enforcement comparison is ControlEvaluation v3 §4–§6,
// implemented here from the text; facts are Control Set v2 §8; Cedar results come from the official core.
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
const args = read('../14-policy-enforcement/cases.json').arguments
const jcs = v => Array.isArray(v) ? `[${v.map(jcs).join(',')}]`
  : v && typeof v === 'object' ? `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${jcs(v[k])}`).join(',')}}`
  : JSON.stringify(v)
const sha256 = s => createHash('sha256').update(s, 'utf8').digest('hex')
const write = (p, v) => writeFileSync(join(here, p), JSON.stringify(v, null, 1) + '\n')
const clone = v => JSON.parse(JSON.stringify(v))

const AGENT = 'urn:example:agent:support'
const T0 = Date.parse('2026-11-02T10:00:00.000Z')
const ENGINE = `cedar-policy@${cedar.getCedarVersion()}`
const BASELINE = 'sigill:baseline-permit'
const uuid = n => '00000000-0000-4000-8000-' + n.toString(16).padStart(12, '0')
const stubSig = (corr, what) => sha256(`stub-signature:${corr}:${what}`)
const isRecord = s => s.type === 'authorization' && s.enforcer !== undefined

// ---- control sets: vector 13's, and three variants ---------------------------------------------------------
const weight = base.cedar.policies.staticPolicies['preview-weight'].conditions
const variants = { '13': base, b: clone(base), c: clone(base), d: clone(base) }
Object.assign(variants.b.cedar.policies.staticPolicies, {
  'halt-weight-call': { effect: 'forbid', principal: { op: 'All' },
    action: { op: '==', entity: { type: 'Action', id: 'tool_call' } },
    resource: { op: '==', entity: { type: 'Tool', id: 'ledger.preview' } },
    conditions: clone(weight), annotations: { effect: 'halt', id: 'halt-weight-call' } },
  'halt-weight-retrieval': { effect: 'forbid', principal: { op: 'All' },
    action: { op: '==', entity: { type: 'Action', id: 'retrieval' } }, resource: { op: 'All' },
    conditions: clone(weight), annotations: { effect: 'halt', id: 'halt-weight-retrieval' } },
})
delete variants.c.cedar
delete variants.d.enforcement
for (const v of ['b', 'c', 'd']) writeFileSync(join(here, `control-set-${v}.json`), JSON.stringify(variants[v], null, 2) + '\n')
// The variants validate in Cedar's strict mode against schema v2 (the rules and the entities).
for (const v of ['b', 'd']) {
  const r = cedar.validate({ validationSettings: { mode: 'strict' }, schema, policies: variants[v].cedar.policies })
  assert.equal(r.type, 'success'); assert.deepEqual(r.validationErrors, [], `variant ${v} validates`)
}
const docFor = c => {
  const d = clone(variants[c.controlSet ?? '13'])
  if (c.enforcement) d.enforcement = { ...d.enforcement, ...c.enforcement }
  return d
}
const digestsOf = d => {
  const { id, version, ...scope } = d
  return { approvalScopeDigest: sha256(jcs(scope)), ...(d.cedar ? { cedarDigest: sha256(jcs(d.cedar)) } : {}) }
}

// ---- envelopes (as vector 14's builder; records, engines, gaps and child runs added) -----------------------
function build(c, idx, correlationId) {
  const doc = docFor(c), entities = doc.cedar?.entities ?? [], events = []
  for (const a of [{ type: 'run_start' }, ...c.events]) {
    const seq = events.length, ms = T0 + seq * 1000
    const step = { type: a.type, eventTime: new Date(ms).toISOString() }
    const objects = [], objectDigests = {}
    const obj = (role, bytes) => {
      const uri = 'objects/' + uuid(0x15b000000000 + idx * 0x100000 + seq * 16 + objects.length)
      objects.push({ uri, role, contentType: 'application/json' }); objectDigests[uri] = sha256(bytes)
    }
    if (a.consequential) step.consequential = true
    if (a.tool) step.tool = { name: a.tool, useId: a.useId }
    if (a.type === 'tool_call') {
      obj('tool-arguments', args[a.args])
      const def = 'definition' in a ? a.definition
        : entities.some(e => e.uid.id === a.tool && e.attrs.definitionSha256) ? `${a.tool} definition` : null
      if (def !== null) obj('tool-definition', def)
    }
    if (a.type === 'tool_result') obj('tool-result', '{"ok":true}')
    if (a.type === 'human_approval') {
      Object.assign(step, { decision: a.decision, approver: 'urn:example:approver:1' })
      const { args: k, ...cv } = a.covers
      step.covers = { ...cv, argumentsSha256: sha256(args[k]) }
      obj('approval-receipt', `{"receipt":${seq}}`)
    }
    if (a.type === 'delegation') {
      step.delegation = { childCorrelationId: 'urn:uuid:' + uuid(0x15d000000000 + idx), childAgentId: a.childAgentId }
      obj('delegation-input', '{"task":"review"}')
    }
    if (a.type === 'delegation_result') step.delegation = { childCorrelationId: 'urn:uuid:' + uuid(0x15d000000000 + idx),
      childRunEndSignatureSha256: stubSig('urn:uuid:' + uuid(0x15d000000000 + idx), 'run_end'), childDisposition: 'completed' }
    if (a.type === 'authorization') {
      step.decision = 'denied'
      if (a.rules) step.rules = a.rules
      step.enforcer = { engine: a.engine ?? ENGINE, factsVersion: '2', reason: a.reason }
    }
    if (a.type === 'run_end') Object.assign(step, { finalSeq: seq, finalPrevSignatureSha256: stubSig(correlationId, seq - 1),
      runDisposition: a.runDisposition ?? 'completed' })
    const binds = seq ? {} : { binds: { controlArtifactSignatureSha256: stubSig(correlationId, 'control'),
      ...(c.child ? { parentCorrelationId: c.child.parentCorrelationId,
        parentDelegationSignatureSha256: c.child.parentDelegationSignatureSha256 } : {}) } }
    const envelope = {
      schemaName: 'AgentExecutionEvidence', schemaVersion: c.schemaVersion ?? '4', evidenceId: uuid(0x15a000000000 + idx * 0x10000 + seq),
      createdAt: new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z'), actor: { type: 'agent', id: AGENT },
      activity: { name: 'support-session', correlationId }, chain: seq ? { seq, prevSignatureSha256: stubSig(correlationId, seq - 1) } : { seq },
      step, ...binds, objects,
    }
    events.push({ envelope, objectDigests })
  }
  return events.filter(e => !(c.drop ?? []).includes(e.envelope.chain.seq))
}

// ---- facts v2 (Control Set v2 §8) over the contiguous prefix -----------------------------------------------
const digestOf = (ev, role) => {
  const a = ev.envelope.objects.filter(o => o.role === role)
  return a.length === 1 ? ev.objectDigests[a[0].uri] : undefined
}
function approvalOne(evs, j, consumed) {
  const e = evs[j].envelope, u = e.step.tool.useId, t = e.step.tool.name, a = digestOf(evs[j], 'tool-arguments')
  const earlier = evs.slice(0, j).map((x, k) => [k, x.envelope.step]).filter(([, s]) => s.type === 'human_approval')
  const argsOk = c => a !== undefined && c.argumentsSha256 === a
  if (earlier.some(([, s]) => s.decision === 'rejected' && s.covers && ((s.covers.useId !== undefined && s.covers.useId === u) || (s.covers.tool === t && argsOk(s.covers)))))
    return { approval: 'rejected' }
  const match = earlier.find(([k, s]) => s.decision === 'approved' && s.covers && s.covers.tool === t && argsOk(s.covers)
    && (s.covers.useId === undefined || s.covers.useId === u)
    && (!s.covers.expiresAt || Date.parse(e.step.eventTime) < Date.parse(s.covers.expiresAt)) && !consumed.has(k))
  if (match) return { approval: 'bound', takes: match[0] }
  return { approval: earlier.length ? 'unbound' : 'none' }
}
function approvalFor(evs, i) {
  const consumed = new Set()
  for (let j = 0; j <= i; j++) {
    if (evs[j].envelope.step.type !== 'tool_call') continue
    const r = approvalOne(evs, j, consumed)
    if (r.takes !== undefined) consumed.add(r.takes)
    if (j === i) return r
  }
}
function request(evs, i, child) {
  const e = evs[i].envelope, s = e.step, seq = e.chain.seq
  const upTo = evs.slice(0, i + 1).map(x => x.envelope)
  const calls = upTo.filter(x => x.step.type === 'tool_call')
  const toolStep = s.type === 'tool_call' || s.type === 'tool_result'
  return {
    principal: { type: 'Agent', id: AGENT }, action: { type: 'Action', id: s.type },
    resource: toolStep ? { type: 'Tool', id: s.tool.name } : { type: 'Step', id: String(seq) },
    context: {
      consequential: s.consequential === true, operation: s.tool?.operation ?? '', stepsSoFar: seq,
      approval: s.type === 'tool_call' ? approvalFor(evs, i).approval : upTo.slice(0, -1).some(x => x.step.type === 'human_approval') ? 'unbound' : 'none',
      isChildRun: child, totalSteps: 0, consequentialCount: upTo.filter(x => x.step.consequential === true).length, unpairedConsequential: 0,
      toolCallsSoFar: calls.length, callsOfThisTool: toolStep ? calls.filter(c => c.step.tool.name === s.tool.name).length : 0,
      denialsSoFar: upTo.slice(0, -1).filter(x => isRecord(x.step)).length,
    },
  }
}
function runLevel(evs, correlationId, child) {
  const all = evs.map(x => x.envelope), finalSeq = all.at(-1).step.finalSeq
  const calls = all.filter(x => x.step.type === 'tool_call'), uses = new Map()
  for (const c of calls) uses.set(c.step.tool.useId, (uses.get(c.step.tool.useId) ?? 0) + 1)
  const unpaired = calls.filter(c => c.step.consequential === true)
    .filter(c => !all.some(d => isRecord(d.step) && d.chain.seq > c.chain.seq && d.step.tool?.useId === c.step.tool.useId))
    .filter(c => uses.get(c.step.tool.useId) > 1 || !all.some(r => r.step.type === 'tool_result' && r.chain.seq > c.chain.seq && r.step.tool.useId === c.step.tool.useId))
  return {
    principal: { type: 'Agent', id: AGENT }, action: { type: 'Action', id: 'run' }, resource: { type: 'Run', id: correlationId },
    context: { consequential: false, operation: '', stepsSoFar: finalSeq, approval: 'none', isChildRun: child, totalSteps: finalSeq,
      consequentialCount: all.filter(x => x.step.consequential === true).length, unpairedConsequential: unpaired.length,
      toolCallsSoFar: calls.length, callsOfThisTool: 0, denialsSoFar: all.filter(x => isRecord(x.step)).length },
  }
}
function evaluator(doc) {
  const rules = doc.cedar?.policies.staticPolicies ?? {}, entities = doc.cedar?.entities ?? []
  const policies = { staticPolicies: { ...rules, [BASELINE]: { effect: 'permit', principal: { op: 'All' }, action: { op: 'All' }, resource: { op: 'All' }, conditions: [] } } }
  return r => {
    const a = cedar.isAuthorized({ ...r, schema, validateRequest: true, policies, entities })
    if (a.type !== 'success') throw new Error(JSON.stringify(a.errors))
    for (const e of a.response.diagnostics.errors) assert.match(e.error.message, /^integer overflow/)
    return { reason: a.response.diagnostics.reason.filter(id => id !== BASELINE).sort(), errors: a.response.diagnostics.errors.map(e => e.policyId).sort() }
  }
}

// ---- Agent Enforcement v1 §5 findings (vector 14's, without a control set) ---------------------------------
function chainFindings(envs) {
  const f = [], at = s => envs.find(e => e.chain.seq === s)
  const records = envs.filter(e => isRecord(e.step)), results = envs.filter(x => x.step.type === 'tool_result'), first = new Map()
  for (const e of results) if (!envs.some(c => c.step.type === 'tool_call' && c.chain.seq < e.chain.seq && c.step.tool.useId === e.step.tool.useId && c.step.tool.name === e.step.tool.name))
    f.push({ code: 'orphan_result', seqs: [e.chain.seq] })
  for (const e of results) { const u = e.step.tool.useId; if (first.has(u)) f.push({ code: 'conflicting_result', seqs: [first.get(u), e.chain.seq] }); else first.set(u, e.chain.seq) }
  for (const e of results) { const d = records.find(r => r.step.tool?.useId === e.step.tool.useId)
    if (d) f.push({ code: 'executed_after_denial', seqs: [d.chain.seq, e.chain.seq].sort((x, y) => x - y) }) }
  const byUse = new Map()
  for (const c of envs.filter(x => x.step.type === 'tool_call')) byUse.set(c.step.tool.useId, [...(byUse.get(c.step.tool.useId) ?? []), c.chain.seq])
  for (const seqs of byUse.values()) if (seqs.length > 1) f.push({ code: 'duplicate_use_id', seqs })
  for (const r of records) {
    const prev = at(r.chain.seq - 1)
    const ok = !(prev && isRecord(prev.step)) && (r.step.tool
      ? prev?.step.type === 'tool_call' && prev.step.tool.name === r.step.tool.name && prev.step.tool.useId === r.step.tool.useId
      : prev?.step.type !== 'tool_call')
    if (!ok) f.push({ code: 'misplaced_decision', seqs: [r.chain.seq] })
  }
  for (const e of envs.filter(x => x.step.type === 'run_end' && x.step.runDisposition === 'halted'))
    if (!(at(e.chain.seq - 1) && isRecord(at(e.chain.seq - 1).step))) f.push({ code: 'unrecorded_halt', seqs: [e.chain.seq] })
  for (const r of records.filter(r => r.step.enforcer.reason === 'unavailable' || !r.step.tool)) {
    const next = at(r.chain.seq + 1)
    if (!(next?.step.type === 'run_end' && next.step.runDisposition === 'halted')) f.push({ code: 'continued_after_halt', seqs: [r.chain.seq] })
  }
  // Every run here is under a v2 policy control set, which the evaluator holds: events that are not all v4 mismatch.
  const notV4 = envs.filter(e => e.schemaVersion !== '4').map(e => e.chain.seq)
  if (notV4.length) f.push({ code: 'evidence_version_mismatch', seqs: notV4 })
  return f
}

// ---- the enforcement comparison (ControlEvaluation v3 §4–§6) ------------------------------------------------
const CHAIN = ['executed_after_denial', 'misplaced_decision', 'unrecorded_halt', 'duplicate_use_id', 'continued_after_halt',
  'evidence_version_mismatch']
const LET = ['refusal_missing', 'unknown_tool_allowed', 'configuration_not_enforced', 'halt_missing']
const FINDINGS = [...LET, 'unfounded_record', 'unfounded_halt', 'reason_mismatch', 'rules_mismatch']
function settingsOf(doc) {
  const e = doc.enforcement ?? {}, mode = e.mode ?? 'observe', defaultEffect = e.defaultEffect ?? 'deny'
  const rules = doc.cedar?.policies.staticPolicies ?? {}
  return { mode, locked: e.lockedConfiguration ?? {}, unknownTools: e.unknownTools ?? 'allow', onRuleError: e.onRuleError ?? 'deny',
    haltAfterDenials: e.haltAfterDenials ?? 0, entities: doc.cedar?.entities ?? [],
    effect: rid => mode === 'enforce' ? (rules[rid]?.annotations.effect ?? defaultEffect) : 'observe' }
}
// §5.2: what was due after the event, from its diagnostics and its facts.
function dueOf(ev, d, req, st, configuration) {
  const s = ev.envelope.step
  if (isRecord(s) || s.type === 'run_end') return null                                         // 1
  if (st.mode !== 'enforce') return null                                                        // 2
  if (s.type === 'run_start' && Object.entries(st.locked).some(([role, hex]) => configuration[role] !== hex))
    return { reason: 'configuration_locked', rules: [], halt: true }                             // 3
  const H = d.reason.filter(r => st.effect(r) === 'halt')
  if (s.type !== 'tool_call') return H.length ? { reason: 'rule', rules: H, halt: true } : null // 5
  const blocking = ids => ids.filter(r => ['deny', 'halt'].includes(st.effect(r)))              // 4
  const entity = st.entities.find(e => e.uid.type === 'Tool' && e.uid.id === s.tool.name)
  const E = blocking(d.errors), R = blocking(d.reason)
  const denial = !entity && st.unknownTools === 'deny' ? { reason: 'unknown_tool', rules: [] }
    : entity?.attrs.definitionSha256 !== undefined && digestOf(ev, 'tool-definition') !== entity.attrs.definitionSha256 ? { reason: 'tool_changed', rules: [] }
    : E.length && st.onRuleError === 'deny' ? { reason: 'rule_error', rules: E }
    : R.length ? { reason: 'rule', rules: R } : null
  if (!denial) return null
  return { ...denial, halt: H.length > 0 || (st.haltAfterDenials > 0 && req.context.denialsSoFar + 1 >= st.haltAfterDenials) }
}
function compare(prefix, hasRunEnd, diag, reqs, st, configuration) {
  const T = prefix.length - 1, at = s => prefix[s]?.envelope
  const records = prefix.map(x => x.envelope).filter(e => isRecord(e.step))
  const engines = [...new Set(records.map(r => r.step.enforcer.engine))]
  const recordedEngine = engines.length === 1 ? engines[0] : undefined
  const chain = chainFindings(prefix.map(x => x.envelope))
    .some(f => CHAIN.includes(f.code) && !(f.code === 'continued_after_halt' && !hasRunEnd && f.seqs[0] === T))
  const notPerformed = chain ? 'chain_inconsistent' : engines.length > 1 ? 'engine_inconsistent'
    : recordedEngine !== undefined && recordedEngine !== ENGINE ? 'engine_unavailable' : undefined
  const m = { comparison: notPerformed ? 'not_performed' : 'performed' }
  if (notPerformed) m.notPerformed = notPerformed
  if (recordedEngine !== undefined) m.recordedEngine = recordedEngine
  if (notPerformed) return { member: m, dues: null }
  const recordedOf = s => {                                                                       // §5.3
    const n = at(s + 1), e2 = at(s + 2)
    if (!n || !isRecord(n.step)) return { out: 'none' }
    return { out: e2?.step.type === 'run_end' && e2.step.runDisposition === 'halted' ? 'halted' : 'refused',
      reason: n.step.enforcer.reason, rules: [...new Set(n.step.rules ?? [])].sort() }
  }
  const isOpen = s => !hasRunEnd && (s === T || (s === T - 1 && isRecord(at(T).step)))           // §5.4
  const decisions = [], dues = []
  for (let s = 0; s <= T; s++) {
    const due = dueOf(prefix[s], diag[s], reqs[s], st, configuration), dueOut = !due ? 'none' : due.halt ? 'halted' : 'refused'
    dues.push(due)
    const unknown = isOpen(s) && s === T, rec = recordedOf(s)
    if (dueOut === 'none' && (unknown || rec.out === 'none')) continue                           // not listed
    const x = { seq: s, due: dueOut }
    if (due) { x.dueReason = due.reason; if (['rule', 'rule_error'].includes(due.reason)) x.dueRules = due.rules }
    if (!unknown) x.recorded = rec.out
    if (isOpen(s)) x.outcome = 'pending'
    else if (rec.out !== 'none' && rec.reason === 'unavailable' && due?.reason !== 'configuration_locked') x.outcome = 'not_checkable'
    else {
      const call = at(s).step.type === 'tool_call', both = dueOut !== 'none' && rec.out !== 'none', rank = { none: 0, refused: 1, halted: 2 }
      const applies = {
        refusal_missing: call && dueOut !== 'none' && due.reason !== 'unknown_tool' && rec.out === 'none',
        unknown_tool_allowed: call && due?.reason === 'unknown_tool' && rec.out === 'none',
        configuration_not_enforced: due?.reason === 'configuration_locked' && rec.out !== 'halted',
        halt_missing: dueOut === 'halted' && due.reason !== 'configuration_locked' && rec.out !== 'halted',
        unfounded_record: dueOut === 'none' && rec.out !== 'none',
        unfounded_halt: dueOut === 'refused' && rec.out === 'halted',
        reason_mismatch: both && rec.reason !== due.reason,
        rules_mismatch: both && rec.reason === due.reason && jcs(rec.rules) !== jcs([...new Set(due.rules)].sort()),
      }
      const f = FINDINGS.filter(k => applies[k])
      // §5.5: a let-through finding applies exactly when the recorded outcome is less than the due one.
      assert.equal(f.some(k => LET.includes(k)), rank[rec.out] < rank[dueOut], `class at seq ${s}`)
      x.outcome = f.some(k => LET.includes(k)) ? 'let_through' : f.length ? 'over_enforced' : 'as_required'
      if (f.length) x.findings = f
    }
    decisions.push(x)
  }
  const outcomes = new Set(decisions.map(x => x.outcome))
  m.decisions = decisions
  m.result = ['let_through', 'over_enforced', 'not_checkable', 'pending'].find(r => outcomes.has(r)) ?? 'as_required'
  return { member: m, dues }
}

// ---- one evaluation: facts, results, comparison -----------------------------------------------------------
function evaluate(name, doc, events, correlationId, configuration, child) {
  const bySeq = new Map(events.map(e => [e.envelope.chain.seq, e]))
  const max = Math.max(...bySeq.keys())
  const missing = []; for (let s = 0; s <= max; s++) if (!bySeq.has(s)) missing.push(s)
  const T = missing.length ? missing[0] - 1 : max
  const prefix = []; for (let s = 0; s <= T; s++) prefix.push(bySeq.get(s))
  const runEnd = prefix.find(e => e.envelope.step.type === 'run_end'), hasRunEnd = runEnd !== undefined
  const reqs = prefix.map((_, i) => request(prefix, i, child)), ev = evaluator(doc)
  const diag = reqs.map(ev), runLevelOn = hasRunEnd && !missing.length
  const rl = runLevelOn ? runLevel(prefix, correlationId, child) : null
  const facts = { factsVersion: '2', throughSeq: T, missingSeqs: missing, runLevel: runLevelOn, entities: doc.cedar?.entities ?? [],
    requests: [...reqs.map((r, i) => ({ seq: i, ...r })), ...(rl ? [{ seq: 'run', ...rl }] : [])] }
  // Per-rule results (Control Set v1 §6), FAIL > INDETERMINATE > PASS, where in request order.
  const rank = { PASS: 0, INDETERMINATE: 1, FAIL: 2 }, rules = doc.cedar?.policies.staticPolicies ?? {}
  const res = Object.fromEntries(Object.keys(rules).sort().map(r => [r, { id: r, result: 'PASS', where: [] }]))
  for (const [where, d] of [...diag.map((d, i) => [String(i), d]), ...(rl ? [['run', ev(rl)]] : [])]) {
    const mark = (r, result) => { const x = res[r]; if (rank[result] > rank[x.result]) x.result = result; x.where.push(where) }
    for (const r of d.errors) mark(r, 'INDETERMINATE')
    for (const r of d.reason) mark(r, 'FAIL')
  }
  const controls = Object.values(res).map(x => x.result === 'PASS' ? { id: x.id, result: 'PASS' } : x)
  const overall = controls.reduce((o, x) => rank[x.result] > rank[o] ? x.result : o, 'PASS')
  const { member, dues } = compare(prefix, hasRunEnd, diag, reqs, settingsOf(doc), configuration)
  const factsBytes = jcs(facts)
  return { facts, factsBytes, member, dues, diag, prefix: { throughSeq: T, finalSeq: runEnd ? runEnd.envelope.step.finalSeq : null, missingSeqs: missing },
    state: hasRunEnd && !missing.length ? 'finalized' : 'partial', controls, overall,
    enforcementFindings: chainFindings(prefix.map(x => x.envelope)) }
}
const expectedOf = (name, covers, controlSet, doc, e) => ({ case: name, covers, controlSet, ...digestsOf(doc),
  factsSha256: sha256(e.factsBytes), prefix: e.prefix, state: e.state, evaluatorEngine: ENGINE, controls: e.controls,
  overall: e.overall, enforcementFindings: e.enforcementFindings, enforcement: e.member })

for (const dir of ['runs', 'expected', 'invalid-evaluations']) { rmSync(join(here, dir), { recursive: true, force: true }); mkdirSync(join(here, dir)) }
const out = {}

// ---- vector 14's 35 guard runs: computed, never copied; the computed due outcome is the guard's ------------
const v14 = read('../14-policy-enforcement/cases.json').cases.map(c => c.name)
const tally = {}
for (const name of v14) {
  const run = read(`../14-policy-enforcement/runs/${name}.json`), want = read(`../14-policy-enforcement/expected/${name}.json`)
  const doc = { ...clone(base), enforcement: run.enforcement }
  const e = evaluate(name, doc, run.events, run.correlationId, run.configuration, false)
  assert.equal(e.factsBytes, readFileSync(join(here, `../14-policy-enforcement/expected/${name}.facts.json`), 'utf8'), `${name}: facts`)
  for (const g of want.events.filter(g => g.sealedBy === 'producer' && g.type !== 'run_end')) {
    const due = e.dues[g.seq]
    if (g.outcome === 'allowed' || g.reason === 'unavailable') assert.equal(due, null, `${name} seq ${g.seq}: nothing due`)
    else assert.deepEqual([due?.reason, due?.rules, due?.halt], [g.reason, g.rules ?? [], g.outcome === 'halted'], `${name} seq ${g.seq}: due = the guard's outcome`)
  }
  assert.deepEqual(e.enforcementFindings, [], `${name}: no chain finding`)
  assert.ok(!(e.member.decisions ?? []).some(d => d.findings), `${name}: no finding`)
  tally[e.member.result] = (tally[e.member.result] ?? 0) + 1
  out[`14-${name}`] = { doc, run, e }
  write(`expected/14-${name}.json`, expectedOf(`14-${name}`, want.covers, '13', doc, e))
}
assert.deepEqual(tally, { as_required: 32, not_checkable: 3 })

// ---- the new runs ------------------------------------------------------------------------------------------
src.cases.forEach((c, k) => {
  const idx = k + 1, doc = docFor(c)
  let correlationId = 'urn:uuid:' + uuid(0x150000000000 + idx), child = c.child
  if (child?.parent) {  // a child of a vector 14 run: its run_start binds that run's delegation (seq 1)
    const p = read(`../14-policy-enforcement/runs/${child.parent}.json`), d = p.events[1].envelope
    correlationId = d.step.delegation.childCorrelationId
    child = { parentCorrelationId: p.correlationId, parentDelegationSignatureSha256: stubSig(p.correlationId, 1) }
  }
  const configuration = Object.fromEntries(Object.entries({ 'instruction-set': 'instruction-set v1', 'tool-manifest': 'tool-manifest v1',
    'execution-policy': 'execution-policy v1', ...c.configuration }).map(([r, v]) => [r, sha256(v)]))
  const events = build({ ...c, child }, idx, correlationId)
  const e = evaluate(c.name, doc, events, correlationId, configuration, !!child)
  out[c.name] = { doc, run: { correlationId, configuration, events }, e }
  write(`runs/${c.name}.json`, { agentId: AGENT, correlationId, controlSet: c.controlSet ?? '13',
    enforcement: doc.enforcement ?? null, configuration, events })
  writeFileSync(join(here, `expected/${c.name}.facts.json`), e.factsBytes)
  write(`expected/${c.name}.json`, expectedOf(c.name, c.covers, c.controlSet ?? '13', doc, e))
})
const member = n => out[n].e.member
const decision = (n, s) => member(n).decisions.find(d => d.seq === s)

// The draft's readings that the computation must confirm (03-vectors.md), a sample per finding and outcome.
assert.deepEqual(decision('e01-refusal-missing', 1).findings, ['refusal_missing'])
assert.deepEqual(decision('e09-unknown-tool-and-halt-missing', 1).findings, ['unknown_tool_allowed', 'halt_missing'])
assert.deepEqual(decision('e17-two-classes-one-event', 5).findings, ['halt_missing', 'rules_mismatch'])
assert.equal(decision('e43-configuration-locked-unavailable-record', 0).outcome, 'over_enforced')
assert.deepEqual(member('e07-halt-missing-denial-count').decisions.map(d => d.findings ?? []), [[], ['halt_missing'], ['halt_missing']])
assert.deepEqual(member('e23-engine-not-available'), { comparison: 'not_performed', notPerformed: 'engine_unavailable', recordedEngine: 'cedar-policy@99.0.0' })
assert.deepEqual(member('e24-engine-inconsistent'), { comparison: 'not_performed', notPerformed: 'engine_inconsistent' })
for (const n of src.cases.map(c => c.name).filter(n => n.startsWith('c')))
  assert.equal(member(n).notPerformed, 'chain_inconsistent', n)
assert.equal(member('e46-open-on-unavailable-record').comparison, 'performed')
assert.deepEqual(out['e46-open-on-unavailable-record'].e.enforcementFindings.map(f => f.code), ['continued_after_halt'])

// ---- ControlEvaluation v3 envelopes ------------------------------------------------------------------------
const hex = s => sha256(s)
function evaluation(n, extra = {}) {
  const { doc, e } = out[n], d = digestsOf(doc)
  return {
    schemaName: 'ControlEvaluation', schemaVersion: '3', kind: 'policy', evidenceId: uuid(0x15f000000000),
    createdAt: '2026-11-02T10:20:00.000Z', actor: { type: 'verifier', id: 'urn:example:policy-evaluator', version: '1.0.0' },
    activity: { name: 'support-session', correlationId: out[n].run.correlationId },
    subject: { controlArtifactSignatureSha256: hex('control'), throughSignatureSha256: hex('through'),
      ...(e.state === 'finalized' ? { runEndSignatureSha256: hex('through') } : {}) },
    controlSet: { id: doc.id, version: doc.version }, controls: e.controls, overall: e.overall,
    evaluatedAt: '2026-11-02T10:19:58.000Z',
    policy: { ...d, policyStatus: 'unapproved',
      evaluator: { engine: ENGINE, factsVersion: '2', ...(doc.cedar ? { schemaSha256: doc.cedar.schemaSha256 } : {}) },
      prefix: e.prefix, state: e.state, enforcement: clone(e.member) },
    objects: [{ uri: 'objects/' + uuid(0x15c000000001), role: 'control-set', contentType: 'application/vnd.sigill.control-set+json', sizeBytes: 4096 },
      { uri: 'objects/' + uuid(0x15c000000002), role: 'evaluation-facts', contentType: 'application/json', sizeBytes: e.factsBytes.length }],
    ...extra,
  }
}
const A = () => evaluation('14-02-denied-by-rule')
const edit = (env, f) => { const x = clone(env); f(x, x.policy?.enforcement); return x }
const notPerformed = (env, reason, engine) => edit(env, (x, m) => { delete m.decisions; delete m.result
  m.comparison = 'not_performed'; m.notPerformed = reason; if (engine) m.recordedEngine = engine; else delete m.recordedEngine })
const kindOf = (kind, actorType) => edit(A(), x => {
  x.kind = kind; delete x.policy; x.actor.type = actorType
  x.subject = { controlArtifactSignatureSha256: hex('control'), runEndSignatureSha256: hex('through') }
  x.controls = [{ id: 'ticket-closed', result: 'PASS' }]; x.overall = 'PASS'
  x.objects = kind === 'state'
    ? [{ uri: 'objects/' + uuid(0x15c000000003), role: 'observed-state', contentType: 'application/json', sizeBytes: 40 },
       { uri: 'objects/' + uuid(0x15c000000001), role: 'control-set', contentType: 'application/json', sizeBytes: 64 }]
    : [{ uri: 'objects/' + uuid(0x15c000000001), role: 'control-set', contentType: 'application/vnd.sigill.control-set+json', sizeBytes: 4096 }]
})
const dec = (x, i, f) => f(x.policy.enforcement.decisions[i])
write('envelopes.json', {
  description: 'Each envelope is validated against control-evaluation-v3.schema.json. `valid` must be accepted, `invalid` rejected.',
  valid: [
    { name: 'example-a-as-required', envelope: A() },
    { name: 'example-b-let-through', envelope: evaluation('e01-refusal-missing') },
    { name: 'example-c-chain-inconsistent', envelope: evaluation('c01-executed-after-denial') },
    { name: 'example-d-no-rules', envelope: evaluation('e40-no-rules-let-through') },
    { name: 'not-performed-engine-unavailable', envelope: evaluation('e23-engine-not-available') },
    { name: 'not-performed-engine-inconsistent', envelope: evaluation('e24-engine-inconsistent') },
    { name: 'pending-without-recorded', envelope: evaluation('e25-open-refusal-pending') },
    { name: 'pending-with-recorded', envelope: evaluation('e26-open-halt-pending') },
    { name: 'controls-empty', envelope: evaluation('e39-no-rules-refused') },
    { name: 'v3-state', envelope: kindOf('state', 'verifier') },
    { name: 'v3-attested', envelope: kindOf('attested', 'producer') },
  ],
  invalid: [
    { name: 'facts-version-1', envelope: edit(A(), x => { x.policy.evaluator.factsVersion = '1' }) },
    { name: 'policy-without-enforcement', envelope: edit(A(), x => { delete x.policy.enforcement }) },
    { name: 'performed-without-decisions', envelope: edit(A(), (x, m) => { delete m.decisions }) },
    { name: 'performed-without-result', envelope: edit(A(), (x, m) => { delete m.result }) },
    { name: 'not-performed-with-decisions', envelope: edit(evaluation('e23-engine-not-available'), (x, m) => { m.decisions = [] }) },
    { name: 'not-performed-with-result', envelope: edit(evaluation('e23-engine-not-available'), (x, m) => { m.result = 'as_required' }) },
    { name: 'not-performed-without-reason', envelope: edit(evaluation('e23-engine-not-available'), (x, m) => { delete m.notPerformed }) },
    { name: 'not-performed-unknown-reason', envelope: edit(evaluation('e23-engine-not-available'), (x, m) => { m.notPerformed = 'engine_missing' }) },
    { name: 'engine-unavailable-without-recorded-engine', envelope: edit(evaluation('e23-engine-not-available'), (x, m) => { delete m.recordedEngine }) },
    { name: 'engine-inconsistent-with-recorded-engine', envelope: edit(evaluation('e24-engine-inconsistent'), (x, m) => { m.recordedEngine = ENGINE }) },
    { name: 'due-reason-unavailable', envelope: edit(A(), x => dec(x, 0, d => { d.dueReason = 'unavailable'; delete d.dueRules })) },
    { name: 'due-none-with-reason', envelope: edit(A(), x => dec(x, 0, d => { d.due = 'none' })) },
    { name: 'refused-without-reason', envelope: edit(A(), x => dec(x, 0, d => { delete d.dueReason; delete d.dueRules })) },
    { name: 'rule-without-rules', envelope: edit(A(), x => dec(x, 0, d => { delete d.dueRules })) },
    { name: 'unknown-tool-with-rules', envelope: edit(A(), x => dec(x, 0, d => { d.dueReason = 'unknown_tool' })) },
    { name: 'rules-empty', envelope: edit(A(), x => dec(x, 0, d => { d.dueRules = [] })) },
    { name: 'let-through-without-findings', envelope: edit(A(), x => dec(x, 0, d => { d.outcome = 'let_through' })) },
    { name: 'as-required-with-findings', envelope: edit(A(), x => dec(x, 0, d => { d.findings = ['refusal_missing'] })) },
    { name: 'unknown-finding', envelope: edit(evaluation('e01-refusal-missing'), x => dec(x, 0, d => { d.findings = ['ran_anyway'] })) },
    { name: 'unknown-outcome', envelope: edit(A(), x => dec(x, 0, d => { d.outcome = 'fine' })) },
    { name: 'decision-unknown-member', envelope: edit(A(), x => dec(x, 0, d => { d.recordedReason = 'rule' })) },
    { name: 'as-required-without-recorded', envelope: edit(A(), x => dec(x, 0, d => { delete d.recorded })) },
    { name: 'state-with-empty-controls', envelope: edit(kindOf('state', 'verifier'), x => { x.controls = [] }) },
    { name: 'attested-with-empty-controls', envelope: edit(kindOf('attested', 'producer'), x => { x.controls = [] }) },
  ],
})

// ---- evaluations a verifier must reject: the correct evaluation of a run, then these edits (RFC 6902 subset)
const at = (n, s) => member(n).decisions.findIndex(d => d.seq === s)
const P = '/policy/enforcement'
const rejects = [
  ['x01-recorded-not-from-chain', 'e01-refusal-missing', false, '`recorded` does not follow from the chain',
    [{ op: 'replace', path: `${P}/decisions/${at('e01-refusal-missing', 1)}/recorded`, value: 'refused' },
     { op: 'replace', path: `${P}/decisions/${at('e01-refusal-missing', 1)}/outcome`, value: 'as_required' },
     { op: 'remove', path: `${P}/decisions/${at('e01-refusal-missing', 1)}/findings` },
     { op: 'replace', path: `${P}/result`, value: 'as_required' }]],
  ['x02-comparison-does-not-recompute', 'e01-refusal-missing', true, 'the comparison does not recompute',
    [{ op: 'replace', path: `${P}/decisions`, value: [] }, { op: 'replace', path: `${P}/result`, value: 'as_required' }]],
  ['x03-result-not-from-decisions', '14-02-denied-by-rule', false, '`result` does not follow from `decisions`',
    [{ op: 'replace', path: `${P}/result`, value: 'let_through' }]],
  ['x04-performed-with-another-core', '14-02-denied-by-rule', false, 'performed with a core other than the recorded engine',
    [{ op: 'replace', path: '/policy/evaluator/engine', value: 'cedar-policy@4.13.0' }]],
  ['x05-engine-unavailable-with-the-same-core', '14-02-denied-by-rule', false, '`engine_unavailable` with recordedEngine equal to evaluator.engine',
    [{ op: 'replace', path: `${P}/comparison`, value: 'not_performed' }, { op: 'add', path: `${P}/notPerformed`, value: 'engine_unavailable' },
     { op: 'remove', path: `${P}/decisions` }, { op: 'remove', path: `${P}/result` }]],
  ['x06-decisions-not-ascending', '14-24-deny-and-halt-one-call', false, 'decisions do not ascend by seq',
    [{ op: 'replace', path: `${P}/decisions`, value: [5, 1, 3].map(s => decision('14-24-deny-and-halt-one-call', s)) }]],
  ['x07-finding-of-the-wrong-class', 'e13-unfounded-halt', false, 'a let-through finding under `over_enforced`',
    [{ op: 'replace', path: `${P}/decisions/${at('e13-unfounded-halt', 1)}/findings`, value: ['halt_missing'] }]],
  ['x08-no-finding-of-the-outcomes-class', 'e06-halt-missing-halt-rule', false, '`let_through` without a let-through finding',
    [{ op: 'replace', path: `${P}/decisions/${at('e06-halt-missing-halt-rule', 5)}/findings`, value: ['rules_mismatch'] }]],
  ['x09-inconsistent-chain-compared', 'c01-executed-after-denial', false, 'the chain is `chain_inconsistent`',
    [{ op: 'replace', path: `${P}/comparison`, value: 'performed' }, { op: 'remove', path: `${P}/notPerformed` },
     { op: 'add', path: `${P}/decisions`, value: [decision('14-02-denied-by-rule', 1)] }, { op: 'add', path: `${P}/result`, value: 'as_required' }]],
  ['x10-chain-inconsistent-claimed', '14-02-denied-by-rule', false, 'the prefix has no finding of §5.1 reason 1',
    [{ op: 'replace', path: `${P}/comparison`, value: 'not_performed' }, { op: 'add', path: `${P}/notPerformed`, value: 'chain_inconsistent' },
     { op: 'remove', path: `${P}/decisions` }, { op: 'remove', path: `${P}/result` }]],
  ['x13-recorded-outcome-without-decision', 'e11-unfounded-record', false, 'an event with a recorded outcome has no decision',
    [{ op: 'replace', path: `${P}/decisions`, value: [] }, { op: 'replace', path: `${P}/result`, value: 'as_required' }]],
  ['x14-not-checkable-without-unavailable', '14-02-denied-by-rule', false, '`not_checkable` where the record does not say `unavailable`',
    [{ op: 'replace', path: `${P}/decisions/${at('14-02-denied-by-rule', 1)}/outcome`, value: 'not_checkable' },
     { op: 'replace', path: `${P}/result`, value: 'not_checkable' }]],
  ['x15-as-required-where-due-is-not-recorded', 'e01-refusal-missing', false, '`as_required` where what is due is not what the chain records',
    [{ op: 'replace', path: `${P}/decisions/${at('e01-refusal-missing', 1)}/outcome`, value: 'as_required' },
     { op: 'remove', path: `${P}/decisions/${at('e01-refusal-missing', 1)}/findings` },
     { op: 'replace', path: `${P}/result`, value: 'as_required' }]],
  ['x11-cedar-digest-without-cedar', 'e39-no-rules-refused', false, '`cedarDigest` without a `cedar` member (§2)',
    [{ op: 'add', path: '/policy/cedarDigest', value: digestsOf(base).cedarDigest }]],
  ['x11-controls-empty-with-rules', '14-02-denied-by-rule', false, '`controls: []` for a control set with rules (§2)',
    [{ op: 'replace', path: '/controls', value: [] }, { op: 'replace', path: '/overall', value: 'PASS' }]],
]
for (const [name, run, needsEngine, because, patch] of rejects)
  write(`invalid-evaluations/${name}.json`, { name, run, needsEngine, because, patch })
console.log(`${Object.keys(out).length} expected enforcement members (${v14.length} from vector 14), ${rejects.length} rejected evaluations`)
