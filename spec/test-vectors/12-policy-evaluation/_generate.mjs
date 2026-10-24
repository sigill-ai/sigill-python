// Generates expected/*.json for vector 12 from runs/*.json and the vector 11 control set.
// Facts: Agent Policy Control Set v1 §5 (factsVersion 1). Results: the official Cedar core.
//   npm i --no-save @cedar-policy/cedar-wasm@4.14.0 && node _generate.mjs
import { createHash } from 'node:crypto'
import { readFileSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const cedar = createRequire(import.meta.url)('@cedar-policy/cedar-wasm/nodejs')
const doc = JSON.parse(readFileSync(join(here, '..', '11-policy-control-set', 'control-set.json'), 'utf8'))
const schema = JSON.parse(readFileSync(join(here, '..', '..', 'agent-policy-cedar-schema-v1.json'), 'utf8'))
const rules = doc.cedar.policies.staticPolicies

// RFC 8785 for the value space used here (strings, safe integers, booleans, null): sorted keys, no whitespace.
const jcs = v => Array.isArray(v) ? `[${v.map(jcs).join(',')}]`
  : v && typeof v === 'object' ? `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${jcs(v[k])}`).join(',')}}`
  : JSON.stringify(v)
const sha256 = s => createHash('sha256').update(s, 'utf8').digest('hex')

function facts(agentId, correlationId, events) {
  const bySeq = new Map(events.map(e => [e.chain.seq, e]))
  const maxSeq = Math.max(-1, ...events.map(e => e.chain.seq))
  const missingSeqs = []
  for (let s = 0; s <= maxSeq; s++) if (!bySeq.has(s)) missingSeqs.push(s)
  const throughSeq = missingSeqs.length ? missingSeqs[0] - 1 : maxSeq
  const prefix = [...bySeq.values()].filter(e => e.chain.seq <= throughSeq).sort((a, b) => a.chain.seq - b.chain.seq)
  const isChildRun = !!bySeq.get(0)?.binds?.parentCorrelationId && bySeq.get(0).step.type === 'run_start'
  const principal = { type: 'Agent', id: agentId }
  const requests = []
  let consequentialCount = 0, sawApproval = false
  for (const e of prefix) {
    const s = e.step, consequential = s.consequential === true
    if (consequential) consequentialCount++
    const toolStep = s.type === 'tool_call' || s.type === 'tool_result'
    requests.push({
      seq: e.chain.seq, principal, action: { type: 'Action', id: s.type },
      resource: toolStep ? { type: 'Tool', id: s.tool?.name ?? '' } : { type: 'Step', id: String(e.chain.seq) },
      context: { consequential, operation: s.tool?.operation ?? '', stepsSoFar: e.chain.seq, approval: sawApproval ? 'unbound' : 'none',
        isChildRun, totalSteps: 0, consequentialCount, unpairedConsequential: 0 },
    })
    if (s.type === 'human_approval') sawApproval = true
  }
  const runEnd = prefix.find(e => e.step.type === 'run_end')
  const runLevel = !!runEnd && missingSeqs.length === 0
  if (runLevel) {
    const finalSeq = runEnd.step.finalSeq ?? runEnd.chain.seq
    const calls = prefix.filter(e => e.step.type === 'tool_call')
    const uses = new Map()
    for (const c of calls) { const u = c.step.tool?.useId; if (u) uses.set(u, (uses.get(u) ?? 0) + 1) }
    const unpaired = calls.filter(c => {
      const u = c.step.tool?.useId
      if (!u || uses.get(u) > 1) return true
      return !prefix.some(e => e.step.type === 'tool_result' && e.chain.seq > c.chain.seq && e.step.tool?.useId === u)
    }).filter(c => c.step.consequential === true).length
    requests.push({ seq: 'run', principal, action: { type: 'Action', id: 'run' }, resource: { type: 'Run', id: correlationId },
      context: { consequential: false, operation: '', stepsSoFar: finalSeq, approval: 'none', isChildRun,
        totalSteps: finalSeq, consequentialCount, unpairedConsequential: unpaired } })
  }
  return { factsVersion: '1', throughSeq, missingSeqs, runLevel, requests }
}

const BASELINE = 'sigill:baseline-permit'
const rank = { PASS: 0, INDETERMINATE: 1, FAIL: 2 }
function evaluate(f) {
  const res = Object.fromEntries(Object.keys(rules).map(id => [id, { id, result: 'PASS', where: [] }]))
  const policies = { staticPolicies: { ...rules, [BASELINE]: { effect: 'permit', principal: { op: 'All' }, action: { op: 'All' }, resource: { op: 'All' }, conditions: [] } } }
  for (const r of f.requests) {
    const a = cedar.isAuthorized({ principal: r.principal, action: r.action, resource: r.resource, context: r.context, schema, validateRequest: true, policies, entities: [] })
    if (a.type !== 'success') throw new Error(JSON.stringify(a.errors))
    const mark = (id, result) => { const x = res[id]; if (!x) return; if (rank[result] > rank[x.result]) x.result = result; x.where.push(String(r.seq)) }
    for (const e of a.response.diagnostics.errors) mark(e.policyId, 'INDETERMINATE')
    for (const id of a.response.diagnostics.reason) mark(id, 'FAIL')
  }
  const controls = Object.values(res).map(c => c.result === 'PASS' ? { id: c.id, result: 'PASS' } : c)
  const overall = controls.reduce((o, c) => rank[c.result] > rank[o] ? c.result : o, 'PASS')
  return { engine: `cedar-policy@${cedar.getCedarVersion()}`, controls, overall }
}

mkdirSync(join(here, 'expected'), { recursive: true })
for (const name of readdirSync(join(here, 'runs')).filter(n => n.endsWith('.json')).sort()) {
  const run = JSON.parse(readFileSync(join(here, 'runs', name), 'utf8'))
  const f = facts(run.agentId, run.correlationId, run.events)
  const bytes = jcs(f)
  writeFileSync(join(here, 'expected', name.replace('.json', '.facts.json')), bytes)
  const out = { factsSha256: sha256(bytes), ...evaluate(f), throughSeq: f.throughSeq, missingSeqs: f.missingSeqs, runLevel: f.runLevel }
  writeFileSync(join(here, 'expected', name.replace('.json', '.results.json')), JSON.stringify(out, null, 1) + '\n')
  console.log(name, out.overall, out.controls.map(c => `${c.id}:${c.result}${c.where ? '@' + c.where.join(',') : ''}`).join(' '))
}
