// Generates control-set.json, expected.json and invalid.json for vector 13 from rules.cedar.
// Agent Policy Control Set v2. Policy JSON, strict validation and entity validation: the official Cedar core.
//   npm i --no-save @cedar-policy/cedar-wasm@4.14.0 && node _generate.mjs   (README: the Docker command)
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'

const here = dirname(fileURLToPath(import.meta.url))
const cedar = createRequire(import.meta.url)('@cedar-policy/cedar-wasm/nodejs')
const read = p => readFileSync(join(here, p), 'utf8')
const schemaV1 = JSON.parse(read('../../agent-policy-cedar-schema-v1.json'))
const schemaV2 = JSON.parse(read('../../agent-policy-cedar-schema-v2.json'))

// RFC 8785 for the value space used here (strings, safe integers, booleans, null): sorted keys, no whitespace.
const jcs = v => Array.isArray(v) ? `[${v.map(jcs).join(',')}]`
  : v && typeof v === 'object' ? `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${jcs(v[k])}`).join(',')}}`
  : JSON.stringify(v)
const sha256 = s => createHash('sha256').update(s, 'utf8').digest('hex')
const ok = r => { if (r.type !== 'success') throw new Error(JSON.stringify(r.errors ?? r)); return r }

// The method of v1 §4 rule 5 reproduces vector 11's schemaSha256.
assert.equal(sha256(jcs(schemaV1)), '3bb5de5a78da26341ee26e240acb96015d20e4da303af32311520950ab1daf73')

const staticPolicies = {}
for (const text of ok(cedar.policySetTextToParts(read('rules.cedar'))).policies) {
  const json = ok(cedar.policyToJson(text)).json
  staticPolicies[json.annotations.id] = json
}
const ent = (type, id, attrs = {}, parents = []) => ({ uid: { type, id }, attrs, parents })
const doc = {
  schemaVersion: '2',
  id: 'acme-support-agent-controls',
  version: '4',
  controls: [],
  cedar: {
    policies: { staticPolicies },
    schemaSha256: sha256(jcs(schemaV2)),
    entities: [
      ent('Agent', 'urn:example:agent:support', {}, [{ type: 'AgentGroup', id: 'tier1' }]),
      ent('AgentGroup', 'tier1'),
      ent('Tool', 'crm.read_customer', { consequential: false, definitionSha256: sha256('crm.read_customer definition') }, [{ type: 'ToolGroup', id: 'crm' }]),
      ent('Tool', 'crm.update_address', { consequential: true, definitionSha256: sha256('crm.update_address definition') }, [{ type: 'ToolGroup', id: 'crm' }]),
      ent('Tool', 'payments.refund', { consequential: true }, [{ type: 'ToolGroup', id: 'payments' }]),
      ent('Tool', 'search.web', { consequential: false }),
      ent('Tool', 'ledger.export'),
      ent('Tool', 'ledger.preview'),
      ent('ToolGroup', 'crm'),
      ent('ToolGroup', 'payments', {}, [{ type: 'ToolGroup', id: 'restricted' }]),
      ent('ToolGroup', 'restricted'),
    ],
  },
  privateControls: [{ id: 'no-card-numbers-in-replies' }],
  coverage: { sourceProfile: 'urn:sigill:recorder:producer-declared', scope: 'all instrumented SDK tool calls', idleSeconds: 1800 },
  enforcement: {
    mode: 'enforce',
    defaultEffect: 'deny',
    lockedConfiguration: { 'tool-manifest': sha256('tool-manifest v1') },
    unknownTools: 'deny',
    onRuleError: 'deny',
    haltAfterDenials: 0,
  },
}

// Strict validation of the rules, and entity validation, against schema v2 (a failure throws).
const v = ok(cedar.validate({ validationSettings: { mode: 'strict' }, schema: schemaV2, policies: { staticPolicies } }))
assert.deepEqual([v.validationErrors, v.validationWarnings], [[], []])
ok(cedar.isAuthorized({ principal: { type: 'Agent', id: 'urn:example:agent:support' }, action: { type: 'Action', id: 'run_start' },
  resource: { type: 'Step', id: '0' }, context: { consequential: false, operation: '', stepsSoFar: 0, approval: 'none', isChildRun: false,
    totalSteps: 0, consequentialCount: 0, unpairedConsequential: 0, toolCallsSoFar: 0, callsOfThisTool: 0, denialsSoFar: 0 },
  schema: schemaV2, validateRequest: true, policies: { staticPolicies }, entities: doc.cedar.entities }))

const text = JSON.stringify(doc, null, 2) + '\n'
writeFileSync(join(here, 'control-set.json'), text)
const effect = p => doc.enforcement.mode !== 'enforce' ? 'observe' : p.annotations.effect ?? doc.enforcement.defaultEffect
const { id, version, ...scope } = doc
writeFileSync(join(here, 'expected.json'), JSON.stringify({
  contentType: 'application/vnd.sigill.control-set+json',
  objectSha256: sha256(text),
  cedarDigest: sha256(jcs(doc.cedar)),
  approvalScopeDigest: sha256(jcs(scope)),
  schemaSha256: doc.cedar.schemaSha256,
  ruleIds: Object.keys(staticPolicies).sort(),
  effects: Object.fromEntries(Object.keys(staticPolicies).sort().map(k => [k, effect(staticPolicies[k])])),
}, null, 2) + '\n')

// Invalid variants: each a mutation of the valid document; `error` is a word the validation error must mention.
const variant = (name, error, mutate) => { const d = structuredClone(doc); mutate(d); return { name, document: JSON.stringify(d), error } }
const pol = d => d.cedar.policies.staticPolicies
const byId = (d, id) => d.cedar.entities.find(e => e.uid.id === id)
const cases = [
  variant('enforcement-unknown-member', 'enforcement', d => { d.enforcement.notify = 'owner' }),
  variant('on-unavailable-removed', 'enforcement', d => { d.enforcement.onUnavailable = { consequential: 'deny', other: 'allow', graceSeconds: 30 } }),
  variant('require-approval-not-in-v2', 'enforcement', d => { d.enforcement.requireApproval = true }),
  variant('enforcement-without-mode', 'mode', d => { delete d.enforcement.mode }),
  variant('unknown-tools-unknown-value', 'unknownTools', d => { d.enforcement.unknownTools = 'warn' }),
  variant('on-rule-error-unknown-value', 'onRuleError', d => { d.enforcement.onRuleError = 'halt' }),
  variant('default-effect-observe', 'defaultEffect', d => { d.enforcement.defaultEffect = 'observe' }),
  variant('locked-configuration-unknown-role', 'lockedConfiguration', d => { d.enforcement.lockedConfiguration['control-set'] = sha256('x') }),
  variant('locked-configuration-not-hex', 'lockedConfiguration', d => { d.enforcement.lockedConfiguration['tool-manifest'] = 'ABC' }),
  variant('halt-after-denials-negative', 'haltAfterDenials', d => { d.enforcement.haltAfterDenials = -1 }),
  variant('halt-after-denials-fraction', 'haltAfterDenials', d => { d.enforcement.haltAfterDenials = 1.5 }),
  variant('annotation-unknown-key', 'annotation', d => { pol(d)['no-web-search'].annotations.severity = 'high' }),
  variant('effect-unknown-value', 'effect', d => { pol(d)['no-web-search'].annotations.effect = 'block' }),
  variant('entity-of-another-type', 'entities', d => { d.cedar.entities.push(ent('Step', '0')) }),
  variant('entity-duplicate-uid', 'entities', d => { d.cedar.entities.push(ent('ToolGroup', 'crm')) }),
  variant('tool-unknown-attribute', 'entities', d => { byId(d, 'crm.read_customer').attrs.owner = 'crm-team' }),
  variant('group-with-attribute', 'entities', d => { byId(d, 'crm').attrs.consequential = true }),
  variant('entity-id-too-long', 'entities', d => { d.cedar.entities.push(ent('Tool', 'x'.repeat(256))) }),
  variant('parent-of-wrong-type', 'parents', d => { byId(d, 'crm.read_customer').parents = [{ type: 'AgentGroup', id: 'tier1' }] }),
  variant('parent-not-declared', 'parents', d => { byId(d, 'crm.read_customer').parents = [{ type: 'ToolGroup', id: 'undeclared' }] }),
  variant('parent-cycle', 'parents', d => { byId(d, 'restricted').parents = [{ type: 'ToolGroup', id: 'payments' }] }),
  variant('too-many-entities', 'entities', d => { while (d.cedar.entities.length < 1025) d.cedar.entities.push(ent('Tool', `bulk.tool-${d.cedar.entities.length}`)) }),
  variant('too-many-policies', 'policies', d => { const p = pol(d)['no-web-search']
    for (let i = 0; Object.keys(pol(d)).length < 257; i++) pol(d)[`bulk-${i}`] = { ...p, annotations: { ...p.annotations, id: `bulk-${i}` } } }),
  variant('cedar-unknown-member', 'cedar', d => { d.cedar.templates = {} }),
  variant('schema-v1-digest', 'schemaSha256', d => { d.cedar.schemaSha256 = sha256(jcs(schemaV1)) }),
  variant('schema-version-1', 'schemaVersion', d => { d.schemaVersion = '1' }),
  variant('v1-document-with-enforcement', 'enforcement', d => { delete d.schemaVersion }),
  // Strict bytes (§2): I-JSON and at most 64 levels of nesting (the outermost object is level 1).
  variant('lone-surrogate', 'I-JSON', d => { d.coverage.scope = 'all calls \ud800' }),
  variant('nested-deeper-than-64', 'depth', d => { let v = 'x'; for (let k = 0; k < 62; k++) v = [v]; d.controls = [{ id: 'deep', value: v }] }),
]
const compact = JSON.stringify(doc)
assert.ok(compact.startsWith('{"schemaVersion":"2",') && compact.includes('"idleSeconds":1800'))
cases.push(
  { name: 'duplicate-member', document: compact.replace('{"schemaVersion":"2",', '{"schemaVersion":"2","schemaVersion":"2",'), error: 'I-JSON' },
  { name: 'integer-beyond-2^53', document: compact.replace('"idleSeconds":1800', '"idleSeconds":9007199254740993'), error: 'I-JSON' },
  // Not UTF-8 without a byte-order mark: the exact bytes as base64.
  { name: 'utf8-byte-order-mark', documentBase64: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(compact, 'utf8')]).toString('base64'), error: 'UTF-8' },
  { name: 'utf16le', documentBase64: Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(compact, 'utf16le')]).toString('base64'), error: 'UTF-8' },
)
const depth = v => v && typeof v === 'object' ? 1 + Math.max(0, ...Object.values(v).map(depth)) : 0
assert.equal(depth(JSON.parse(cases.find(c => c.name === 'nested-deeper-than-64').document)), 65)
assert.ok(depth(doc) <= 64)
assert.equal(JSON.parse(cases.find(c => c.name === 'too-many-entities').document).cedar.entities.length, 1025)
assert.equal(Object.keys(JSON.parse(cases.find(c => c.name === 'too-many-policies').document).cedar.policies.staticPolicies).length, 257)
writeFileSync(join(here, 'invalid.json'), JSON.stringify({
  description: 'Documents every implementation must reject (Validate returns at least one error mentioning `error`; nothing throws). `document` is the exact UTF-8 text; `documentBase64` the exact bytes where they are not UTF-8 text without a byte-order mark.',
  cases,
}, null, 2) + '\n')
console.log('control set', sha256(text), 'scope', sha256(jcs(scope)), 'schema', doc.cedar.schemaSha256, 'invalid cases', cases.length)
