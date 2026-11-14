# Agent Policy Control Set v2 (draft)

Status: **draft**. Extends [Agent Policy Control Set v1](./agent-policy-control-set-v1.md)
with local enforcement: a guard in the producer may deny a tool call or halt a run before
the action, and records the decision as sealed evidence (Execution Evidence v4,
[Agent Enforcement v1](./agent-enforcement-v1.md)). The facts are extended so that anyone
holding the control set and the signed events can recompute every decision. Rules of v1
apply unless this document changes them.

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Recognition

A `control-set` object is a policy control set when its object `contentType` is
`application/vnd.sigill.control-set+json` (v1 §1, unchanged). It is a **v2** control set
when it carries `"schemaVersion": "2"`. A document without `schemaVersion` is v1 and v1
rules apply unchanged; any other value of `schemaVersion` (including `"1"`) is invalid.

A run whose Control Artifact carries a v2 control set MUST use Execution Evidence
`schemaVersion "4"` for every event (Agent Enforcement v1 §3.1).

## 2. Document

A JSON object in UTF-8 without a byte-order mark, I-JSON (RFC 7493): no repeated member
names, no integers beyond ±(2^53 − 1), no lone surrogates; and nested at most 64 levels
deep (the outermost object is level 1). Bytes that break any of these are invalid. The
integer limit applies to every number whose value is integral, however it is written:
`9007199254740993.0` and `9.007199254740993e15` are invalid; a number written with a
fraction or exponent whose value is an integer within the range (`20.0`, `2e1`) is valid
and denotes that integer. Members:

| Member | Required | Meaning |
|---|---|---|
| `schemaVersion` | yes | `"2"`. |
| `id`, `version`, `controls`, `privateControls`, `coverage` | as v1 | Unchanged from v1 §2. |
| `cedar` | no | `{ "policies", "schemaSha256", "entities"? }` (§4, §5). |
| `enforcement` | no | What the guard does with the rules (§6). Absent: observe, the v1 behaviour. |

No other top-level member is allowed. `cedar` has exactly the members `policies` and
`schemaSha256`, and optionally `entities`; any other member is invalid.

## 3. Digests

Computed exactly as v1 §3:

- `cedarDigest` = SHA-256(JCS(`cedar`)). `cedar.entities` is inside it.
- `approvalScopeDigest` = SHA-256(JCS(document without `id` and `version`)).
  `schemaVersion`, `enforcement` and `cedar.entities` are inside it: changing an effect,
  a limit, a group membership or the mode changes what an owner approved.

## 4. Cedar policies

v1 §4 rules 1–4 apply (forbid only, the evaluator's baseline permit, `id` annotation equal
to the key, no templates, the integer range). Rule 5 becomes: `schemaSha256` is the SHA-256
of JCS(`agent-policy-cedar-schema-v2.json`), and the policy set validates against that
schema in Cedar's strict mode. In addition:

6. Allowed annotation keys are `id` and `effect`, each with a string value. Any other
   annotation key is invalid.
7. `effect` is `observe`, `deny` or `halt`. The **effective effect** of a rule is its
   `effect` annotation; without one it is `enforcement.defaultEffect`. When there is no
   `enforcement` member, or `enforcement.mode` is `observe`, every rule is `observe`
   whatever its annotation.
8. At most 256 policies.

| Effect | Guard behaviour when the rule matches (§7) |
|---|---|
| `observe` | Nothing. The rule is still evaluated and reported (v1 §6). |
| `deny` | A `tool_call` it matches is denied. On any other event: nothing. |
| `halt` | A `tool_call` it matches is denied and the run halted; on any other event it matches, the run is halted. |

The effect never changes the result: a matching `observe` rule is `FAIL` in a Control
Evaluation exactly like a `deny` rule (v1 §6).

## 5. Entities

`cedar.entities` is an optional array in Cedar's JSON entities format. It declares the
tools, tool groups, agents and agent groups the rules refer to; it is the `entities`
input of every request (§8).

```json
"entities": [
  { "uid": { "type": "Tool", "id": "payments.refund" },
    "attrs": { "consequential": true, "definitionSha256": "hex…" },
    "parents": [ { "type": "ToolGroup", "id": "payments" } ] },
  { "uid": { "type": "ToolGroup", "id": "payments" }, "attrs": {}, "parents": [] }
]
```

| Rule | |
|---|---|
| Size | At most 1024 entities. |
| Members | Each entity has exactly `uid`, `attrs` and `parents` (no `tags`). `uid` is exactly `{ "type", "id" }`, both strings, `id` 1–255 characters (counted in Unicode code points, as JSON Schema `maxLength` counts). |
| Types | `Tool`, `ToolGroup`, `Agent`, `AgentGroup`. Any other type is invalid. |
| Unique | No two entities share a `uid`. |
| Attributes | `Tool` may carry `consequential` (boolean) and `definitionSha256` (64 lowercase hex); nothing else. Every other type has `attrs: {}`. |
| Parents | `Tool` → `ToolGroup`; `ToolGroup` → `ToolGroup`; `Agent` → `AgentGroup`; `AgentGroup` has none. Each parent MUST be an entity of the same array; no parent is listed twice; the hierarchy is acyclic. |
| Schema | The array validates as entities against `agent-policy-cedar-schema-v2.json` in the Cedar core. |

A tool is **known** when `cedar.entities` holds a `Tool` entity whose `id` is its
`step.tool.name`. An agent's entity, when present, is `Agent::"<actor.id>"`.

`consequential` is the producer's declared classification of the tool. It is independent
of `step.consequential` on the event; rules choose which one they test
(`resource has consequential && resource.consequential`, or `context.consequential`).

`definitionSha256` binds the tool: the SHA-256 of the tool's definition as the producer's
runtime holds it (e.g. its entry in the tool manifest). A `tool_call` of such a tool
carries that definition as its `tool-definition` object (Agent Enforcement v1 §3.3), and
the guard denies the call when the signed digest differs (§7.2).

## 6. Enforcement

| Member | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `"observe"` \| `"enforce"` | required | `observe`: the guard never denies or halts. |
| `defaultEffect` | `"deny"` \| `"halt"` | `"deny"` | Effect of a rule without an `effect` annotation. |
| `lockedConfiguration` | object, role → 64 lowercase hex | `{}` | Keys ⊆ {`instruction-set`, `tool-manifest`, `execution-policy`, `model-config`}. The Control Artifact's object of that role MUST exist and have exactly this SHA-256 (§7.4). |
| `unknownTools` | `"deny"` \| `"allow"` | `"allow"` | A `tool_call` whose tool is not known (§5). |
| `onRuleError` | `"deny"` \| `"allow"` | `"deny"` | A `deny` or `halt` rule in Cedar's `diagnostics.errors` for a `tool_call`. |
| `haltAfterDenials` | integer ≥ 0 | `0` (never) | Halt the run at the denial that brings the run's enforcement records to this number. |

No other member is allowed. With `mode: "observe"` the other members are allowed,
validated and have no effect. Integers are I-JSON integers within the stated ranges.

## 7. Enforcement semantics

The **guard** is the producer component that applies the policy before an action. It
holds the control set of the run's Control Artifact and every event of the run it has
sealed. This section applies only with `enforcement.mode: "enforce"`; with `observe`, or
without `enforcement`, the guard never denies or halts and seals no enforcement record.

An **enforcement record** is an `authorization` event with an `enforcer` member (Agent
Enforcement v1 §3.4); every enforcement record is a denial (`decision: "denied"`). The guard
seals at most one per decided event, directly after it. A **halt** is the guard sealing
`run_end` with `runDisposition: "halted"` directly after an enforcement record; a halt is
never a second record. After a halt the producer starts no tool (Agent Enforcement v1 §4
rule 2).

### 7.1 Every event

For every event the guard builds the event's facts-v2 request (§8) — exactly the request
an evaluator builds for the same event — and evaluates it in the Cedar core with the
baseline permit, as v1, after the event is sealed (the facts of an event depend only on the
events up to and including it).

The guard never acts on the evaluation of an event it sealed itself (its enforcement
records and the `run_end` of a halt) nor on the producer's own `run_end`, and the run-level
request (§8) has no guard effect. These are still ordinary events for an evaluator.

The decision on one event and the sealing of its record and halt are atomic with respect
to other events of the same run: no other event of the run is sealed in between.

### 7.2 `tool_call`

The `tool_call` event is sealed first; it records the attempt. Then the first that
applies gives the reason of the one enforcement record:

1. `unavailable` — the Cedar core cannot evaluate the request (§7.5);
2. `unknown_tool` — the tool is not known (§5) and `unknownTools` is `"deny"`;
3. `tool_changed` — the call's `Tool` entity has `definitionSha256`, and the call does not
   carry exactly one `tool-definition` object whose signed digest equals it;
4. `rule_error` — `onRuleError` is `"deny"` and `diagnostics.errors` holds rule ids whose
   effective effect is `deny` or `halt`; `rules` = those ids;
5. `rule` — `diagnostics.reason` holds rule ids whose effective effect is `deny` or `halt`;
   `rules` = those ids.

Otherwise the call is allowed and nothing is sealed. An erroring or matching `observe`
rule never denies. `rules` is sorted by unsigned UTF-16 code units, without repeats, and
never contains the baseline permit; it is absent for the other reasons.

The record names the call in `step.tool` (`name` and `useId` equal the call's). The tool
MUST NOT be executed, and no `tool_result` is recorded for that `useId`.

Steps 2 and 3 use only `cedar.entities` and signed object digests, so an evaluator
recomputes them without any content.

**Halt after a denial.** After the record, the run is halted iff the reason is
`unavailable`; or any rule id in Cedar's `diagnostics.reason` for the call has effective
effect `halt`, whether or not it is listed in the record's `rules` (a matching `halt` rule
always halts, whatever reason won the record); or `haltAfterDenials` is greater than 0 and
the number of enforcement records in the run, this one included, equals it. The record
itself is unchanged: its reason and `rules` follow the order above.

### 7.3 Other events

Only a matching rule with effective effect `halt` has a guard effect on an event other than
`tool_call`: one enforcement record (reason `rule`, `rules` = the matching `halt` ids, no
`tool`) directly after that event, then the halt. A `deny` rule, or an erroring rule, has
no guard effect there. When the Cedar core cannot evaluate the event's request (§7.5), the
record has reason `unavailable` (no `tool`), then the halt.

Delegation is enforced the same way: each run is enforced under its **own** control set,
and a parent's rules never apply to a child's events. A parent that must not delegate
writes a `halt` rule on `Action::"delegation"`: the guard halts right after the
`delegation` event, and the child MUST NOT be started.

### 7.4 Start gate

Before the agent acts, the guard seals `run_start` and checks, in order, the first that
applies:

1. `configuration_locked` — an entry of `lockedConfiguration` whose role is absent from
   the Control Artifact, or whose object digest differs;
2. `unavailable` — the Cedar core cannot be loaded (§7.5).

Otherwise `run_start` is decided like any other non-tool event (§7.3). Any halt decided at
`run_start` — a locked configuration, an engine that cannot evaluate, or a `halt` rule
matching the `run_start` event — is a **refused start**: the Control Artifact, `run_start`,
one enforcement record without `tool` (reason `configuration_locked`, `unavailable` or
`rule` respectively), and `run_end` with `runDisposition: "halted"`. The agent takes no
action.

### 7.5 Engine failure and sealing failure

When the guard cannot evaluate an event's request — the Cedar core fails to load or
returns a failure for the request — the decision is reason `unavailable` and the run is
halted (§7.2–§7.4). There is no setting for this. An answer that names a policy not in the
call — in `diagnostics.reason` or as a `policyId` in `diagnostics.errors`, where the call
holds the control set's rules plus the baseline permit — is malformed and counts as such a
failure: reason `unavailable`.

A sealing failure is governed by common rules §6 rule 3 unchanged: the producer MUST NOT
continue the chain and nothing is sealed later; a `tool_call` that could not be sealed MUST
NOT be executed. The run then verifies as `run_open` or `run_invalid`. In an enforced run
a producer's own instrumentation (model-call recording, agent-model-calls-v1.md) MUST NOT
let the agent go on after a sealing failure: it sends no further model request, and a
failure to record a model call is raised to the caller instead of being ignored.
Delivering artifacts to an index (common rules §6.1) is not part of the chain: a delivery
failure is not a sealing failure, and it neither stops nor halts an enforced run.

## 8. Facts (factsVersion 2)

Facts v2 are facts v1 (v1 §5) with the changes below; everything else is identical,
including one request per event of the contiguous received prefix and the run-level
request.

| Attribute | Per event | Run level |
|---|---|---|
| `toolCallsSoFar` | number of `tool_call` events with seq ≤ this seq | total |
| `callsOfThisTool` | `tool_call` / `tool_result`: number of `tool_call` events with the same `step.tool.name` and seq ≤ this seq; otherwise 0 | 0 |
| `denialsSoFar` | number of enforcement records (§7) with seq < this seq | total |
| `approval` | `tool_call`: §8.1. Every other type: `"unbound"` when an earlier `human_approval` exists, else `"none"` | `"none"` (as v1) |
| `unpairedConsequential` | 0 | as v1, except that a consequential `tool_call` with a later enforcement record naming its `useId` (`step.tool.useId`) is not counted |

The request's `entities` are `cedar.entities` of the control set (none when absent). Denied
calls are `tool_call` events and count in `toolCallsSoFar` and `callsOfThisTool`.

**Facts document.** The facts are handed on as the facts document of Control Evaluation v2
§4.5 — the v1 shape: `factsVersion`, `throughSeq`, `missingSeqs`, `runLevel` and `requests`,
each request with its `seq` (`"run"` for the run-level request), `principal`, `action`,
`resource` and `context` — with `factsVersion` `"2"`, the requests of this section, and one
more top-level member, `entities`, always present: `cedar.entities` of the control set, or
`[]` when absent. Its digest is the lowercase hex SHA-256 of its JCS form.

### 8.1 `approval` on a `tool_call`

For a `tool_call` with `useId` `u`, tool name `t`, and `a` = the signed SHA-256 of its
`tool-arguments` object (undefined unless the event has exactly one): earlier means lower
seq; `covers` is `step.covers` of a `human_approval` (Agent Enforcement v1 §3.5). The first
that matches:

1. `rejected` — an earlier `human_approval` with `decision: "rejected"` whose `covers` has
   (`useId` present and equal to `u`), or (`tool == t` and `argumentsSha256 == a`). Sticky
   for the run: a later approval does not lift it. A rejection ignores `expiresAt`.
2. `bound` — an earlier `human_approval` H with `decision: "approved"` whose `covers` has
   `tool == t` and `argumentsSha256 == a` and (`useId` absent or equal to `u`), whose
   `expiresAt` is absent or later than this event's `step.eventTime` (compared as
   instants), and that has not bound an earlier `tool_call`.
3. `unbound` — any earlier `human_approval` exists.
4. `none`.

Strings are compared exactly. An undefined `a` equals nothing.

**One approval binds at most one call.** Walk the `tool_call` events in seq order; a call
whose `approval` is `bound` takes (consumes) the lowest-seq approval that matches it under
rule 2 and is not yet consumed. Consumption is a property of the facts — a call consumes
exactly when its `approval` is `bound` — independent of what the guard decided for it. A
second call with the same tool and arguments is therefore not `bound` by the same approval.

### 8.2 Conventions

This section changes no fact; it states what §8 and v1 §5 already fix.

**Every event of the prefix is an event of the facts.** A refused `tool_call`, an enforcement
record and the `run_end` of a halt each have a seq and a request, and each is a step:
`stepsSoFar` is the event's `chain.seq`, whoever sealed it and whatever was decided. The
Control Artifact is not an event.

**What a counter includes.** For the event at seq *s*:

| Attribute | Counts | The event itself |
|---|---|---|
| `stepsSoFar` | events with seq < *s* (so it equals *s*) | excluded |
| `toolCallsSoFar`, `callsOfThisTool` | `tool_call` events with seq ≤ *s* | included |
| `consequentialCount` | events with `step.consequential: true` and seq ≤ *s* | included |
| `denialsSoFar` | enforcement records with seq < *s* | excluded |

A refused call counts in `toolCallsSoFar`, in `callsOfThisTool` and, when consequential, in
`consequentialCount`. A call's record has a higher seq than the call, so a call's
`denialsSoFar` never counts its own refusal.

**The facts are those of the recorded chain.** They count what was sealed, not what should
have been: a call that was let through counts as a call, an enforcement record counts as a
denial whether or not it was due, and a record that is missing is not counted. An approval is
consumed by the call it binds whether that call was then allowed or refused (§8.1).

**`haltAfterDenials`.** For a `tool_call` for which a denial is due (§7.2), "the number of
enforcement records in the run, this one included" is its `denialsSoFar` + 1, and the guard
halts when that equals `haltAfterDenials`. In a run in which each record was due and each due
halt was sealed the number never passes `haltAfterDenials`, so "equals" and "is at least" say
the same. They differ only on a chain that has stepped over the number without halting — a
halt that was skipped, or a record that was not due. An evaluator therefore takes the halt as
due when `denialsSoFar` + 1 is at least `haltAfterDenials` (ControlEvaluation v3 §5.2). A
missing record delays the halt by one denial; a record that was not due brings it one denial
earlier.

## 9. Results

Unchanged from v1 §6: per rule from Cedar's diagnostics, FAIL > INDETERMINATE > PASS.

A policy evaluation of a run under a v2 control set is a
[ControlEvaluation v3](./control-evaluation-v3.md). Besides these results it carries the
enforcement comparison (§5 there): what §7 required for each event against what the chain
records.

## 10. Test vectors

- `test-vectors/13-policy-control-set-v2/`: a v2 document with `enforcement` and
  `cedar.entities`, its digests and `schemaSha256`, and invalid variants.
- `test-vectors/14-policy-enforcement/`: v4 runs with, per event, the facts-v2 request,
  Cedar's diagnostics and the guard's outcome; runs with each verifier finding.
- `test-vectors/15-policy-enforcement-evaluation/`: the expected enforcement comparison
  (ControlEvaluation v3 §5) for vector 14's runs and for runs with each of its findings.

## 11. Decisions and open questions

- **Open:** a way for the policy's issuer to suspend an agent, or to gate the start of a
  run on a current approval, is left to a later round.
