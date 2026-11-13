# Agent Enforcement v1 — Specification (draft)

**Status:** draft.
**Extends:** [AgentExecutionEvidence](./agent-execution-evidence-v1.md) (`schemaVersion "4"`)
**Schema:** [`agent-execution-evidence-v4.schema.json`](./agent-execution-evidence-v4.schema.json)
**Common rules:** [`agent-profiles-common-v1.md`](./agent-profiles-common-v1.md)
**Policy:** [Agent Policy Control Set v2](./agent-policy-control-set-v2.md)

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Problem

A declared policy evaluated after a run (Control Set v1) shows what an agent did wrong; it
cannot stop it. A producer that wants its guard to refuse a tool call or stop a run before
the action needs the refusal to be evidence too: sealed in the run's chain, tied to the
call it refused, and recomputable by anyone from the control set and the signed events —
without any content (arguments, prompts, results) leaving the producer.

## 2. Model

Version 4 is version 3 plus:

- `step.tool.useId` is REQUIRED on `tool_call` and `tool_result`, so every result names
  its call and every decision names the call it decided;
- the object role `tool-definition` on `tool_call`: the definition of the tool called;
- `step.rules` and `step.enforcer` on `authorization`: the guard's denial (an
  **enforcement record**);
- `step.covers` on `human_approval`: the call an approval or rejection is for;
- `runDisposition: "halted"`: the guard stopped the run.

The guard's behaviour is Control Set v2 §7. This document defines the evidence.

## 3. Schema changes

### 3.1 Versions

| Execution artifacts of one run | all `"1"`, `"2"`, `"3"` or `"4"`; never mixed |
|---|---|

- `AgentExecutionEvidence` gains `schemaVersion: "4"`: v3 plus the members below.
- A run whose Control Artifact carries a control set with `schemaVersion: "2"` (Control
  Set v2 §1) MUST use `"4"` for every event (finding `evidence_version_mismatch`, §5).
  Other runs MAY use `"4"`.
- Verifiers dispatch the execution schema on `schemaVersion` and accept 1–4. A v4 member
  in a v1–v3 artifact is a schema violation. The v1–v3 schemas are not changed.
- The v4 schema enforces the `step.eventTime` format the common rules already require (§4
  there): RFC 3339, UTC `Z`, at most three fraction digits.
- `AgentControlArtifact` and `ControlEvaluation` are unchanged.

### 3.2 `step.tool.useId`

REQUIRED on `tool_call` and `tool_result` (v3: optional), 1–255 characters; in v4
`step.tool.name` is also at most 255 characters. Every length cap in this document is
counted in Unicode code points, as JSON Schema `maxLength` counts. The `useId` is opaque,
compared exactly, and MUST be unique per `tool_call` in the run (finding
`duplicate_use_id`). A `tool_result` carries the `useId` of the call it answers and the same
`tool.name`.

A retry is a new `tool_call` and MUST NOT reuse a `useId`, in particular not that of a
denied call. A producer whose ids come from a model (a model's tool-use id) derives a
distinct id for each re-attempt of the same model request, e.g. by appending a counter.

### 3.3 Object role `tool-definition` (`tool_call`)

A `tool_call` MAY carry one object with role `tool-definition`: the tool's definition as
the producer's runtime holds it when it makes the call (for example its entry in the tool
manifest). Like every object, only its digest is sealed. When the call's `Tool` entity in
the control set declares `definitionSha256`, the guard denies the call unless it carries
exactly one `tool-definition` object whose signed digest equals it (reason `tool_changed`,
Control Set v2 §7.2). The role is not allowed on other step types, and at most one appears
per `tool_call` (schema rules).

### 3.4 `step.rules` and `step.enforcer` (`authorization`)

```json
"step": {
  "type": "authorization",
  "eventTime": "2026-11-02T10:00:02.000Z",
  "decision": "denied",
  "tool": { "name": "payments.refund", "useId": "call-1" },
  "rules": ["restricted-needs-bound-approval"],
  "enforcer": {
    "engine": "cedar-policy@4.14.0",
    "factsVersion": "2",
    "reason": "rule"
  }
}
```

| Member | Rule |
|---|---|
| `rules` | Optional array of 0–256 rule ids (`^[A-Za-z0-9._-]{1,64}$`), unique. |
| `enforcer.engine` | The Cedar core the guard used, `cedar-policy@<x.y.z>`. |
| `enforcer.factsVersion` | `"2"`. |
| `enforcer.reason` | `rule`, `rule_error`, `unknown_tool`, `tool_changed`, `unavailable` or `configuration_locked` (Control Set v2 §7.2–§7.5). |

When `enforcer` is present (an **enforcement record**), the schema requires:

- `decision` is `denied`; there are no `allowed` records;
- `step.consequential`, when present, is `false`; `detail` and `policyId` are absent;
- `step.tool` (`name` and `useId`): always for `unknown_tool`, `tool_changed` and
  `rule_error`; never for `configuration_locked`; optional for `rule` and `unavailable`;
- `rules`: present and non-empty for `rule` and `rule_error`; absent for `tool_changed`;
  absent or empty otherwise.

That a `rule` or `unavailable` record carries `tool` exactly when it decides a `tool_call`
(then equal to that call's) is a producer rule, not a schema rule; a verifier checks it as
`misplaced_decision` (§5). A record without `tool` is always a halt.

An `authorization` without `enforcer` keeps its v1 meaning (producer-defined `decision`
vocabulary) and is never an enforcement record, with or without `rules`.

### 3.5 `step.covers` (`human_approval`)

```json
"step": {
  "type": "human_approval",
  "eventTime": "2026-11-02T10:00:03.000Z",
  "decision": "approved",
  "approver": "urn:example:approver:7f3a",
  "covers": {
    "tool": "payments.refund",
    "argumentsSha256": "hex…",
    "expiresAt": "2026-11-02T10:15:00Z"
  }
}
```

| Member | | Rule |
|---|---|---|
| `tool` | REQUIRED | The covered call's `step.tool.name`, 1–255 characters. |
| `argumentsSha256` | REQUIRED | The SHA-256 (64 lowercase hex) of the covered call's `tool-arguments` object, as the call's signature carries it. |
| `useId` | optional | Restricts the approval or rejection to the call with this `useId`, 1–255 characters. |
| `expiresAt` | optional | Same format as `eventTime` (RFC 3339, UTC `Z`, at most millisecond precision). An approval is not `bound` to a call whose `eventTime` is at or after it (compared as instants). A rejection ignores it. |

`covers` is optional and allowed only on `human_approval`; `decision` stays `approved` or
`rejected`. How `covers` sets the `approval` fact is Control Set v2 §8.1. A `human_approval`
without `covers` keeps its v1 meaning and can make `approval` only `unbound`.

An approval names what is approved — a tool and its exact arguments — and binds at most one
call. It does not need to know the call's `useId` in advance: after a call is denied for
lack of approval, the approval is recorded and the retry (a new `tool_call` with a new
`useId`, §3.2) is `bound`. A rejection is sticky for the run: by `useId` when it names one,
and by tool and arguments always.

### 3.6 `runDisposition: "halted"`

`run_end` MAY carry `halted`: the guard stopped the run (Control Set v2 §7). A halted
`run_end` comes directly after the enforcement record that caused it (finding
`unrecorded_halt`).

A child's `halted` is recorded in its parent's `delegation_result` as `childDisposition`,
which equals the child's `runDisposition` as before; only a v4 parent can record it, so a
parent whose child may be enforced uses v4. A v1–v3 parent cannot record `halted`; whatever
it records differs from the child's `run_end`, which the tree verifier reports as
`result_mismatch` (agent-delegation-v1.md §6.4). For delegation rules a halted run counts as
`aborted` (agent-delegation-v1.md §4 rule 5, §6.5).

Each run is enforced under its own control set; a parent's rules never apply to a child's
events (Control Set v2 §7.3).

## 4. Producer rules

1. Seal the `tool_call` before deciding it, the enforcement record before refusing, and
   the `tool_result` only for an executed call (Control Set v2 §7.2).
2. A denied call is never executed and gets no `tool_result`. A retry is a new `tool_call`
   with a new `useId` (§3.2).
3. The guard's events are part of the run's chain like any other: same signer, same
   `seq` rules, same timestamp policy. A sealing failure stops the run (common rules §6
   rule 3); nothing is sealed late.
4. **Event budget.** In enforce mode a producer keeps room for one enforcement record and
   the `run_end` of a halt within the bundle limit (common rules §7), next to the
   delegation reserve (agent-delegation-v1.md §4 rule 6), and refuses a new event that
   would use it.
5. Never put arguments, prompts, results or approver names in `rules`, `enforcer`,
   `covers` or `detail`. `covers` carries a digest, a tool alias and optionally a `useId`.

## 5. Verification

v4 artifacts are validated against the v4 schema; all common-rules checks apply. A verifier
adds the check `enforcement` for a v4 run, and for a run of any version when it is given
the bytes of a `control-set` object with the policy content type; on a run that is not v4
only `evidence_version_mismatch` can occur. The check is `bad` when any of these findings
is present.
"Previous" and "next" mean seq − 1 and seq + 1.

| Finding | When |
|---|---|
| `orphan_result` | A `tool_result` whose `useId` no earlier `tool_call` of the run used. |
| `conflicting_result` | A second `tool_result` for the same `useId`. |
| `executed_after_denial` | A `tool_result` for a `useId` that an enforcement record names in `step.tool.useId`. |
| `duplicate_use_id` | Two or more `tool_call` events share a `useId` (one finding per `useId`, listing every such call). |
| `misplaced_decision` | An enforcement record whose previous event is itself an enforcement record; an enforcement record with `tool` whose previous event is not a `tool_call` with the same `tool.name` and `useId`; or an enforcement record without `tool` whose previous event is a `tool_call`. |
| `unrecorded_halt` | A `run_end` with `runDisposition: "halted"` whose previous event is not an enforcement record. |
| `continued_after_halt` | An enforcement record with reason `unavailable`, or without `tool` (every record without `tool` is a halt), whose next event is not a `run_end` with `runDisposition: "halted"`. |
| `evidence_version_mismatch` | Only when the verifier is given the control-set bytes, the run's `control-set` object has the policy content type (Control Set v1 §1, compared exactly), and the run's events are not all v4: reported **unless** the bytes parse under the strict rules of Control Set v2 §2 (UTF-8 without a byte-order mark, I-JSON, at most 64 levels) as a JSON object without a `schemaVersion` member (a v1 control set). Bytes that do not parse strictly, or are not an object, are a mismatch: the check fails closed. |

Each finding lists the seqs involved. A `bad` `enforcement` check makes the run
`run_invalid` (common rules §8): the record contradicts itself.

Whether a halt was due after a record with `tool` other than `unavailable` (a matching
`halt` rule, or the denial count) needs the control set, and so does whether a denial was due at all; these are
an evaluator's job. **A verifier does not evaluate the policy: a guard that skips a due
denial or halt is not detected by a verifier.** Detecting it is recomputation by an
evaluator (§6), specified with evaluations of v2 control sets in a later round.

## 6. Recomputing decisions (informative)

With the control-set bytes and the signed events, anyone can rebuild each event's facts-v2
request (Control Set v2 §8), run the Cedar core named in `enforcer.engine`, apply Control
Set v2 §7 and compare with the enforcement records in the chain. The `unknown_tool` and
`tool_changed` checks need only `cedar.entities` and the signed object digests, not the
definition's content.

What this cannot show:

- that a guard did not skip a due denial or halt, unless someone recomputes (§5);
- anything about a run whose `control-set` object does not carry the policy content type:
  it is not a policy control set, so no enforcement is expected of the run and the version
  check does not apply. What a run declares as its control set is part of the signed
  Control Artifact and visible to whoever reads the evidence;
- that a human approved: `bound` shows only that the producer recorded an approval linked
  to the call;
- whether the engine in fact failed when a record says `unavailable`;
- that a denied tool was not executed outside the recorded run.

## 7. Test vectors

`test-vectors/14-policy-enforcement/`: v4 runs as sealed by a guard, with per event the
facts-v2 request, Cedar's diagnostics and the guard's outcome; v4 envelopes the schema
accepts and rejects; runs with each §5 finding.

## 8. Decisions and open questions

- **Why not reuse `policyId`:** a guard decision names several rules and must be told apart
  from a producer's own `authorization`; `enforcer` marks it.
- **One record per decision:** a halt is the `run_end` after the record, never a second
  record, so every record sits directly after the event it decides (`misplaced_decision`).
- **Open:** a way for the policy's issuer to suspend an agent, or to gate the start of a
  run on a current approval, is left to a later round.
- **Open:** evaluations of a v2 control set are specified in a later round. Until then an
  evaluator cannot seal a `kind: "policy"` Control Evaluation for one (Control Evaluation
  v2 fixes `evaluator.factsVersion` to `"1"`).
