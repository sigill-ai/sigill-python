# ControlEvaluation v2 — Specification (draft)

**Status:** draft.
**Content type:** `application/vnd.sigill.control-evaluation+json` (unchanged from v1)
**Schema:** [`control-evaluation-v2.schema.json`](./control-evaluation-v2.schema.json)
**Common rules:** [`agent-profiles-common-v1.md`](./agent-profiles-common-v1.md)
**Builds on:** [ControlEvaluation v1](./control-evaluation-v1.md), [Agent Policy Control Set v1](./agent-policy-control-set-v1.md)

v1 can only carry what a verifier observed in a target system: it requires an
`observed-state` object. A run checked against a declared policy has no such state;
its evidence is the signed events themselves. v2 adds `kind`, with one kind per member
of the control set, so each statement is made by the party that can make it and
signed by that party:

| `kind` | Evaluates | Made by | Basis |
|---|---|---|---|
| `state` | `controls` (state controls) | a verifier reading the target system | what it observed |
| `policy` | `cedar` (forbid rules) | an evaluator running the open engine on the open facts | recomputable by anyone |
| `attested` | `privateControls` | the producer | the producer's word |

The key words MUST, SHOULD and MAY are used as in RFC 2119. Rules of v1 apply unless
this document changes them.

## 1. Envelope

```json
{
  "schemaName": "ControlEvaluation",
  "schemaVersion": "2",
  "kind": "policy",
  "evidenceId": "<uuid>",
  "createdAt": "2026-10-24T15:52:00Z",
  "actor": { "type": "verifier", "id": "urn:example:policy-evaluator", "version": "1.0.0" },
  "activity": { "name": "support-session", "correlationId": "urn:uuid:<run>" },
  "subject": {
    "controlArtifactSignatureSha256": "hex…",
    "runEndSignatureSha256": "hex…",
    "throughSignatureSha256": "hex…"
  },
  "controlSet": { "id": "support-agent-controls", "version": "3" },
  "controls": [
    { "id": "allowed-tools", "result": "FAIL", "where": ["3"] },
    { "id": "max-steps", "result": "PASS" }
  ],
  "overall": "FAIL",
  "evaluatedAt": "2026-10-24T15:51:58Z",
  "policy": {
    "approvalScopeDigest": "hex…",
    "cedarDigest": "hex…",
    "policyStatus": "approved_before_run",
    "evaluator": { "engine": "cedar-policy@4.14.0", "factsVersion": "1", "schemaSha256": "hex…" },
    "prefix": { "throughSeq": 7, "finalSeq": 7, "missingSeqs": [] },
    "state": "finalized",
    "privateControlsReported": "reported"
  },
  "objects": [
    { "uri": "objects/<uuid>", "role": "control-set",      "contentType": "application/vnd.sigill.control-set+json" },
    { "uri": "objects/<uuid>", "role": "evaluation-facts", "contentType": "application/json" },
    { "uri": "objects/<uuid>", "role": "policy-approval",  "contentType": "application/vnd.sigill.policy-approval+json" }
  ]
}
```

## 2. Fields common to all kinds

| Field | Required | Rule |
|---|---|---|
| `schemaVersion` | yes | `"2"`. |
| `kind` | yes | `state`, `policy` or `attested`. |
| `actor.type` | yes | `verifier` for `state` and `policy`; `producer` for `attested`. |
| `subject.controlArtifactSignatureSha256` | yes | `signatureSha256` of the run's Control Artifact. |
| `subject.runEndSignatureSha256` | see kind | `signatureSha256` of `run_end`. |
| `controlSet` | yes | MUST equal `controlSet` in the Control Artifact. |
| `controls[]` | yes, ≥ 1 | `{ id, result, detail?, where? }`, `result` is `PASS`, `FAIL` or `INDETERMINATE`. The set of ids is fixed by the kind (§3–§5): none missing, none extra, none repeated. |
| `overall` | yes | `FAIL` if any control is `FAIL`, else `INDETERMINATE` if any is, else `PASS`. A verifier MUST check this; in v1 it was only asserted. |
| `evaluatedAt` | yes | The evaluator's claim of when it evaluated. Seal time is proven by `sigTst`. |
| `supersedes` | no | `{ evidenceId, signatureSha256 }` of an earlier evaluation of the same kind, run and control set that this one replaces (§6). |

Exactly one `control-set` object is REQUIRED for every kind, with the same URI and digest
as the `control-set` object in the Control Artifact (v1 §3).

## 3. `kind: "state"`

As v1. `controls[]` are the ids of the control set's `controls`. `subject.runEndSignatureSha256`
is required. Objects: `control-set`, at least one `observed-state`, at most one
`baseline-state`. No `policy` member.

## 4. `kind: "policy"`

The control-set object MUST be a policy control set (content type
`application/vnd.sigill.control-set+json`) with a `cedar` member.

### 4.1 Controls

Exactly one entry per Cedar rule, keyed by its `id` annotation. `result` is the rule's
result over every request of the evaluated facts, per Control Set v1 §6. `where` lists,
for `FAIL` and `INDETERMINATE`, the requests that produced it: the seq as a decimal string,
or `"run"` for the run-level request, in request order. `where` is absent for `PASS`.

### 4.2 The `policy` member

| Field | Required | Rule |
|---|---|---|
| `approvalScopeDigest` | yes | Control Set v1 §3, computed from the control-set object bytes. A verifier recomputes it. |
| `cedarDigest` | yes | Control Set v1 §3. A verifier recomputes it. |
| `policyStatus` | yes | `approved_before_run`, `approved_after_start` or `unapproved` (§4.4). |
| `evaluator.engine` | yes | The Cedar core that evaluated, as `cedar-policy@<x.y.z>`. |
| `evaluator.factsVersion` | yes | `"1"` (Control Set v1 §5). |
| `evaluator.schemaSha256` | yes | MUST equal the control set's `cedar.schemaSha256`. |
| `prefix.throughSeq` | yes | Last seq of the contiguous received prefix that was evaluated. |
| `prefix.finalSeq` | yes | `run_end`'s `finalSeq`, or `null` when no `run_end` was received. |
| `prefix.missingSeqs` | yes | Seqs below the highest received seq that were missing; the events after the first gap were not evaluated. |
| `state` | yes | `finalized`: `run_end` received and no gap. `partial`: sealed with a gap or without `run_end` after the evaluator's waiting period (§7). |
| `privateControlsReported` | when the control set declares `privateControls` | `reported`, `missing` or `pending`: whether an `attested` evaluation covering every private control had been received when this evaluation was made (`pending`: still within the waiting period). |

`subject.throughSignatureSha256` is REQUIRED: the `signatureSha256` of the event at
`prefix.throughSeq`. `subject.runEndSignatureSha256` is REQUIRED when `state` is `finalized`
and absent otherwise.

### 4.3 Objects

| Role | Count | Content |
|---|---|---|
| `control-set` | 1 | As §2. |
| `evaluation-facts` | 1 | The facts document (§4.5), exact JCS bytes. |
| `policy-approval` | 0–1 | The exact bytes of the sealed approval record the status rests on. REQUIRED when `policyStatus` is `approved_before_run` or `approved_after_start`, absent for `unapproved`. |

No `observed-state` or `baseline-state`.

### 4.4 Policy status

Defined against the Control Artifact's timestamp (`genTime`) and the approval record's
`effectiveAt`, with a margin equal to the timestamp token's stated accuracy (else one
second):

- `approved_before_run`: an approval of this `approvalScopeDigest` was in effect before
  `genTime` minus the margin, was not revoked before `genTime` plus the margin, and the
  Control Artifact's timestamp was issued when it was sealed.
- `approved_after_start`: an approval exists, but not one that satisfies the above.
- `unapproved`: no approval of this `approvalScopeDigest`.

The approval record's `approvalScopeDigest` MUST equal `policy.approvalScopeDigest` (an
approval covers every byte variant of the same scope; its `controlSetSha256` names the
variant that was reviewed and is informative). The record's own seal MAY be supplied with
the evaluation; a verifier that has it checks that the seal's envelope digest is the
`policy-approval` object's digest and that its timestamp is not later than the status
requires.

### 4.5 Facts document

```json
{
  "factsVersion": "1",
  "throughSeq": 7,
  "missingSeqs": [],
  "runLevel": true,
  "requests": [
    { "seq": 0, "principal": { "type": "Agent", "id": "…" }, "action": { "type": "Action", "id": "run_start" },
      "resource": { "type": "Step", "id": "0" }, "context": { "approval": "none", "consequential": false, "…": "…" } },
    { "seq": "run", "…": "…" }
  ]
}
```

The requests of Control Set v1 §5, built from the signed events of the evaluated prefix, in
order; `runLevel` is true when the run-level request is present. The facts are fully
determined by the signed events, the Control Artifact's `agent.id` and the run's
`correlationId`. A verifier MUST rebuild them and MUST compare the JCS bytes with the
`evaluation-facts` object; any difference makes the evaluation invalid. The facts carry no
content: no arguments, prompts or results.

### 4.6 Reproducing the results

The facts and the policy are enough to recompute every result with the official Cedar core
named in `evaluator.engine`: `controls[]` MUST equal Control Set v1 §6 applied to the facts.
A verifier that has the engine MUST recompute. A verifier without it MUST report the
results as not recomputed; the facts are still checked (§4.5).

## 5. `kind: "attested"`

The producer's own results for the control set's `privateControls`. `controls[]` holds
exactly one entry per declared private control id; a missing id makes the evaluation
invalid. Objects: `control-set` only. `subject.runEndSignatureSha256` is required. An
optional `attested` member `{ evaluatorId, evaluatorVersion }` names the producer's
evaluating component. The results are the producer's word; what a verifier can check is
that every declared private control was reported.

## 6. Superseding

Evaluations are append-only. Late events, a new facts or engine version, or new findings
in the chain produce a new evaluation with `supersedes` naming its predecessor; the
predecessor is never changed or deleted. Among evaluations of one kind, run and control
set, the current one is the one no other valid evaluation supersedes. Two valid
evaluations that both claim to be current are a finding.

## 7. When an evaluator seals (informative)

An evaluator evaluates the contiguous prefix as events arrive and seals only:

- `finalized`, after `run_end` and a waiting period for late uploads (recommended
  default ten minutes);
- `partial`, when a gap stays open past that waiting period, or when no `run_end` arrives
  within a horizon (recommended default 24 hours). A run that goes quiet within the
  horizon gets a preliminary, unsigned result and an alert, never a sealed verdict.

A later event or a filled gap produces a superseding evaluation (§6).

## 8. Signer

As v1 §4, the evaluation is always timestamped and SHOULD be sealed with a certificate
other than the agent's. A verifier MAY be given its expected evaluation signers.

An evaluation sealed with a shared service certificate (one several parties can seal
with) is only attributable to the service operator when the JAdES protected header
carries the operator's reserved role in `srAts.claimed` (ETSI TS 119 182-1 §5.2.6):

```json
"srAts": { "claimed": [ { "mediaType": "application/vnd.sigill.sealed-for",
                           "encoding": "8bit", "qVals": ["urn:sigill:role:policy-evaluator"] } ] }
```

`encoding` is a JSON Schema `contentEncoding` value (`8bit`: the value is the plain string).
The operator MUST emit this value only for its own statements, never on a seal requested
by a customer. A verifier MUST NOT attribute a `policy` evaluation to Sigill unless the
seal carries it.

## 9. Verification summary

A v2 evaluation is valid when the signature covers the envelope, the timestamp is
valid, the envelope conforms to the schema and to the rules of its kind, the subject names
this run, the control set matches the Control Artifact, `overall` follows from
`controls[]`, and for `policy`: both digests recompute, the facts rebuild byte-exactly, the
approval record matches (§4.4), and the results recompute when the engine is available.
Evaluations are reported on their own and never change the run's verdict.

A `policy` evaluation can only be checked with its `control-set` and `evaluation-facts`
bytes (and its `policy-approval` bytes when approved), so a verifier given its digests alone
MUST NOT report it valid. The facts and the policy carry no prompts, arguments or results,
so a bundle can carry them without carrying content. An `attested` evaluation likewise needs
the `control-set` bytes to show every private control was reported. A `state` evaluation
keeps v1 behaviour: without the control set's bytes its control ids are not checked.
