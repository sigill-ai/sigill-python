# Agent Delegation v1 — Sub-agent runs (draft)

**Status:** r4, 2026-10-11. Normative once merged together with its test vectors
(`test-vectors/agent-run-tree/`). Extends [Agent Evidence Profiles v1](./agent-profiles-common-v1.md);
everything there applies unless stated otherwise.

r2 addressed the first review (scope, state machine, cardinality, ordering wording,
versioning, attribution, fingerprint, limits, event budget). r3 pins every finding code
(§6.3), the field rules of the two new step types (§3.2, §3.3), per-agent attribution
(§5), root derivation (§6.3), and adds an informative producer mapping for Claude Code
(§11), based on observed hook behaviour. r4 makes the fingerprint order normative (§6.8:
UTF-16 code units), states that `tree_finalized` means complete evidence, not successful
work (§6.5), and tightens the Claude Code pairing rule (§11). The integer domain of
`seq` / `finalSeq` is clarified in the common rules (§1).

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Problem

An agent that starts sub-agents has no correct way to record them under v1:

- **Children's events in the parent's chain.** This breaks as soon as children run
  concurrently, because `seq` is gap-free under one signer. It also breaks when a child
  runs under another certificate, or under its own control basis.
- **Children as separate runs.** Nothing ties them to the parent. A child run can be
  removed, swapped or added afterwards, and no verifier can tell.

This extension gives each child its own run and binds parent and child in both directions,
so the relationship becomes part of the signed evidence.

## 2. Model

- A **run tree** is a root run plus every run it delegated to, recursively.
- Every run in the tree is a complete run:
  - its own `correlationId`;
  - its own Control Artifact;
  - its own chain from `run_start` to `run_end`;
  - its own signer;
  - optionally its own Control Evaluations.
- A **delegation edge** connects one `delegation` event in a parent's chain to one child
  run.

Each edge is bound in three places:

| # | Where | Field | Kind |
|---|---|---|---|
| 1 | parent `delegation` event | `delegation.childCorrelationId`, `delegation.childAgentId` | a signed **declaration** of the child's identity (not a hash reference) |
| 2 | child `run_start` | `binds.parentDelegationSignatureSha256`, `binds.parentCorrelationId` | a `signatureSha256` reference to the parent's `delegation` event |
| 3 | parent `delegation_result` event | `delegation.childRunEndSignatureSha256`, `delegation.childDisposition` | a `signatureSha256` reference to the child's `run_end` |

What the references prove is **signature order**, nothing more (common rules §2, §4):

- Binding 2: the child's `run_start` was sealed after the parent's `delegation` signature
  existed.
- Binding 3: the child's `run_end` signature existed before the parent's
  `delegation_result` was sealed.

Neither proves when the child actually began or acted. That the child does nothing before
its `run_start` is sealed is a producer requirement (§4), not a verified fact (common rules
§8.1). The child's Control Artifact is bound by the child's own `run_start` (v1). Its
order relative to the `delegation` is **not** proven in this version (§10).

### 2.1 What a verified tree fixes

Given:
- valid signatures on every artifact;
- a valid, trusted timestamp on the root's `run_end`;
- a verifier that knows which root it expects (§6.7);

the following are fixed as of that timestamp: the signed envelopes of every run reachable
from the root through bindings 2 and 3, their Control Artifacts (through each `run_start`'s
`binds`), and the object digests those envelopes commit to.

**Not fixed by the tree:**
- Control Evaluations. They point at a `run_end`, but nothing points back at them; each is
  judged on its own (common rules §8).
- Unprotected-header augmentation (later `sigTst`, revocation data). This is excluded from
  bindings by design (common rules §2).
- Payload availability.
- Anything the producers did not record.

Children keep v1's mandatory timestamps: their Control Artifact and `run_end` are always
timestamped. The root anchor narrows the rewrite window for the children's *unstamped*
events. It does not replace the children's own timestamps.

## 3. Schema changes

### 3.1 Versions

- `AgentExecutionEvidence` gains `schemaVersion: "2"`: v1 plus the fields below.
- `AgentControlArtifact` and `ControlEvaluation` stay at `"1"`. This extension changes
  neither.
- Allowed combinations:

| Profile | Version |
|---|---|
| Execution artifacts of one run | all `"1"` or all `"2"`; never mixed |
| Control Artifact | `"1"` |
| Control Evaluation | `"1"` |

- A run that delegates, or that is a child, MUST use execution `"2"`.
- Verifiers dispatch the execution schema on `schemaVersion`. The common-rules checks apply
  to both versions, with the v2 schema used for v2 artifacts.
- The v1 schemas are not changed.

### 3.2 New step types

`step.type` (v2) gains `delegation` and `delegation_result`.

```json
"step": {
  "type": "delegation",
  "eventTime": "2026-10-10T09:00:02.120Z",
  "consequential": false,
  "timestamp": "none",
  "delegation": {
    "childCorrelationId": "urn:uuid:<child run>",
    "childAgentId": "urn:example:agent:security-reviewer",
    "useId": "toolu_…"
  }
}
```

```json
"step": {
  "type": "delegation_result",
  "eventTime": "2026-10-10T09:04:11.410Z",
  "consequential": false,
  "timestamp": "none",
  "delegation": {
    "childCorrelationId": "urn:uuid:<child run>",
    "childRunEndSignatureSha256": "hex…",
    "childDisposition": "completed"
  }
}
```

| Field | Rule |
|---|---|
| `delegation.childCorrelationId` | REQUIRED in both types. Opaque, under `activity.correlationId`'s rules. |
| `delegation.childAgentId` | REQUIRED in `delegation`. An expectation: it MUST equal the child Control Artifact's `agent.id`. |
| `delegation.useId` | OPTIONAL. Correlates with a `tool_call` that requested the child. |
| `delegation.childRunEndSignatureSha256` | REQUIRED in `delegation_result`. |
| `delegation.childDisposition` | REQUIRED in `delegation_result`. MUST equal the child `run_end`'s `runDisposition`. |

- `step.delegation` is REQUIRED in `delegation` and `delegation_result` and MUST NOT
  appear in any other step type.
- A `delegation` MUST NOT carry `childRunEndSignatureSha256` or `childDisposition`.
- A `delegation_result` MUST NOT carry `childAgentId`; the declaration in the matching
  `delegation` is the only one.
- `step.delegation` is `additionalProperties: false`.

`step.consequential` MAY be `true` on a `delegation`. SDKs SHOULD set it when the child is
granted write authority. It follows the normal timestamp policy; there is no special
delegation flag in this version (§7).

New object role `delegation-input` (v2): the instruction given to the child. It stays
with the producer.

### 3.3 Child binding

In a child's `run_start` (v2), `binds` gains:

```json
"binds": {
  "controlArtifactSignatureSha256": "hex…",
  "parentDelegationSignatureSha256": "hex…",
  "parentCorrelationId": "urn:uuid:<parent run>"
}
```

- Both new fields are REQUIRED in a child's `run_start`, and absent in a root's: either
  both are present or neither is.
- No other event carries them (schema rule).
- A run is a **root** when its `run_start` carries no parent binding, and a **child** when
  it does. A run with no readable `run_start` is neither; it is `run_invalid` (common rules
  §8) and is reported as `unreachable_run` unless a parent's `delegation` declares it.

### 3.4 Identifier comparison

`correlationId`, `childCorrelationId` and `parentCorrelationId` are compared as exact
signed strings: case-sensitive, with no prefix stripping and no normalization. This is
unlike `evidenceId` (common rules §1). Producers SHOULD use `urn:uuid:` with lower-case
hex.

## 4. Producer rules

1. Seal `delegation` before starting the child. The child MUST NOT act before its own
   `run_start` is sealed. This is a producer requirement and cannot be verified.
2. Seal the child's Control Artifact, and then its `run_start` with all three `binds`.
3. Seal `delegation_result` only after the child's `run_end` is sealed, whatever the
   child's disposition.
4. At most one `delegation_result` per `delegation`. It MUST come after that `delegation`
   in the same parent run.
5. A parent with an unresolved delegation (no `delegation_result`) MAY close only with
   `runDisposition` `aborted` or `failed`. Closing `completed` with an unresolved
   delegation is a violation (§6.4).
6. **Event budget.** The bundle limit (common rules §7) applies per run. A parent MUST
   keep `outstandingDelegations + 1` sequence slots free: one `delegation_result` per open
   delegation, plus `run_end`. SDKs MUST refuse a new event or delegation that would use
   that reserve.
7. **Cancellation.** When a child exceeds a timeout or is cancelled:
   - If the child can still close, close it (`aborted` or `failed`) and record the result.
   - Otherwise, close the parent as `aborted` or `failed` with the delegation unresolved.

   Sealed references MUST be stored so that a crashed producer can resume, and retries
   MUST be idempotent (the same `delegation` is never sealed twice).
8. A producer waiting for a child MUST NOT hold the parent chain's sealing lock. Other
   parent events may be sealed meanwhile, in capture order.
9. Children MAY run concurrently and MAY delegate further (depth limit §6.1).
10. A `childCorrelationId` MUST appear in exactly one `delegation` in the whole tree. A
    run never delegates to itself.

## 5. Signers and attribution

- The one-signer rule (common rules §3) applies **per run**. Runs in a tree MAY have
  different signers.
- Attribution policy is the verifier's and is scoped by trust context: a mapping from
  (organisation context, `agent.id`) to expected signer(s) (`x5t#S256`). The relying party
  supplies the mapping for one organisation context at a time. A run whose `agent.id` is
  in the mapping and whose signer is not among the expected ones fails `signatures`
  (common rules §3), so the run, and with it the tree, is invalid. A run whose `agent.id`
  is in the mapping and matches reports `affiliation: confirmed`.
- `agent.id` alone is not a global namespace (it is defined below tenant level). A
  verifier MUST NOT look up expected signers by `agent.id` without an organisation
  context.
- Without such a policy, each run reports `affiliation: unknown`. This is separate from
  structural validity.
- A shared certificate (e.g. a platform seal) proves signature consistency, not
  affiliation. Verifiers MUST report `affiliation: unknown` for runs signed with one,
  unless an external identity policy says otherwise.
- **Cross-tree and cross-tenant grafting** is detected structurally only when the
  signed references disagree (`unbound`, `child_only`). A run grafted with consistent
  references, by someone able to sign with the same shared key, is detectable only under
  an expected-root anchor (§6.7) or an attribution policy. This spec does not claim more.

## 6. Verification

### 6.1 Tree bundle and limits

```json
{
  "format": "AgentRunTreeBundle",
  "bundleVersion": "1",
  "rootCorrelationId": "urn:uuid:…",
  "runs": [ { /* AgentRunBundle, common rules §7 */ }, … ]
}
```

**Limits** (checked before anything else):

| Limit | Value |
|---|---|
| runs | 1–256 |
| depth | ≤ 8 (root = 0) |
| execution artifacts, whole tree | ≤ 20 000 |
| payload entries, whole tree | ≤ 50 000 |
| payload bytes, whole tree | ≤ 512 MiB |

- Each run also keeps the common-rules per-run limits.
- A limit exceeded makes the tree `tree_invalid` (finding `limit_exceeded`), and
  verification stops there: no run verdicts, no edges, no fingerprint. The depth limit is
  found after the root is derived, so that result still names the root. Resource exhaustion
  never yields `tree_finalized`.
- `rootCorrelationId` and the order of `runs[]` are indexes for humans. The verifier
  derives everything from signed envelopes.

### 6.2 Per run

Each run is verified as in common rules §8, with the execution schema chosen by version
(§3.1). Its verdict is never changed by the tree.

### 6.3 Structural rules (each violation is a `bad` finding)

Structure is derived from the signed envelopes of every supplied run, whatever that run's
own verdict. A run's `correlationId` is the one its envelopes sign (common rules §8).

| Code | When |
|---|---|
| `duplicate_run` | Two supplied runs sign the same `correlationId`. |
| `no_root` | No supplied run is a root (§3.3). |
| `multiple_roots` | More than one supplied run is a root. |
| `unreachable_run` | A supplied run is not reachable from the root. Reachable: the root, and any run that a reachable run declares in a `delegation` or that binds a reachable run as its parent. |
| `cycle` | Following parent bindings from some run returns to that run. |
| `self_delegation` | A `delegation` declares its own run's `correlationId`, or a `run_start` names its own run as parent. |
| `duplicate_delegation` | One parent run declares the same `childCorrelationId` in more than one `delegation`. |
| `child_two_parents` | `delegation` events in two different runs declare the same `childCorrelationId`. |
| `orphan_result` | A `delegation_result` names a child that its run never declares in a `delegation`. |
| `result_before_delegation` | A `delegation_result`'s `seq` is lower than that of the `delegation` declaring the same child. |
| `duplicate_result` | A run has two `delegation_result`s for the same child. |
| `agent_mismatch` | A `delegation`'s `childAgentId` differs from the supplied child's Control Artifact `agent.id` (or, without one, its `run_start` `actor.id`). |
| `unexpected_root` | An expected root was given (§6.7) and the derived root does not match. |
| `limit_exceeded` | A §6.1 limit is exceeded. Verification stops there. |

The derived root, when there is exactly one, is the tree's root even if other
findings are present.

### 6.4 Per edge

For each `delegation` in a supplied run, and each child `run_start` with a parent binding:

**Binding state:**

| State | When |
|---|---|
| `mutually_bound` | The parent's `delegation` declares the child's exact `correlationId` and `agent.id`, and the child's `run_start` references that `delegation`'s `signatureSha256` and the parent's `correlationId`. |
| `child_missing` | The parent delegates; no run with that `correlationId` is supplied. |
| `parent_missing` | A child references a parent `correlationId` that is not supplied. |
| `unbound` | Both sides are supplied but disagree: wrong `signatureSha256`, wrong `parentCorrelationId`, the child's `run_start` has no parent binding although the parent declared it, or the child binds a parent run that declares no `delegation` for it. Always `bad`. |

**Completion state:**

| State | When |
|---|---|
| `result_bound` | The `delegation_result`'s `childRunEndSignatureSha256` and `childDisposition` match the supplied child's `run_end`. |
| `result_mismatch` | They do not match. Always `bad`. |
| `result_unresolved` | There is a `delegation_result`, but the child, or the child's `run_end`, is not supplied. |
| `no_result` | There is no `delegation_result`. |

### 6.5 Tree verdict — decision algorithm

Evaluate in order and stop at the first match:

```
1. any limit_exceeded                                   → tree_invalid
2. any structural finding (§6.3)                        → tree_invalid
3. any run verdict run_invalid                          → tree_invalid
4. any edge unbound | result_mismatch | parent_missing  → tree_invalid
5. any edge result_unresolved (a result names a child that is withheld), or
   child_missing under a parent whose run_end is 'completed'
                                                        → tree_invalid   (withheld evidence)
6. any edge no_result where the parent's run_end is 'completed'
                                                        → tree_invalid   (§4 rule 5)
7. every run run_finalized, every edge mutually_bound + result_bound
                                                        → tree_finalized
8. otherwise                                            → tree_open
```

At step 8 the verifier MUST list why the tree is open:
- `run_open` runs;
- edges with `no_result` or `child_missing` under a parent that has no `run_end`;
- edges unresolved under a parent closed `aborted` or `failed`. These carry the finding
  "parent terminated; evidence incomplete". A terminated tree with unresolved evidence
  never becomes finalized, and the verifier never suggests that more activity will follow.

`tree_finalized` describes the completeness of the evidence, not the success of the work: a
child closed `aborted` or `failed` whose run is supplied and whose result is bound is
complete evidence, and its tree can be finalized (step 7).

The tree verdict never upgrades a run.

An edge is reported once per `delegation`, plus once per child whose parent binding
matches no `delegation` (`parent_missing` or `unbound`, with completion `no_result`).

### 6.6 Evaluations

A Control Evaluation names exactly one run and is reported under that run. It is not
covered by the tree's anchor (§2.1). A tree-level evaluation is out of scope.

### 6.7 Expected root

A verifier MAY be given the expected root: its `correlationId`, and/or the root
`run_end`'s `signatureSha256`, and/or its signer. When given, a bundle whose derived root
does not match is `tree_invalid` (finding `unexpected_root`). Without it, a verifier
proves internal consistency of the supplied tree, not that it is the tree the relying
party had in mind.

### 6.8 Tree fingerprint

For caching, a deterministic fingerprint over everything the tree verdict depends on:

```
runs  = [ { "c": signed correlationId, "f": runFingerprint (common rules §8.2) } ]
        sorted by c, then f (see below)
tree  = sha256hex(JCS({ "format": "AgentRunTreeBundle", "bundleVersion": "1",
                         "root": derived root correlationId, "runs": runs }))
```

- Sort `c`, then `f`, lexicographically by unsigned UTF-16 code units, without
  normalization, case folding or locale collation; a prefix sorts before the longer string.
  (This is the order of .NET `StringComparer.Ordinal` and of JavaScript string comparison;
  a code-point sort differs for characters outside the Basic Multilingual Plane.)
- The tree fingerprint is null if any run fingerprint is null, or the root cannot be
  derived.
- A cache key MUST also include the verifier version, the rules version, the
  expected-root and attribution policy, and the trust policy.
- A change in any evaluation, payload or run therefore changes the key.

### 6.9 Scope

`tree_finalized` means, under §2.1's conditions:
- the root's control basis was sealed first;
- each child's `run_start` was sealed after its parent's `delegation` signature existed;
- each child's `run_end` signature existed before its parent's `delegation_result` was
  sealed;
- the signed envelopes of every run are unchanged since the root's `run_end` was
  timestamped.

It does not prove:
- that every sub-agent the system started was recorded;
- when any child actually acted;
- that children did only what the parent intended;
- that evaluations are complete;
- who operates a shared certificate.

## 7. Timestamp policy

- There are no new mandatory timestamps, and the policy fields are unchanged
  (`AgentControlArtifact` stays `"1"`).
- A producer wanting delegation edges anchored sooner sets `step.timestamp: "required"`
  on `delegation` and `delegation_result`, or sets `step.consequential: true` under
  `timestampPolicy.consequential`.
- A dedicated policy flag would need a Control Artifact v2. It is deferred (§10).

## 8. Privacy

- `childAgentId`, `childCorrelationId` and `parentCorrelationId` are opaque identifiers,
  under the same rules as `actor.id`.
- What the parent asked the child to do is only ever a `delegation-input` object, held by
  the producer.
- The delegation graph itself is metadata. A service may index it only from envelopes
  the producer chose to upload, as it indexes any other signed envelope field. An index is
  a view: a tree verdict always comes from verifying the signed runs (§6), never from the
  index alone.

## 9. Test vectors

Stub-signer vectors live in `test-vectors/agent-run-tree/` (stub signer and verifier as in
`test-vectors/agent-run/README.md`). Each vector pins the tree verdict, every run's
verdict, every edge's binding and completion state, the set of finding codes, the open
reasons and the tree fingerprint. Expected values are declared by the generator, never
derived from an SDK.

They cover:

1. **States.** A finalized tree; a child still open; a child closed but no result yet;
   a parent closed `completed` with an unresolved delegation; a parent closed `aborted`
   with one; a withheld child; a child closed `failed` with a matching result.
2. **Structure.** Orphan result; result before its delegation; duplicate result;
   duplicate run ids; no root; two roots; a disconnected run; self-delegation; a cycle;
   the same child declared by two parents; the same child declared twice by one parent.
3. **Binding.** A delegation replayed into another parent; the right `signatureSha256`
   with the wrong `parentCorrelationId`; a broken grandchild edge under a sound child edge;
   `childAgentId` mismatch; a result naming the wrong `run_end`; a result with the wrong
   disposition.
4. **Run-level.** An invalid child signature; a v1 artifact inside a v2 run; a v1 root
   that delegates (schema violation).
5. **Attribution.** An expected-root mismatch; an expected signer per agent, met and not
   met.
6. **Not covered by the anchor.** A later evaluation on a child: the tree verdict is
   unchanged, the fingerprint changes.
7. **Determinism.** Reordered `runs[]`: identical result and fingerprint; correlation ids
   with U+E000 and U+10000 pin the §6.8 order (UTF-16 code units).
8. **Limits.** Depth 8 and 9; 257 runs.

The SDK tests additionally cover the producer rules: event budget reserve (§4 rule 6), no
`completed` close with an open delegation (§4 rule 5), one result per delegation.

A real-signature tree from the Sigill test tenant (`test-vectors/11-agent-delegated-run/`)
follows once the platform seals v2 artifacts.

## 10. Decisions and open questions

**Decided in r2:**
- `delegation` MAY be consequential; it is not consequential by default.
- No attach to an existing run: a delegation always creates a new child run. A later,
  separate relation type can express dependencies on existing runs.
- Server-side indexing of trees gets its own specification.

**Open:**
- **Child Control Artifact binding the parent.** Should the child's Control Artifact also
  bind the `delegation` signature? That would prove *delegation → child control basis*
  order. It is deferred: the r2 scope does not claim that order.
- **Policy flag.** Should there be a `timestampPolicy.delegation` flag? It requires a
  Control Artifact v2, and is deferred until that version is needed for another reason.

## 11. Producer mapping: Claude Code (informative)

How the Sigill plugin for Claude Code applies this extension. Observed with Claude Code
2.1 hook inputs on 2026-10-10, including three sub-agents launched in parallel.

| Hook | Observed | Evidence |
|---|---|---|
| `PreToolUse` (tool `Agent`) | Fires in the parent before the sub-agent exists; carries `tool_use_id` and `subagent_type`. | Parent `delegation`: a fresh `childCorrelationId` (`urn:uuid:`), `childAgentId` from `subagent_type`, `useId` = `tool_use_id`, `delegation-input` = digest of the instruction. |
| `SubagentStart` | Fires once per sub-agent with its `agent_id` and `agent_type`, before any of its tool calls. Carries no `tool_use_id`. | Child Control Artifact, then child `run_start` binding the pending `delegation`. |
| Hooks with `agent_id` | Every tool hook inside a sub-agent carries its `agent_id`. | Events in the child run. |
| `PostToolUse` (tool `Agent`) | Returns `agentId` for the `tool_use_id`; `status` is `async_launched` for background sub-agents. | Confirms the pairing (below). |
| `SubagentStop` | Fires when the sub-agent finishes; may come after the parent's `Stop`. | Child `model_output` and `run_end`, then the parent's `delegation_result`. |
| `SessionEnd` | Ends the session. | Every child still open is closed `aborted` and resolved in the parent before the parent's `run_end`. |

**Pairing.** `SubagentStart` does not name the `tool_use_id` that launched it. In every
observed case, parallel launches included, Claude Code ran `PreToolUse` → `SubagentStart`
→ `PostToolUse` for one sub-agent before the next. The plugin binds a `SubagentStart` only
when exactly one unpaired `delegation` of that `subagent_type` is pending; otherwise the
sub-agent's events stay in the parent run, tagged, and the delegation stays unresolved (the
parent then closes `aborted`). It checks every binding against
`PostToolUse.tool_response.agentId`; on a contradiction it seals a `checkpoint` in the parent
whose `detail` starts with `capture-fidelity:` and stops pairing for the rest of the session.
Pairing fidelity is a producer property: the tree verdict proves the signed bindings, not
that every launch was paired as it happened.

