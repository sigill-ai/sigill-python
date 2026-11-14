# ControlEvaluation v3 — Specification (draft)

**Status:** draft.
**Content type:** `application/vnd.sigill.control-evaluation+json` (unchanged)
**Schema:** [`control-evaluation-v3.schema.json`](./control-evaluation-v3.schema.json)
**Common rules:** [`agent-profiles-common-v1.md`](./agent-profiles-common-v1.md)
**Builds on:** [ControlEvaluation v2](./control-evaluation-v2.md), [Agent Policy Control Set v2](./agent-policy-control-set-v2.md), [Agent Enforcement v1](./agent-enforcement-v1.md)

v2 evaluates a run against a v1 policy control set: facts v1, and nothing is expected of the
producer during the run. A v2 control set is enforced by a guard in the producer (Control Set
v2 §7) and is evaluated on facts v2. v3 is v2 with two changes to `kind: "policy"`: the facts
are facts v2, and the evaluation carries the **enforcement comparison** — for each event, what
the control set required the guard to do against what the chain records. A reader can then tell
a forbidden action that was stopped, as the policy required, from one that was let through.

The key words MUST, SHOULD and MAY are used as in RFC 2119. Rules of v2 apply unless this
document changes them; "v2 §n" is a section of ControlEvaluation v2.

## 1. Versions

| Control set of the run | `kind: "policy"` evaluation |
|---|---|
| v1 (no `schemaVersion` member) | ControlEvaluation v2. A v3 `policy` evaluation of it is invalid. |
| v2 (`schemaVersion: "2"`) | ControlEvaluation v3. A v2 `policy` evaluation of it is invalid (v2 fixes `evaluator.factsVersion` to `"1"`). |

- `schemaVersion` is `"3"`.
- `kind: "state"` and `kind: "attested"` are v2 §3 and §5 unchanged, and MAY be sealed as
  either version.
- Verifiers dispatch the evaluation schema on `schemaVersion`. The v1 and v2 schemas are not
  changed.

## 2. `kind: "policy"`

v2 §4 applies with these changes:

| v2 | v3 |
|---|---|
| §4, control set | MUST be a v2 policy control set (Control Set v2 §1). Its `cedar` member MAY be absent or hold no policy: a control set may enforce with `unknownTools` and `lockedConfiguration` alone. |
| §4.1, `controls` | One entry per Cedar rule, per Control Set v2 §9 over the facts of §3; `[]` when the control set has no rule, and `overall` is then `PASS`. A matching rule is `FAIL` whatever its effect and whatever the guard did about it. |
| §4.2, `cedarDigest` | REQUIRED exactly when the control set has a `cedar` member. |
| §4.2, `evaluator.schemaSha256` | REQUIRED exactly when the control set has a `cedar` member; then equal to `cedar.schemaSha256`. |
| §4.2, `evaluator.factsVersion` | `"2"`. |
| §4.2, `evaluator.engine` | The core chosen by §4. |
| §4.2, new member | `enforcement`, REQUIRED (§6). |
| §4.5, facts document | The facts document of Control Set v2 §8 (`factsVersion` `"2"`, with `entities`). |

`overall` follows from `controls[]` alone, as v2 §2. The enforcement comparison never changes
`controls[]` or `overall`; it is read beside them. An evaluation can therefore be `PASS` and
`let_through`: an unknown tool that was allowed matches no rule.

## 3. Inputs and facts

An evaluator needs exactly:

1. the run's Control Artifact: its envelope and the object digests its signature confirms;
2. the events of the evaluated prefix (v2 §4.2): each envelope and the object digests its
   signature confirms;
3. the control-set document: the exact bytes whose SHA-256 is the signed digest of the
   Control Artifact's `control-set` object.

A digest supplied beside a signature (a bundle's `objectDigests`) counts only when the
signature confirms it (common rules §8).

No payload is needed and none is read — no arguments, prompts, results or definitions:

| Step | Reads |
|---|---|
| Facts v2 (Control Set v2 §8) | Typed envelope fields; for `approval` on a `tool_call`, the signed digest of its `tool-arguments` object (§8.1). |
| `unknown_tool` | `step.tool.name` and `cedar.entities`. |
| `tool_changed` | The signed digest of the call's `tool-definition` object and the entity's `definitionSha256`. |
| `rule`, `rule_error` | Cedar's diagnostics for the event's facts request. |
| `configuration_locked` | The Control Artifact's object roles and signed digests, and `enforcement.lockedConfiguration`. |
| The comparison's preconditions (§5.1) | Typed envelope fields. |

The facts are fully determined by the signed events and their signed object digests, the
Control Artifact's `agent.id`, the run's `correlationId` and the control set's
`cedar.entities`. A verifier rebuilds them and compares the bytes as v2 §4.5.

## 4. Engine

One Cedar core computes an evaluation: `policy.evaluator.engine` names it, for the results
and for the comparison alike. Every request of the facts is evaluated as Control Set v2 §7.1
— also when the control set has no rule: the baseline permit alone, as the guard evaluates it.
The core MUST answer every request; when it refuses one there is no evaluation of that prefix.

The **recorded engine** of the prefix is the `enforcer.engine` of its enforcement records,
when it holds at least one and all name the same core. Engine names are compared as exact
strings.

| The prefix's enforcement records | The evaluator uses |
|---|---|
| none | its own core |
| all name one core, which the evaluator can run | that core (MUST) |
| all name one core, which the evaluator cannot run | its own core, for the results only (§5.1: `engine_unavailable`) |
| name more than one core | its own core, for the results only (§5.1: `engine_inconsistent`) |

An evaluator MUST NOT perform the comparison with a core other than the recorded engine. An
evaluator implementation SHOULD keep every core version it has ever shipped available, so
that runs sealed under an earlier guard stay comparable. An evaluator that later has the
recorded engine seals a superseding evaluation (v2 §6).

## 5. Enforcement comparison

The comparison takes the events of the evaluated prefix in seq order. For the event *e* at
seq *s*:

- its **diagnostics** are the rule ids in Cedar's `diagnostics.reason` (without the baseline
  permit) and in `diagnostics.errors`, for *e*'s facts request;
- **effective effect** is Control Set v2 §4 rule 7;
- `denialsSoFar` is *e*'s fact.

An **enforcement record** is an `authorization` with an `enforcer` member (Agent Enforcement
v1 §3.4), whoever sealed it. *T* is `prefix.throughSeq`.

The comparison takes each seq at most once: two events with the same seq, or an event without
a seq, are an input error, not a finding, and no comparison is made. Events after a `run_end`
inside the prefix are compared as ordinary events.

### 5.1 When the comparison is performed

`enforcement.comparison` is `not_performed`, with the first reason that applies:

1. `chain_inconsistent` — the prefix has one of these findings of Agent Enforcement v1 §5:
   `executed_after_denial`, `misplaced_decision`, `unrecorded_halt`, `duplicate_use_id`,
   `continued_after_halt`, `evidence_version_mismatch`.
2. `engine_inconsistent` — the enforcement records of the prefix name more than one core.
3. `engine_unavailable` — the prefix has a recorded engine and the evaluator cannot run it.

Otherwise it is `performed`.

A chain with one of the findings of reason 1 contradicts its own records: a refused call has a
result, a record does not sit after the event it decides, a halt is not recorded or the run
went on after it. The comparison reads records by position (§5.3) and would report as refused
or halted what the chain itself shows was not. A run under a v2 control set whose events are
not all Execution Evidence v4 (`evidence_version_mismatch`; the evaluator always holds the
control set) cannot carry an enforcement record at all, so every due refusal would read as
missing.

The findings are taken over the events of the prefix alone, with one exemption: when the
prefix holds no `run_end`, a record at *T* is not `continued_after_halt`, because its next
event is unknown, not absent (§5.4). A verifier given the same events does report
`continued_after_halt` for that record: it judges the evidence as it stands, and evidence that
ends on a halting record does not hold the halt. The evaluation does not say otherwise. It
compares the events before, reports the decided event as `pending` — which asserts nothing —
and is superseded when the next event arrives: by the halting `run_end`, or by any other
event, which makes the prefix `chain_inconsistent`.

`not_performed` states that nothing was compared. It carries no `decisions` and no `result`,
and MUST NOT be read, summarised or displayed as `as_required`.

### 5.2 What was due

The **due outcome** of *e* is `none`, `refused` (one enforcement record) or `halted` (one
enforcement record, then the halt). When it is not `none` it has a **due reason** and **due
rules**. The first that applies:

1. *e* is an enforcement record or a `run_end`: `none` (Control Set v2 §7.1).
2. The control set has no `enforcement` member, or `mode: "observe"`: `none`.
3. *e* is `run_start`, and an entry of `lockedConfiguration` names a role of which the Control
   Artifact has no object, or whose signed digest differs: `halted`, reason
   `configuration_locked`, no rules (Control Set v2 §7.4).
4. *e* is a `tool_call`: the first of reasons 2–5 of Control Set v2 §7.2 that applies is the
   due reason, with the rules that step gives (`rule_error`, `rule`) or none (`unknown_tool`,
   `tool_changed`). When none applies: `none`. Otherwise `halted` when a rule id in
   `diagnostics.reason` has effective effect `halt`, or `haltAfterDenials` is greater than 0
   and `denialsSoFar` + 1 is at least `haltAfterDenials`; else `refused`.
5. Any other event: when `diagnostics.reason` holds rule ids with effective effect `halt`:
   `halted`, reason `rule`, rules = those ids (Control Set v2 §7.3). Otherwise `none`.

Due rules are sorted as Control Set v2 §7.2. The run-level request has no due outcome (Control
Set v2 §7.1). Reason `unavailable` is never due: the evaluator's core answered every request
(§4), and whether the guard's did cannot be recomputed.

The due outcome is computed on the recorded chain (Control Set v2 §8.2): it does not depend on
whether an earlier due outcome was recorded. "At least" in item 4 is the guard's "equals"
(Control Set v2 §7.2) on every chain in which each record was due and each due halt was
sealed; on a chain that has stepped over the number, every later denial is still due to halt.

### 5.3 What is recorded

The **recorded outcome** of *e* is read by position from the events after it (Control Set v2
§7: the record directly after the decided event, the halt directly after the record):

- `halted` — the event at *s* + 1 is an enforcement record and the event at *s* + 2 is a
  `run_end` with `runDisposition: "halted"`;
- `refused` — the event at *s* + 1 is an enforcement record and the event at *s* + 2 is not
  such a `run_end`;
- `none` — otherwise.

The **recorded reason** and **recorded rules** are that record's `enforcer.reason` and
`rules`; absent `rules` and `[]` are the same, and order does not matter. In a chain that is
compared (§5.1) the record at *s* + 1 is the record of *e*: it follows no other record, names
*e* when *e* is a `tool_call`, and names no call otherwise.

### 5.4 Open events

When the prefix holds no `run_end`, the events after *T* are unknown, not absent: the run has
not ended, or events are missing (v2 §4.2). Then *e* is **open** when *s* = *T*, or when
*s* = *T* − 1 and the event at *T* is an enforcement record. For the open event at *T* the
recorded outcome is unknown. For the open event at *T* − 1 it is `refused`: the record is
there, whether a halt follows is not known. Nothing is asserted about an open event, and
nothing about any event after *T*. When the prefix holds `run_end`, no event is open.

### 5.5 Outcome and findings

An event is **listed** when its due outcome or its recorded outcome is not `none`; the open
event at *T* is listed when its due outcome is not `none`. Its **outcome** is the first that
applies:

1. `pending` — the event is open (§5.4).
2. `not_checkable` — the recorded reason is `unavailable` and the due reason is not
   `configuration_locked` (§5.6).
3. `let_through` — a finding of class *let through* applies.
4. `over_enforced` — a finding of class *over-enforced* applies.
5. `as_required` — the recorded outcome, reason and rules are the due ones.

Findings are reported only for outcomes 3 and 4. The list is closed:

| Finding | Class | Applies when |
|---|---|---|
| `refusal_missing` | let through | *e* is a `tool_call`, the due outcome is not `none`, the due reason is not `unknown_tool`, and the recorded outcome is `none`. |
| `unknown_tool_allowed` | let through | *e* is a `tool_call`, the due reason is `unknown_tool`, and the recorded outcome is `none`. |
| `configuration_not_enforced` | let through | The due reason is `configuration_locked` and the recorded outcome is not `halted`. |
| `halt_missing` | let through | The due outcome is `halted`, the due reason is not `configuration_locked`, and the recorded outcome is not `halted`. |
| `unfounded_record` | over-enforced | The due outcome is `none` and the recorded outcome is not `none`. |
| `unfounded_halt` | over-enforced | The due outcome is `refused` and the recorded outcome is `halted`. |
| `reason_mismatch` | over-enforced | Neither outcome is `none`, and the recorded reason is not the due reason. |
| `rules_mismatch` | over-enforced | Neither outcome is `none`, the recorded reason is the due reason, and the recorded rules are not the due rules, compared as sets. |

Several findings may apply to one event; they are listed in the order of the table. With
`none` < `refused` < `halted`, a let-through finding applies exactly when the recorded outcome
is less than the due one: the guard did less than required. An over-enforced finding never
means that the chain records an action the control set forbids; it says nothing of what the
producer did outside the recorded run (§8).

The record carries no effect. A wrong effect therefore shows only through these findings: a
`halt` rule applied as `deny` is `halt_missing`, a `deny` rule applied as `halt` is
`unfounded_halt`, a `deny` or `halt` rule applied as `observe` is `refusal_missing`, and an
`observe` rule applied as `deny` is `unfounded_record`.

After `halt_missing` or `configuration_not_enforced` at seq *s*, every later event of the run
was sealed after the run had to stop. Those events are compared like any others, on the
recorded chain; they are not findings for that reason alone.

### 5.6 `unavailable`

A record with reason `unavailable` says that the guard's core could not evaluate the event
(Control Set v2 §7.5). An evaluator cannot show that it could or could not. The event is
`not_checkable`: neither `as_required` nor a finding. Its due outcome is still reported: what
the control set required of a guard whose core answered.

Such a record always halts, and in a chain that is compared the halting `run_end` follows it
(§5.1): the run ends there and no later event remains to compare.

One case is checkable. The configuration check needs no core and comes before the engine
(Control Set v2 §7.4), so when `configuration_locked` was due, a record `unavailable` is
`reason_mismatch`.

## 6. The `enforcement` member

`policy.enforcement` is REQUIRED in a v3 `policy` evaluation, for every v2 control set —
also without an `enforcement` member in the control set or with `mode: "observe"`, where
nothing is due.

| Field | Required | Rule |
|---|---|---|
| `comparison` | yes | `performed` or `not_performed` (§5.1). |
| `notPerformed` | exactly when `not_performed` | `chain_inconsistent`, `engine_inconsistent` or `engine_unavailable` (§5.1). |
| `recordedEngine` | exactly when the prefix has a recorded engine (§4) | That `enforcer.engine`. Equal to `evaluator.engine` when `performed`; different from it when `engine_unavailable`. |
| `decisions` | exactly when `performed` | One entry per listed event (§5.5), ascending `seq`. May be empty. |
| `result` | exactly when `performed` | The first of `let_through`, `over_enforced`, `not_checkable`, `pending` that is the `outcome` of some decision; `as_required` when none is, or when `decisions` is empty. It speaks for the evaluated prefix only: a prefix that stops at a gap can be `as_required` with `state: "partial"`. |

A decision:

| Field | Required | Rule |
|---|---|---|
| `seq` | yes | The seq of the event *e*. It is the `where` value of the rules that matched it (v2 §4.1). |
| `due` | yes | `none`, `refused` or `halted` (§5.2). |
| `dueReason` | exactly when `due` is not `none` | `rule`, `rule_error`, `unknown_tool`, `tool_changed` or `configuration_locked`. |
| `dueRules` | exactly when `dueReason` is `rule` or `rule_error` | The due rules, non-empty, sorted, without repeats. |
| `recorded` | absent exactly when the event is open and *s* = *T* | `none`, `refused` or `halted` (§5.3, §5.4). |
| `outcome` | yes | `as_required`, `let_through`, `over_enforced`, `not_checkable` or `pending` (§5.5). |
| `findings` | exactly when `outcome` is `let_through` or `over_enforced` | The findings that apply, in the order of §5.5, without repeats. For `let_through` at least one is of class let through; for `over_enforced` none is. |

The recorded reason and rules are not repeated: they are in the event at `seq` + 1.

## 7. Verification

A v3 `policy` evaluation is valid when it is valid under v2 §9 with the changes of §2 and the
facts of §3, and `policy.enforcement` equals, member for member, the comparison of §4–§6
recomputed from the run. A verifier that has the core named in `evaluator.engine` MUST
recompute `decisions` and `result`; a verifier without it MUST report the comparison as not
recomputed, as for the results (v2 §4.6). Until a comparison is recomputed, what was due is
the evaluator's statement, not the verifier's: a member that passes every check below can
still be false. The comparison counts as **recomputed** only when it
is `performed` and a verifier holding the core that `evaluator.engine` names has reproduced it;
a `not_performed` comparison is never recomputed — it states that nothing was compared, and a
verifier reports it as such, not as a pass. A verifier reports what the comparison says (`comparison`,
`result`) only for an evaluation it found valid; of an evaluation it rejects, for whatever
reason, it reports neither.

Whether or not it has the core, a verifier checks what does not need it:

- `chain_inconsistent` is given exactly when the prefix has a finding of §5.1 reason 1;
- `recordedEngine` and `engine_inconsistent` follow from the enforcement records of the
  prefix;
- `comparison` is `performed` only when the prefix holds no enforcement record or
  `evaluator.engine` is the recorded engine;
- `engine_unavailable` is invalid when `recordedEngine` equals `evaluator.engine`;
- each decision's `recorded` follows from the chain; every event with a recorded outcome
  other than `none` has a decision; `decisions` ascend by `seq`; `findings` fit the
  `outcome`; `result` follows from `decisions`;
- an `outcome` of `not_checkable` stands only where the record after the event has reason
  `unavailable`, and an `outcome` of `as_required` only where `due`, `dueReason` and
  `dueRules` are the recorded outcome, reason and rules (compared as §5.3 says).

That the evaluator could not run the recorded engine is otherwise the evaluator's statement.

The comparison is recomputed from the run, not from the `evaluation-facts` object alone: the
facts do not carry the records' reasons and rules, the halting `run_end`, or the digests of
§3.

## 8. Scope

An evaluation names exactly one run and compares it with that run's own control set. A child
run is evaluated like any other run, under its own control set; a parent's rules never apply
to a child's events (Control Set v2 §7.3), and `isChildRun` is the only fact a run has about
its tree. A tree-level evaluation stays out of scope (Agent Delegation v1 §6.6). In
particular, that a child was started although its parent's guard halted at the `delegation`
is not a finding of the parent's evaluation or of the child's.

The comparison does not show:

- which tool was in fact run: `step.tool.name` is the producer's name for it;
- that the `tool-arguments` and `tool-definition` digests of a call are those of what was in
  fact sent and run: the per-call digests are the producer's claim;
- an action recorded under another step type: only a `tool_call` can be refused, and a tool
  use sealed as another event is compared as that event;
- that a human approved, or who: `bound` shows that the producer recorded an approval covering
  the call;
- when an approval in fact expired: expiry is compared with the call's `step.eventTime`, the
  producer's claim;
- that a refused tool, or anything after a halt, was not run outside the recorded run;
- whether a record was sealed by the guard or by other code of the producer: both seal with
  the run's signer, and an evaluator knows a record only by its `enforcer` member;
- whether the guard's core in fact failed where a record says `unavailable` (§5.6);
- which core the guard ran, when the run holds no enforcement record (§4);
- that the configuration whose digests the Control Artifact seals is the one the runtime used;
- who the agent is: `agent.id` is the producer's own name for it, so a Control Artifact that
  names the agent otherwise makes a rule scoped to an agent or agent group not match; only an
  approval of the policy binds the agent;
- anything a rule matches only at run level: the run-level request has no due outcome;
- anything about events after the evaluated prefix (§5.4).

A producer can keep the comparison from being performed: by naming a core the evaluator does
not have, by naming two, or by sealing a chain that contradicts itself (§5.1). The evaluation
then says `not_performed` and why. It never says `as_required`.

## 9. Test vectors

`test-vectors/15-policy-enforcement-evaluation/`: for every run of vector 14 the expected
`enforcement` member; runs with each finding of §5.5; chains that are not compared;
`unavailable`; a recorded engine the evaluator does not have and records naming two cores;
runs without `run_end` and with a gap; a control set without rules; a child run; envelopes
the v3 schema accepts and rejects; evaluations a verifier must reject.

## 10. Decisions

- **A rule's result keeps its meaning.** A matching rule is `FAIL` whether it was only
  observed, refused or let through; `decisions[]` says which. `overall` is not changed by the
  comparison.
- **Over-enforcement is a lighter class.** The chain records no forbidden action; the record
  is wrong.
- **`unavailable` is neither accepted nor a finding.** It always halts, so it can never hide
  an action that was let through.
- **Never another core.** A comparison made with a different Cedar version would be a guess.
- **A chain that contradicts itself is not compared.** Position is only meaningful when every
  record sits after the event it decides and no refused call has a result. This also removes
  the double finding a late record would give — a missing refusal at the call and an unfounded
  record at the event before the record: a late record is `misplaced_decision`, and the
  comparison is not performed.
- **"At least" for the denial count.** With "equals", one record that was not due would step
  over the number and no later denial would ever be due to halt; an over-enforced finding
  would then stand for an action that should have stopped the run.
- **No partial comparison.** The checks that need no core (`unknown_tool`, `tool_changed`,
  `configuration_locked`) are not performed on their own when the core is missing.
