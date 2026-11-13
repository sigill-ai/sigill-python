# Vector 14 — policy enforcement (draft)

Runs of the guard (`agent-policy-control-set-v2.md` §7) over vector 13's control set, sealed as
Execution Evidence v4 (`agent-enforcement-v1.md`). Expected Cedar results come from the
official core, `@cedar-policy/cedar-wasm` 4.14.0.

| File | Content |
|---|---|
| `cases.json` | The source: per case, what the producer attempts in order, overrides of `enforcement` and of the Control Artifact's configuration, and engine-failure inputs; the findings runs. |
| `runs/<case>.json` | The run as the guard sealed it: `enforcement` (vector 13's, with the override), the Control Artifact's object digests (`configuration`), and `events[]`: `{ sealedBy, envelope, objectDigests }`. |
| `expected/<case>.facts.json` | The facts-v2 document (Control Set v2 §8: Control Evaluation v2 §4.5's shape, `factsVersion` `"2"`, `entities`), exact JCS bytes, as vector 12's `<run>.facts.json`. |
| `expected/<case>.json` | `approvalScopeDigest` of the case's control set; `factsSha256` (lowercase hex SHA-256 of `<case>.facts.json`, as in vector 12's `results.json`); per event the facts-v2 `request`, Cedar's `diagnostics` (`reason` without the baseline permit, `errors`, both rule ids, sorted) and the guard's `outcome`; the run-level request; `notExecuted` (attempted results of denied calls before any halt, never recorded); `discarded` (every action after a halt — it takes precedence: a denied call's result after the halt counts here, not in `notExecuted`); per-rule `controls` and `overall` (Control Set v1 §6). |
| `findings/<case>.json` | Hand-built runs with the expected Agent Enforcement v1 §5 findings, in the order of its table. |
| `envelopes.json` | Envelopes the schema of their `schemaVersion` must accept (`valid`) and reject (`invalid`). |

The control set of a case is vector 13's `control-set.json` with `enforcement` replaced by
the run file's `enforcement`. Every request's `entities` are that control set's
`cedar.entities`. Signatures are stubs: `prevSignatureSha256` = SHA-256 of
`stub-signature:<correlationId>:<seq − 1>`; the facts do not depend on them.
`argumentsSha256` and object digests are SHA-256 of the bytes in `cases.json` `arguments`.

`outcome` is what the guard did after sealing a producer event: `allowed`, `denied` or
`halted`, with `reason` and `rules` of the one enforcement record it sealed. The guard's
own events (`sealedBy: "guard"`: the record and, after a halt, `run_end`) follow in `events`
and carry no outcome. A `tool_call` whose `approval` is `bound` has `boundBy`: the seq of
the approval it consumed (Control Set v2 §8.1). The generator asserts that every guard run
has no Agent Enforcement v1 §5 finding.

Calls of `crm.read_customer` and `crm.update_address` (entities with `definitionSha256`)
carry a `tool-definition` object with the bytes `<tool> definition` unless the case says
otherwise. Where the case models an engine failure (`engineFails`, `engineFailsAtStart`),
`diagnostics` are what an evaluator computes afterwards; the guard had none. The rule errors
of cases 10, 25, 27 and 32 are real Long overflows; the generator asserts that the Cedar core
reports every rule error in this vector as `integer overflow`.

| Case | Covers | Guard |
|---|---|---|
| 01-allowed-call | a known, unrestricted call | allowed |
| 02-denied-by-rule | a `deny` rule scoped to an agent group | denied `rule` |
| 03-shadow-rule | an `observe` rule matches, never denies | allowed |
| 04-approval-laundering | approval of call A does not cover call B | A allowed (`bound`), B denied |
| 05-sticky-rejection-use-id | rejection by `useId` wins over a later approval | denied (`rejected`) |
| 06-sticky-rejection-arguments | rejection by tool and arguments under a new `useId` | denied (`rejected`) |
| 07-approve-then-retry | denied, then approved by tool and arguments (no `useId`), retried under a new `useId` | denied, then allowed (`bound`) |
| 08-approval-expired | `expiresAt` passed | denied (`unbound`) |
| 09-unknown-tool | no `Tool` entity, `unknownTools: deny` | denied `unknown_tool` |
| 10-rule-error | Long overflow in a `deny` rule | denied `rule_error` |
| 11-halt-on-retrieval | a `halt` rule on a `retrieval` (uses `denialsSoFar`) | record without `tool`, halted |
| 12-halt-after-denials | `haltAfterDenials: 2` | second denial: one record, halted |
| 13-group-rule | `resource in ToolGroup::"restricted"` through a nested group | denied `rule` |
| 14-loop-limit | `callsOfThisTool` limits the fourth call | denied `rule` |
| 15-denied-not-unpaired | a denied consequential call is not unpaired at run level | `unpairedConsequential` 0 |
| 16-observe-mode | `mode: observe` | nothing denied, no record |
| 17-start-configuration-locked | tool manifest differs from `lockedConfiguration` | start refused `configuration_locked` |
| 18-start-engine-unavailable | Cedar core cannot be loaded at start | start refused `unavailable` |
| 19-approval-names-use-id | an approval naming `call-2` does not bind `call-1` with the same arguments | `call-1` denied, `call-2` allowed |
| 20-approval-binds-once | one approval, two identical calls | first allowed (`bound`), second denied (`unbound`) |
| 21-tool-definition-match | `tool-definition` digest equals `definitionSha256` | allowed |
| 22-tool-definition-mismatch | another definition digest | denied `tool_changed` |
| 23-tool-definition-missing | no `tool-definition` object | denied `tool_changed` |
| 24-deny-and-halt-one-call | the third refund matches a `deny` and a `halt` rule | one record with both ids, halted |
| 25-erroring-observe-rule | only an `observe` rule errors | allowed |
| 26-unknown-tools-allow | `unknownTools: allow`, unknown tool | allowed |
| 27-on-rule-error-allow | `onRuleError: allow`, the only matching `deny` rule errors | allowed |
| 28-engine-failure-tool-call | Cedar core fails for a `tool_call` | record `unavailable` with `tool`, halted |
| 29-engine-failure-non-tool | Cedar core fails for a `model_output` | record `unavailable` without `tool`, halted |
| 30-delegation-halt | a `halt` rule on `Action::"delegation"` | record without `tool`, halted; no child started |
| 31-unknown-tool-halt-rule | unknown tool `fs.wipe` that a `halt` rule matches | denied `unknown_tool` (no `rules`), halted |
| 32-rule-error-halt-rule | `export-weight` errors, `halt-consequential-export` matches | denied `rule_error` (`rules` = `export-weight` only), halted |
| 33-rejection-by-use-id-only | rejection names `call-1` with another arguments digest | denied (`rejected`) |
| 34-approval-expires-at-event-time | `expiresAt` equals the call's `eventTime` | denied (`unbound`) |
| 35-two-approvals-two-calls | two matching approvals, three identical calls | `boundBy` 1, then 2; the third is `unbound` and, as the third refund, also trips `halt-refund-loop`: denied, halted |

| Findings run | Expected |
|---|---|
| f1-clean | none |
| f2-orphan-result | `orphan_result` |
| f3-conflicting-result | `conflicting_result` |
| f4-executed-after-denial | `executed_after_denial` |
| f5-unrecorded-halt | `unrecorded_halt` |
| f6-duplicate-use-id | `duplicate_use_id` |
| f7-misplaced-decision | `misplaced_decision` twice: a record with `tool` after a non-call, and one without `tool` after a call |
| f8-continued-after-halt | `continued_after_halt` |
| f9-evidence-version-mismatch | `evidence_version_mismatch` (v3 events; vector 13's control set supplied as `application/vnd.sigill.control-set+json`: `controlSetContentType`) |
| f10-version-mismatch-not-a-policy-control-set | none (the same bytes supplied as `application/json`: not a policy control set) |
| f11-continued-after-delegation-halt | `continued_after_halt` (a record without `tool` after a `delegation`, then the producer continues) |
| f12-record-after-record | `misplaced_decision` (a record directly after a record) |
| f13-version-mismatch-control-set-not-strict | `evidence_version_mismatch`: v3 events, policy content type, bytes with a repeated member — they do not parse strictly, so the check fails closed |
| f14-v1-policy-control-set-with-v3-events | none: vector 11's v1 control set (strict object without `schemaVersion`) with v3 events |
| f15-result-names-another-tool | `orphan_result`: the `tool_result` has the call's `useId` but names another tool |

A findings run with a supplied control set carries `controlSetContentType` and the exact bytes
as `controlSetBase64`.

An implementation MUST produce the requests exactly and, running the official core, the same
diagnostics; a guard replaying the `producer` events MUST seal the same `guard` events.

Regenerate from the repository root (Docker, no host Node), after vector 13:

```bash
docker run --rm -v "$PWD":/w -w /w/spec/test-vectors/14-policy-enforcement node:22 \
  sh -c 'npm i --no-save --prefix /tmp/c @cedar-policy/cedar-wasm@4.14.0 >/dev/null && NODE_PATH=/tmp/c/node_modules node _generate.mjs'
```
