# Vector 15 — policy enforcement evaluation (draft)

The enforcement comparison of ControlEvaluation v3 (`control-evaluation-v3.md` §4–§6) — for each event of a run
under a v2 control set, what the control set required the guard to do against what the chain records — over vector
14's 35 guard runs and 60 runs in which the guard did less, or more, than required, or whose chain contradicts itself.
Expected Cedar results come from the official core, `@cedar-policy/cedar-wasm` 4.14.0. The evaluator of the vector
holds exactly one core, `cedar-policy@4.14.0`.

| File | Content |
|---|---|
| `cases.json` | The source of the 60 new runs: explicit event lists, records and halts included, because these runs are not what a correct guard seals. |
| `control-set-b.json`, `control-set-c.json`, `control-set-d.json` | Variants of vector 13's document: B adds two `halt` rules that overflow Cedar's Long (`halt-weight-call` on a `tool_call` of `ledger.preview`, `halt-weight-retrieval` on a `retrieval` once `toolCallsSoFar` ≥ 1); C has no `cedar` member (no rules, no entities); D has no `enforcement` member. |
| `runs/<case>.json` | As vector 14: `agentId`, `correlationId`, `controlSet` (`13`, `b`, `c` or `d`), `enforcement`, the Control Artifact's object digests (`configuration`), `events[]` (`envelope`, `objectDigests`). No `sealedBy`: an evaluator cannot know it. |
| `expected/<case>.facts.json` | The facts-v2 document of the evaluated prefix (Control Set v2 §8), exact JCS bytes. |
| `expected/<case>.json` | `approvalScopeDigest`, `cedarDigest` (when the control set has `cedar`), `factsSha256`, `prefix`, `state`, `evaluatorEngine`, per-rule `controls` and `overall`, the Agent Enforcement v1 §5 findings of the prefix (`enforcementFindings`), and `enforcement`: the member exactly as it stands in the evaluation. |
| `expected/14-<case>.json` | The same for each run of vector 14 (its run and facts files are vector 14's). |
| `envelopes.json` | ControlEvaluation v3 envelopes the schema must accept (`valid`) and reject (`invalid`). |
| `invalid-evaluations/<x>.json` | Evaluations a verifier must reject: `run` (a case of this vector), `needsEngine`, `because`, and `patch` — RFC 6902 `add` / `replace` / `remove` operations applied to the correct v3 evaluation of that run before it is sealed. |

The control set of a run is vector 13's `control-set.json` with `enforcement` replaced by the run file's
`enforcement`, or the variant the run names. Signatures are stubs, as in vector 14; the facts and the comparison do
not depend on them. Configuration digests, `argumentsSha256` and object digests are SHA-256 of the bytes in vector
14's `cases.json`.

**The generator computes, it never copies.** `_generate.mjs` implements ControlEvaluation v3 §5 from the text: for
each event the due outcome (§5.2) from Cedar's diagnostics, the control set and the facts; the recorded outcome by
position (§5.3); open events (§5.4); outcome and findings (§5.5). For vector 14's 35 runs it asserts that the facts
are vector 14's bytes, that the computed due outcome, reason and rules of every producer event equal the guard's
recorded `outcome`, `reason` and `rules` in vector 14's expected files (`denied` = `refused`; an `unavailable`
outcome is due `none`), and that no run has a finding: 32 `as_required`, 3 `not_checkable` (18, 28, 29).

| Group | Cases |
|---|---|
| Let through | `e01`–`e10`, `e44`: `refusal_missing`, `unknown_tool_allowed`, `configuration_not_enforced`, `halt_missing` |
| Over-enforced | `e11`–`e18`, `e43`: `unfounded_record`, `unfounded_halt`, `reason_mismatch`, `rules_mismatch` |
| As required, less common settings | `e33`–`e42`, `e49`, `e50`: `defaultEffect: halt`, `tool_changed` over a rule, `onRuleError: allow`, erroring `halt` rules, `unknownTools: allow`, no `cedar`, no `enforcement`, an absent locked role, rule order, `[]` against absent |
| The recorded chain | `e19`, `e20`, `e21`, `e32`: a missing record delays a halt by the count, an unfounded one brings it earlier, a stepped-over count ("at least"), a refused call consumes its approval |
| `unavailable` | `e22` (and vector 14's 18, 28, 29; `e43` is the one checkable case) |
| Engine | `e23` (a core the evaluator does not have: `engine_unavailable`), `e24` (two cores: `engine_inconsistent`) |
| Partial runs | `e25`–`e29`, `e45`–`e48`: `pending`, gaps, prefixes that end on a record |
| Child runs | `e30`, `e31` (a child of vector 14's case 30) |
| Not compared | `c01`–`c10`: each finding of §5.1 reason 1 (`chain_inconsistent`); `c10` is sealed as Execution Evidence v3 (`evidence_version_mismatch`) |

`x11` is two files: a `cedarDigest` for a control set without `cedar`, and `controls: []` for one with rules.

An implementation MUST produce the facts byte for byte and, running the official core, the same `controls`,
`overall` and `enforcement`; a verifier MUST reject every evaluation of `invalid-evaluations/`.

Regenerate from the repository root (Docker, no host Node), after vector 14:

```bash
docker run --rm -v "$PWD":/w -w /w/spec/test-vectors/15-policy-enforcement-evaluation node:22 \
  sh -c 'npm i --no-save --prefix /tmp/c @cedar-policy/cedar-wasm@4.14.0 >/dev/null && NODE_PATH=/tmp/c/node_modules node _generate.mjs'
```
