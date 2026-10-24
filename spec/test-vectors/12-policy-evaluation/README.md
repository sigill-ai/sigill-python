# Vector 12 — policy evaluation (facts and results)

Eight runs (`runs/*.json`: the agent id, correlationId and the typed fields of each execution
event) evaluated against the policy control set of vector 11.

| File | Content |
|---|---|
| `expected/<run>.facts.json` | The facts document (`control-evaluation-v2.md` §4.5), exact JCS bytes. |
| `expected/<run>.results.json` | `factsSha256`, the prefix, and per-rule results with `where`, from the official Cedar core. |

| Run | What it covers | Overall |
|---|---|---|
| 01-clean | allowed tools, paired call | PASS |
| 02-rogue | a forbidden tool, consequential calls without approval, an unpaired call | FAIL |
| 03-approval-unbound | `approval` becomes `unbound` after a `human_approval` | PASS |
| 04-gap | seq 2 missing: the call at seq 3 is held back, no run-level request | PASS (partial) |
| 05-child-run | `isChildRun` from run_start's `binds.parentCorrelationId` | PASS |
| 06-open-no-run-end | no `run_end`: no run-level request | PASS (open) |
| 07-max-steps | `stepsSoFar` beyond the limit, per step and at run level | FAIL |
| 08-duplicate-use-id | two calls share a `useId`: both count as unpaired | FAIL |

An implementation MUST produce the facts byte for byte. Results MUST match when it runs the
official Cedar core. Regenerate with `node _generate.mjs` (needs `@cedar-policy/cedar-wasm@4.14.0`).
