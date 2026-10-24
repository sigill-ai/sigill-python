# Agent Policy Control Set v1 (draft)

Status: **draft**. Defines a declared agent policy carried in the Control Artifact's
`control-set` object, how the policy is identified, and the facts a run is evaluated on.
Nothing here changes the Control Artifact, Execution Evidence or Control Evaluation
schemas.

## 1. Recognition

A `control-set` object is a policy control set when its object `contentType` is
`application/vnd.sigill.control-set+json`. With any other content type (today:
`application/json`) the object keeps its existing meaning (`{id, version, controls}`
state controls, vector 10) and carries no policy.

## 2. Document

A UTF-8 JSON object, I-JSON (RFC 7493). Members:

| Member | Required | Meaning |
|---|---|---|
| `id` | yes | String, the control set id. Equal to the Control Artifact's `controlSet.id`. |
| `version` | yes | String, a label. Equal to the Control Artifact's `controlSet.version`. |
| `controls` | yes | Array of state controls, unchanged from today (strings or objects with a string `id`). May be empty. |
| `cedar` | no | `{ "policies": <Cedar JSON policy set>, "schemaSha256": <hex> }` — the shared policy (§4). |
| `privateControls` | no | Array of `{ "id": <string> }`: content rules the producer evaluates itself and must report. Ids unique. |
| `coverage` | no | `{ "sourceProfile": <string>, "scope": <string>, "idleSeconds": <integer ≥ 0> }`: what the recording source is meant to capture, as declared by the producer. |

No other top-level member is allowed. The producer keeps the document as a file and
gives the same bytes to every run; the digests in §3 do not depend on formatting.

## 3. Digests

Both are lowercase hex SHA-256 over the RFC 8785 (JCS) canonical form:

- `cedarDigest` = SHA-256(JCS(`cedar`)). Absent when there is no `cedar` member.
  Identifies the rules: rule diff, simulation, caches.
- `approvalScopeDigest` = SHA-256(JCS(document without `id` and `version`)).
  Identifies everything an owner approves: rules, private controls, state controls and
  coverage. Removing a private control or raising `idleSeconds` changes it; changing
  only `id` or `version` does not.

The `control-set` object digest in the Control Artifact is over the exact bytes, as for
every object.

## 4. Cedar policies

`cedar.policies` is a Cedar JSON policy set (`{ "staticPolicies": { … } }`). Rules for a
step-1 policy (tripwire mode — nothing is enforced):

1. Every policy has `"effect": "forbid"`. The evaluator adds one fixed baseline
   `permit (principal, action, resource);`, so a deny always names the rule that fired. The
   evaluator keys it with an id outside the rule-id alphabet of rule 2 (`sigill:baseline-permit`),
   so no producer rule can share its id.
2. Every policy carries an `id` annotation, and its key in `staticPolicies` equals it.
   Ids are unique and at most 64 characters of `[A-Za-z0-9._-]`.
3. No templates and no template links.
4. Integer literals stay within ±2^53 − 1 so every JSON implementation reads them exactly.
5. `schemaSha256` is the SHA-256 of JCS(`agent-policy-cedar-schema-v1.json`), and the
   policy validates against that schema in Cedar's strict mode.

Write rules on `consequential`, not `operation`: the `operation` vocabulary is open.

## 5. Facts (factsVersion 1)

One Cedar request per event of the contiguous received prefix (seq 0…k), in seq order,
plus one run-level request when `run_end` is received.

| Request part | Per event | Run level |
|---|---|---|
| principal | `Agent::"<actor.id>"` | same |
| action | `Action::"<step.type>"` | `Action::"run"` |
| resource | `Tool::"<step.tool.name>"` for `tool_call` / `tool_result`, else `Step::"<seq>"` | `Run::"<activity.correlationId>"` |

Context (all attributes always present):

| Attribute | Per event | Run level |
|---|---|---|
| `consequential` | `step.consequential` (default false) | false |
| `operation` | `step.tool.operation`, else `""` | `""` |
| `stepsSoFar` | `chain.seq` | `finalSeq` |
| `approval` | `"unbound"` when an earlier `human_approval` exists, else `"none"` | `"none"` |
| `isChildRun` | run_start has `binds.parentCorrelationId` | same |
| `totalSteps` | 0 | `finalSeq` |
| `consequentialCount` | consequential events up to and including this seq | total |
| `unpairedConsequential` | 0 | consequential `tool_call`s without a later (higher seq) `tool_result` of the same `useId`; a call without `useId`, or whose `useId` another `tool_call` also uses, counts as unpaired |

`approval` gains `bound` and `rejected` with `covers` in Execution Evidence v3.

## 6. Results

Per rule, from Cedar's diagnostics, never from the overall decision alone: a rule id in
`diagnostics.reason` is FAIL, in `diagnostics.errors` INDETERMINATE, otherwise PASS.
Per rule over all requests and overall: FAIL > INDETERMINATE > PASS.

## 7. Test vector

`test-vectors/11-policy-control-set/` holds a document, its expected `cedarDigest`,
`approvalScopeDigest` and `schemaSha256`, and a variant that differs only in
`version` (same `approvalScopeDigest`).
