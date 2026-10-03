# ControlEvaluation v1 — Specification

**Content type:** `application/vnd.sigill.control-evaluation+json`
**Schema:** [`control-evaluation-v1.schema.json`](./control-evaluation-v1.schema.json)
**Common rules:** [`agent-profiles-common-v1.md`](./agent-profiles-common-v1.md)

The Control Evaluation seals what an independent verifier observed after a
run and how each control in the pre-sealed control set came out. Sigill
seals the claim; it does not evaluate anything.

## 1. Envelope

```json
{
  "schemaName": "ControlEvaluation",
  "schemaVersion": "1",
  "evidenceId": "<uuid>",
  "createdAt": "2026-09-16T08:01:00Z",
  "actor": { "id": "urn:acme:verifier:crm-state", "type": "verifier", "version": "1.3.0" },
  "activity": { "name": "customer-address-change", "correlationId": "urn:uuid:<run>" },
  "subject": {
    "runEndSignatureSha256": "hex…",
    "controlArtifactSignatureSha256": "hex…"
  },
  "controlSet": { "id": "customer-write-v4", "version": "4" },
  "controls": [
    { "id": "address-equals-requested", "result": "PASS" },
    { "id": "status-unchanged", "result": "FAIL", "detail": "status changed from active to suspended" }
  ],
  "overall": "FAIL",
  "evaluatedAt": "2026-09-16T08:00:58Z",
  "objects": [
    { "uri": "urn:uuid:…", "role": "observed-state", "contentType": "application/json" },
    { "uri": "urn:uuid:…", "role": "control-set",    "contentType": "application/json" }
  ]
}
```

## 2. Profile fields

| Field | Required | Rule |
|---|---|---|
| `actor.type` | yes | `verifier`. |
| `actor.version` | yes | Version of the verifier component. |
| `subject.runEndSignatureSha256` | yes | `signatureSha256` of the run's `run_end` artifact. |
| `subject.controlArtifactSignatureSha256` | yes | `signatureSha256` of the run's Control Artifact. |
| `controlSet` | yes | MUST equal `controlSet` in the Control Artifact. |
| `controls[]` | yes, ≥ 1 | `{ id, result, detail? }`; `result` is `PASS`, `FAIL` or `INDETERMINATE`. |
| `overall` | yes | `PASS`, `FAIL` or `INDETERMINATE`. Asserted by the verifier, not derived by the SDK. |
| `evaluatedAt` | yes | When the state was read. Producer's claim. |

`INDETERMINATE` is used when the verifier could not read the state, or when
the control set it evaluated against does not match the one in the Control
Artifact.

## 3. Object roles

Closed set: `observed-state`, `control-set`, `baseline-state`. Exactly one
`control-set` object is REQUIRED and MUST have the same URI and digest as
the `control-set` object in the Control Artifact; that is how a verifier
proves the same controls applied before and after. At least one
`observed-state` object is REQUIRED. When the Control Artifact carries a
`baseline-state`, the evaluation SHOULD carry the same object (URI and
digest); every "unchanged" result then rests on a baseline that was sealed
before the run and is bound to the conclusion. A different baseline digest
is reported by the run verifier as `baselineDigestMatches: false`.

## 4. Identity and time

The verifier SHOULD seal with its own certificate, distinct from the
agent's. Sigill supports several certificates per tenant and
`sign-hashes` takes the certificate per call, so no platform change is
needed. A separate tenant for the verifier is the stronger production
pattern. The one-signer rule (common rules §3) covers the Control Artifact and
the events, not the evaluation; a run verifier reports the evaluation's
signer and chain trust separately and MAY be given its expected signer.

A Control Evaluation is always timestamped: it is a statement made at a time.
