# AgentExecutionEvidence v1 — Specification

**Content type:** `application/vnd.sigill.agent-execution+json`
**Schema:** [`agent-execution-evidence-v1.schema.json`](./agent-execution-evidence-v1.schema.json)
**Common rules:** [`agent-profiles-common-v1.md`](./agent-profiles-common-v1.md)

One artifact per event during a run. The artifacts of one run form a chain
that starts with `run_start`, which binds the Control Artifact, and ends with
`run_end`, which closes the run.

## 1. Envelope

```json
{
  "schemaName": "AgentExecutionEvidence",
  "schemaVersion": "1",
  "evidenceId": "<uuid>",
  "createdAt": "2026-09-16T08:00:05Z",
  "actor": { "id": "contract-agent", "type": "agent" },
  "activity": { "name": "customer-address-change", "correlationId": "urn:uuid:<run>" },
  "chain": { "seq": 1, "prevSignatureSha256": "hex…" },
  "step": {
    "type": "tool_call",
    "eventTime": "2026-09-16T08:00:04.120Z",
    "consequential": true,
    "timestamp": "none",
    "tool": { "name": "crm.update_customer", "operation": "update" }
  },
  "binds": { "controlArtifactSignatureSha256": "hex…" },
  "objects": [
    { "uri": "urn:uuid:…", "role": "tool-arguments", "contentType": "application/json" }
  ]
}
```

## 2. Chain (normative)

- `chain.seq` is 0 in `run_start` and increases by exactly 1 per artifact.
- `chain.prevSignatureSha256` is `signatureSha256` (common rules §2) of the
  previous artifact in the run. It is REQUIRED for `seq ≥ 1` and MUST be
  absent for `seq = 0`.
- Two artifacts of one run MUST NOT share a `seq`. A producer that fails to
  seal an event MUST NOT advance `seq`; gaps are never legitimate.

## 3. Binding to the Control Artifact

`binds.controlArtifactSignatureSha256` is REQUIRED in `run_start`. It is
OPTIONAL in later artifacts and, when present, MUST equal the value in
`run_start`. Repeating it lets every artifact point at the control basis on
its own.

## 4. Step

`step.type` is one of `run_start`, `retrieval`, `tool_call`,
`authorization`, `human_approval`, `tool_result`, `model_output`,
`checkpoint`, `run_end`. A `checkpoint` carries nothing and exists to anchor
the chain head with a timestamp (`step.timestamp: "required"`), e.g. while a
long run is idle.
`step.eventTime` is REQUIRED, carries millisecond precision and is the
producer's claim; seal time is proven by `sigTst`. `step.consequential`
(boolean, default `false`) marks an external side effect (a write-class tool
call, a payment, a delivered message); `step.timestamp` (`required` or
`none`) is the producer's timestamp decision. Whether an event had to be
timestamped is recomputed by the verifier from the Control Artifact's policy
(common rules §4).

Type-specific fields:

| `type` | Fields |
|---|---|
| `tool_call` | `tool.name` REQUIRED, `tool.operation` and `tool.useId` (correlates the call with its `tool_result`) optional |
| `authorization` | `decision` REQUIRED (producer-defined vocabulary, e.g. `allowed`, `allow_with_human_approval`, `denied`), `policyId` optional |
| `human_approval` | `decision` REQUIRED (`approved` or `rejected`), `approver` optional (an identifier, not a name). What the approval covers is the content of the `approval-receipt` object, held by the producer |
| `run_end` | `finalSeq`, `finalPrevSignatureSha256`, `runDisposition` REQUIRED; `runDisposition` is `completed`, `aborted` or `failed` |
| all | `detail` optional free text |

`finalSeq` equals the `run_end` artifact's own `chain.seq`;
`finalPrevSignatureSha256` equals its own `chain.prevSignatureSha256`. The
duplication is deliberate: a verifier can check closure without trusting the
chain fields of the same artifact.

## 5. Object roles

Closed set: `tool-arguments`, `tool-result`, `approval-receipt`,
`identity-assertion`, `retrieved-context`, `model-output`, `model-input`.
`objects[]` MAY be empty (`run_start`, `authorization`, `run_end` typically
carry none).
