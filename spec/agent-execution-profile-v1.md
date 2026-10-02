# AgentExecutionProfileV1 — Specification

**Status:** v1.0 · **Builds on:** [AiEvidenceEnvelopeV2](ai-evidence-envelope-v2.md)

A profile of the AI evidence envelope v2 for **multi-step agent runs**. A run
is recorded as an ordered sequence of ordinary v2 artifacts — one per
security-relevant step — that are cryptographically chained, so a verifier
holding the run can tell whether steps were removed, reordered, inserted or
spliced in from another run, and whether the producer finalized the run.

Every artifact in a run is a normal v2 `{envelope, signature}` pair (v2 §6),
sealed through the same blind mechanism (v2 §5, §8): the producer sends
digests and opaque URIs, receives a JAdES signature, and assembles the
artifact locally. Nothing in this profile changes what Sigill receives.

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Terms

| Term | Meaning |
|---|---|
| **Run** | One execution of an agent, from `run_start` to `run_end`, identified by `activity.correlationId`. |
| **Step** | One artifact in a run. Its kind is its `stepType`. |
| **Producer** | The software that records the run (typically an SDK embedded in the agent's host). |
| **Identity record** | A standalone artifact binding the agent's configuration (manifest, instructions, tools, model configuration, execution policy). Runs reference it from `run_start`. |
| **Bundle** | The portable container of a run's artifacts (§7). |
| **Anchor** | A step carrying a valid RFC 3161 signature timestamp. The `run_end` anchor fixes the whole chain in time. |

## 2. Envelope conventions

Every step is an `AiEvidenceEnvelope` v2 envelope with:

| Field | Value |
|---|---|
| `purpose.category` | `"agent-execution"` (steps) or `"agent-identity"` (identity record). `purpose.businessContext` is free. |
| `actor.type` | `"agent"` |
| `actor.id` | The stable, opaque agent identifier (e.g. `urn:example:agent:support-triage`). MUST be identical across a run and its identity record. MUST NOT carry personal data. |
| `activity.name` | The step type. |
| `activity.correlationId` | The run identifier. REQUIRED and non-empty on every step, identical across the run; absent on the identity record. Verifiers take the run identifier only from these signed values, never from a bundle or index field. An opaque value such as `urn:uuid:…` is RECOMMENDED. |
| `activity.parentEvidenceId` | The previous step's `evidenceId`; for `run_start`, the identity record's `evidenceId`. A *semantic* link only (v2 §3.3). |
| `chain` | Present on every step, absent on the identity record (§4). |
| `objects[]` | The step's detached payloads, described as in v2 §3.1. |
| `extensions["ai.sigill.agent-execution"]` | The profile block (§3). |

The envelope is canonicalized, hashed and signed exactly as any v2 envelope
(v2 §4, §5). It MUST validate against the complete v2 schema
(`ai-evidence-envelope-v2.schema.json`) — optional sections such as
`sourceTrace`, `processingMetadata`, `policyMetadata`, `chain` and per-object
`metadata` are optional to supply, never exempt from validation when present —
and MUST be valid I-JSON (canonicalizable). Producers MUST write `evidenceId` and
`parentEvidenceId` as bare UUIDs; verifiers SHOULD also accept the
`urn:uuid:<uuid>` form.

## 3. The profile block

All profile semantics live in the signed extension block
`extensions["ai.sigill.agent-execution"]`. A verifier reads them **only from
the signed envelope** — never from an index, file name or database column
next to it.

### 3.1 Common fields (every step)

| Field | Type | Meaning |
|---|---|---|
| `stepType` | string, REQUIRED | `run_start`, `retrieval`, `tool_call`, `tool_result`, `approval`, `model_output`, `checkpoint`, `run_end`, or a producer-defined value. Verifiers treat unknown values as ordinary steps. |
| `agentVersion` | string | The agent build the step was produced by. MUST equal `run_start`'s when `run_start` carries one. |
| `eventTime` | date-time | When the producer observed the event. A producer **claim**; only timestamps prove time. |
| `consequential` | boolean | The step had an external side effect (a write-class tool call, a delivered message, an export). Consequential steps are always anchored (§5). |
| `timestamp` | `"required"` \| `"none"` | The producer's own timestamp decision for this step. Informational: the verifier recomputes the requirement from the signed policy (§5) and also honours `"required"`. |
| `objectKinds` | object | Map from each `objects[].uri` to a profile kind (§3.4). Kinds live here, not in per-object `metadata`, because they are profile semantics. |

### 3.2 `run_start`

A run has exactly one `run_start`, at `chain.seq` 0. In addition to §3.1 it
carries:

| Field | Meaning |
|---|---|
| `agentIdentityEvidenceId` | The identity record's `evidenceId`. |
| `assuranceProfile` | `"throughput"` or `"per-event"` (§5). When present it MUST equal `timestampPolicy.profile`. |
| `timestampPolicy` | REQUIRED. `{ "profile", "everyEvents", "everySeconds", "runStart", "runEnd": true, "consequential": true }` (§5): `profile` a known profile, `everyEvents`/`everySeconds` non-negative integers, `runStart` a boolean, `runEnd` and `consequential` exactly `true`. |

and exactly one object of each **configuration kind**: `instruction-set`,
`tool-manifest`, `model-config`, `execution-policy`. Their digests MUST equal
the identity record's objects of the same kinds. Further objects (the user's
request, the turn's context) MAY follow.

### 3.3 `run_end`

A run has at most one `run_end`, and it is the last step. It commits to the
chain head:

| Field | Meaning |
|---|---|
| `finalSeq` | `chain.seq` of the step immediately before `run_end`. |
| `finalPrevSignatureSha256` | The chain digest (§4) of that step. Equal to `run_end`'s own `chain.prevSignatureSha256`; repeated here as an explicit commitment. |
| `runDisposition` | `"completed"`, `"failed"` or `"aborted"`. |
| `usage` | OPTIONAL free object (e.g. token counts). |

`run_end` MUST carry a valid signature timestamp. Because it commits to the
head, that single token anchors every signature before it.

### 3.4 Object kinds

| Kind | Typical role | Where |
|---|---|---|
| `agent-manifest` | `input` | identity record |
| `instruction-set` | `input` | identity record, `run_start` |
| `tool-manifest` | `input` | identity record, `run_start` |
| `model-config` | `input` | identity record, `run_start` |
| `execution-policy` | `input` | identity record, `run_start` |
| `registration-record` | `input` | identity record |
| `user-request` | `prompt` | any step |
| `retrieved-context` | `context` | `retrieval` |
| `tool-arguments` | `input` | `tool_call` |
| `tool-result` | `output` | `tool_result` |
| `approval-decision` | `input` | `approval` |
| `model-output` | `output` | `model_output` |

Producers MAY define further kinds. The `execution-policy` describes what the
agent is allowed to do (scope, allowlists, limits); the `tool-manifest` only
describes the tools.

### 3.5 The identity record

A standalone artifact (no `chain`, no `correlationId`) with
`purpose.category: "agent-identity"`, `activity.name: "agent_identity"` and
the profile block:

| Field | Meaning |
|---|---|
| `recordType` | `"agent-identity"` |
| `stepType` | `"record:agent-identity"` |
| `agentId` | Equal to `actor.id`. |
| `agentVersion` | The agent build registered. |
| `configSha256` | Configuration digest, below. |
| `registeredBy` | OPTIONAL opaque identifier of whoever registered the configuration. MUST NOT be personal data. |
| `eventTime` | Registration time (claim). |

Objects: exactly one each of `agent-manifest`, `instruction-set`,
`tool-manifest`, `model-config`, `execution-policy`, `registration-record`.

The configuration digest is

```
configSha256 = SHA-256( JCS({
  "agentManifest":   sha256hex(agent-manifest bytes),
  "instructionSet":  sha256hex(instruction-set bytes),
  "toolManifest":    sha256hex(tool-manifest bytes),
  "modelConfig":     sha256hex(model-config bytes),
  "executionPolicy": sha256hex(execution-policy bytes)
}) )
```

so that one value identifies one configuration. A verifier MUST recompute it
from the identity record's objects and compare it with the signed
`configSha256`. A producer SHOULD reuse an
existing identity record while the configuration is unchanged, and MUST
register a new one when it changes. The identity record MUST be timestamped.

## 4. The chain

`chain.seq` is zero-based and contiguous within a run. `chain.prevSignatureSha256`
is absent at `seq: 0` and present on every later step.

**Preimage (normative — this closes v2 §3.4):** `prevSignatureSha256` is the
lowercase hex SHA-256 over the **base64url-decoded JWS Signature Value** of
the previous artifact's **classical** signature — the first entry of the
General JWS `signatures[]` whose protected header `alg` does not start with
`ML-DSA` (for a flattened JWS: its `signature` member).

Only the signature value is hashed. Unprotected headers (signature
timestamps, revocation values) are excluded, so later augmentation of an
artifact never breaks the chain. Because the signature value commits to the
whole envelope via `sigD`, each link commits to everything the previous step
signed, including its own link.

## 5. Timestamp policy

Signing every step is cheap; timestamping every step is not. The producer
chooses an **assurance profile** and signs it, once, into `run_start`:

```json
"timestampPolicy": {
  "profile": "throughput",
  "everyEvents": 10,
  "everySeconds": 300,
  "runStart": false,
  "runEnd": true,
  "consequential": true
}
```

- **`per-event`** — every step is timestamped. For low-volume,
  high-consequence agents.
- **`throughput`** — every step is signed and chained immediately;
  timestamps are required on: `run_end`; every `checkpoint`; every step with
  `consequential: true`; `run_start` when `runStart` is true; any step
  declaring `timestamp: "required"`; the N-th step since the last required
  timestamp (`everyEvents`, 0 = off); and the first step whose `eventTime` is
  `everySeconds` or more after the last required timestamp's `eventTime`
  (0 = off).

The verifier walks the chain in `seq` order and recomputes, from the signed
policy alone, which steps were required to carry a timestamp:

```
sinceStamp := 0; lastStampTime := null
for each step in seq order:
  required := profile = "per-event"
           or stepType ∈ {run_end, checkpoint}
           or consequential
           or (seq = 0 and runStart)
           or (everyEvents > 0 and sinceStamp + 1 ≥ everyEvents)
           or (everySeconds > 0 and seq > 0 and lastStampTime ≠ null and eventTime ≠ null
               and eventTime − lastStampTime ≥ everySeconds)
           or timestamp = "required"
  if required: sinceStamp := 0; lastStampTime := eventTime
  else:        sinceStamp := sinceStamp + 1
  if seq = 0 and lastStampTime = null: lastStampTime := eventTime
```

A producer that wants its chain head anchored during idle periods records a
`checkpoint` step (`{"checkpoint": {"reason": "idle"}}` in the profile block);
checkpoints are always required to carry a timestamp.

## 6. Producer rules

1. Each step is sealed before the next is built: `prevSignatureSha256` needs
   the previous signature.
2. A step whose timestamp is required MUST be sealed with a timestamp. If the
   sealing service returns no timestamp, the producer MUST treat the run as
   failed rather than continue the chain without it.
3. After any sealing failure the producer MUST NOT continue the chain. The
   run then verifies as `run_open` or `run_invalid`, never as finalized.
4. Payload bytes stay with the producer. Only digests and opaque URIs reach
   the sealing service (v2 §8).

## 7. The bundle

The portable form of a run:

```json
{
  "profile": "AgentExecutionProfileV1",
  "bundleVersion": "1",
  "correlationId": "urn:uuid:…",
  "agentIdentity": { "envelope": {…}, "signature": {…}, "objectDigests": { "<uri>": "<sha256 hex>" } },
  "artifacts": [
    { "envelope": {…}, "signature": {…}, "objectDigests": { "<uri>": "<sha256 hex>" } }
  ],
  "payloads": { "<uri>": "<base64>" }
}
```

- `bundleVersion` MUST be `"1"`.
- `artifacts[]` holds every step, in `seq` order (verifiers sort anyway).
  At most 2000 artifacts.
- `objectDigests` carries each object's SHA-256 as recorded by the producer.
  Digests are what a blind verification needs; they reveal no content.
- `payloads` is OPTIONAL. When a payload is supplied, the verifier hashes it
  and uses that digest instead of the recorded one, which upgrades the
  `objects` check from "digests match" to "content matches". Every payload
  key MUST be the URI of a signed object of some artifact in the bundle
  (including the identity record); anything else is unsigned data.
- `agentIdentity` MAY be `null` or absent; the `identity` check then reports
  the gap.

Parsing is strict: a malformed entry, a non-hex digest or invalid base64
invalidates the whole bundle. Nothing is skipped silently.

## 8. Verification

A run verifier runs nine checks and reports each as `ok`, `warn` or `bad`:

| Check | `bad` when |
|---|---|
| `correlation` | A step carries no signed, non-empty `correlationId`, or its `correlationId` differs from the other steps'. |
| `sequence` | A `seq` is missing, duplicated or a step has no `chain`; or the run does not have exactly one `run_start`, at `seq` 0. Missing positions are listed. |
| `chain` | Any `prevSignatureSha256` does not match the chain digest (§4) of the step before it, or `seq` 0 carries one. |
| `envelope` | A step does not validate against the complete v2 schema or is not valid I-JSON (§2), lacks a profile block, breaks the §2 conventions (`actor.type`, `purpose.category`, `activity.name` = step type), or its signed actor/version differs from `run_start`'s. |
| `signatures` | Any step's signature fails to verify. |
| `timestamps` | A step required by §5 lacks a valid timestamp, a present timestamp is invalid, or `run_start`'s signed policy is absent or malformed (§3.2). `warn` while no valid `run_end` anchor exists. |
| `objects` | A signed object was not supplied, no longer matches, the signature and envelope disagree on the object list, or unsigned objects were supplied (as an artifact's digests or as a bundle payload no artifact signed). `warn` when every object matched by digest but some payloads were not supplied. |
| `finalization` | There is more than one `run_end`, `run_end` is not last, has no valid `runDisposition`, its `finalSeq`/`finalPrevSignatureSha256` do not match the observed head, or it lacks a valid anchor. `warn` when there is no `run_end`. |
| `identity` | `run_start` references an identity record that is absent; the record is not a well-formed identity record (§3.5); its signature, objects, timestamp, linkage or actor/version fail; its object kinds are not exactly one each; its `configSha256` differs from the recomputed digest; or `run_start`'s configuration objects are duplicated or differ from the record's. `warn` when no identity record is declared. |

The **run verdict** is:

- `run_invalid` — any check is `bad`;
- `run_finalized` — no check is `bad` and a `run_end` exists;
- `run_open` — no check is `bad` and there is no `run_end` (the run is still
  running, or its producer stopped without finalizing).

Malformed evidence is a verdict, never an error: a verifier reports it as
`run_invalid` with findings and does not raise.

**Signature verification** of each artifact is the v2 object-level verdict
(v2 §7): the verifier supplies the JCS digest of its own copy of the envelope
under `urn:sigill:envelope` plus one digest per object, and takes signature
validity, object matches, timestamp and certificate from the result. It may
run offline or through the blind `POST /seal/verify-objects` endpoint (v2
§7.1); either way only digests leave the verifier.

**Scope.** A finalized verdict establishes the integrity and capture order of
what was sealed, under the signatures and timestamps shown. It does not
establish that every event of the agent was captured, that producer-claimed
event times are true, or that no other run took place. Verifiers SHOULD show
this scope next to the verdict.

### 8.1 Bundle fingerprint

To cache or de-duplicate verification results, a verifier MAY compute a
deterministic fingerprint over everything verification depends on:

```
one(a)      = { "e": sha256hex(JCS(a.envelope)), "s": sha256hex(JCS(a.signature)), "d": a.objectDigests }
artifacts   = [ { "seq": a.envelope.chain.seq (or -1), …one(a) } for a in artifacts ]
              sorted by seq, then by e
identity    = one(agentIdentity) or null
payloads    = [ { "uri": uri, "sha256": sha256hex(bytes) } for uri in sorted(payloads) ]
fingerprint = sha256hex(JCS({ "profile", "artifacts", "identity", "payloads" }))
```

When an envelope or signature is not valid I-JSON the fingerprint is
undefined (null); the run is invalid anyway.

## 9. Privacy

- Object URIs, `actor.id`, `correlationId` and `registeredBy` are opaque;
  none may carry personal data (v2 §9).
- Payload bytes never reach Sigill. Including them in a bundle is the
  producer's decision, made per recipient.
- The configuration objects (instructions, tool manifest, policy) are often
  confidential to the producer. Verification by digest needs only their
  hashes; share the bytes only with parties entitled to read them.

## 10. Test vectors

`test-vectors/agent-run/` contains cross-language vectors: the chain digest
over fixed JWS inputs, the configuration digest, and complete run bundles with
their expected verdicts under a deterministic stub signature verifier. See its
README.
