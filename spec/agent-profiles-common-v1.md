# Agent Evidence Profiles v1 — Common Rules

**Status:** v1.0, normative.

Three sibling profiles of [`AiEvidenceEnvelopeV2`](./ai-evidence-envelope-v2.md)
together describe one controlled agent run:

| Phase | Profile | Content type (`sigD.ctys[0]`) | Count per run |
|---|---|---|---|
| Before | [Agent Control Artifact](./agent-control-artifact-v1.md) | `application/vnd.sigill.agent-control+json` | one |
| During | [Agent Execution Evidence](./agent-execution-evidence-v1.md) | `application/vnd.sigill.agent-execution+json` | one per event |
| After | [Control Evaluation](./control-evaluation-v1.md) | `application/vnd.sigill.control-evaluation+json` | zero or more |

They are sibling profiles in the sense of v2 §2: each is its own content type
with its own schema, sealed through the identical blind mechanism
(`POST /seal/sign-hashes`), never an `extensions` block. v2 §4
(canonicalization), §5 (JAdES binding), §6 (artifact container) and §8 (what
Sigill receives) apply unchanged. This document holds what the three share.

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Family core and conformance

Every profile envelope carries the v2 family core:

| Field | Rule |
|---|---|
| `schemaName` | Profile constant: `AgentControlArtifact`, `AgentExecutionEvidence` or `ControlEvaluation`. |
| `schemaVersion` | `"1"`. |
| `evidenceId` | A bare UUID, as the v2 family core requires. Verifiers SHOULD also accept the `urn:uuid:<uuid>` form and compare identifiers after removing that prefix and lower-casing. |
| `createdAt` | RFC 3339 UTC with `Z`. The producer's clock. |
| `actor` | `{ type, id, version? }`. `type` is `user`, `service`, `system` or `agent` for the first two profiles and `verifier` for Control Evaluation. |
| `activity` | `{ name, correlationId }`, **both required**. `correlationId` is the run identifier; every artifact of one run carries the same, non-empty value. |
| `objects[]` | Detached objects, index-aligned with `sigD.pars[1…]` as v2 §3.1 and §5.2 prescribe. Each profile defines its own closed set of `role` values. |
| `extensions` | Optional, producer-private, as v2 §2. Never carries profile semantics. |

**Conformance.** Every envelope MUST validate against its profile's complete
schema — optional fields are optional to supply, never exempt from validation
when present — and MUST be valid I-JSON: no repeated member names anywhere
(including inside the base64url protected header of its signature), no
integers beyond ±2^53, no lone surrogates, no NaN or Infinity. Schemas are
`additionalProperties: false` throughout; the only open fields are
`extensions` and per-object `metadata`.

## 2. The binding rule (normative)

All references between artifacts use one mechanism:

> **signatureSha256(A)** = lowercase hex SHA-256 over the base64url-decoded
> JWS Signature Value of the classical signature entry of artifact A.

- Every artifact's JWS MUST carry **exactly one classical signature entry** —
  one `signatures[]` element whose readable protected header has an `alg`
  not starting with `ML-DSA`, or a flattened JWS — plus at most the hybrid
  ML-DSA entry, which never participates in binding. An entry whose
  protected header cannot be read counts as classical. So the signature a
  reference commits to and the signature that is verified are the same one.
- The signature value MUST be strict base64url (alphabet `A–Z a–z 0–9 - _`,
  no padding); otherwise the artifact has no `signatureSha256`.
- Unprotected headers (timestamps, revocation values) are excluded, so later
  augmentation never breaks a reference.

| Reference | Field | Points to |
|---|---|---|
| Chain link | `chain.prevSignatureSha256` | the previous Execution Evidence artifact |
| Run to controls | `binds.controlArtifactSignatureSha256` | the run's Control Artifact |
| Evaluation to run | `subject.runEndSignatureSha256`, `subject.controlArtifactSignatureSha256` | the `run_end` artifact and the Control Artifact |

Because a reference derives from a signature, it can only be produced after
the target was sealed — which is what makes "sealed before the first event"
provable.

## 3. One signer per run (normative)

The chain protects the order of a run against its producer, but not against
anyone else who can produce a valid signature (another tenant, a rotated key,
a self-signed key): truncating a run and appending forged events whose links
compute from the public signatures is otherwise undetectable.

- The **signer** of an artifact is the `x5t#S256` value in the protected
  header of its classical signature entry. That header MUST also carry `x5c`,
  and `x5t#S256` MUST equal the base64url SHA-256 of the DER certificate
  `x5c[0]`.
- The Control Artifact and every Execution Evidence artifact of a run MUST
  have the same signer. A Control Evaluation is signed by its verifier and
  MAY — SHOULD, in production — have a different signer of its own.
- A verifier MAY be given the signer(s) it expects, separately for the run
  and for evaluations, and then fails anything signed by others.
- **Consistency is not identity.** One signer proves one key signed the whole
  run, not *whose* key it is. Verifiers report the signing certificate's chain
  trust as the signature service established it (`trusted_chain` or
  `platform` when it chains to a trusted root) and warn whenever it is
  anything else and no expected signers were given.
- A signature verifier plugged into a run verifier MUST verify each signature
  against `x5c[0]` of the same protected header that names the signer — never
  against a key looked up by `kid`, tenant or registry. `POST
  /seal/verify-objects` does.

## 4. Timestamp policy (normative)

Signing every event is cheap; timestamping every event is not, in money or in
latency. The default is therefore: **seal every event, timestamp to wrap up.**

The policy is signed in the Control Artifact (`timestampPolicy`), so it is
locked before the run starts:

```json
"timestampPolicy": {
  "profile": "throughput",
  "everyEvents": 0,
  "everySeconds": 0,
  "consequential": false
}
```

| Field | Default | Meaning |
|---|---|---|
| `profile` | `throughput` | `throughput`: events are sealed B-B (signature only, no timestamp, no OCSP) unless a rule below requires a timestamp. `per-event`: every event is timestamped. |
| `everyEvents` | `0` (off) | Require a timestamp on the N-th event since the last one. |
| `everySeconds` | `0` (off) | Require a timestamp on the first event `everySeconds` or more after the last required one. |
| `consequential` | `false` | Require a timestamp on every event with `step.consequential: true`. |

Always timestamped, whatever the policy: the **Control Artifact**, **`run_end`**
and every **Control Evaluation**. An event MAY declare `step.timestamp:
"required"` to be timestamped anyway (a producer may require more, never
less).

A verifier recomputes, from the signed policy alone, which events had to carry
a timestamp:

```
sinceStamp := 0; lastStampTime := null
for each event in seq order:
  required := profile = "per-event"
           or type = "run_end"
           or (policy.consequential and step.consequential)
           or (everyEvents > 0 and sinceStamp + 1 ≥ everyEvents)
           or (everySeconds > 0 and seq > 0 and lastStampTime ≠ null and eventTime ≠ null
               and eventTime − lastStampTime ≥ everySeconds)
           or step.timestamp = "required"
  if required: sinceStamp := 0; lastStampTime := eventTime
  else:        sinceStamp := sinceStamp + 1
  if seq = 0 and lastStampTime = null: lastStampTime := eventTime
```

`step.eventTime` carries millisecond precision, and a producer MUST decide on
exactly that truncated value, so producer and verifier always agree.

Without the Control Artifact (`run_only`) the policy is unknown: the verifier
requires only `run_end` and declared events and reports `timestamps: warn`
(the run is invalid anyway, §8: `control`). A Control Artifact without
`timestampPolicy` is judged under the defaults above, with a warning.

**What this proves.** The order of events is proven by the chain. An
unstamped event's time is bounded above by the next timestamped artifact's
`sigTst` (the chain makes every earlier signature exist before it) and below
only by the order of the chain: it was sealed after the Control Artifact's
signature existed, because it commits to it. A timestamp is an upper bound on
when a signature existed, never a lower one, and it sits in the unprotected
header, so it can be added later. The exact time is the producer's claim.
Anyone who can seal with the run's certificate — Sigill's key store, used
through the tenant's API credentials — could in principle rewrite the
unstamped events of a run until `run_end` is timestamped. Timestamping
consequential events narrows that window at the cost of one timestamp each.

## 5. Detached objects

Everything under `objects[]` stays with the producer (v2 §3.1). `uri` SHOULD be
`urn:uuid:<uuid>`; it is opaque and never dereferenced; it MUST NOT carry
personal data. `contentType` SHOULD be set. The same object MAY appear in
several artifacts (the control set appears in both the Control Artifact and
the Control Evaluation); when it does, the URI and the digest MUST be
identical in each.

## 6. Producer rules

1. The Control Artifact is sealed before `run_start`; each event is sealed
   before the next is built (`prevSignatureSha256` needs the previous
   signature).
2. An artifact whose timestamp is required MUST be sealed with one. If the
   sealing service returns none, the producer MUST treat the run as failed.
3. After any sealing failure the producer MUST NOT continue the chain; the
   run then verifies as `run_open` or `run_invalid`, never as finalized.
4. A producer SHOULD validate every envelope against §1–§4 before sealing it,
   so it never seals an artifact its own verifier would reject. Producer
   extension data never uses the profile's own member names.
5. Payload bytes stay with the producer. Only digests, opaque URIs and object
   content types reach the sealing service (v2 §8); producers SHOULD NOT send
   operation labels derived from event types.

## 7. The bundle

The portable form of a controlled run:

```json
{
  "format": "AgentRunBundle",
  "bundleVersion": "1",
  "correlationId": "urn:uuid:…",
  "controlArtifact": { "envelope": {…}, "signature": {…}, "objectDigests": { "<uri>": "<sha256 hex>" } },
  "artifacts":       [ { "envelope": {…}, "signature": {…}, "objectDigests": {…} } ],
  "evaluations":     [ { "envelope": {…}, "signature": {…}, "objectDigests": {…} } ],
  "payloads": { "<uri>": "<base64>" }
}
```

- `artifacts[]` holds the Execution Evidence, at most 2000. `controlArtifact`
  MAY be null; `evaluations` and `payloads` MAY be absent.
- `objectDigests` carries each object's SHA-256 as recorded by the producer;
  a blind verification needs only these. A supplied payload is hashed and
  used instead, which upgrades `objects` from "digests match" to "content
  matches". Every payload key MUST be the URI of a signed object of some
  artifact in the bundle.
- `correlationId` in the bundle is an index for humans; verifiers take the
  run identifier only from the signed envelopes.
- Parsing is strict: a malformed entry, a non-hex digest, invalid base64, a
  repeated member name or a non-JSON constant invalidates the whole bundle
  and lists every problem found.

## 8. Verification

A verifier takes a bundle and reports these checks, each `ok`, `warn` or `bad`.
Later checks run even when earlier ones fail, so the report is complete.

| Check | `bad` when |
|---|---|
| `correlation` | An event carries no signed, non-empty `correlationId`, or it differs from the run's. |
| `sequence` | A `seq` is missing, duplicated or absent; or the run does not have exactly one `run_start`, at `seq` 0. Missing positions are listed. |
| `chain` | Any `prevSignatureSha256` is not `signatureSha256` of the previous event, or `seq` 0 carries one. |
| `envelope` | An artifact fails its profile schema or §1 conformance, or its signed actor/version differs from `run_start`'s. |
| `signatures` | A signature fails; an artifact does not carry exactly one classical signature; an event's or the Control Artifact's signer differs from the run's or cannot be established; the run's signer is not among the expected signers; or a hybrid seal's ML-DSA commitment is anything but `absent` or `verified`. |
| `timestamps` | An artifact required by §4 lacks a valid timestamp, a present timestamp is invalid, or the signed policy is malformed. `warn` while no valid `run_end` anchor exists, or without the Control Artifact. |
| `objects` | A signed object was not supplied, no longer matches, a supplied payload contradicts its supplied digest, the signature and envelope disagree on the object list, or unsigned data was supplied. `warn` when every object matched by digest but some payloads were not supplied. |
| `finalization` | More than one `run_end`; `run_end` is not last; it has no valid `runDisposition`; its `finalSeq` is not its own `seq`, or its `finalPrevSignatureSha256` is not its own `chain.prevSignatureSha256`; or it lacks a valid timestamp. `warn` when there is no `run_end`. |
| `control` | The Control Artifact the run binds is not supplied (`run_only`): `run_start` must bind one, so a bundle without it is always incomplete, and omitting it would otherwise hide a broken control basis or a stricter policy; `run_start`'s `binds.controlArtifactSignatureSha256` is not `signatureSha256` of the supplied Control Artifact, or a later event binds another; the Control Artifact fails its own signature, objects or timestamp, its `correlationId` is not the run's, or its `agent` is not the run's actor. |

**Run verdict:** any `bad` → `run_invalid`; no `run_end` → `run_open`;
otherwise `run_finalized`. Malformed evidence is a verdict, never an error: a
verifier never raises on it.

**Binding state:** `bound` (run and its Control Artifact), `run_only`,
`control_only` (a Control Artifact without events), `unbound`.

**Seal time, as defence in depth** (reported as warnings, never fatal): the
Control Artifact's `sigTst` genTime is not later than `run_start`'s plus one
second for TSA accuracy (`controlSealedBeforeRun`; `null` when `run_start` has
no timestamp, which is the default policy), and no timestamped event claims an
`eventTime` later than its own `sigTst` genTime plus six seconds — five
seconds of clock skew and one of TSA accuracy (`eventTimesPlausible`; `null`
when no event is timestamped).
Seal times are never compared along the chain: `prevSignatureSha256` proves
that order already.

**Evaluations** are reported per evaluation, never merged into the run
verdict: `subjectBound` (its `subject` names this run's `run_end` and Control
Artifact), `controlSetDigestMatches`, `baselineDigestMatches` (when both
carry a `baseline-state`), its own signature, timestamp, signer and chain
trust, and `overall` and `controls[]` **unchanged**. A verifier never
evaluates controls.

**Signature verification** of each artifact is the v2 object-level verdict
(v2 §7): the verifier supplies the JCS digest of its own copy of the envelope
under `urn:sigill:envelope` plus one digest per object, offline or through the
blind `POST /seal/verify-objects`; either way only digests leave the
verifier.

**Scope.** `run_finalized` with `overall: PASS` means: the control basis was
sealed before the first event, all recorded events are unchanged since
`run_end` was timestamped and are in the recorded order, the run was closed
under one signer, and the named verifier reported PASS against the
pre-sealed control set. It does not establish that every event was captured,
that `eventTime` is true, that no other run took place, that the verifier
measured correctly, or — unless the verifier was given expected signers — who
produced the run. Unstamped events could have been rewritten by anyone able
to seal with the run's certificate until `run_end` was timestamped (§4).
Verifiers SHOULD show this scope next to the verdict.

### 8.1 What verification cannot see

The agent can act first and seal the control basis and chain afterwards;
binding and time are then both consistent. Only tying the seals to the
external effect exposes it: the harness waits for the seal of `tool_call`,
`authorization` and `human_approval` before the tool runs, or the evaluating
verifier puts the target record's modification time in `observed-state` and
checks that the `tool_call` seal lies before it.

### 8.2 Bundle fingerprint

A deterministic fingerprint over everything the verdict depends on, for
caching:

```
one(a)      = { "e": sha256hex(JCS(a.envelope)), "s": sha256hex(JCS(a.signature)), "d": a.objectDigests }
artifacts   = [ { "seq": a.envelope.chain.seq if a non-negative integer, else -1, …one(a) } ] sorted by seq, then e
control     = one(controlArtifact) or null
evaluations = [ one(e) ] sorted by e
payloads    = [ { "uri", "sha256": sha256hex(bytes) } ] sorted by uri
fingerprint = sha256hex(JCS({ "format", "artifacts", "control", "evaluations", "payloads" }))
```

It is undefined (null) when any envelope or signature is not valid I-JSON.

## 9. Privacy

Object URIs, `actor.id`, `correlationId` and approver references are opaque;
none carries personal data. Payload bytes never reach Sigill. Configuration
objects (instructions, tool manifest, policy) are often confidential:
verification by digest needs only their hashes.

## 10. Test vectors

- [`test-vectors/agent-run/`](./test-vectors/agent-run/README.md):
  cross-language vectors — binding digests, and complete bundles with their
  expected verdicts under a deterministic stub signer.
- [`test-vectors/10-agent-controlled-run/`](./test-vectors/10-agent-controlled-run/README.md):
  one run sealed for real by the Sigill test tenant (canonical bytes, and the
  profile layer checked offline; signature validity needs the platform).

## 11. Design decisions (record)

- **Three sibling profiles, not an `extensions` block** (2026-10-03): follows
  v2 §2; replaces the earlier extensions-based AgentExecutionProfileV1 draft,
  which never shipped.
- **One signer per run** (2026-10-03): closes forged appends by another
  signer; the evaluation keeps its own signer.
- **Seal every event, timestamp to wrap up** (2026-10-03): 1–3 timestamps per
  run, not one per event. Deliberately deviates from the agent-execution MVP
  proposal's mandatory checkpoint after every consequential event; that is a
  policy option (`consequential: true`) instead.
- **The rewrite window is accepted** (2026-10-03): with the default policy,
  unstamped events can be rewritten by anyone able to seal with the run's
  certificate until `run_end` is timestamped (§4). Shown in the scope text;
  `consequential: true` or a cadence narrows it.
- **A missing Control Artifact fails the run** (2026-10-03): `run_start` must
  bind one, so `run_only` means it was left out, and leaving it out must not
  turn an invalid run into a finalized one.
- **`finalSeq` is `run_end`'s own `seq`**, duplicated in its step block, so
  closure is checkable without trusting the same artifact's chain fields.
- **Bare UUID `evidenceId`**, as the v2 family core requires. The `urn:uuid:`
  form is accepted by the SDK verifiers (their validator's `format: uuid`
  allows it); a general JSON Schema validator that enforces formats rejects
  it.
