# AiEvidenceEnvelopeV1 — Specification

This document is the normative specification of the **AI Evidence Envelope, version 1**
(`schemaName: "AiEvidenceEnvelope"`, `schemaVersion: "1"`).

The envelope is a tamper-evident record of an AI generation call. It is designed to be:

- **Reusable** across business domains (nothing here is consumer-specific or business-domain-specific).
- **Cross-language deterministic** — the same logical envelope produces a byte-identical canonical form
  whether produced by .NET, Python, or any future SDK.
- **PII-safe by design** — sensitive payloads (prompts, responses, retrieved documents) are referenced
  by hash, never stored inline. The envelope can be retained even when the payloads must be deleted.
- **Verifiable offline** — given the envelope, the external payloads it references, and the embedded
  RFC 3161 timestamp, anyone can re-derive the canonical bytes, recompute the hash, and confirm the
  timestamp asserts that hash.

The machine-readable schema is [`ai-evidence-envelope-v1.schema.json`](./ai-evidence-envelope-v1.schema.json).

## 1. Envelope shape

The envelope is a single JSON object. Every field is documented in the JSON Schema; the high-level
groupings are:

| Group | Fields | Purpose |
|---|---|---|
| Identity | `schemaName`, `schemaVersion`, `evidenceId`, `createdAt` | Self-identification of the record. |
| Context | `purpose`, `actor`, `activity` | Why the call happened, who or what triggered it, what business activity it serves. |
| AI call | `model`, `prompt`, `inputs`, `retrievedContext`, `sourceTrace`, `output`, `outputArtifacts` | What was sent to the model, what came back, and the provenance of any retrieved context. |
| Operational | `processingMetadata`, `policyMetadata` | Token usage, durations, applied redactions, consent. |
| Cryptographic | `integrity`, `proofs` | The envelope's own hash and the proofs (RFC 3161 timestamps) that bind it. |

Only `schemaName`, `schemaVersion`, `evidenceId`, `createdAt`, `purpose`, `actor`, `activity`,
`model`, and `integrity` are required. All other top-level fields are optional and producers
include them as appropriate.

## 2. Payload references — keeping PII out of the envelope

Most fields that could carry sensitive content (`prompt`, each entry of `inputs`, `retrievedContext`,
`output`, each entry of `outputArtifacts`) use the `payloadRef` shape. A `payloadRef` is *either* inline
*or* a hash reference — never both:

```jsonc
// Inline form — only for non-sensitive content
{
  "contentType": "text/plain",
  "encoding": "utf-8",
  "inline": "Summarise the attached invoice."
}

// Hash-reference form — for any content that is or may be PII
{
  "ref": "prompt-001",
  "contentType": "text/plain",
  "encoding": "utf-8",
  "hash": {
    "alg": "SHA-256",
    "hex": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "sizeBytes": 32
  }
}
```

The hash MUST be computed over the *raw bytes* of the payload as it was actually fed to the model.
For UTF-8 text, that is the UTF-8 encoded bytes of the string. For binary attachments, that is the
file bytes. The `encoding` field records which interpretation applies.

The `ref` value is an opaque, producer-chosen identifier. A verifier supplies a
`{ ref → bytes }` map at verification time; the SDK looks up each referenced payload, hashes it,
and confirms the digest matches.

## 3. Canonicalization

The envelope is canonicalized using **RFC 8785 / JCS** (JSON Canonicalization Scheme).
This is the only canonicalization scheme accepted in v1.

JCS is chosen because:

- It is an IETF-published standard with reference implementations in C#, Java, Python, Go, JavaScript,
  Ruby, Rust, and others. A multi-language envelope demands a multi-language canonicalizer, and
  rolling our own would create a long-tail support liability.
- It is purely text-level: object keys sorted by UTF-16 code-unit order, no whitespace, ECMAScript
  number formatting. The output is byte-identical across runtimes.
- It is widely used in identity infrastructure (W3C Verifiable Credentials Data Integrity, sigstore,
  COSE/JOSE adjacent work).

## 4. The envelope hash — what is bound, and how

The `integrity.envelopeHash` is a SHA-256 (default) digest of the canonical envelope **with the
hash-bearing fields removed before canonicalization**. This avoids a chicken-and-egg problem:
the hash cannot include itself.

The exact procedure that producers and verifiers MUST follow is:

1. Take the full envelope object.
2. **Remove** the field `integrity.envelopeHash`.
3. **Remove** the field `proofs` (proofs are added *after* hashing).
4. Canonicalize the resulting object with RFC 8785.
5. Compute the digest of the canonical UTF-8 bytes with the chosen algorithm.
6. Set `integrity.envelopeHash` to `{ "alg": "SHA-256", "hex": "<lowercase hex>" }`.
7. Add `proofs[]` entries that bind to that exact hex string.

The verifier reverses this: strip `integrity.envelopeHash` and `proofs`, canonicalize, hash, and
compare against the stripped value. If equal, the envelope is intact and the proofs apply.

> **Note.** `integrity.canonicalization` itself IS included in the canonical bytes — it asserts
> *which* canonicalizer the producer claims to have used, and the verifier checks the assertion is
> consistent with what it can verify.

## 5. Proofs

`proofs[]` is an array, not a single value. v1 defines exactly one proof type:

```jsonc
{
  "type": "rfc3161",
  "tsrBase64": "...base64-encoded TimeStampToken...",
  "tsaName": "DigiCert",
  "genTime": "2026-05-08T13:42:00Z",
  "serial": "1234567890",
  "qualified": false
}
```

The TSR is obtained by calling Sigill's `POST /tsa/stamp` with the envelope hash bytes as the input
file (see SDK implementations). The TSR cryptographically binds the hash to the TSA's asserted time.

`tsaName`, `genTime`, `serial`, `qualified`, and `policyOid` are convenience copies; the
authoritative values are the ones inside `tsrBase64`. A verifier MUST re-derive them from the
parsed TSR rather than trusting the convenience copies.

The array shape leaves the door open to:

- **Timestamp chains** — produced by Sigill's `POST /tsa/restamp` before a TSA certificate expires.
  Each restamp is appended to `proofs[]` in chronological order.
- **Future proof types** — JWS / CAdES / ASiC are explicitly out of scope for v1 but the array shape
  means they can be added without a schema break.

## 6. Field stability and forward compatibility

- `additionalProperties: false` is enforced at the top level and in nested objects to prevent
  silent schema drift. Producers MUST NOT add unknown top-level fields.
- The spec adds new optional fields by minor JSON-Schema revisions; consumers MUST tolerate the
  presence of any documented optional field even if their SDK predates it. (Canonicalization
  ensures unknown-but-documented fields still produce a deterministic hash.)
- A breaking change increments `schemaVersion` to `"2"`. v1 envelopes remain verifiable indefinitely.

## 7. Error model

The SDKs surface four explicit failure modes during verification:

| Error | Meaning |
|---|---|
| `canonicalization_failed` | The envelope is not valid I-JSON or contains constructs JCS rejects (e.g. NaN). |
| `hash_mismatch` | The recomputed envelope hash does not match `integrity.envelopeHash.hex`, OR a referenced external payload's hash does not match its registered hash. The SDK reports which. |
| `invalid_proof` | The TSR fails to parse, or its embedded message-imprint does not match the envelope hash, or its TSA signature is invalid. |
| `timestamp_unavailable` | A producer-side error: every TSA Sigill tried failed. The envelope is sealed *without* a proof; verification will report `proofs` is empty. |

Verification produces a structured result rather than raising on the first issue, so consumers
can render a complete report.

## 8. Test vectors

The [`test-vectors/`](./test-vectors/) directory contains three reference scenarios. Each scenario
ships:

- `input.json` — the envelope input (pre-hashing).
- `external-payloads/` — files matching the `ref` values used inside.
- `canonical.json` — the exact canonical bytes that both SDKs MUST produce after stripping
  `integrity.envelopeHash` and `proofs`.
- `envelope-hash.txt` — the SHA-256 hex of `canonical.json`.
- `expected.json` — the fully-formed envelope that should result, minus proofs (which depend on
  Sigill's response and so are not byte-stable).

The .NET and Python test suites both load these vectors and assert byte equality of canonical output
and hex equality of the envelope hash. This is the cross-language interop guarantee.

The three scenarios are:

1. **complete-ai-call** — every optional field populated, all payloads inline (small fixtures).
2. **pii-redacted** — prompt and output are hash references, not inline; `policyMetadata.redactionApplied` is true.
3. **missing-external-payload** — verification scenario where one referenced payload is *not* supplied,
   and the verifier reports which `ref` was missing.

## 9. Versioning of the spec itself

This document tracks the `v1` family. Editorial clarifications and additive optional fields land
on the same spec version. A change that would invalidate previously-sealed envelopes — a different
canonicalization, a renamed required field, a removed field — produces `v2` and a new schema file
alongside this one.
