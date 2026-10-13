# AiEvidenceEnvelopeV2 — Specification

**Status: v2.1, 13 Oct 2026** (v2.0 agreed 12 Aug 2026). Supersedes
[`AiEvidenceEnvelopeV1`](./README.md) for *producing* evidence;
v1 envelopes remain verifiable indefinitely and nothing re-signs old evidence.
v2.1 changes only the *form* of the `sigD.pars` references — relative
locator references instead of URNs (§3.1, §5.2, §5.4); envelopes, schemas and
`schemaVersion` are unchanged, and v2.0 seals stay verifiable.
**The opaque-identifier requirement on remote paths (§3.1) is load-bearing
for hashing anonymity and is normative** — it MUST NOT be relaxed to guidance
in future revisions.

This is the format contract; the Sigill platform signing and verification
endpoints are documented in the platform API reference. That contract is
**blind in both directions**: the producer sends digests and opaque URIs and
receives the JWS; the **artifact is always assembled client-side**; platform
verification takes the JWS plus a digest map and returns cryptographic
verdicts. Sigill never receives the envelope — everything envelope-shaped in
this document (schema validation, canonicalization, role coverage) is the
SDK's job.

**Scope** — this document versions exactly one format: the **AI evidence
envelope** (`AiEvidenceEnvelope`) produced by the Sigill SDKs and the browser
extension. Other Sigill envelope formats are **sibling profiles** — their own
content types, their own schemas, signed through the same JAdES multi-object
mechanism — not instances of this schema, and not versioned by this
document.

**Regulatory positioning** (scope honesty): this format supports
record-keeping, provenance and audit evidence — the Article 12-style
traceability dimension of the EU AI Act. It is **not** an AI-output
transparency marking: Article 50's machine-readable marking obligations
concern the published output channel itself, and a detached seal does not
satisfy them.

The machine-readable schemas are
[`ai-evidence-envelope-v2.schema.json`](./ai-evidence-envelope-v2.schema.json)
(the envelope) and
[`ai-evidence-artifact-v2.schema.json`](./ai-evidence-artifact-v2.schema.json)
(the distributed file). Normative reference for the signature:
**ETSI TS 119 182-1 V1.2.1 (2024-07)** — clause numbers below cite it.

---

## 1. What changed, and why

v1 evidence is **timestamped, not signed**: the envelope carries its own hash
(`integrity`) and an RFC 3161 timestamp (`proofs[]`). It proves *when*, never
*who*. v2 rebases the format on JAdES: the envelope becomes one of several
detached data objects bound by a JAdES signature, and every AI evidence
becomes an **advanced electronic seal**, inheriting at zero new mechanism
cost:

- **origin** — the tenant's seal certificate (platform or BYOC), via `x5c`;
- **trusted time** — `sigTst` signature timestamps, standard or qualified;
- **post-quantum** — an ML-DSA-87 hybrid signer (RFC 9964) as a second
  `signatures[]` entry;
- **revocation evidence** — `rVals` (full OCSP responses);
- **third-party validation** — DSS/ETSI validators instead of our own spec.

Two v1 constructs disappear because the JWS now owns them:

| v1 | v2 |
|---|---|
| `integrity.envelopeHash` (self-hash, with the "strip `integrity`+`proofs` before canonicalizing" procedure) | Gone. The envelope is hashed **as-is** — it is detached object 0 of the signature and never self-references. The chicken-and-egg hack is deleted, not ported. |
| `proofs[]` (RFC 3161 TSRs over the envelope hash) | Gone. Trusted time is the signature's `sigTst` (§5.3.4), riding the platform's normal renewal/restamp rails. |
| per-payload `hash` values (`payloadRef.hash`) | Gone from the envelope. The **one and only copy** of each content digest is the *signed* copy in `sigD.hashV`. The envelope describes; the signature binds. |

## 2. Family core, profile fields, extensions

The envelope family (this schema and its sibling profiles) shares a **core
vocabulary** that generic viewers and verifiers can render without
profile-specific code:

- **Core** (family-shared): `schemaName`, `schemaVersion`, `evidenceId`,
  `createdAt`, `actor`, `activity`, `objects[]` (with roles), `chain`,
  `extensions`.
- **AI-profile fields** (this schema): `purpose`, `model`,
  `processingMetadata`, `policyMetadata`, `sourceTrace`.
- **`extensions`** is the named extension point: an object whose keys are
  extension identifiers (reverse-DNS recommended) and whose values are
  objects owned entirely by that extension. Extensions are signed like
  everything else but carry no cross-profile semantics; unknown extensions
  are ignored, never rejected. `extensions` is for **producer-private data
  within a profile** — sibling profiles are not extensions: a sibling
  profile is its own content type with its own schema, carrying its
  trust-model-specific data as profile fields. Trust levels are never mixed
  into this profile's customer-asserted core.

The schema stays `additionalProperties: false` everywhere: the *only* place
for unmodelled data is `extensions` (and per-object `metadata`). This
preserves v1's drift protection while giving the family room to grow.

## 3. The envelope

A single JSON object; every field is documented in the schema. High-level
groupings:

| Group | Fields | Purpose |
|---|---|---|
| Identity | `schemaName` (`"AiEvidenceEnvelope"`), `schemaVersion` (`"2"`), `evidenceId`, `createdAt` | Self-identification of the record. |
| Context | `purpose`, `actor`, `activity` | Why the call happened, who or what triggered it. `actor.type` gains `"agent"` in v2. |
| AI call | `model`, `objects[]`, `sourceTrace` | What was sent and produced (by reference), and retrieval provenance. |
| Operational | `processingMetadata`, `policyMetadata` | Token usage, durations, redactions, consent. |
| Sequencing | `chain` | Cryptographic chaining for multi-step agent runs (§3.4). |
| Extension | `extensions` | Named extension point (§2). |

Required: `schemaName`, `schemaVersion`, `evidenceId`, `createdAt`, `purpose`,
`actor`, `activity`, `model`, `objects`.

### 3.1 `objects[]` — the payload descriptions

v1's `prompt` / `inputs` / `retrievedContext` / `output` / `outputArtifacts`
collapse into one descriptive list:

```jsonc
"objects": [
  { "uri": "objects/6f1c2a4e-0b7d-4c1e-9a52-3d8f0e1b7c90", "role": "prompt",
    "contentType": "text/plain", "encoding": "utf-8", "sizeBytes": 214 },
  { "uri": "objects/0d3b9e57-8a21-4f6c-b4d0-71c5e2a9f346", "role": "context",
    "contentType": "text/markdown", "encoding": "utf-8",
    "metadata": { "rank": 0, "score": 0.93, "source": "kb://article/118" } },
  { "uri": "objects/a85e0f12-6c3d-4b97-8e41-c2f9d07b5a63", "role": "output",
    "contentType": "text/markdown", "encoding": "utf-8" },
  { "uri": "objects/3c7d1b98-e4a6-4f05-9d2c-58b0a1e6f714", "role": "artifact",
    "contentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "encoding": "binary", "metadata": { "filename": "report.xlsx" } }
]
```

Rules (normative):

- **Roles**: `prompt | input | context | output | artifact | log`. The
  envelope says what each object *is*; the signature says what it *hashes to*.
- **URIs are caller-chosen, opaque locator references** (since v2.1).
  TS 119 182-1 §5.2.8.3.1 requires every `pars` entry to be a URI-reference
  that, once resolved (a relative reference against a default HTTP base),
  is a *locator* in the sense of RFC 3986 §1.1.3. A URN is a name, not a
  locator, so v2.0's `urn:` identifiers do not meet that clause; v2.1
  replaces them (rationale and evidence: §12). Sigill never dereferences
  them, and no verifier needs to: digests are always computed from
  caller-supplied bytes, never fetched (§5.4).
- **Production reference profile** (normative for NEW output, never applied
  when verifying historical evidence). Every object URI a producer emits
  MUST match Sigill's deliberately narrower profile:

  ```
  ref     = segment *( "/" segment )
  segment = 1*( ALPHA / DIGIT / "." / "_" / "~" / "-" )   ; and not "." or ".."
  ```

  That is: non-empty segments; no scheme or `:`; no authority (`//`); no
  leading or trailing `/`; no `\`, whitespace or control characters; no
  `?`, `#` or `%` (no percent-encoding, so byte-exact comparison stays
  exact). Absolute URLs are excluded too, even though ETSI allows them: a
  validator may dereference them, which leaks names and opens a request
  surface for third-party verifiers. Size limits are those of the signing
  endpoints and are unchanged. SDKs generate `objects/<uuid>` (lower-case
  UUID) by default. **Transition allowance (§10.1):** until the signing
  service enforces this profile, a new seal may re-reference an object an
  earlier seal bound under a legacy URI (an evaluation of a run that
  straddles an upgrade reuses the control set its Control Artifact sealed);
  the URI is kept, never renamed. Once the profile is enforced, such a seal is
  refused, and the producer starts a fresh run whose objects conform. This
  governs emission only: historical and transitional seals stay verifiable.
- **On any remote path, opacity is a privacy requirement, not a style
  choice**: URIs sent to the platform (blind signing, blind verification)
  MUST carry no personal data and no content-derived names — hashing
  anonymity is defeated by a `pars` entry like
  `contract-olsen-vs-hansen.pdf`. The `objects/<uuid>` default is opaque;
  human-meaningful names (filenames, paths) belong in the object's
  `metadata`, which stays inside the envelope and never leaves the producer.
  (A stored-seal opt-in on the platform retains the JWS, which embeds the
  signed URIs — opaque identifiers are what keep that retention clean.)
- **URIs MUST be unique** across `objects[]`, compared **byte-exactly** as
  strings (no normalization, no case folding). Producers MUST reject
  duplicates; verifiers MUST fail on them. The same content MAY appear under
  two URIs (e.g. the same bytes as both `input` and `context`) — identity is
  the URI, not the digest.
- `sigill-envelope.json` and `urn:sigill:envelope` are **reserved** for the
  envelope itself (§5.2) and MUST NOT appear in `objects[]`. Producers MUST
  reject both; verifiers MUST fail on either.
- **`encoding`** records how the hashed bytes were derived: `utf-8` (text
  serialized as UTF-8) or `binary` (raw file bytes). RECOMMENDED for text
  payloads — a verifier handed a *string* cannot otherwise reliably reproduce
  the digest.
- **`objects: []` is legal**: a metadata-only record, sealing just the
  envelope. (The signature still binds one object — the envelope.)
- **No digests in the envelope.** `hashV` in the signature is the single,
  signed source of truth. Duplicating hashes here would create a second copy
  that can disagree with the signed one.

### 3.2 RAG provenance

Retrieval attributes that v1 attached to `retrievedContext` entries
(`rank`, `score`, `source`) move to the per-object `metadata` block (see the
example above; keys are typed in the schema). The document-level provenance
trail `sourceTrace` (source ids, snapshot hashes, retrieval times) is
**unchanged from v1**.

### 3.3 `activity.parentEvidenceId` vs `chain`

Two linking mechanisms, deliberately distinct:

- **`activity.parentEvidenceId`** is a *semantic* link — "this evidence
  continues from that one". No cryptographic claim; it survives re-issuance.
- **`chain`** (§3.4) is a *cryptographic* sequence — each step commits to the
  previous step's signature bytes. Tampering with any step breaks every
  subsequent link.

A multi-step record MAY use both; a verifier MUST NOT treat
`parentEvidenceId` as integrity evidence.

### 3.4 `chain`

```json
"chain": { "seq": 3, "prevSignatureSha256": "hex…" }
```

Zero-based `seq`; lowercase SHA-256 hex over the previous step's signature;
`prevSignatureSha256` absent at `seq: 0`. The preimage is normative: the
base64url-decoded JWS Signature Value of the previous artifact's classical
signature (the first `signatures[]` entry whose `alg` is not ML-DSA).

What constitutes a step, and the rest of the run semantics (step types,
timestamp policy, finalization, the binding to the control basis), are defined by
the [Agent Evidence Profiles](agent-profiles-common-v1.md) (§2 binding rule). Producers SHOULD
NOT emit `chain` outside a profile that defines it.

## 4. Canonicalization

The envelope is canonicalized with **RFC 8785 / JCS** before hashing — the
same scheme, for the same reasons, as v1 (§3 of the v1 spec: IETF standard,
reference implementations in every SDK language, byte-identical output across
runtimes). The canonical form is encoded as UTF-8.

Unlike v1 there is **no field-stripping step**: the envelope is canonicalized
*exactly as distributed*. `JCS(envelope)` → digest → `sigD.hashV[0]`. A
producer MUST NOT mutate the envelope after signing; a single byte of
difference (after canonicalization) breaks `hashV[0]`.

## 5. The JAdES binding (normative)

The signature is a JAdES signature per ETSI TS 119 182-1 V1.2.1, baseline
B-B or B-T, using the multi-object detached mechanism. This is the profile
Sigill ships in production today (single-object since v1.2.1 went live;
multi-object validated against the EU DSS reference validator), extended to
n objects.

### 5.1 Fixed profile values

| Aspect | Value | TS 119 182-1 |
|---|---|---|
| Serialization | General JWS JSON Serialization; JWS Payload **absent** | RFC 7515 §7.2.1 |
| Detachment | `sigD` with `mId = "http://uri.etsi.org/19182/ObjectIdByURIHash"` | §5.2.8.3.3 |
| Payload contribution | empty stream — binding is entirely via the signed `hashV` | §5.2.8.3.3 |
| Encoding | `b64: false` | §5.1.10, RFC 7797 |
| Criticality | `crit` MUST be present and contain `"sigD"`; this profile fixes `crit: ["sigD","b64"]` | §5.1.9 |
| `cty` header | absent (`sigD.ctys` carries the types) | §5.1.3 |
| Classical signer | `alg: RS256` (current platform issuance), `x5t#S256` + `x5c`, `iat` (NumericDate, seconds) | §5.1.7, §5.1.11 |
| Classical digests | `hashM: "S256"` — SHA-256 | §5.2.8.1 |
| PQC signer (optional) | second `signatures[]` entry: `alg: ML-DSA-87` (RFC 9964), `x5t#o`, own `sigD` with `hashM: "S512"` — SHA-512 | §5.2.2.2, §5.2.8.1 NOTE 1 |
| Timestamps | `etsiU` → `sigTst` on the classical signer's unprotected header (B-T), standard or qualified | §5.3.4 |
| Revocation | `etsiU` → `rVals` (optional) | §5.3.5 |

Verifiers SHALL accept any asymmetric JWS `alg` consistent with the signing
certificate; producers currently emit RS256 classically. Because `b64` is
`false`, each `hashV[i]` is the base64url-encoded digest **of the raw object
bytes** (§5.2.8.1, item 1) — never of a base64 intermediate.

### 5.2 sigD layout

```
pars[0]  = "sigill-envelope.json"         hashV[0] = b64url(digest(JCS(envelope)))
pars[1…] = objects[0…].uri, in order      hashV[1…] = b64url(digest(payload bytes))
ctys[0]  = "application/vnd.sigill.ai-evidence+json"
ctys[1…] = objects[0…].contentType, or "" when absent
```

Alignment rules (normative — these resolve the "1:1 by uri" ambiguity):

1. `pars`, `hashV` and `ctys` have equal length and are index-aligned
   (§5.2.8.1).
2. `pars[0]` names the envelope. New output MUST use exactly
   `sigill-envelope.json` (the *locator* envelope reference). Verifiers MUST
   accept exactly two values: `sigill-envelope.json` and the v2.0 value
   `urn:sigill:envelope` (the *legacy* envelope reference); anything else is
   `alignment_invalid`. The form is read from the individual classical
   signature entry being verified, after its header has been structurally
   validated — never from configuration, a neighbouring artifact or the
   producer's version. The two values are not aliases: no normalization, no
   general URI equivalence, and the digest map supplied for verification
   (§7.1) is keyed by the value this very signature carries. `ctys[0]` is
   exactly the AI-evidence content type. `ctys[0]` is the **profile
   discriminator** — TS 119 182-1 §5.1.3 keeps the `cty` header parameter
   out of sigD-bearing signatures, so the type of object 0 is where a
   consumer learns "this is AI evidence".
3. `pars[i]` for `i ≥ 1` equals `envelope.objects[i-1].uri` — same order,
   byte-exact string equality. No entry may be added, dropped, or reordered
   on either side; duplicate `pars` entries are invalid.
4. `ctys[i]` for `i ≥ 1` equals `envelope.objects[i-1].contentType`
   byte-exactly, or the empty string when the envelope omits `contentType`
   (§5.2.8.1: empty string when the type is implied).
5. When the PQC signer is present, its `sigD` carries the **same `pars` and
   `ctys`** — byte-identical, including the envelope reference form — and
   SHA-512 digests of the **same bytes** in `hashV`. One evidence record, two
   independent cryptographic commitments to it. A form mismatch between the
   two entries is `alignment_invalid`.

Each signature entry carries at most one `sigD` (§5.2.8.1); in the hybrid
case each signer has its own (§5.2.8.1 NOTE 1). Referenced objects never pull
in further references (§5.2.8.1 requirement 4) — the envelope *describes*
the payloads, but every payload is bound **directly** by `hashV`, so the
no-chaining rule is satisfied by construction.

### 5.3 What the platform adds

`iat` is the signer's claimed time; `sigTst` is the trusted time. The
`sigTst` token becomes the linked transaction on the platform's evidence
rails: renewal horizons and archival restamps work unchanged, so AI evidence
enters the preservation story on day one.

### 5.4 Resolving references (v2.1)

`pars` entries are resolved against a **logical, per-artifact HTTP base**,
for example `http://artifact.invalid/<n>/` — an offline mapping, never a live
fetch. Whoever presents an artifact to a validator (an SDK, an export, an
adapter) maps each resolved reference to a document it supplies: the
envelope bytes for `pars[0]`, the payload bytes for an object it holds, or a
digest record for an object it only knows by digest. A folder in an export
archive is a convenience for that mapping, not the base itself.

- Hash and signature verification is separate from document availability.
  A validator that cannot obtain an object's bytes can still verify the
  signature and every digest it is given.
- **Sigill never fetches a `pars` reference** — neither the platform's blind
  verifier nor the SDK verifiers, nor Sigill's exports and adapters, which
  supply the documents themselves. Signed references are attacker-controlled
  input; these are scoped digest/signature verifiers, not general
  URI-fetching validators. A third-party validator may resolve references
  against whatever base it is configured with; the reference syntax alone
  does not prevent that, so artifacts are presented to validators with their
  documents supplied.

**Reference forms when reporting.** A legacy envelope reference
(`urn:sigill:envelope`) is reported as an explanatory diagnostic —
"legacy URN envelope reference; retained for compatibility, not locator
form" — never as a warning or a failed check; the form classifier never
asserts validity on its own (signature, digest, profile, chain and trust
checks decide that). An artifact is described as using locator references
only after *every* `pars` entry has been checked, never from `pars[0]`
alone. A historical reference outside the production profile (an absolute
URL, another URI form) is a Sigill production-profile distinction, not by
itself an ETSI non-conformance.

## 6. The artifact

One self-contained file — `*.ai-evidence.json`, media type
`application/vnd.sigill.ai-evidence+json`:

```json
{ "envelope": { …v2 envelope… }, "signature": { …General JWS JSON… } }
```

The wrapper is deliberately trivial. A validator that only understands
TS 119 182-1 can verify the `signature` member directly, given the canonical
envelope bytes as object 0 and the payloads the caller can supply.

The artifact is **always assembled by the producer**: under the blind
platform contract (§8) Sigill returns the `signature` member and has never
seen the `envelope` member, so no artifact ever exists server-side.

*Alternatives considered and rejected*: distributing envelope and JWS
separately (loses self-containment — the strongest property of the format);
carrying the envelope in an unprotected JWS header (legal but semantically
wrong: the envelope IS signed data, via `hashV[0]`, and unprotected placement
invites confusion).

## 7. Verification — completeness, not membership

An AI-Act-style record must distinguish **"every signed object was supplied
and verified"** from **"one payload existed"**. The verification contract has
two levels; the object level is the default for AI evidence.

**Object-level** (the record-keeping verdict): the verifier supplies bytes
(or digests) per referenced URI and receives:

- a per-object verdict list (`uri`, `role`, `cty`, supplied, hashMatch);
- `missing` — signed objects the caller supplied nothing for;
- `unreferenced` — supplied URIs the signature never signed (flagged, never
  silently accepted);
- **`complete`** — signature valid AND every signed object matched.

Signature/certificate/timestamp validity is computed independently of content
claims: a partial supply yields an honest "signature valid, record
incomplete", never a blended verdict.

**Multiple-signature policy** (normative): object claims and the validity
verdict are always taken from the *same* signature entry, and the **first
cryptographically valid sigD-bearing classical signature wins** (in
`signatures[]` order). Object lists are never merged across signatures;
later valid signatures do not broaden the evidence set — one signature
defines one record. Skipped invalid entries are reported as warnings. The
ML-DSA signer is verified *against the winning record* (same `pars`, SHA-512
digests), reported as `pqc: verified | failed | absent | not_checked`.

**Hybrid seals are both-required** (normative): a seal carrying an ML-DSA
signer has made two commitments to the record, and the record-keeping
verdict requires both. `complete` is reachable only when `pqc` is `absent`
or `verified`; verifying a hybrid seal with SHA-256 digests alone yields
`pqc: not_checked` and `complete: false`, with a warning naming the gap —
the classical verdict never masquerades as full hybrid verification. On the
remote path the SHA-512 digests travel as a second map (`digests512`),
keyed by the same URIs.

**Role coverage** ("is a prompt and an output present?") is an
*envelope-layer* check — `sigD` knows URIs and digests, not roles. The
compound verdict is: signature valid ∧ all objects verified ∧ required roles
present.

**Membership-level** (single-hash lookup): "does this digest appear in this
signature?" — retained for spot checks; never presented as record
verification.

### 7.1 Where verification runs

- **Offline (SDK, full fidelity)**: the SDK holds the artifact and the
  payloads, so it checks everything — JWS + JCS + `hashV` + TST parse,
  schema conformance, role coverage. No Sigill dependency; same posture as
  the v1 verifier.
- **Via the platform (hashing anonymity)**: the request is the JWS
  `signature` member plus a SHA-256 digest per referenced `pars` URI
  (`digests`) and, for hybrid seals, the SHA-512 map (`digests512`) keyed
  by the same URIs — the envelope's own digests are simply the entries for
  the envelope reference the signature carries (`pars[0]`: either
  `sigill-envelope.json` or, for v2.0 seals, `urn:sigill:envelope`; §5.2
  rule 2), computed client-side with JCS. A client builds that key from the
  signature it is verifying and never inserts both values. No special case:
  the envelope is just object 0. Omitted or partial `digests512` on a
  hybrid seal yields `pqc: not_checked` (a mismatch yields `failed`) and
  can never produce `complete: true`. Sigill sees certificates, signed
  hashes and opaque identifiers; never the envelope, never content. The response
  is the cryptographic verdict set above (per-object,
  `missing`/`unreferenced`, `pqc`, `complete`, the multiple-signature
  policy applied server-side).
- **Division of labour**: the platform verifies *what was signed*; the
  verifier's own copy of the envelope says *what the objects mean*. Envelope
  schema validation and role coverage are therefore client-side always —
  the compound verdict (signature valid ∧ all objects verified ∧ required
  roles present) is assembled by the SDK, on either path.

### 7.2 Error model

| Error | Meaning |
|---|---|
| `schema_invalid` | The envelope does not validate against the v2 schema, or `objects[]` violates a normative rule (duplicate URI, reserved URI). |
| `canonicalization_failed` | The envelope is not valid I-JSON or contains constructs JCS rejects. |
| `envelope_hash_mismatch` | `JCS(envelope)` does not hash to `hashV[0]` — the envelope shown is not the envelope signed. |
| `alignment_invalid` | `pars`/`hashV`/`ctys` lengths differ, `pars[0]` is not one of the two envelope references, `pars[1…]` does not match `objects[]` by the rules of §5.2, `pars` contains duplicates, or the PQC entry's `pars`/`ctys` differ from the classical entry's. |
| `object_hash_mismatch` | A supplied payload's digest does not match its signed `hashV` entry. Reported per object. |
| `invalid_signature` | JWS signature verification failed for every sigD-bearing classical entry. |
| `invalid_timestamp` | A `sigTst` token fails to parse, its message imprint does not match, or its TSA signature is invalid. |

Verification produces a structured result rather than raising on the first
issue, so consumers can render a complete report.

## 8. What Sigill receives and persists

**Blind by architecture**: Sigill's nature is to not accept
and store GDPR data, and the contract enforces it structurally. On produce,
Sigill receives digests, opaque URIs, MIME types and the caller-chosen
label/tags — never the envelope, never content; there is no parameter to send
either. On verify, Sigill receives the JWS and the digest map(s) — `digests`,
plus `digests512` when verifying a hybrid seal (§7.1). What it
persists is exactly what any seal operation persists today (operation row,
`DocumentHash` = envelope hash, timestamp token, label/tags) plus a
**name-free** digest manifest (digests + ctys + count — no URIs at rest).
Under the existing detached-seals opt-in it stores the JWS only, never the
artifact.

The envelope — with its actor/activity/model/purpose metadata that can
constitute personal data — lives exclusively with the producer, inside the
artifact they hold. See §9.

## 9. GDPR posture (producer guidance)

- Keep personal identifiers out of `actor.id`, `uri` values, labels and tags
  — supply opaque or hashed identifiers. For `uri`, labels and tags this is
  normative on remote paths (§3.1); for `actor.id` the SDKs offer hashing at
  source (opt-in helper). Note the actor id never reaches Sigill under the
  blind contract — hashing it protects the producer's own artifact and
  whoever they share it with.
- A workload identity is a system account; an agent acting on-behalf-of a
  person may make the id + timestamps personal data. This is
  producer-supplied and opaque to Sigill.
- The honest claim is "content cannot be reconstructed from what Sigill
  holds" — not "no personal data, period". A digest of personal content is
  not automatically non-personal under every DPA reading; the position is
  strong because content never leaves the producer.

## 10. Migration from v1

Field mapping:

| v1 | v2 |
|---|---|
| `prompt` (payloadRef) | `objects[]` entry, role `prompt` |
| `inputs[]` | role `input` |
| `retrievedContext[]` | role `context`; `rank`/`score`/`source` → `metadata` |
| `output` | role `output` |
| `outputArtifacts[]` | role `artifact` |
| — | role `log` (new in v2) |
| `payloadRef.ref` | `objects[].uri` |
| `payloadRef.hash` | signed `sigD.hashV` entry (not in the envelope) |
| `payloadRef.contentType` / `encoding` / `metadata` | same names on the object entry |
| `payloadRef.inline` | **removed** — see breaking changes |
| `integrity` | **removed** — envelope is signed object 0 |
| `proofs[]` | **removed** — `sigTst` in the signature |
| `sourceTrace` | unchanged |
| `actor.type` | enum gains `agent` |
| `activity.parentEvidenceId` | kept; semantic link only (§3.3) |

Breaking changes producers must handle:

1. **Inline payloads are gone.** v2 is hash-only by design; there is no
   `inline`. Content that v1 embedded must be hashed client-side — the SDK
   `seal()` helpers do this transparently for supplied strings/bytes.
2. **One digest algorithm per signer.** A JAdES `sigD` has a single `hashM`
   for *all* objects: SHA-256 (classical) and SHA-512 (PQC signer). v1's
   per-hash algorithm choice — including SHA-384 — does not carry over.
3. **`encoding: "base64"` is removed** together with `inline` (it existed to
   record verbatim-embedded content). v2 knows `utf-8` and `binary`.
4. **`schemaVersion` is `"2"`** — major-only, per v1 precedent.

v1 envelopes remain verifiable with the v1 verifier indefinitely. The SDKs
keep the v1 path for `verify()`, deprecate it for `produce()`.

### 10.1 From v2.0 to v2.1 (reference form)

Nothing in the envelope changes; only `sigD.pars` does.

| | v2.0 | v2.1 |
|---|---|---|
| Envelope, `pars[0]` (set by the signing service) | `urn:sigill:envelope` | `sigill-envelope.json` |
| Objects, `pars[1…]` (chosen by the producer) | any opaque URI; SDK default `urn:uuid:<uuid>` | production profile (§3.1); SDK default `objects/<uuid>` |

- **Verifiers first.** Every verifier accepts both envelope references
  (§5.2 rule 2) before any producer emits the new one. A verifier that only
  knows v2.0 rejects a v2.1 seal with `alignment_invalid`; it must be
  upgraded to read v2.1 seals.
- **Producers.** Object URIs in the production profile are readable by v2.0
  verifiers too (object URIs were always opaque), so producers can switch
  them independently. The envelope reference switches on the signing
  service, after the verifiers.
- **History is never rewritten.** `pars` lives in the protected header;
  v2.0 seals keep their URN references and stay verifiable indefinitely.
  They are reported with the legacy diagnostic (§5.4), not as failures.
- **Unsigned state.** A producer holding objects it has not yet sealed (for
  example a prompt waiting for the model's answer) may re-mint their URIs in
  the new form before the envelope is canonicalized; a URI already bound by
  a seal is never rewritten.
- **Enforcement.** The signing service first accepts legacy object URIs (so
  runs that straddle the upgrade can finish and be evaluated), then refuses
  every object URI outside the production profile. After that, a seal that
  would re-reference a legacy-bound object fails with an upgrade message:
  the producer restarts with a fresh, conforming run. Nothing is renamed and
  no exemption is kept for previously sealed objects.

## 11. Test vectors

`test-vectors/` gains v2 scenarios alongside the v2 implementation
(signatures depend on issued certificates and are not byte-stable). Two
vector classes:

1. **Canonicalization vectors** (byte-stable, cross-language): envelope input
   → exact canonical bytes → SHA-256/SHA-512 hex. These gate the .NET/Python
   interop exactly like v1's `canonical.json` files.
2. **Verification vectors** (fixed test certificate): full artifacts with
   known-good and known-broken objects, exercising every §7.2 error and the
   multiple-signature policy.

## 12. Design decisions (record)

Decisions made during review of this version, recorded so future revisions
revisit them deliberately:

- **Artifact container**: the self-contained `{envelope, signature}` file
  (§6); separate distribution and unprotected-header carriage rejected.
- **Canonicalization**: RFC 8785/JCS (§4); byte-exact as-transmitted
  envelopes rejected (simpler spec, brittle tooling).
- **Blind platform contract, both directions** (§7.1, §8): digests + opaque
  URIs in / JWS out, artifact assembled client-side, blind verification,
  name-free persistence. Follows from the design principle that Sigill does
  not accept and store personal data. A blind endpoint is also
  content-type-agnostic by construction — sibling profiles sign through the
  identical mechanism with their own cty.
- **`encoding` enum**: `utf-8 | binary` (§3.1); `base64` fell with inline
  payloads.
- **`extensions` shape**: named, object-valued blocks for producer-private
  data within a profile (§2); sibling profiles are their own content types,
  never extensions.
- **Metadata-only records**: `objects: []` is legal (§3.1); role and count
  requirements belong in per-profile verification policy, not the schema.
- **Actor-id hashing**: opt-in SDK helper, not default-on (§9) — default-on
  gives stronger privacy but worse UX for the producer's own audit, and the
  actor id never reaches Sigill either way.
- **`chain`**: reserved with open semantics (§3.4) rather than omitted, so
  the field name and shape were stable before multi-step producers existed.
  Closed by the Agent Evidence Profiles v1: the classical-signature preimage is
  normative, and step semantics belong to the agent profiles, not the family core.
- **Locator references instead of URNs** (v2.1, 13 Oct 2026; §3.1, §5.2,
  §5.4, §10.1). v2.0 used URNs deliberately as pure identifiers, relying on
  EU DSS matching detached objects by name. TS 119 182-1 V1.2.1 §5.2.8.3.1
  (unchanged since V1.1.1, and in draft EN 319 182-1 V1.2.4 §5.2.7.3.1)
  requires each `pars` entry to resolve to a locator; a URN does not.
  Evidence, from seals built with the production signer: EU DSS 6.3
  validated URN and relative references alike (signature intact and valid,
  every `sigD` entry found and intact); the ETSI JAdES Conformance Checker
  (profile TS 119 182-1 V1.2.1) aborted its `sigD` check on URN references
  and never ran signature verification, while relative references passed
  every structural check and signature verification — its only remaining
  errors were the expected "cannot get the referenced bytes" for detached
  content it cannot be given. Choices: the envelope reference is a constant
  (`sigill-envelope.json`) because blind signing never sees the envelope, and
  resolution is per artifact (§5.4), so a constant cannot collide; the name
  is not `envelope.json` so it cannot clash with a producer's own object
  name. Object references use a UUID rather than a digest because the same
  bytes may appear under two URIs. The production profile is narrower than
  ETSI (no absolute URLs, no percent-encoding) to keep references opaque,
  free of network locations and byte-exact. The opaque-identifier
  requirement is unchanged. The checker and DSS results are a dated
  observation (13 Oct 2026, the tools' versions of that day), not a blanket
  conformance claim; digest verification against independently supplied
  detached content remains the authoritative check. Rejected: an ASiC-E container for a run's seals (EN 319 162
  defines ASiC for CAdES and XAdES only, and EU DSS has no JAdES ASiC
  support) and several independent seals in one JWS (the ETSI checker does
  not accept that input).
