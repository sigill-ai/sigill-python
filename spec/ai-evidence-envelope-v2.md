# AiEvidenceEnvelopeV2 — Specification

**Status: AGREED, 12 Aug 2026** (founder review Raymond + Hallvard —
sigill-dotnet#4 / platform#37). Supersedes
[`AiEvidenceEnvelopeV1`](./README.md) for *producing* evidence;
v1 envelopes remain verifiable indefinitely and nothing re-signs old evidence.
Standing review condition: **the opaque-URN requirement on remote paths
(§3.1) is load-bearing for hashing anonymity and stays normative** — it MUST
NOT be relaxed to guidance in future revisions.

This is the format contract only. The platform API is specified separately in
the platform repo (`docs/ai-evidence-jades-profile.md`, PR #37) and will not
be built until this document is agreed. That contract is **blind in both
directions** (platform [D8], 12 Aug): the producer sends digests and opaque
URIs and receives the JWS; the **artifact is always assembled client-side**;
platform verification takes the JWS plus a digest map and returns
cryptographic verdicts. Sigill never receives the envelope — everything
envelope-shaped in this document (schema validation, canonicalization, role
coverage) is the SDK's job.

**Scope disambiguation** — "envelope" means three things in the Sigill family
today. This document versions exactly one of them: the **AI evidence
envelope** (`AiEvidenceEnvelope`) produced by the SDKs and the browser
extension. `EvidenceEnvelopeV3` in sigill-evidence is a **separate version
track that persists**; it is expected to become another *consumer* of the same
JAdES multi-object signing layer (its own content type, its own schema), not
an instance of this schema.

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

The envelope family (this schema, and future profiles such as the
sigill-evidence envelope) shares a **core vocabulary** that generic viewers
and verifiers can render without profile-specific code:

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
  within a profile** — sibling profiles are not extensions: sigill-evidence
  is its own profile with its own cty and its own schema, carrying its
  trust-model-specific data (the registry-anchored identity graph) as
  profile fields. Trust levels are never mixed into this profile's
  customer-asserted core.

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
| Sequencing | `chain` (reserved) | Cryptographic chaining for multi-step agent runs (§5.4). |
| Extension | `extensions` | Named extension point (§2). |

Required: `schemaName`, `schemaVersion`, `evidenceId`, `createdAt`, `purpose`,
`actor`, `activity`, `model`, `objects`.

### 3.1 `objects[]` — the payload descriptions

v1's `prompt` / `inputs` / `retrievedContext` / `output` / `outputArtifacts`
collapse into one descriptive list:

```jsonc
"objects": [
  { "uri": "urn:acme:run-42:prompt", "role": "prompt", "contentType": "text/plain",
    "encoding": "utf-8", "sizeBytes": 214 },
  { "uri": "urn:acme:run-42:ctx-0",  "role": "context", "contentType": "text/markdown",
    "encoding": "utf-8", "metadata": { "rank": 0, "score": 0.93, "source": "kb://article/118" } },
  { "uri": "urn:acme:run-42:output", "role": "output", "contentType": "text/markdown",
    "encoding": "utf-8" },
  { "uri": "report.xlsx",            "role": "artifact", "contentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "encoding": "binary" }
]
```

Rules (normative):

- **Roles**: `prompt | input | context | output | artifact | log`. The
  envelope says what each object *is*; the signature says what it *hashes to*.
- **URIs are caller-chosen, opaque identifiers**. Sigill never dereferences
  them. (TS 119 182-1 §5.2.8.3.1 frames `pars` entries as resolvable
  URI-references; this profile deliberately uses them as pure identifiers —
  digests are always computed from caller-supplied bytes, never fetched. The
  EU DSS reference validator accepts this; it matches detached objects to
  `pars` entries by name.)
- **On any remote path, opacity is a privacy requirement, not a style
  choice**: URIs sent to the platform (blind signing, blind verification)
  MUST carry no personal data and no content-derived names — hashing
  anonymity is defeated by a `pars` entry like
  `contract-olsen-vs-hansen.pdf`. SDKs generate `urn:uuid:`-based
  identifiers by default; human-meaningful names (filenames, paths) belong
  in the object's `metadata`, which stays inside the envelope and never
  leaves the producer. (A stored-seal opt-in on the platform retains the
  JWS, which embeds the signed URIs — opaque URNs are what keep that
  retention clean.)
- **URIs MUST be unique** across `objects[]`, compared **byte-exactly** as
  strings (no normalization, no case folding). Producers MUST reject
  duplicates; verifiers MUST fail on them. The same content MAY appear under
  two URIs (e.g. the same bytes as both `input` and `context`) — identity is
  the URI, not the digest.
- `urn:sigill:envelope` is **reserved** for the envelope itself (§4) and MUST
  NOT appear in `objects[]`.
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
- **`chain`** (§5.4) is a *cryptographic* sequence — each step commits to the
  previous step's signature bytes. Tampering with any step breaks every
  subsequent link.

A multi-step record MAY use both; a verifier MUST NOT treat
`parentEvidenceId` as integrity evidence.

### 3.4 `chain` — reserved

```json
"chain": { "seq": 3, "prevSignatureSha256": "hex…" }
```

The mechanism is defined (zero-based `seq`; lowercase SHA-256 hex over the
previous step's signature; `prevSignatureSha256` absent at `seq: 0`), the
semantics are **deliberately open in v2.0**: what constitutes a "step"
(turn / tool call / run), and the exact preimage of `prevSignatureSha256`
(RECOMMENDED: the base64url-decoded JWS Signature Value of the previous
artifact's classical signature), are fixed only when a real agent case
exists. Producers other than experiments SHOULD omit `chain` until then.

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
pars[0]  = "urn:sigill:envelope"          hashV[0] = b64url(digest(JCS(envelope)))
pars[1…] = objects[0…].uri, in order      hashV[1…] = b64url(digest(payload bytes))
ctys[0]  = "application/vnd.sigill.ai-evidence+json"
ctys[1…] = objects[0…].contentType, or "" when absent
```

Alignment rules (normative — these resolve the "1:1 by uri" ambiguity):

1. `pars`, `hashV` and `ctys` have equal length and are index-aligned
   (§5.2.8.1).
2. `pars[0]` is exactly `urn:sigill:envelope`; `ctys[0]` is exactly the
   AI-evidence content type. `ctys[0]` is the **profile discriminator** —
   TS 119 182-1 §5.1.3 keeps the `cty` header parameter out of
   sigD-bearing signatures, so the type of object 0 is where a consumer
   learns "this is AI evidence".
3. `pars[i]` for `i ≥ 1` equals `envelope.objects[i-1].uri` — same order,
   byte-exact string equality. No entry may be added, dropped, or reordered
   on either side; duplicate `pars` entries are invalid.
4. `ctys[i]` for `i ≥ 1` equals `envelope.objects[i-1].contentType`
   byte-exactly, or the empty string when the envelope omits `contentType`
   (§5.2.8.1: empty string when the type is implied).
5. When the PQC signer is present, its `sigD` carries the **same `pars` and
   `ctys`** and SHA-512 digests of the **same bytes** in `hashV`. One evidence
   record, two independent cryptographic commitments to it.

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
digests), reported as `pqc: verified | failed | absent`.

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
  `signature` member plus a digest per referenced `pars` URI — the
  envelope's own digest is simply the entry for `urn:sigill:envelope`,
  computed client-side with JCS. No special case: the envelope is just
  object 0. Sigill sees certificates, signed hashes and opaque URNs; never
  the envelope, never content. The response is the cryptographic verdict
  set above (per-object, `missing`/`unreferenced`, `complete`, the
  multiple-signature policy applied server-side).
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
| `alignment_invalid` | `pars`/`hashV`/`ctys` lengths differ, `pars[1…]` does not match `objects[]` by the rules of §5.2, or `pars` contains duplicates. |
| `object_hash_mismatch` | A supplied payload's digest does not match its signed `hashV` entry. Reported per object. |
| `invalid_signature` | JWS signature verification failed for every sigD-bearing classical entry. |
| `invalid_timestamp` | A `sigTst` token fails to parse, its message imprint does not match, or its TSA signature is invalid. |

Verification produces a structured result rather than raising on the first
issue, so consumers can render a complete report.

## 8. What Sigill receives and persists

**Blind by architecture** (platform [D8]): Sigill's nature is to not accept
and store GDPR data, and the contract enforces it structurally. On produce,
Sigill receives digests, opaque URIs, MIME types and the caller-chosen
label/tags — never the envelope, never content; there is no parameter to send
either. On verify, Sigill receives the JWS and a digest map. What it
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

## 11. Test vectors

`test-vectors/` gains v2 scenarios **when the platform endpoint exists**
(signatures depend on platform-issued certificates and are not byte-stable).
Two vector classes are planned:

1. **Canonicalization vectors** (byte-stable, cross-language): envelope input
   → exact canonical bytes → SHA-256/SHA-512 hex. These gate the .NET/Python
   interop exactly like v1's `canonical.json` files.
2. **Verification vectors** (fixed test certificate): full artifacts with
   known-good and known-broken objects, exercising every §7.1 error and the
   multiple-signature policy.

## 12. Open points for this review

Settled by prior review (platform PR #37) and treated as fixed here: the
self-contained `{envelope, signature}` artifact [D1], JCS canonicalization
[D2], and the **blind platform contract in both directions** [D8] (12 Aug:
digests + opaque URIs in / JWS out, artifact assembled client-side, blind
verification, name-free persistence — design principle: Sigill does not
accept and store GDPR data). D8 also absorbs the content-type-driven-endpoint
ask [D7]: a blind endpoint is content-type-agnostic by construction, and
`EvidenceEnvelopeV3` signs through the identical mechanism with its own cty.
Still open — veto or bless per point:

- **[O1] `encoding` enum**: reduced to `utf-8 | binary` (base64 fell with
  inline). Sufficient, or does any producer hash base64-normalized content?
- **[O2] `extensions` shape**: named extension blocks, object-valued, keyed
  by profile id / reverse-DNS (§2). Does this match the family-core intent
  for sigill-evidence carrying its identity graph?
- **[O3] Metadata-only records**: `objects: []` is legal (envelope-only
  seal). Keep, or require ≥ 1 payload?
- **[O4] Actor-id hashing default** (= platform D4): opt-in helper
  (recommended) vs default-on.
- **[O5] `chain` reservation** (= platform D5): reserved with the
  recommended-preimage note in §3.4, semantics open. OK to ship reserved, or
  omit entirely until the agent case exists?
