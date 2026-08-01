# sigill-sdk (Python)

[![PyPI](https://img.shields.io/pypi/v/sigill-sdk.svg)](https://pypi.org/project/sigill-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/sigill-ai/sigill-python/blob/main/LICENSE)

Tamper-evident **AI evidence envelopes** for Python. Build an `AiEvidenceEnvelopeV1`
record of any AI generation, seal it with an RFC 3161 timestamp via [Sigill](https://sigill.ai),
and verify it offline at any later point.

The cryptographic primitives — RFC 8785 canonical JSON, SHA-256 hash binding, RFC 3161
timestamp parsing — are all handled inside the SDK. You hand it your prompt, response,
and metadata; you get back a signed envelope. Apps don't need to implement
canonicalization, hash binding, or timestamp protocol logic themselves.

For the underlying spec — what's in an envelope, what gets hashed in what order, what
"valid" means — see [`spec/README.md`](https://github.com/sigill-ai/sigill-python/blob/main/spec/README.md).
The same spec ships in this repo's sibling: the [.NET SDK at sigill-dotnet](https://github.com/sigill-ai/sigill-dotnet).
Identical test vectors, byte-compatible output.

## Install

```bash
pip install sigill-sdk
```

Python 3.9+. The only runtime dependencies are `httpx`, `jcs` (the reference RFC 8785
implementation), and `asn1crypto`.

## 30-second example

```python
from sigill_sdk import SigillClient, EnvelopeBuilder

client = SigillClient(api_key="sigill_...")  # from Settings → API Keys at sigill.ai

envelope = (
    EnvelopeBuilder()
    .with_purpose(category="summarization", business_context="support-ticket-summary")
    .with_actor(type="service", id="svc-support-summarizer", tenant_id="tenant-acme")
    .with_activity(name="ticket.summarize", correlation_id="trace-abc-123")
    .with_model(provider="anthropic", name="claude-opus-4-7",
                parameters={"max_tokens": 1024, "temperature": 0.2})
    .with_prompt_inline("Summarize the following support ticket in three bullet points.")
    .with_output_inline("Customer reports login fails after password reset.")
    .build()
)

sealed = client.seal(envelope)
# sealed["integrity"]["envelopeHash"]   ← SHA-256 of canonical JSON
# sealed["proofs"][0]["tsrBase64"]      ← RFC 3161 timestamp from Sigill

# ...persist sealed somewhere durable (DB, S3, your audit log)...

# Later — re-verify cryptographically. Anyone with the sealed envelope can do this:
result = client.verify(sealed)
assert result.is_valid
print("Stamped at:", result.timestamps[0]["gen_time"], "by", result.timestamps[0]["tsa_name"])
```

That's the whole hot path. Everything below is detail you only reach for when you need it.

## Keeping PII out of the envelope

For sensitive prompts and responses, store **hash references** in the envelope instead
of the content itself. The SDK hashes the bytes you supply, records the hash in the
envelope, and the original bytes are yours to keep, redact, or delete.

```python
prompt_bytes = "Classify identity doc. Subject: Jane Doe, born 1985-03-14.".encode()
response_bytes = b'{"document_type":"passport","confidence":0.97}'

envelope = (
    EnvelopeBuilder()
    .with_purpose(category="classification", regulatory_basis=["EU-AI-Act:Annex-III"])
    .with_actor(type="user", id="user-9b2f1a", tenant_id="tenant-acme")
    .with_activity(name="kyc.classify")
    .with_model(provider="anthropic", name="claude-opus-4-7")
    .with_prompt_ref("prompt", content_type="text/plain")
    .with_output_ref("output", content_type="application/json")
    .with_policy_metadata(redactionApplied=True, redactionPolicy="pii-redaction-v3")
    .build()
)

sealed = client.seal(
    envelope,
    external_payloads={"prompt": prompt_bytes, "output": response_bytes},
)
# The envelope now contains SHA-256("prompt bytes") and SHA-256("response bytes")
# under prompt.hash and output.hash. The bytes themselves are NOT stored.
```

When you later need to audit, supply the bytes again — verify confirms they hash to
the same registered values:

```python
result = client.verify(
    sealed,
    external_payloads={"prompt": prompt_bytes, "output": response_bytes},
)
assert result.is_valid
```

If the bytes have been deleted or modified, verification reports exactly which `ref`
is missing or wrong:

```python
result = client.verify(sealed, external_payloads={"prompt": prompt_bytes})
# result.is_valid -> False
# result.issues[0].kind   -> VerificationIssueKind.HASH_MISMATCH
# result.issues[0].target -> "output"
# result.issues[0].message -> "payload_not_supplied: external bytes for ref 'output' …"
```

## CAdES document sealing

For workflows where you need to cryptographically seal a specific file or JSON blob
(not a full AI evidence envelope), the SDK supports **CAdES detached signatures**
(`.p7s`). This is the right choice when you want a compact, verifiable proof that a
particular document was sealed by a named Sigill certificate at a specific moment.

```python
from sigill_sdk import SigillClient

client = SigillClient(api_key="sigill_...")

# Obtain a certificate ID from the Sigill dashboard (Settings → Certificates).
CERT_ID = "5f498b84-65e2-404c-8791-65d70e3f385b"

document = b'{"decision": "approved", "amount": 42000}'

# Seal: only the SHA-256 hash of the document is sent to Sigill — the document
# itself never leaves your system.
p7s: bytes = client.seal_cades(document, certificate_id=CERT_ID, label="decision.json")

# p7s is a standard PKCS#7 / CMS detached signature (.p7s). Store it alongside
# the document — you need both to verify later.

# Verify: again, only the hash is transmitted — the document stays local.
result = client.verify_cades(document, p7s)

assert result.is_valid
print(result.signer)   # CN=Sigill Platform Seal, O=SIGILL AS, …
print(result.trust)    # "trusted_chain"
print(result.gen_time) # "2026-06-25T16:49:04Z"
```

### Post-quantum (hybrid) sealing

Pass `pqc=True` to add a post-quantum **ML-DSA-87** (FIPS 204) signer alongside
the classical one — a single `.p7s` with two independently-verifiable signatures
(RFC 5652 §5.1 + RFC 9882). Content still never leaves your system (only SHA-256
and SHA-512 digests are sent).

```python
p7s = client.seal_cades(document, certificate_id=CERT_ID, label="decision.json", pqc=True)

result = client.verify_cades(document, p7s)
assert result.is_valid                    # classical signer — the legal instrument
if result.post_quantum:
    print(result.post_quantum.algorithm)        # "ml-dsa-87"
    print(result.post_quantum.signature_valid)  # True
    print(result.post_quantum.content_bound)    # "yes"
    print(result.post_quantum.trusted)          # "not_evaluated" (self-signed platform cert)
```

`is_valid` reflects the classical signer only — the post-quantum signer is
additive (quantum-resistant protection, not a qualified/legal upgrade), and is
reported separately via `result.post_quantum`.

`CadesVerifyResult` fields:

| Field | Type | Meaning |
|---|---|---|
| `is_valid` | `bool` | `hash_match and signature_valid and error is None` |
| `hash_match` | `bool` | Document hash matches the value embedded in the `.p7s` |
| `signature_valid` | `bool` | RSA/ECDSA signature over signed attributes is valid |
| `signer` | `str \| None` | Subject DN of the signing certificate |
| `trust` | `str \| None` | `"trusted_chain"`, `"self_signed"`, `"dev_ca"`, … |
| `tsa_name` | `str \| None` | TSA that issued the embedded timestamp |
| `gen_time` | `str \| None` | Timestamp generation time (ISO 8601) |
| `qualified` | `bool` | Whether the embedded timestamp is eIDAS-qualified |
| `error` | `str \| None` | Set when `is_valid` is `False` |
| `warnings` | `list[str]` | Non-fatal issues found during verification |

If you also hold an external `.tsr` file (e.g. from a separate timestamping step),
pass it as `tsr=`:

```python
result = client.verify_cades(document, p7s, tsr=tsr_bytes)
```

## JAdES sealing for JSON

For JSON and JSONL content — API payloads, agent logs, AI evidence — prefer
**JAdES** (ETSI TS 119 182-1), the ETSI signature format for JSON. Same
detached, hash-only model as CAdES: only digests are transmitted, and the
returned `.jades.json` artifact verifies against the exact original bytes
(re-serializing the JSON breaks it by design).

```python
log = open("agent-log.json", "rb").read()

jades = client.seal_jades(log, certificate_id=CERT_ID,
                          label="agent-log.json", content_type="application/json")
# store agent-log.json.jades.json alongside the log

result = client.verify_jades(log, jades)
assert result.is_valid
```

`pqc=True` works here too — the ML-DSA-87 signer is added as a second JWS
`signatures[]` entry (RFC 9964). `JadesVerifyResult` has the same fields as
`CadesVerifyResult`.

To seal an AI evidence envelope with a JAdES organisation seal in addition to
its RFC 3161 proof, sign the canonical bytes:

```python
sealed = client.seal(envelope, external_payloads=payloads)
canonical = canonicalize(sealed)  # from sigill_sdk
jades = client.seal_jades(canonical, certificate_id=CERT_ID,
                          label="envelope.jades.json", content_type="application/json")
```

## PAdES PDF sealing — the PDF never leaves your machine

For PDFs, the SDK produces an embedded **PAdES** signature (ETSI EN 319 142-1)
without uploading the document. It assembles the PDF signature revision locally,
sends Sigill only the ByteRange SHA-256 digest, embeds the returned CMS, and —
when the certificate chain supports it — upgrades the seal to **B-LT/B-LTA** by
writing the Document Security Store and a document timestamp, all locally.

```python
pdf = open("contract.pdf", "rb").read()

result = client.seal_pades(
    pdf,
    certificate_id=CERT_ID,
    label="contract.pdf",
    qualified=False,        # True → eIDAS-qualified timestamps throughout
    reason="Approved",      # optional, lands in the PDF /Reason field
)

open("contract_sealed.pdf", "wb").write(result.sealed_pdf)
print(result.format)          # "pades-b-lta" | "pades-b-lt" | "pades-b-t" | "pades-bes"
print(result.timestamped_by)  # TSA name, or None if no timestamp could be embedded
```

The sealed PDF validates like any server-produced PAdES seal (Adobe, DSS,
`POST /seal/verify`). Verification requires the PDF and stays server-side.

### Unsupported PDFs and the upload fallback

The local parser handles xref-table PDFs, xref-stream PDFs (PDF 1.5+), and
FlateDecode object streams. When it cannot handle a document's structure,
`seal_pades()` raises `PdfUnsupported` **before anything is transmitted** — with
the default settings the privacy guarantee is absolute: nothing but digests ever
leaves your machine.

If your data policy permits it, opt in to the server-side fallback and such
documents are sealed by uploading them to `POST /seal/sign` instead (identical
PAdES output, but the PDF is transmitted to Sigill):

```python
result = client.seal_pades(pdf, certificate_id=CERT_ID, allow_upload_fallback=True)  # default False
```

Post-quantum hybrid sealing is not offered for PAdES — the baseline profile
allows a single `SignerInfo` per signature. For an ML-DSA-87 hybrid seal over a
PDF, use `seal_cades(pdf, certificate_id=CERT_ID, pqc=True)` and keep the
detached `.p7s` alongside the file.

### Crash-safe sealing: the two-phase flow

`seal_pades()` prepares, signs, and embeds in one call. If your pipeline can
die between the server signing (the seal is minted and billed) and your process
persisting the result, use the two-phase flow with the tenant's **Store PAdES
seal data** setting (Settings → Preferences, off by default):

```python
checkpoint = client.prepare_pades(pdf)
save(checkpoint.prepared_pdf)               # your checkpoint — plain bytes

result = client.seal_prepared_pades(checkpoint.prepared_pdf, CERT_ID)
# ... process dies before result.sealed_pdf was persisted? Resume later:

cms = client.get_seal_cms(operation_id)     # re-fetch the escrowed CMS
sealed = SigillClient.complete_pades(load(), cms)  # offline recovery
```

`complete_pades()` needs no network and recovers a **valid sealed PDF at the
level the CMS carries** — B-T when the signature timestamp succeeded, else
B-BES. LTV material (the DSS and the archival DocTimeStamp that `ltv=True`
would have appended) is **not reconstructed** on the resume path: with
`ltv=False` the recovery is byte-identical to the uninterrupted flow; with the
default LTV ladder it recovers the B-T seal, and B-LT/B-LTA can be reached
later by re-sealing. Without the escrow setting, a signing response lost
before embedding cannot be recovered at all.

## Evidence lifecycle: tags, CI gates, and audit packages

Every seal and stamp is an **evidence** in the Sigill evidence store — with a
renewal horizon, verification history, and a custody log. The SDK exposes the
lifecycle surface an automated caller needs:

```python
# Tag at creation — the grouping/filter dimension of the evidence store
# (≤10 per evidence, ≤40 chars). Available on every seal method.
client.seal_cades(artifact, CERT_ID, tags=["release-4.2", "backend"])

# CI gate: does evidence exist, and how close is the renewal horizon?
rec = client.get_evidence_record(artifact)
if rec is None:
    raise SystemExit("artifact was never sealed")
print(rec.cert_not_after)   # the horizon — fail the build when too close

# Public existence check (no API key needed) — consent-gated: None unless the
# evidence owner opted in to public lookups. Third-party release verification.
found = client.lookup(artifact)

# Everything an auditor needs, independently verifiable offline:
# tokens, certificates, verification report, custody log, SHA-256 manifest.
zip_bytes = client.export_audit_package(rec.transaction_id)
```

Expiry-reminder policy can be set per evidence at creation on every seal
method: `reminders="on"` (with `reminder_days=30/60/90/180`), `"off"` (muted),
or the default `"inherit"`.

## Error handling

Producer-time errors raise; verification errors are collected. This split is
deliberate: when sealing, you have a single in-flight operation that either works or
doesn't. When verifying, an audit UI wants every problem at once, not just the first.

| When | Surface | Spec §7 kind |
|---|---|---|
| `seal()` — every TSA Sigill tried failed | `TimestampUnavailable` (with `failures: list`) | `timestamp_unavailable` |
| `seal()` — caller pre-declared a hash that doesn't match supplied bytes | `HashMismatch` | `hash_mismatch` |
| `seal()` — input contains values JCS rejects (NaN, Infinity) | `CanonicalizationFailed` | `canonicalization_failed` |
| `verify()` — anything wrong | `result.issues[]`, `result.is_valid == False` | per-issue `kind` field |

A typical seal-with-fallback:

```python
from sigill_sdk import SigillClient, TimestampUnavailable

try:
    sealed = client.seal(envelope, external_payloads=payloads)
    persist(sealed)
except TimestampUnavailable as e:
    # All TSAs in our rotation failed. Persist the envelope unsealed and seal it later.
    log.warning("TSA outage: %d attempts, failures=%r", e.attempts, e.failures)
    persist_for_async_sealing(envelope, payloads)
```

## Cross-language interop

This SDK and the [.NET SDK at sigill-dotnet](https://github.com/sigill-ai/sigill-dotnet)
share the same spec, JSON Schema, and test vectors. An envelope sealed by either
SDK verifies with either SDK — the canonical bytes are byte-identical.

The interop guarantee is enforced by tests: both test suites read the same files
under [`spec/test-vectors/`](https://github.com/sigill-ai/sigill-python/blob/main/spec/test-vectors/)
and assert that their canonical output matches the committed reference bytes. The `spec/` directory
in this repo is a vendored copy; the canonical source lives under `spec/` in
[sigill-dotnet](https://github.com/sigill-ai/sigill-dotnet) too, and the bytes are
byte-identical between the two.

## Pinning a specific TSA

By default, `seal()` uses Sigill's `auto` mode — round-robin across the TSAs you have
enabled, with automatic failover. That's the recommended setting for production: you
get redundancy at no cost.

If you need to record that a *specific* TSA produced the timestamp (compliance reason,
specific policy OID), pass it explicitly:

```python
sealed = client.seal(envelope, tsa_slug="digicert")           # SHA-256, US TSA
sealed = client.seal(envelope, tsa_slug="sectigo")            # SHA-512
sealed = client.seal(envelope, tsa_slug="skid-ecc",           # eIDAS Qualified
                     qualified=True)
```

Available slugs and their properties: see [Sigill's TSA documentation](https://sigill.ai/docs).

## Async / context manager

`SigillClient` is a sync client built on `httpx.Client`. Wrap it in `with` to ensure
the underlying HTTP connection pool is closed when you're done:

```python
with SigillClient(api_key="...") as client:
    sealed = client.seal(envelope)
```

If you need an async API, open an issue — it's a thin wrapper away.

## Lower-level surface

The SDK exposes its primitives in case you need them outside the `seal/verify` flow:

```python
from sigill_sdk import canonicalize, compute_envelope_hash

canonical_bytes = canonicalize({"b": 2, "a": 1})  # → b'{"a":1,"b":2}'
digest_hex, canonical_bytes = compute_envelope_hash(envelope)
```

This is what every test vector is built from, and it's what the cross-language interop
guarantee comes down to.

## What this SDK is not

It is not a substitute for **TSA chain validation**. The SDK confirms the TSR's
embedded message-imprint matches your envelope, but it does not — by design in v1 —
validate the TSA's certificate chain back to a trust anchor. Sigill's
`POST /tsa/verify` endpoint does that server-side; for offline trust-anchor
validation, use a dedicated library like
[`sigstore-python`](https://github.com/sigstore/sigstore-python) or shell out to
`openssl ts -verify`. v2 of this SDK will provide a pluggable trust policy.

## Development

```bash
git clone https://github.com/sigill-ai/sigill-python.git
cd sigill-python
pip install -e ".[dev]"
pytest
```

The 39-test suite runs offline in <1s. CI runs against Python 3.9 through 3.13.

## License

Apache 2.0 — see [`LICENSE`](https://github.com/sigill-ai/sigill-python/blob/main/LICENSE).
