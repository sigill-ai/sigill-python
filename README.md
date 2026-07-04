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
