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

### Object references (AiEvidenceEnvelopeV2 v2.1)

ETSI TS 119 182-1 §5.2.8.3.1 requires each `sigD.pars` entry to resolve to a
*locator*, so object URIs are relative references: when you omit `uri`, the
SDK generates `objects/<uuid>`, and a `uri` you set must match the
[production profile](spec/ai-evidence-envelope-v2.md#31-objects--the-payload-descriptions)
(segments of `A–Z a–z 0–9 . _ ~ -` separated by `/`; no `urn:`, no URLs, no
filenames with personal data). `sigill-envelope.json` and `urn:sigill:envelope`
are reserved for the envelope.

Verification reads both envelope references — `sigill-envelope.json` and the
`urn:sigill:envelope` of seals made before v2.1 — from each signature itself,
so old evidence and runs that straddle an upgrade keep verifying. The legacy
form is reported in `result.notes` (informational, never a failure):

```python
from sigill_sdk import EnvelopeReferenceForm, classify_envelope_reference

if classify_envelope_reference(signed_pars0) is EnvelopeReferenceForm.LEGACY_URN:
    print(result.notes)
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
    qualified=False,             # True → eIDAS-qualified timestamps throughout
    signer_name="ACME Corp AS",  # recommended: your seal cert's subject CN —
                                 # lands in /Name, what Acrobat shows before
                                 # validation runs (otherwise "Unknown")
    reason="Approved",           # optional, lands in the PDF /Reason field
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

## Agent runs: verifiable multi-step execution

For agents that call tools, retrieve context and act over several steps, a
single envelope is not enough: you need to show which controls applied before
the run, which security-relevant events were captured and in what order, and
that nothing captured was changed or removed afterwards. Three sibling
profiles of the v2 envelope ([common rules](spec/agent-profiles-common-v1.md))
cover one controlled run:

| Phase | Profile | What it seals |
|---|---|---|
| Before | [Control Artifact](spec/agent-control-artifact-v1.md) | configuration, control set, baseline, timestamp policy |
| During | [Execution Evidence](spec/agent-execution-evidence-v1.md) | one artifact per event, chained by signature |
| During | [Model Calls](spec/agent-model-calls-v1.md) (execution `schemaVersion "3"`) | per model call: the model that served it and the provider's own ids for the call, so the provider can confirm it against its logs; prompts and responses as digests only |
| During | [Enforcement (draft)](spec/agent-enforcement-v1.md) (execution `schemaVersion "4"`) | the guard's denials and halts before the action, recomputable from the [policy control set v2](spec/agent-policy-control-set-v2.md) |
| After | [Control Evaluation](spec/control-evaluation-v1.md), [v2 (draft)](spec/control-evaluation-v2.md) | what an independent verifier observed, and each control's result; v2 adds policy evaluations (reproducible from the run's facts) and the producer's own attested results |

To record model calls, start the run with `records_model_calls=True` and give any
provider client built on httpx a `ModelCallTransport` (Anthropic, OpenAI, Azure
OpenAI, Amazon Bedrock, Gemini API, Vertex AI; `AsyncModelCallTransport` for async
clients). Values come from the provider's response; for any other provider call
`record_model_call`.

```python
http = httpx.Client(transport=ModelCallTransport(run))
```

```python
from sigill_sdk import (AgentAuthorization, AgentConfiguration, AgentControlSet, AgentDefinition,
                        AgentRunBundle, AgentRunObject, ControlEvaluationRequest, ControlResult)

agent = AgentDefinition(
    agent_id="urn:example:agent:support-triage",   # opaque — no personal data
    agent_version="2.4.0",
    configuration=AgentConfiguration(
        instruction_set=system_prompt_bytes,
        tool_manifest=tool_schemas_json,
        execution_policy=allowlist_and_limits_json,
        model_config=model_and_sampling_json,
    ),
)

# Seals the Control Artifact (timestamped), then run_start, which binds it.
run = client.start_agent_run(
    agent,
    certificate_id=cert_id,
    activity="support-ticket-close",
    control_set=AgentControlSet("ticket-close-v2", "2", control_set_json),
    baseline_state=ticket_before_json,      # what "unchanged" controls are checked against
)

run.record_tool_call("lookup_ticket", args_json, operation="read", use_id="call-1")
run.record_tool_result("lookup_ticket", result_json, use_id="call-1")

# A write that needs a human: the policy decision, the approval, then the call.
run.record_authorization(AgentAuthorization("allow_with_human_approval", policy_id="support-tools-v1"))
run.record_human_approval(
    "approved",
    receipt=approval_receipt_json,          # bound by digest; bytes stay with you
    identity_assertion=approver_id_token,   # e.g. the IdP token of the approver
    approver="urn:example:approver:42")     # opaque — never a name or e-mail
run.record_tool_call("close_ticket", args_json, operation="write", consequential=True)

run.record_model_output(answer_bytes)
bundle = run.finish("completed")            # run_end, timestamped
```

An independent verifier then reads the target's state and seals its
evaluation, with its own certificate:

```python
evaluation = verifier_client.seal_control_evaluation(ControlEvaluationRequest(
    certificate_id=verifier_cert_id,
    verifier_id="urn:example:verifier:ticket-state", verifier_version="1.3.0",
    control_artifact=run.control_artifact, run_end=bundle.artifacts[-1],
    observed_state=[AgentRunObject.json("observed-state", ticket_after)],
    controls=[ControlResult("ticket-closed", "PASS"), ControlResult("owner-unchanged", "PASS")],
    overall="PASS",
))
open("run.json", "w").write(bundle.with_evaluations(evaluation).to_json())
```

Later, anyone holding the bundle can verify it:

```python
result = client.verify_agent_run(AgentRunBundle.parse(open("run.json").read()))
# result.verdict     -> "run_finalized" | "run_open" | "run_invalid"
# result.checks      -> correlation, sequence, chain, envelope, signatures,
#                       timestamps, objects, finalization, control: ok | warn | bad
# result.binding     -> "bound" | "run_only" | "control_only" | "unbound"
# result.findings    -> exactly what failed, e.g. "Sequence gap: no artifact for seq 2 (deleted or withheld)."
# result.evaluations -> per evaluation: valid (read this one), the parts it is made of — subject_bound,
#                       control_set_digest_matches, baseline_digest_matches, signature_valid, timestamp_valid,
#                       objects_complete — and overall exactly as the verifier claimed it
print(result.scope)  # what a verdict does — and does not — establish
```

What to know:

- **Content never leaves your machine.** Sealing and verification send digests
  and opaque URNs only. A bundle carries digests by default; pass
  `retain_payloads=True` (or use `bundle.with_payloads(...)`) only when the
  recipient may read the content — supplying payloads upgrades the `objects`
  check from "digests match" to "content matches".
- **Seal every event, timestamp to wrap up.** Every event is signed and
  chained; by default RFC 3161 timestamps go only on the Control Artifact,
  `run_end` and each Control Evaluation — three for a whole run. The policy is
  signed into the Control Artifact, so the verifier knows which events had to
  carry one. Opt into more with `AgentTimestampPolicy(consequential=True)`
  (every consequential event), `every_events` / `every_seconds` (a cadence),
  `PER_EVENT`, `require_timestamp=True` on one event, or `run.checkpoint()`
  from a timer while a long run is idle.
- **One certificate per run.** The Control Artifact and every event must be
  sealed with the same certificate; the verifier fails a run that mixes
  signers, so events forged by anyone else cannot be appended. Pin your
  certificates' thumbprints with
  `client.verify_agent_run(bundle, expected_signers=[thumbprint])`
  (`result.signer` shows the run's), and the verifier's with
  `expected_evaluation_signers`.
- **Keep the Control Artifact with the run.** `run_start` binds it, so a
  bundle without it fails the `control` check: leaving it out must not hide a
  stricter policy or a broken control basis.
- **What the default does not prove.** Events without a timestamp could be
  rewritten by anyone able to seal with the run's certificate until `run_end`
  is timestamped; `result.scope` says so. Timestamp consequential events to
  narrow that window.
- **Timestamps count only from a trusted TSA.** The signature service reports
  each timestamp's TSA trust; until it reports `trusted_chain` or `qualified`,
  the result carries a "TSA trust not established" warning.
- **Evaluations never change the run verdict.** They are reported on their
  own: `overall` is the named verifier's claim (given a policy engine, the
  verifier recomputes a policy evaluation's results — see "Policy engine"). Read it only when `valid` is true — the evaluation is then
  signed over its own envelope, timestamped, intact, and bound to this run's
  `run_end`, Control Artifact and pre-sealed control set.
- **Persist as you go.** `on_artifact_sealed` runs after each artifact is
  sealed, in order. A sealing failure stops the chain; the partial bundle
  (`run.to_bundle()`) verifies as open or invalid, never as finalized.
- **Bring your own verifier.** `verify_agent_run(bundle, verifier)` accepts any
  callable `(signature, digests) -> BlindObjectsVerdict`; `remote_verifier(client)`
  is the blind endpoint used above.

### Showing a run in Sigill

Sealing sends Sigill digests only, so a run is not shown in your organisation's Sigill
unless you also deliver it. `deliver_run=True` uploads each artifact to the organisation's
evidence index as it is sealed, in chain order:

```python
run = client.start_agent_run(agent, certificate_id=cert_id, activity="refund",
                             control_set=controls, deliver_run=True)
...
bundle = run.finish("completed")
print(run.delivery)   # AgentRunDelivery(status="delivered", delivered=…, pending=0, run_id=…, error=None)
```

- **What leaves the machine:** each artifact's signed envelope, signature and object
  digests. That is the agent id and version, its tenant id and identity reference, the
  activity name and run id, the control set's id and version, step types and times, tool
  names, operations and use ids, authorization decisions and policy ids, rule ids and guard
  reasons, approver references, sub-agent ids, model names, deployments and regions, provider
  request ids, token counts and stop reasons, object URIs, content types and sizes, any
  `detail` text, and the signing certificate inside each signature. The names, identifiers
  and texts among them are your own values, uploaded as written. Never arguments, results,
  prompts, outputs or receipts; the policy document only with `disclose_policy=True` (then it
  travels on the Control Artifact's upload, and `run.policy_disclosure` is that upload's
  result).
- **It never stops the run.** Each upload runs after `on_artifact_sealed` in the same
  ordered turn. A failure never raises, never breaks or halts the run, and is not a sealing
  failure ([common rules §6.1](spec/agent-profiles-common-v1.md)). Only an answer that
  accepts the artifact counts: 200 or 201 with status `indexed` or `exists`; redirects are
  never followed, even with an `http_client` of yours that follows them. A temporary failure (408, 429, 5xx, no answer in time) holds the uploads as
  `pending` and they are tried again at a later step after a back-off (5 s, doubling to
  5 min). Any other answer is `rejected`: nothing more is sent, and the index keeps a true
  prefix of the run. In an enforced run the guard's `PolicyDenied` / `RunHalted` is raised
  after the upload, as it is after the callbacks.
- **The worst case, plainly:** each turn's uploads share 10 s (at most 10 s per upload), and
  `run_end` makes one last attempt within 30 s. So with the index unreachable a step can take
  up to 10 s longer and the run's end up to 30 s; a guard refusal still blocks the call at
  once, but its exception is raised after that wait. What does not fit stays `pending` for a
  later turn. Bounded are each wait for the index (connecting, sending, every read) and the
  response body as a whole (by the deadline plus at most one read wait); not bounded as a
  whole are the response headers, so an index that
  keeps sending header bytes with short pauses can make an upload take longer.
- **`run.delivery`** is `None` when delivery was not requested, else an `AgentRunDelivery`:
  `status` (`delivered`, `pending` or `rejected`), how many artifacts are `delivered` and
  `pending`, the index's `run_id` and the last `error` (which artifact, then the status code
  and the index's code, or the kind of failure — never the index's message text).
- **Catch up later:** `client.deliver_agent_run(bundle)` uploads a bundle — the Control
  Artifact, then the events by seq; evaluations are not uploaded, and neither is the policy
  document. Re-delivering is safe, a partial bundle is fine, and it stops at the first
  failure and says where.
- **Free text is bounded,** with or without `deliver_run`: a step's `detail` at most 512
  characters; the activity name, an approver reference, a decision and an object's content
  type at most 255; an object's `metadata` and the envelope's `extensions` at most 2,048
  bytes of JSON (neither can be set through this SDK; the bound is there for envelopes built
  by other means). A longer value is refused with `ValueError` before anything is sealed —
  never shortened. (New in 0.15.0: 0.14 accepted longer values.) No other value is
  length-bounded.
- `deliver_run` needs a `SigillClient`; any other client is refused before anything is
  sealed.

### Tool calls and bound approvals (Execution Evidence v4, draft)

A run whose control set is a [policy control set v2](spec/agent-policy-control-set-v2.md)
(`"schemaVersion": "2"`, loaded with `AgentPolicy.control_set_from_document`) is
sealed as execution `schemaVersion "4"` ([Agent Enforcement v1](spec/agent-enforcement-v1.md)).
Every tool call then carries a use id, unique in the run, and its result names it.
Only the guard ([Enforcement](#enforcement-deny-a-call-halt-a-run)) writes enforcement records:
`record` refuses `enforcer` and `rules` on an event.

`begin_tool_call` seals the call and returns a `ToolCall` that seals the matching
result. The use id is generated unless you pass one; `definition` seals the digest
of the tool's definition as your runtime holds it.

```python
call = run.begin_tool_call("crm.update_address", args_json, consequential=True,
                           definition=manifest_entry_json)
result = update_address(args_json)   # an exception here seals no result
call.complete(result)
```

An approval can name the call it is for: a tool and the digest of its exact
arguments, optionally one use id, optionally an expiry. Only digests are sealed.
In the facts (`AgentPolicy.build_facts_v2`) an approval binds at most one call; a
rejection is sticky for the run.

```python
from sigill_sdk import ApprovalCovers

run.record_human_approval("approved", approver="urn:example:approver:7f3a",
                          covers=ApprovalCovers.for_arguments("payments.refund", args_json,
                                                              expires_at=deadline))
run.begin_tool_call("payments.refund", args_json, consequential=True).complete(result)
# or, for a call already sealed: covers=call.covers()
```

`verify_agent_run` adds the `enforcement` check for a v4 run (and fails an older run
whose supplied policy control set is not a strict v1 document): its findings, such as a result
without a call or a tool executed after a denial, are in `result.enforcement_findings`.

### Policy engine

The SDK bundles the official [Cedar](https://github.com/cedar-policy/cedar) core
(`cedar-policy` 4.14.0) as one WebAssembly module, `sigill_sdk/_policy/sigill_cedar.wasm`
(sha256 `a0cd395067e77a157116f6b25bcdb612d34c61d1a4446918d75da1a07c80d1f3`), and runs it
in-process with [Wasmtime](https://wasmtime.dev). Install the host with the `policy` extra:

```bash
pip install "sigill-sdk[policy]"
```

`CedarEngine` checks the module's sha256 and version before it runs it, gives it no
filesystem, network, clock, environment or stdio and at most 256 MiB of memory, and can
be shared between threads. Any object with `version`, `authorize(call)` and
`validate(call)` (the `PolicyEngine` protocol) can stand in for it. The licences and notices
of Cedar and the other Rust crates compiled into the module are in
[`THIRD-PARTY-NOTICES.md`](https://github.com/sigill-ai/sigill-python/blob/main/THIRD-PARTY-NOTICES.md),
which the wheel and sdist also carry.

```python
from sigill_sdk import AgentPolicy, CedarEngine, verify_agent_run

engine = CedarEngine()
problems = AgentPolicy.validate_strict(document, engine)   # + Cedar strict mode, schema and entities
facts = AgentPolicy.build_facts(agent_id, correlation_id, [a.envelope for a in bundle.artifacts])
evaluation = AgentPolicy.evaluate(document, facts, engine)  # per rule PASS / FAIL / INDETERMINATE
# evaluation.rules feed PolicyEvaluationRequest.rules; evaluation.engine its engine

result = verify_agent_run(bundle, verifier, engine=engine)
# result.evaluations[i].results_recomputed: a policy evaluation's results, recomputed and equal
```

With an engine, the verifier recomputes the results of a policy evaluation (of a v1 or a v2
control set) from its sealed facts; results that differ make that evaluation invalid, naming the first
rule that differs, and so does a request the engine refuses. An evaluation made with another
Cedar version, an engine failure, or a verification past its recomputation budget
(a fixed number of control-set bytes × facts requests) is not recomputed (a note says so). Without an engine nothing changes: the results are the evaluator's.

### Enforcement: deny a call, halt a run

A v2 policy control set with `"enforcement": {"mode": "enforce", ...}` makes the SDK's
guard stop the agent before the action ([Control Set v2](spec/agent-policy-control-set-v2.md) §6–§8,
[Agent Enforcement v1](spec/agent-enforcement-v1.md)). Such a run needs a policy engine;
starting it without one is a `ValueError`, and the control set is validated strictly
before anything is sealed.

```python
from sigill_sdk import CedarEngine, Enforcement, PolicyDenied, RunHalted

run = client.start_agent_run(agent, certificate_id=cert_id, activity="refund",
                             control_set=AgentPolicy.control_set_from_document(document),
                             enforcement=Enforcement(CedarEngine(), on_event=print))
try:
    result = run.invoke_tool("payments.refund", args_json, lambda: refund(args_json),
                             consequential=True)    # refund() runs only if the call is allowed
except PolicyDenied as denied:
    print(denied.reason, denied.rules, denied.use_id, denied.halted)
except RunHalted:
    pass                                            # the run is over; stop the agent
bundle = run.finish()                               # a halted run: its bundle, nothing more sealed
```

The guard evaluates every event after it is sealed. What the caller sees:

- **A denied call.** The `tool_call` is sealed (the attempt), then one enforcement record
  (`authorization` with `enforcer`) directly after it, then `begin_tool_call`,
  `record_tool_call` or `invoke_tool` raises `PolicyDenied` (`reason`, `rules`, `tool`,
  `use_id`, `seq`, `record`, `halted`). No `ToolCall` is returned, and a result for that
  use id is refused. A retry is a new call with a new use id.
- **A halt.** A matching `halt` rule, `haltAfterDenials`, or an engine that fails (reason
  `unavailable`) seals the record and then `run_end` with `runDisposition: "halted"`. The
  recording call raises `RunHalted` (or `PolicyDenied` with `halted`), `run.halted` is true,
  every later recording call raises `RunHalted` repeating the halt's `reason`, `rules`, `seq`
  and `record`, and a child of the halted run is not started.
  The model-call transport raises it too, and sends no further model calls. In an enforced
  run it also raises a failure to record a model call (after `on_error`) and sends nothing for
  a broken or finished run.
- **A refused start.** A `lockedConfiguration` digest that differs from the Control
  Artifact's, an engine that cannot load or cannot validate the control set, or a `halt` rule
  on `run_start`: `start_agent_run` raises `StartRefused`, whose
  `run` is the closed run (Control Artifact, `run_start`, record, halted `run_end`).
- **`on_event`** receives an `EnforcementEvent` (`denied`, `halted`, `start_refused`, or
  `observed` for rules that matched without effect, such as an `observe` rule; `tool` and
  `use_id` are set on a `tool_call` or `tool_result`) after the evidence is sealed, in seal
  order, before the exception reaches the caller. Any engine answer that is not a
  well-formed `isAuthorized` answer counts as an engine failure.
- Messages and attributes name the tool, the use id, rule ids, the reason and seqs; never
  arguments, results or definitions.

The decision, its record and the halt are sealed under the run's lock, with no other event
in between, also when several threads record on one run. The run's state is checked once more after the
call's callbacks have run and, in `invoke_tool`, immediately before the function is called; a
halt sealed by another thread after that check does not stop the function. A sealing failure breaks the run as
before, and the tool does not run. In enforce mode the event budget keeps room for one
enforcement record and the halting `run_end`. With `mode: "observe"`, a v1 control set or
another control set, nothing is denied or sealed; an engine passed anyway reports matching
rules as `observed`, and if it cannot load or validate at the start, `start_agent_run` raises
its `PolicyEngineError` before anything is sealed.

Examples (scripted agents, no model calls) in [`examples/`](examples/), with their
[control set](examples/control-set.json); each reads `SIGILL_API_KEY`,
`SIGILL_CERTIFICATE_ID`, `SIGILL_BASE_URL` (default: the SDK's default endpoint) and
`SIGILL_CA_BUNDLE` (for a private CA), and prints its run and verification:

- `loop_until_halted.py`: an agent retries a forbidden call until the run is halted;
- `graph_agent.py`: two branches record concurrently on one run, one is denied, the other
  finishes, plus a delegated child run;
- `approval_flow.py`: a refund is denied, approved with `covers`, retried and allowed.

What enforcement does and does not show:

- Enforcement is done by the producer's own SDK, in the producer's process.
- A stop means the SDK refused the call; it does not mean the tool could not be reached
  another way.
- That a denied tool did not run is not proven by the evidence; the evidence shows the
  denial and that no result was recorded.
- Anyone with the control set and the signed events can recompute every decision, except a
  record with reason `unavailable`: whether the engine in fact failed cannot be recomputed.
- An engine that does not answer holds the run: there is no timeout on a decision.
- Model calls the SDK cannot recognise or parse are not recorded, so no rule sees them.
- A tool that is already executing when another event halts the run is not stopped by the SDK;
  its result is not sealed.
- A child run is refused after its parent halted only when it is started from the delegation
  object the parent returned in the same process.

### Evaluating enforcement: did the guard do what the control set required?

A verifier checks that the guard's records hang together; it cannot tell whether a due denial
or halt was skipped. The enforcement comparison of a
[ControlEvaluation v3](spec/control-evaluation-v3.md) can: from the Control Artifact, the signed
events with their signed object digests and the control-set bytes — no payloads, so what an
evidence index holds is enough — it recomputes, for every event, what was **due**, and compares
it with what the chain **records**.

```python
member = AgentPolicy.compare_enforcement(bundle.control_artifact, bundle.artifacts, document, engine)
# {"comparison": "performed", "recordedEngine": "cedar-policy@4.14.0", "result": "let_through",
#  "decisions": [{"seq": 1, "due": "refused", "dueReason": "rule", "dueRules": ["no-web-search"],
#                 "recorded": "none", "outcome": "let_through", "findings": ["refusal_missing"]}]}

facts = AgentPolicy.build_facts_v2(agent_id, correlation_id, bundle.artifacts, document)
results = AgentPolicy.evaluate(document, facts, engine)
prepared = ControlEvaluation.prepare_policy(PolicyEvaluationRequest(
    ..., rules=results.rules, engine=results.engine, enforcement=member))   # schemaVersion "3"
```

`verify_agent_run(bundle, verifier, engine=engine)` checks a v3 evaluation's comparison; its
core-free rules are checked without an engine too. Read `evaluation.enforcement_result`, not
only `evaluation.valid`: a valid evaluation whose `enforcement_comparison` is `not_performed`
compared nothing, and that is not a pass. `enforcement_recomputed` is true only for a
`performed` comparison that the verifier reproduced with the core the evaluation names.
A v1 control set is evaluated as a ControlEvaluation v2, as before. Rule results and `overall`
keep their meaning: a forbidden call that the guard refused is still `FAIL`; the comparison
says it was refused.

| Outcome of an event | Meaning | Findings |
|---|---|---|
| `as_required` | the chain records what was due | — |
| `let_through` | the chain records less than was due | `refusal_missing`, `unknown_tool_allowed`, `configuration_not_enforced`, `halt_missing` |
| `over_enforced` | the chain records more than was due, or the wrong reason or rules; it records no forbidden action | `unfounded_record`, `unfounded_halt`, `reason_mismatch`, `rules_mismatch` |
| `not_checkable` | the record says the guard's core was `unavailable` | — |
| `pending` | the evaluated prefix ends on this event or its record: what follows is not known | — |

The `result` speaks for the evaluated prefix only: a run with a gap is compared up to the gap,
and can be `as_required` with `state: "partial"`.

The comparison is `not_performed` — never `as_required` — when the chain contradicts its own
records (`chain_inconsistent`), the records name two cores (`engine_inconsistent`) or a core the
evaluator does not have (`engine_unavailable`); it is never computed with another Cedar version.

What it does not show: which tool was in fact run under a name; that the argument and definition
digests are those of what was sent; an action recorded as another step type; that a human
approved; whether a record was sealed by the guard or other code of the producer; whether the
core in fact failed where a record says `unavailable`; which core the guard ran when the run has
no record; that the sealed configuration is the one the runtime used; that a refused tool was
not run outside the recorded run; who the agent is (`agent.id` is the producer's own name);
anything after the evaluated prefix ([§8](spec/control-evaluation-v3.md)).

### Sub-agents: run trees

An agent that starts sub-agents records each one as its own run, bound to the
parent in both directions ([Agent Delegation v1](spec/agent-delegation-v1.md)).
Children may run concurrently and under their own certificate and controls.

```python
from sigill_sdk import AgentRunTreeBundle, AgentRunTreeOptions

parent = client.start_agent_run(agent, certificate_id=cert_id, activity="pr-review",
                                control_set=controls, delegating=True)

# The parent declares the child before it starts; only the instruction's digest is sealed.
delegation = parent.delegate("urn:example:agent:security-reviewer", task_bytes, use_id="call-7")

# The child's run_start binds the parent's delegation event.
child = client.start_child_agent_run(reviewer_agent, delegation, certificate_id=reviewer_cert_id,
                                     activity="pr-review", control_set=reviewer_controls)
child.record_tool_call("repo.read_file", args_json, operation="read")
child.finish("completed")

parent.complete_delegation(child)   # binds the child's run_end
parent.finish("completed")

tree = AgentRunTreeBundle(parent.correlation_id, [parent.to_bundle(), child.to_bundle()])
result = client.verify_agent_run_tree(tree)
# result.verdict -> "tree_finalized" | "tree_open" | "tree_invalid"
# result.edges   -> per delegation: mutually_bound | child_missing | parent_missing | unbound,
#                   and result_bound | result_mismatch | result_unresolved | no_result
# result.runs    -> every run with its own verdict, which the tree never changes
print(result.scope)
```

- **A withheld child is detected.** The parent's `delegation_result` names the
  child's `run_end`; a tree that leaves the child out, swaps it, or edits it is
  `tree_invalid`.
- **A child elsewhere.** A child in another process rebuilds the
  `AgentDelegation` from its four values; the parent then records the result
  with `parent.complete_delegation(child_correlation_id,
  child_run_end_signature_sha256, child_disposition)`.
- **Close what you open.** A parent cannot close `completed` while a delegation
  has no result; close it `aborted` or `failed` instead, and the tree reports
  "parent terminated; evidence incomplete". The recorder keeps one event slot
  per open delegation, plus `run_end`, inside the 2,000-event bundle limit.
- **Attribution needs a policy.** Pass
  `AgentRunTreeOptions(expected_signers={agent_id: [thumbprint]}, expected_root_correlation_id=...)`
  to bind the tree to what you expected; without it a shared certificate
  proves consistency, not who ran each sub-agent.
- **Delivery is per run.** A child run is shown in Sigill only when it is started with
  `deliver_run=True` itself; it does not inherit the parent's choice.

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

The same holds for agent runs: both verifiers reproduce every shared
agent-run vector — verdict, checks, binding, findings and warnings — so a run
recorded with either SDK verifies identically with the other. The run-tree vectors
([`agent-run-tree/`](spec/test-vectors/agent-run-tree/README.md)) pin the
delegation rules the same way; both SDKs reproduce all of them.

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

## Verifying a release

Every release is sealed with Sigill before it is published: the wheel and the
sdist each get a detached CAdES seal (`.p7s`) with a qualified (eIDAS) RFC 3161 timestamp and a
post-quantum hybrid signature (ML-DSA-87 strengthens the classic seal). The
seals are attached to the [GitHub release](https://github.com/sigill-ai/sigill-python/releases).
PyPI serves the same bytes, so to check a download, put the file and its `.p7s`
into [sigill.ai/verify](https://sigill.ai/verify).

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
