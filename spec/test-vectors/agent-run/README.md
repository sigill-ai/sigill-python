# Agent Evidence Profiles v1 — test vectors

Cross-language vectors for [the agent profiles](../../agent-profiles-common-v1.md).
Every SDK consumes them and must reproduce the expected values exactly.

| File | Asserts |
|---|---|
| `signature-sha256.json` | The binding digest (common rules §2) over General, hybrid (ML-DSA entry first), flattened and non-base64url JWS inputs. |
| `runs/*.json` with `bundle` | A complete bundle (§7) and its expected run verdict, the nine check states, the binding state, the listed missing `seq` values, the §8.2 fingerprint, the per-evaluation outcomes, `controlSealedBeforeRun` and `eventTimesPlausible` (`null` when not comparable), substrings that must appear among the findings, and substrings that must appear among the warnings together with the exact number of warnings. |
| `runs/*.json` with `bundleText` | A container that must not parse at all; `expected.parseError` must appear among the parse errors. |
| `runs/71-*` … `runs/78-*` | The v2.1 reference form (AiEvidenceEnvelopeV2 §3.1, §5.2, §5.4): runs whose envelope reference is `sigill-envelope.json` and whose object URIs are production-profile references (`objects/…`); a run that switches form at seq 2 while its evaluation reuses the legacy URIs the Control Artifact sealed; both transitional combinations; an unknown envelope reference; each reserved envelope name used as an object URI. A legacy reference is never a warning, so vectors 01–70 are unchanged. |
| `runs/80-*` … `runs/98-*` | Control Evaluation v2 (`control-evaluation-v2.md`) over a run whose control set is the policy control set of vector 11: a passing and a failing policy evaluation (the latter with its approval record); facts that are not the run's; an approval scope digest that does not recompute; `overall` not following from `controls[]`; a rule not reported; an approval record of another scope; a partial evaluation superseded by a finalized one (`current`); an evaluation without the "sealed for" role; a digests-only bundle; attested evaluations with and without every private control; an approval object that is not JSON and a malformed srAts, both reported, never thrown; a qualified-time requirement met, not met, omitted, contradicted and claimed without an approval (§4.7, `qualifiedRequired` / `qualifiedMet`). Per-evaluation expectations add `kind`, `factsMatch`, `policyDigestsMatch`, `current` and `sealedFor` where they apply. The claimed results of every valid policy evaluation equal the official Cedar core's. |
| `runs/99-*` … `runs/104-*` | Agent Model Calls v1 (`agent-model-calls-v1.md`): a version 3 run whose model call carries `model`, `vendorRefs` and `usage` (expectations pin `modelCalls` / `modelCallsWithVendorRefs`); model-call members in a version 1 event; a version 3 run with one version 1 event; a vendor id that is not printable ASCII; an unknown `kind`; model-call members on a `tool_call`. |

The reference run is three timestamps for the whole run — the Control
Artifact, `run_end` and the Control Evaluation — with every other event
sealed B-B (common rules §4).

## The stub signer

Real JAdES signatures depend on issued certificates and are not byte-stable,
so the vectors are signed by a **stub** that keeps the JWS shape the profiles
read, and SDK tests verify them with the matching **stub verifier** in place
of `POST /seal/verify-objects`.

Stub signer, per artifact:

- `pars = [<envelope reference>, objects[].uri…]`, where the envelope
  reference is `urn:sigill:envelope` (legacy, vectors 01–70 and parts of
  73–75) or `sigill-envelope.json` (v2.1). A verifier reads it from each
  artifact's own signature and keys the envelope digest it supplies by it;
  `hashV = [b64url(SHA-256(JCS(envelope))), b64url(SHA-256(object))…]`;
  `ctys = [<profile content type>, objects[].contentType…]` (`""` when absent),
  index-aligned with `pars` as the platform signs it.
- `protected = b64url(JCS({"alg": "ES256", "sigD": {"pars", "hashV", "ctys"},
  "x5c": [base64(cert)], "x5t#S256": b64url(SHA-256(cert))}))`. The run's
  artifacts use certificate A; the Control Evaluation uses certificate V (its
  own verifier); forged artifacts use certificate B.
- `signature = b64url(SHA-256(ASCII(protected)))`.
- A timestamped artifact carries an unprotected
  `header.stubTimestamp = {"genTime", "valid"}`.

Stub verifier, given `{signature, digests}`:

1. Take the first `signatures[]` entry whose protected `alg` does not start
   with `ML-DSA`. Headers are read leniently (a repeated member name: the
   last value wins), as a lenient signature service might; refusing such a
   header is the profile layer's job.
2. `signatureValid` ⇔ its `signature` equals `b64url(SHA-256(ASCII(protected)))`.
3. For each `pars[i]`: `supplied` ⇔ a digest is given for it; `hashMatch` ⇔
   that digest equals `hex(b64url-decode(hashV[i]))`. The stub knows nothing
   about envelope references: it matches digests to `pars` entries by exact
   string, as the platform does.
4. `missing` = pars with no digest; `unreferenced` = digests whose URI is not
   in pars.
5. `complete` ⇔ `signatureValid` and every par matched.
6. Timestamp: present ⇔ `header.stubTimestamp` exists; its `signatureValid`
   is its `valid`; `tsaName` is `"Stub TSA"`; `trust` is its `trust`, or
   `"trusted_chain"` when absent.
7. Certificate: `{subject: "CN=Stub Signer", issuer: "CN=Stub CA",
   notAfter: "2030-01-01T00:00:00Z", isSelfSigned: false, trust: "trusted_chain"}`.

The stub has no security value. It pins every profile-layer rule
byte-for-byte across languages.

## Regenerating

```bash
pip install jcs
python _generate.py
```

Deterministic: regenerating produces byte-identical files, and stale vectors
are removed first.
