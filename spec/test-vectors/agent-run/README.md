# Agent Evidence Profiles v1 — test vectors

Cross-language vectors for [the agent profiles](../../agent-profiles-common-v1.md).
Every SDK consumes them and must reproduce the expected values exactly.

| File | Asserts |
|---|---|
| `signature-sha256.json` | The binding digest (common rules §2) over General, hybrid (ML-DSA entry first), flattened and non-base64url JWS inputs. |
| `runs/*.json` with `bundle` | A complete bundle (§7) and its expected run verdict, the nine check states, the binding state, the listed missing `seq` values, the §8.2 fingerprint, the per-evaluation outcomes, and substrings that must appear among the findings. |
| `runs/*.json` with `bundleText` | A container that must not parse at all; `expected.parseError` must appear among the parse errors. |

The reference run is three timestamps for the whole run — the Control
Artifact, `run_end` and the Control Evaluation — with every other event
sealed B-B (common rules §4).

## The stub signer

Real JAdES signatures depend on issued certificates and are not byte-stable,
so the vectors are signed by a **stub** that keeps the JWS shape the profiles
read, and SDK tests verify them with the matching **stub verifier** in place
of `POST /seal/verify-objects`.

Stub signer, per artifact:

- `pars = ["urn:sigill:envelope", objects[].uri…]`;
  `hashV = [b64url(SHA-256(JCS(envelope))), b64url(SHA-256(object))…]`;
  `ctys = [<profile content type>]`.
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
   that digest equals `hex(b64url-decode(hashV[i]))`.
4. `missing` = pars with no digest; `unreferenced` = digests whose URI is not
   in pars.
5. `complete` ⇔ `signatureValid` and every par matched.
6. Timestamp: present ⇔ `header.stubTimestamp` exists; its `signatureValid`
   is its `valid`; `tsaName` is `"Stub TSA"`.
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
