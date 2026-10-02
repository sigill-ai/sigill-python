# AgentExecutionProfileV1 test vectors

Cross-language vectors for [the profile](../../agent-execution-profile-v1.md).
Every SDK consumes them and must reproduce the expected values exactly.

| File | Asserts |
|---|---|
| `chain-digest.json` | §4 chain digest over General, hybrid (ML-DSA entry first) and flattened JWS inputs. |
| `config-digest.json` | §3.6 configuration digest from the configuration objects (base64), with and without the optional model-config. |
| `runs/*.json` | Complete bundles (§7) with their expected run verdict, the nine check states, the listed missing `seq` values, the §8.1 fingerprint, and substrings that must appear among the findings. |

## The stub signer

Real JAdES signatures depend on issued certificates and are not byte-stable,
so the run vectors are signed by a **stub** that keeps the JWS shape the
profile reads, and the SDK tests verify them with the matching **stub
verifier** in place of `POST /seal/verify-objects`.

Stub signer, per artifact:

- `pars = ["urn:sigill:envelope", objects[].uri…]`;
  `hashV = [b64url(SHA-256(JCS(envelope))), b64url(SHA-256(object))…]`.
- `protected = b64url(JCS({"alg": "ES256", "sigD": {"pars", "hashV"}}))`.
- `signature = b64url(SHA-256(ASCII(protected)))`.
- A timestamped artifact carries an unprotected
  `header.stubTimestamp = {"genTime", "valid"}`.

Stub verifier, given `{signature, digests}`:

1. Take the first `signatures[]` entry whose protected `alg` does not start
   with `ML-DSA`.
2. `signatureValid` ⇔ its `signature` equals `b64url(SHA-256(ASCII(protected)))`.
3. For each `pars[i]`: `supplied` ⇔ a digest is given for it; `hashMatch` ⇔ that
   digest equals `hex(b64url-decode(hashV[i]))`.
4. `missing` = pars with no digest; `unreferenced` = digests whose URI is not in pars.
5. `complete` ⇔ `signatureValid` and every par matched.
6. Timestamp: present ⇔ `header.stubTimestamp` exists; its `signatureValid` is
   its `valid`, `tsaName` is `"Stub TSA"`.
7. Certificate: `{subject: "CN=Stub Signer", issuer: "CN=Stub CA",
   notAfter: "2030-01-01T00:00:00Z", isSelfSigned: false}`.

The stub has no security value. It exists so that every profile-layer rule
(chain, sequence, timestamp policy, finalization, identity, fingerprint) is
pinned byte-for-byte across languages.

## Regenerating

```bash
pip install jcs
python _generate.py
```

Deterministic: regenerating produces byte-identical files. Expected verdicts
are declared in the generator, not derived from an SDK, so a regression in
either SDK fails against them.
