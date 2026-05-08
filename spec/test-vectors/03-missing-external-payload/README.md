# Vector 03 — missing / mismatched external payload

This vector reuses the **sealed envelope from vector 02** to drive the *verification failure* paths.
Producer-side it is identical to vector 02; the interesting cases are during verification.

The SDK test suites use this vector to exercise three failure modes:

1. **Missing payload** — verify with `externalPayloads = { "ctx-1": ..., "output": ... }`. The verifier
   must report `hash_mismatch` against `prompt` with reason `payload_not_supplied`.

2. **Wrong payload** — verify with `prompt` mapped to a *different* set of bytes. The verifier must
   report `hash_mismatch` against `prompt` with reason `digest_does_not_match`, and supply both the
   expected and computed digests in the structured result.

3. **Tampered envelope** — take vector 02's `expected.json`, mutate any field (e.g. change
   `model.name`), and run verification. The verifier must report `hash_mismatch` against the
   envelope itself with reason `envelope_hash_does_not_match`.

The .NET and Python test suites cover all three; see their respective `EnvelopeVerificationTests`
files.

This vector ships no `_generate.py` — there is nothing to seal beyond what vector 02 already produces.
