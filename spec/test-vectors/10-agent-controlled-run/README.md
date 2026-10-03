# Test vector 10 — agent controlled run

One complete controlled agent run, sealed for real by the Sigill test tenant
on 2026-09-19 (standard timestamps, no PQC; resealed after the first set
turned out to carry fabricated `eventTime` values, which
`eventTimesPlausible` caught). It is the design example: the
run `customer-address-change`, agent `contract-agent` v17, control set
`customer-write-v4`, seven events (seq 0 to 6) and one Control Evaluation
with `overall: FAIL` on `status-unchanged`. All payloads are synthetic.

```
10-agent-controlled-run/
├── artifacts/            nine {envelope, signature} files, one per artifact
│   ├── 00-control-artifact.agent-control.json
│   ├── 10-run_start … 16-run_end.agent-execution.json
│   └── 90-control-evaluation.control-evaluation.json
├── objects/              the detached objects (bytes) the artifacts bind
├── objects.json          uri → file
├── canonical/            JCS bytes and SHA-256 of every envelope (byte-stable)
├── expected-result.json  offline verification result for the intact set
├── _generate.py          writes canonical/, asserts hash == signed hashV[0]
└── _validate.py          schema + normative-rule check of the whole set
```

Two vector classes, as `ai-evidence-envelope-v2.md` §11 defines them:

1. **Canonicalization** (`canonical/`): any implementation, including a
   later Python port, must reproduce these bytes and digests exactly. CI regenerates them and fails on any drift.
2. **Verification** (`artifacts/` + `objects/`): the signatures are real and
   verify against the Sigill test tenant's certificate. Offline, a verifier
   can check envelope integrity (`hashV[0]`), object completeness, the chain,
   finalization, binding, the seal-time sanity check (`sigTst` genTime of the
   control not later than `run_start`, within stated accuracy) and the
   evaluation subject; signature validity
   needs the platform or a TS 119 182-1 validator and is `null` in
   `expected-result.json`.

It predates the agreed v1 details: its `evidenceId`s use the `urn:uuid:` form
(which verifiers accept), its Control Artifact signs no `timestampPolicy`
(judged under the defaults, with a warning) and every artifact is
timestamped. It verifies as `run_finalized`, `bound`. The sabotage cases
(changed object, removed or swapped events, foreign event, swapped control
basis, wrong evaluation subject, swapped control set, and the rest) are
pinned with the stub signer in [`../agent-run/`](../agent-run/README.md).

The SDK tests check the canonical bytes offline and, when the platform is
reachable, verify the whole set against the live blind `POST
/seal/verify-objects`. The set is frozen: refreshing it means sealing a new
run with the SDK against the Sigill test tenant and replacing the directory.

The nine seals were issued by six different TSAs in the platform pool
(Microsoft, GlobalSign, Sectigo, SwissSign, DigiCert and one unnamed), with
`accuracy` 500 ms, 1 s or unspecified, and genTime with or without
fractional seconds. Any time comparison must allow for that.
