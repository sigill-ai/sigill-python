# Agent Delegation v1 — run-tree vectors

Cross-language vectors for [Agent Delegation v1](../../agent-delegation-v1.md). Every SDK
consumes them through the **stub signer and verifier** described in
[`../agent-run/README.md`](../agent-run/README.md) and must reproduce the expected values
exactly.

Each `trees/*.json` holds:

| Member | Meaning |
|---|---|
| `tree` | An `AgentRunTreeBundle` (§6.1). |
| `options` | Optional relying-party expectations (§5, §6.7): `expectedRootCorrelationId`, `expectedSigners` (`agent.id` → `x5t#S256`). |
| `expected.verdict` | `tree_finalized`, `tree_open` or `tree_invalid`. |
| `expected.root` | The root derived from signed envelopes, or `null`. |
| `expected.runs` | Each run's own verdict by `correlationId` (empty when a limit stops verification). |
| `expected.edges` | Every edge: `parent`, `child`, `binding`, `completion` (§6.4). |
| `expected.findings` | The set of §6.3 finding codes. |
| `expected.openReasons` | The set of open-reason codes: `run_open`, `delegation_pending`, `parent_terminated`. |
| `expected.fingerprint` | The §6.8 tree fingerprint, or `null`. |
| `expected.affiliations` | Optional: per run, `confirmed`, `unknown` or `mismatch`. |

The runs use certificate A unless a vector says otherwise; vector 52 signs child A with
certificate B.

## Regenerating

```bash
pip install jcs
python _generate.py
```

Deterministic: regenerating produces byte-identical files, and stale vectors are removed
first. It imports the stub signer from `../agent-run/_generate.py` unchanged.
