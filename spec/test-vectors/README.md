# Test vectors

Three reference scenarios. Each SDK consumes them and asserts byte-equality of the canonical
output and hex-equality of the envelope hash. This is what makes the spec cross-language
deterministic in practice rather than just on paper.

## Layout

```
test-vectors/
├── 01-complete-ai-call/
│   ├── input.json              ← envelope before hashing
│   ├── canonical.json          ← exact bytes both SDKs must produce
│   ├── envelope-hash.txt       ← lowercase SHA-256 hex of canonical.json
│   ├── expected.json           ← the sealed envelope minus proofs
│   └── _generate.py            ← reference computation (uses jcs PyPI pkg)
├── 02-pii-redacted/
│   ├── input.json
│   ├── external-payloads/      ← bytes referenced by payloadRef.ref
│   │   ├── prompt.txt
│   │   ├── ctx-1.txt
│   │   └── output.json
│   ├── canonical.json
│   ├── envelope-hash.txt
│   ├── expected.json
│   └── _generate.py
└── 03-missing-external-payload/
    └── README.md               ← exercises verification failure paths against vector 02
```

## Regenerating

The `_generate.py` scripts use [`jcs`](https://pypi.org/project/jcs/) (the reference RFC 8785
implementation by the spec's co-author) to compute canonical bytes. They are deterministic — the
generated files SHOULD be byte-identical on every run.

```bash
pip install jcs
python 01-complete-ai-call/_generate.py
python 02-pii-redacted/_generate.py
```

If you change `input.json`, regenerate. CI fails if the committed `canonical.json` /
`envelope-hash.txt` no longer match the input.

## Why these three

The acceptance criteria call for "at least three scenarios"; we picked the three that exercise
the structurally distinct paths:

| Vector | Payload model | What it proves |
|---|---|---|
| 01 | All inline | The basic seal/verify loop with no external lookups. |
| 02 | All hash-referenced | The PII-safe model — envelope can be retained even when payloads are deleted. |
| 03 | Same as 02 | All three verification failure modes return structured errors, not exceptions. |

Adding a fourth would be testing implementation detail rather than spec behaviour. If the spec
grows new structural features (a new proof type, a new canonicalization), it gets a new vector.
