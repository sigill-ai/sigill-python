"""Generate canonical/expected/hash for vector 02 (PII-redacted).

The producer hashes the external payload bytes and writes them into the matching
payloadRef.hash before sealing. This script does the same.
"""
import hashlib
import json
import sys
from pathlib import Path

import jcs

VECTOR_DIR = Path(__file__).parent
INPUT = VECTOR_DIR / "input.json"
PAYLOADS = VECTOR_DIR / "external-payloads"


def sha256_of(path: Path) -> tuple[str, int]:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def envelope_hash_input(env: dict) -> dict:
    stripped = json.loads(json.dumps(env))
    if "integrity" in stripped and "envelopeHash" in stripped["integrity"]:
        del stripped["integrity"]["envelopeHash"]
    if "proofs" in stripped:
        del stripped["proofs"]
    return stripped


REF_FILES = {
    "prompt": PAYLOADS / "prompt.txt",
    "ctx-1": PAYLOADS / "ctx-1.txt",
    "output": PAYLOADS / "output.json",
}


def populate_hashes(node):
    """Walk the envelope; for every payloadRef with a 'ref' but no 'hash', fill in the hash."""
    if isinstance(node, dict):
        if "ref" in node and "hash" not in node and "inline" not in node:
            ref = node["ref"]
            if ref in REF_FILES:
                hex_, n = sha256_of(REF_FILES[ref])
                node["hash"] = {"alg": "SHA-256", "hex": hex_, "sizeBytes": n}
        for v in node.values():
            populate_hashes(v)
    elif isinstance(node, list):
        for v in node:
            populate_hashes(v)


def main() -> int:
    envelope = json.loads(INPUT.read_text())
    populate_hashes(envelope)
    envelope["integrity"] = {"canonicalization": "RFC8785"}

    canonical = jcs.canonicalize(envelope_hash_input(envelope))
    digest = hashlib.sha256(canonical).hexdigest()

    (VECTOR_DIR / "canonical.json").write_bytes(canonical)
    (VECTOR_DIR / "envelope-hash.txt").write_text(digest + "\n")

    envelope["integrity"]["envelopeHash"] = {"alg": "SHA-256", "hex": digest}
    (VECTOR_DIR / "expected.json").write_text(
        json.dumps(envelope, indent=2, ensure_ascii=False) + "\n"
    )

    print(f"canonical.json: {len(canonical)} bytes")
    print(f"envelope hash:  {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
