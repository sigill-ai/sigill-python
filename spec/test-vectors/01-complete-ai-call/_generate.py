"""Generate canonical.json and envelope-hash.txt for test vector 01.

This is the reference computation. Both the .NET and Python SDKs must produce
byte-identical canonical bytes and hex digests.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import jcs  # RFC 8785 reference implementation

VECTOR_DIR = Path(__file__).parent
INPUT = VECTOR_DIR / "input.json"


def envelope_hash_input(envelope: dict) -> dict:
    """Strip the fields excluded from hashing per spec §4."""
    stripped = json.loads(json.dumps(envelope))  # deep copy
    if "integrity" in stripped and "envelopeHash" in stripped["integrity"]:
        del stripped["integrity"]["envelopeHash"]
    if "proofs" in stripped:
        del stripped["proofs"]
    return stripped


def main() -> int:
    with INPUT.open("rb") as fh:
        envelope = json.load(fh)

    # The producer would set integrity.canonicalization before hashing
    envelope["integrity"] = {"canonicalization": "RFC8785"}

    to_hash = envelope_hash_input(envelope)
    canonical_bytes = jcs.canonicalize(to_hash)
    digest = hashlib.sha256(canonical_bytes).hexdigest()

    (VECTOR_DIR / "canonical.json").write_bytes(canonical_bytes)
    (VECTOR_DIR / "envelope-hash.txt").write_text(digest + "\n")

    # The expected envelope = original + integrity.envelopeHash, no proofs (since proofs
    # depend on a TSA round-trip and aren't byte-stable).
    envelope["integrity"]["envelopeHash"] = {"alg": "SHA-256", "hex": digest}
    (VECTOR_DIR / "expected.json").write_text(
        json.dumps(envelope, indent=2, ensure_ascii=False) + "\n"
    )

    print(f"canonical.json: {len(canonical_bytes)} bytes")
    print(f"envelope hash:  {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
