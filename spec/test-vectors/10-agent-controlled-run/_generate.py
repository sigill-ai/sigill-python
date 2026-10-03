"""Canonical bytes and envelope hashes for test vector 10 (agent controlled run).

For every artifact in artifacts/, writes canonical/<name>.canonical.json (the
exact JCS bytes of the envelope) and canonical/<name>.envelope-hash.txt, and
asserts that the hash equals hashV[0] in the artifact's classical signature.
Any implementation must reproduce these bytes exactly.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

import jcs  # RFC 8785 reference implementation

VECTOR_DIR = Path(__file__).parent
ARTIFACTS = VECTOR_DIR / "artifacts"
OUT = VECTOR_DIR / "canonical"


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def classical_entry(signature: dict) -> dict:
    for entry in signature["signatures"]:
        header = json.loads(b64url_decode(entry["protected"]))
        if not header.get("alg", "").startswith("ML-DSA"):
            return entry
    raise SystemExit("no classical signature entry")


def main() -> int:
    OUT.mkdir(exist_ok=True)
    for path in sorted(ARTIFACTS.glob("*.json")):
        artifact = json.loads(path.read_text(encoding="utf-8"))
        canonical = jcs.canonicalize(artifact["envelope"])
        digest = hashlib.sha256(canonical).hexdigest()

        header = json.loads(b64url_decode(classical_entry(artifact["signature"])["protected"]))
        signed_hex = b64url_decode(header["sigD"]["hashV"][0]).hex()
        if signed_hex != digest:
            raise SystemExit(f"{path.name}: envelope hash {digest} != signed hashV[0] {signed_hex}")

        stem = path.name.split(".")[0]
        (OUT / f"{stem}.canonical.json").write_bytes(canonical)
        (OUT / f"{stem}.envelope-hash.txt").write_text(digest + "\n")
        print(f"{path.name}: {len(canonical)} bytes, {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
