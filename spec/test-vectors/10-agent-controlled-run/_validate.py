"""Validate every envelope in artifacts/ against its profile schema, and check
the normative rules the schemas cannot express (chain, binding, subject,
object digests). Exit code 0 means the vector is internally consistent.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

VECTOR_DIR = Path(__file__).parent
SPEC = VECTOR_DIR.parent.parent
SCHEMAS = {
    "application/vnd.sigill.agent-control+json": "agent-control-artifact-v1.schema.json",
    "application/vnd.sigill.agent-execution+json": "agent-execution-evidence-v1.schema.json",
    "application/vnd.sigill.control-evaluation+json": "control-evaluation-v1.schema.json",
}


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def classical(signature: dict) -> tuple[dict, dict]:
    for entry in signature["signatures"]:
        header = json.loads(b64url_decode(entry["protected"]))
        if not header.get("alg", "").startswith("ML-DSA"):
            return entry, header
    raise SystemExit("no classical signature entry")


def signature_sha256(signature: dict) -> str:
    entry, _ = classical(signature)
    return hashlib.sha256(b64url_decode(entry["signature"])).hexdigest()


def main() -> int:
    errors: list[str] = []
    validators = {cty: Draft202012Validator(json.loads((SPEC / f).read_text())) for cty, f in SCHEMAS.items()}
    for v in validators.values():
        Draft202012Validator.check_schema(v.schema)

    objects_index = json.loads((VECTOR_DIR / "objects.json").read_text())
    payloads = {uri: (VECTOR_DIR / rel).read_bytes() for uri, rel in objects_index.items()}

    by_cty: dict[str, list] = {c: [] for c in SCHEMAS}
    for path in sorted((VECTOR_DIR / "artifacts").glob("*.json")):
        artifact = json.loads(path.read_text(encoding="utf-8"))
        _, header = classical(artifact["signature"])
        sig_d = header["sigD"]
        cty = sig_d["ctys"][0]
        for err in validators[cty].iter_errors(artifact["envelope"]):
            errors.append(f"{path.name}: schema: {err.message} at {'/'.join(str(p) for p in err.absolute_path)}")
        # objects[] aligned with pars[1:], digests match supplied payloads
        pars, hash_v = sig_d["pars"][1:], sig_d["hashV"][1:]
        uris = [o["uri"] for o in artifact["envelope"]["objects"]]
        if uris != pars:
            errors.append(f"{path.name}: objects[] not aligned with sigD.pars")
        for uri, h in zip(pars, hash_v):
            if uri not in payloads:
                errors.append(f"{path.name}: payload {uri} not supplied")
            elif hashlib.sha256(payloads[uri]).hexdigest() != b64url_decode(h).hex():
                errors.append(f"{path.name}: payload {uri} digest mismatch")
        by_cty[cty].append(artifact)

    controls = by_cty["application/vnd.sigill.agent-control+json"]
    runs = sorted(by_cty["application/vnd.sigill.agent-execution+json"], key=lambda a: a["envelope"]["chain"]["seq"])
    evals = by_cty["application/vnd.sigill.control-evaluation+json"]
    if len(controls) != 1:
        errors.append("expected exactly one Control Artifact")
    control_sha = signature_sha256(controls[0]["signature"]) if controls else ""

    prev = None
    for i, a in enumerate(runs):
        env = a["envelope"]
        if env["chain"]["seq"] != i:
            errors.append(f"seq {env['chain']['seq']} at position {i}")
        if i == 0 and env["step"]["type"] != "run_start":
            errors.append("first event is not run_start")
        if i > 0 and env["chain"].get("prevSignatureSha256") != prev:
            errors.append(f"prevSignatureSha256 broken at seq {i}")
        if "binds" in env and env["binds"]["controlArtifactSignatureSha256"] != control_sha:
            errors.append(f"binds does not point at the Control Artifact at seq {i}")
        prev = signature_sha256(a["signature"])
    run_end = runs[-1]["envelope"] if runs else None
    if not run_end or run_end["step"]["type"] != "run_end":
        errors.append("last event is not run_end")
    else:
        if run_end["step"]["finalSeq"] != run_end["chain"]["seq"]:
            errors.append("finalSeq != run_end.seq")
        second_to_last = signature_sha256(runs[-2]["signature"]) if len(runs) >= 2 else None
        if run_end["step"]["finalPrevSignatureSha256"] != second_to_last:
            errors.append("finalPrevSignatureSha256 != second-to-last signature")
    run_end_sha = signature_sha256(runs[-1]["signature"]) if runs else ""

    def control_set_digest(artifact: dict) -> str | None:
        _, header = classical(artifact["signature"])
        for obj, h in zip(artifact["envelope"]["objects"], header["sigD"]["hashV"][1:]):
            if obj["role"] == "control-set":
                return b64url_decode(h).hex()
        return None

    for e in evals:
        subject = e["envelope"]["subject"]
        if subject["runEndSignatureSha256"] != run_end_sha or subject["controlArtifactSignatureSha256"] != control_sha:
            errors.append("evaluation subject not bound to this run")
        if controls and control_set_digest(e) != control_set_digest(controls[0]):
            errors.append("control-set digest differs between evaluation and Control Artifact")

    for err in errors:
        print("ERROR:", err)
    print(f"{len(controls)} control artifact(s), {len(runs)} event(s), {len(evals)} evaluation(s): {'OK' if not errors else 'FAILED'}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
