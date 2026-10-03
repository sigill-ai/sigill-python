# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Reference generator for the Agent Evidence Profiles v1 test vectors.

Deterministic: fixed identifiers, times and bytes, so every run produces
byte-identical files. Signatures are produced by the *stub signer* described
in README.md — not real JAdES — so the vectors exercise the profile layer
(binding, chain, sequence, signer, timestamp policy, finalization, control
binding, evaluations, fingerprint) without depending on issued certificates.
Expected results are declared here, never derived from an SDK.

    pip install jcs
    python _generate.py
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import jcs

HERE = Path(__file__).parent
ENVELOPE_URI = "urn:sigill:envelope"
RUN = "urn:uuid:00000000-0000-4000-9000-000000000001"
ACTIVITY = "support-ticket-close"
AGENT = {"id": "urn:example:agent:support-triage", "version": "2.4.0"}
CERT_A = b"stub signing certificate A (the producer)"
CERT_B = b"stub signing certificate B (someone else)"
CERT_V = b"stub signing certificate V (the evaluating verifier)"
CTY = {
    "control": "application/vnd.sigill.agent-control+json",
    "event": "application/vnd.sigill.agent-execution+json",
    "evaluation": "application/vnd.sigill.control-evaluation+json",
}


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sha256hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def uuid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def write(name: str, value, *, ascii_only: bool = False) -> None:
    path = HERE / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=ascii_only) + "\n", encoding="utf-8")


# ── Stub signer (see README.md) ─────────────────────────────────────────────

def signer_header(cert: bytes) -> dict:
    """x5c / x5t#S256 as real JAdES carries them: thumbprint = b64url(SHA-256(DER x5c[0]))."""
    return {"x5c": [base64.b64encode(cert).decode()], "x5t#S256": b64u(hashlib.sha256(cert).digest())}


def stub_sign(envelope: dict, digests: dict, cty: str, *, timestamp: str | None, cert: bytes = CERT_A,
              hybrid: bool = False, dup_alg: bool = False) -> dict:
    pars = [ENVELOPE_URI] + [o["uri"] for o in envelope["objects"]]
    hash_v = [b64u(hashlib.sha256(jcs.canonicalize(envelope)).digest())] + \
             [b64u(bytes.fromhex(digests[u])) for u in pars[1:]]
    # ctys is index-aligned with pars: the profile type, then each object's contentType ("" when absent).
    ctys = [cty] + [o.get("contentType", "") for o in envelope["objects"]]
    header = jcs.canonicalize({"alg": "ES256", "sigD": {"pars": pars, "hashV": hash_v, "ctys": ctys},
                               **signer_header(cert)})
    if dup_alg:  # a repeated member name: parsers disagree on which value wins, so the header is unreadable
        header = header.replace(b'{"alg":"ES256"', b'{"alg":"ES256","alg":"ES256"', 1)
    protected = b64u(header)
    entry: dict = {"protected": protected, "signature": b64u(hashlib.sha256(protected.encode()).digest())}
    if timestamp is not None:
        entry["header"] = {"stubTimestamp": {"genTime": timestamp, "valid": True}}
    entries = [entry]
    if hybrid:
        entries.insert(0, {"protected": b64u(jcs.canonicalize({"alg": "ML-DSA-87"})),
                           "signature": b64u(b"post-quantum signature value")})
    return {"signatures": entries}


def signature_sha256(jws: dict) -> str:
    for e in jws["signatures"]:
        alg = json.loads(base64.urlsafe_b64decode(e["protected"] + "=" * (-len(e["protected"]) % 4)))["alg"]
        if alg.upper().startswith("ML-DSA"):
            continue
        return sha256hex(base64.urlsafe_b64decode(e["signature"] + "=" * (-len(e["signature"]) % 4)))
    raise ValueError("no classical signature")


def objects_block(objs: list) -> list:
    return [{"uri": uri, "role": role, "contentType": ctype, "sizeBytes": len(data)} for uri, role, ctype, data in objs]


def artifact(env: dict, objs: list, cty: str, *, stamp_at: str | None, cert: bytes = CERT_A,
             dup_alg: bool = False) -> dict:
    digests = {uri: sha256hex(data) for uri, _, _, data in objs}
    return {"envelope": env, "signature": stub_sign(env, digests, cty, timestamp=stamp_at, cert=cert, dup_alg=dup_alg),
            "objectDigests": digests}


def stamp_of(a: dict) -> str | None:
    old = a["signature"]["signatures"][-1].get("header", {}).get("stubTimestamp")
    return old["genTime"] if old else None


def resign(a: dict, cty: str, cert: bytes = CERT_A) -> None:
    a["signature"] = stub_sign(a["envelope"], a["objectDigests"], cty, timestamp=stamp_of(a), cert=cert)


# ── The three profiles ──────────────────────────────────────────────────────

POLICY = {"profile": "throughput", "everyEvents": 0, "everySeconds": 0, "consequential": False}
CONTROL_OBJS = [
    ("urn:example:obj:instruction-set", "instruction-set", "text/plain", b"You triage support tickets. Close only with approval."),
    ("urn:example:obj:tool-manifest", "tool-manifest", "application/json", b'{"tools":["lookup_ticket","close_ticket"]}'),
    ("urn:example:obj:execution-policy", "execution-policy", "application/json", b'{"allow":["lookup_ticket","close_ticket"]}'),
    ("urn:example:obj:model-config", "model-config", "application/json", b'{"temperature":0}'),
    ("urn:example:obj:control-set", "control-set", "application/json", b'{"controls":["ticket-closed","owner-unchanged"]}'),
    ("urn:example:obj:baseline-state", "baseline-state", "application/json", b'{"ticket":"4411","status":"open","owner":"team-a"}'),
]


def control_artifact(payloads: dict, *, policy=POLICY, cert: bytes = CERT_A, n: int = 1, tweak=None,
                     stamp_at: str | None = "2026-10-01T08:59:01Z", cty: str = CTY["control"]) -> dict:
    env = {
        "schemaName": "AgentControlArtifact", "schemaVersion": "1", "evidenceId": uuid(n),
        "createdAt": "2026-10-01T08:59:00.000Z",
        "actor": {"type": "system", "id": "urn:example:harness:prod"},
        "activity": {"name": ACTIVITY, "correlationId": RUN},
        "agent": dict(AGENT),
        "controlSet": {"id": "ticket-close-v2", "version": "2"},
        "objects": objects_block(CONTROL_OBJS),
    }
    if policy is not None:
        env["timestampPolicy"] = policy
    if tweak:
        tweak(env)
    for uri, _, _, data in CONTROL_OBJS:
        payloads[uri] = data
    return artifact(env, CONTROL_OBJS, cty, stamp_at=stamp_at, cert=cert)


def at(minute: int) -> str:
    return f"2026-10-01T09:{minute:02d}:00.000Z"


STEPS = [
    {"type": "tool_call", "minute": 1, "step": {"tool": {"name": "lookup_ticket", "operation": "read"}},
     "objects": [("tool-arguments", "application/json", b'{"ticket":"4411"}')]},
    {"type": "tool_result", "minute": 2, "step": {"tool": {"name": "lookup_ticket"}},
     "objects": [("tool-result", "application/json", b'{"status":"open"}')]},
    {"type": "model_output", "minute": 3,
     "objects": [("model-output", "text/plain", b"Reset the session cache and retry.")]},
]


def build_run(steps: list, payloads: dict, *, control: dict | None, finish: bool = True, start_type: str = "run_start",
              tweak=None, end_cert: bytes = CERT_A, end_stamp: bool = True, start_stamp: bool = False,
              end_stamp_at: str | None = None) -> list:
    """steps: [{type, minute, step:{…}, objects:[(role, ctype, bytes)], stamp, consequential, cert, dupAlg}]."""
    arts: list = []
    bind_value = signature_sha256(control["signature"]) if control else None

    def seal(step_type, minute, step_fields, objs, stamp, consequential, cert, dup_alg=False, stamp_at=None,
             cty=CTY["event"]):
        seq = len(arts)
        uris = [(f"urn:example:obj:s{seq}-{role}", role, ctype, data) for role, ctype, data in objs]
        step = {"type": step_type, "eventTime": at(minute), "consequential": consequential,
                "timestamp": "required" if stamp else "none"}
        step.update(copy.deepcopy(step_fields))
        env = {
            "schemaName": "AgentExecutionEvidence", "schemaVersion": "1", "evidenceId": uuid(100 + seq),
            "createdAt": at(minute),
            "actor": {"type": "agent", "id": AGENT["id"], "version": AGENT["version"]},
            "activity": {"name": ACTIVITY, "correlationId": RUN},
            "chain": {"seq": seq},
            "step": step,
            "objects": objects_block(uris),
        }
        if seq > 0:
            env["chain"]["prevSignatureSha256"] = signature_sha256(arts[-1]["signature"])
        if step_type == "run_end":
            step["finalSeq"] = seq
            step["finalPrevSignatureSha256"] = env["chain"]["prevSignatureSha256"]
        if seq == 0 and bind_value is not None:
            env["binds"] = {"controlArtifactSignatureSha256": bind_value}
        if tweak:
            tweak(seq, env)
        for uri, _, _, data in uris:
            payloads[uri] = data
        stamp_time = (stamp_at or at(minute).replace(".000", "")) if stamp else None
        arts.append(artifact(env, uris, cty, stamp_at=stamp_time, cert=cert, dup_alg=dup_alg))

    seal(start_type, 0, {}, [("model-input", "text/plain", b"Ticket 4411: login fails after reset.")],
         start_stamp, False, CERT_A)
    for s in steps:
        seal(s["type"], s["minute"], s.get("step", {}), s.get("objects", []), s.get("stamp", False),
             s.get("consequential", False), s.get("cert", CERT_A), s.get("dupAlg", False), cty=s.get("cty", CTY["event"]))
    if finish:
        seal("run_end", steps[-1]["minute"] + 1, {"runDisposition": "completed"}, [], end_stamp, False, end_cert,
             stamp_at=end_stamp_at)
    return arts


def rechain(arts: list, from_seq: int) -> None:
    """Re-link and re-sign events from `from_seq` on after an earlier event's signature changed."""
    for i in range(from_seq, len(arts)):
        e = arts[i]["envelope"]
        e["chain"]["prevSignatureSha256"] = signature_sha256(arts[i - 1]["signature"])
        if e["step"]["type"] == "run_end":
            e["step"]["finalPrevSignatureSha256"] = e["chain"]["prevSignatureSha256"]
        resign(arts[i], CTY["event"])


def evaluation(payloads: dict, control: dict, run_end: dict, *, tweak=None,
               control_set_bytes: bytes | None = None, baseline_bytes: bytes | None = None,
               cert: bytes = CERT_V) -> dict:
    cs = next(o for o in CONTROL_OBJS if o[1] == "control-set")
    bl = next(o for o in CONTROL_OBJS if o[1] == "baseline-state")
    objs = [
        ("urn:example:obj:observed-state", "observed-state", "application/json",
         b'{"ticket":"4411","status":"closed","owner":"team-a"}'),
        (cs[0], "control-set", cs[2], control_set_bytes if control_set_bytes is not None else cs[3]),
        (bl[0], "baseline-state", bl[2], baseline_bytes if baseline_bytes is not None else bl[3]),
    ]
    env = {
        "schemaName": "ControlEvaluation", "schemaVersion": "1", "evidenceId": uuid(900),
        "createdAt": "2026-10-01T09:30:00.000Z",
        "actor": {"type": "verifier", "id": "urn:example:verifier:ticket-state", "version": "1.3.0"},
        "activity": {"name": ACTIVITY, "correlationId": RUN},
        "subject": {"runEndSignatureSha256": signature_sha256(run_end["signature"]),
                    "controlArtifactSignatureSha256": signature_sha256(control["signature"])},
        "controlSet": {"id": "ticket-close-v2", "version": "2"},
        "controls": [{"id": "ticket-closed", "result": "PASS"}, {"id": "owner-unchanged", "result": "PASS"}],
        "overall": "PASS",
        "evaluatedAt": "2026-10-01T09:29:00.000Z",
        "objects": objects_block(objs),
    }
    if tweak:
        tweak(env)
    payloads["urn:example:obj:observed-state"] = objs[0][3]
    return artifact(env, objs, CTY["evaluation"], stamp_at="2026-10-01T09:30:01Z", cert=cert)


def bundle(control, arts, evaluations=(), payloads=None) -> dict:
    b = {"format": "AgentRunBundle", "bundleVersion": "1", "correlationId": RUN,
         "controlArtifact": control, "artifacts": arts}
    if evaluations:
        b["evaluations"] = list(evaluations)
    if payloads is not None:
        b["payloads"] = {u: base64.b64encode(d).decode() for u, d in sorted(payloads.items())}
    return b


# ── Fingerprint (common rules §8.2) ─────────────────────────────────────────

def is_i_json(v) -> bool:
    if isinstance(v, bool) or v is None or isinstance(v, float):
        return True
    if isinstance(v, int):
        return abs(v) <= 2 ** 53
    if isinstance(v, str):
        return not any(0xD800 <= ord(c) <= 0xDFFF for c in v)
    if isinstance(v, list):
        return all(is_i_json(x) for x in v)
    return all(is_i_json(k) and is_i_json(x) for k, x in v.items())


def fingerprint(b: dict) -> str | None:
    every = b["artifacts"] + ([b["controlArtifact"]] if b.get("controlArtifact") else []) + b.get("evaluations", [])
    if not all(is_i_json(a["envelope"]) and is_i_json(a["signature"]) for a in every):
        return None

    def one(a):
        return {"e": sha256hex(jcs.canonicalize(a["envelope"])), "s": sha256hex(jcs.canonicalize(a["signature"])),
                "d": dict(sorted(a.get("objectDigests", {}).items()))}
    arts = []
    for a in b["artifacts"]:
        chain = a["envelope"].get("chain")
        raw = chain.get("seq") if isinstance(chain, dict) else None
        seq = raw if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0 else -1
        arts.append({"seq": seq, **one(a)})
    arts.sort(key=lambda x: (x["seq"], x["e"]))
    evals = sorted((one(e) for e in b.get("evaluations", [])), key=lambda x: x["e"])
    pls = [{"uri": u, "sha256": sha256hex(base64.b64decode(v))} for u, v in sorted((b.get("payloads") or {}).items())]
    return sha256hex(jcs.canonicalize({
        "format": b["format"], "artifacts": arts,
        "control": one(b["controlArtifact"]) if b.get("controlArtifact") else None,
        "evaluations": evals, "payloads": pls}))


def _time(v):
    from datetime import datetime
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00")) if isinstance(v, str) else None
    except ValueError:  # not a real date-time: the verifier does not read it either
        return None


def seal_time(b: dict):
    """Reference for the §8 seal-time results: (controlSealedBeforeRun, eventTimesPlausible).
    Every stub timestamp is valid; artifacts that are not I-JSON are not read."""
    from datetime import timedelta
    allowance, accuracy = timedelta(seconds=6), timedelta(seconds=1)
    ctl = b.get("controlArtifact")
    ctl_at = _time(stamp_of(ctl)) if ctl else None
    events = [a for a in b["artifacts"] if is_i_json(a["envelope"]) and is_i_json(a["signature"])]
    events.sort(key=lambda a: a["envelope"]["chain"]["seq"])
    line = [(_time(a["envelope"]["step"].get("eventTime")), _time(stamp_of(a))) for a in events]
    stamped = [at for _, at in line if at is not None]
    before = (ctl_at <= stamped[0] + accuracy) if ctl_at and stamped else None
    plausible = None
    for i, (claimed, _) in enumerate(line):
        if claimed is None:
            continue
        if ctl_at is not None:
            plausible = (True if plausible is None else plausible) and claimed >= ctl_at - allowance
        upper = next((at for _, at in line[i:] if at is not None), None)
        if upper is not None:
            plausible = (True if plausible is None else plausible) and claimed <= upper + allowance
    return before, plausible


CHECKS = ("correlation", "sequence", "chain", "envelope", "signatures", "timestamps", "objects", "finalization",
          "control")
ALL_OK = {k: "ok" for k in CHECKS}
EVAL_OK = {"subjectBound": True, "controlSetDigestMatches": True, "baselineDigestMatches": True,
           "signatureValid": True, "timestampValid": True, "objectsComplete": True, "valid": True, "overall": "PASS"}


def scenario(name, description, b, verdict, checks, *, binding="bound", missing=None, findings=None,
             evaluations=None, ascii_only=False, warnings=None) -> None:
    """warnings: substrings, and their exact number."""
    before, plausible = seal_time(b)
    exp = dict(ALL_OK)
    exp.update(checks)
    write(f"runs/{name}.json", {
        "description": description, "bundle": b,
        "expected": {
            "verdict": verdict, "checks": exp, "binding": binding, "missingSeqs": missing or [],
            "fingerprint": fingerprint(b), "findingsContain": findings or [],
            "warningsContain": warnings or [], "warningCount": len(warnings or []),
            "controlSealedBeforeRun": before, "eventTimesPlausible": plausible,
            "evaluations": evaluations if evaluations is not None else [EVAL_OK] * len(b.get("evaluations", [])),
        },
    }, ascii_only=ascii_only)


def standard(*, policy=POLICY, steps=STEPS, **kw):
    p: dict = {}
    control = control_artifact(p, policy=policy)
    arts = build_run(steps, p, control=control, **kw)
    return p, control, arts


def main() -> None:
    runs = HERE / "runs"
    if runs.is_dir():  # stale vectors must not survive a regeneration
        for f in runs.glob("*.json"):
            f.unlink()

    env = {"x": 1, "objects": []}
    plain = stub_sign(env, {}, CTY["event"], timestamp=None)
    hybrid = stub_sign(env, {}, CTY["event"], timestamp="2026-10-01T09:00:00Z", hybrid=True)
    flattened = {"protected": plain["signatures"][0]["protected"], "signature": plain["signatures"][0]["signature"]}
    write("signature-sha256.json", [
        {"name": "general-jws", "signature": plain, "expected": signature_sha256(plain)},
        {"name": "hybrid-mldsa-first", "description": "The ML-DSA entry is skipped; unprotected headers are ignored.",
         "signature": hybrid, "expected": signature_sha256(hybrid)},
        {"name": "flattened-jws", "signature": flattened, "expected": signature_sha256(plain)},
        {"name": "non-base64url-signature", "description": "Characters outside the base64url alphabet: no digest.",
         "signature": {"signatures": [dict(plain["signatures"][0], signature=plain["signatures"][0]["signature"] + "!!")]},
         "expected": None},
    ])

    p, control, arts = standard()
    ev = evaluation(p, control, arts[-1])
    scenario("01-finalized-digests-only", "Control basis, events sealed B-B, a timestamped run_end and a PASS "
             "evaluation: three timestamps for the whole run. Digests only, so objects is 'warn'.",
             bundle(control, arts, [ev]), "run_finalized", {"objects": "warn"})
    scenario("02-finalized-with-payloads", "The same run with every payload supplied: every check ok.",
             bundle(control, arts, [ev], p), "run_finalized", {})

    p, control, arts = standard(finish=False)
    scenario("03-open", "No run_end yet: run_open; finalization and timestamps warn.", bundle(control, arts),
             "run_open", {"objects": "warn", "finalization": "warn", "timestamps": "warn"})

    p, control, arts = standard()
    del arts[2]
    scenario("04-withheld-event", "seq 2 removed: the gap is listed and the chain breaks.", bundle(control, arts),
             "run_invalid", {"objects": "warn", "sequence": "bad", "chain": "bad"}, missing=[2],
             findings=["Sequence gap"])

    p, control, arts = standard()
    arts[3]["envelope"]["step"]["eventTime"] = "2026-10-01T08:58:00.000Z"
    scenario("05-envelope-edited", "model_output's envelope was edited after signing (its eventTime moved before "
             "the control basis).", bundle(control, arts), "run_invalid", {"objects": "bad"},
             findings=["the signature does not cover this envelope"],
             warnings=["earlier than the Control Artifact's timestamp"])

    p, control, arts = standard()
    arts[2]["envelope"]["activity"]["correlationId"] = "urn:uuid:00000000-0000-4000-9000-000000000002"
    resign(arts[2], CTY["event"])
    rechain(arts, 3)
    scenario("06-cross-run-splice", "A validly signed event of another run is spliced in (links recomputed).",
             bundle(control, arts), "run_invalid", {"objects": "warn", "correlation": "bad"},
             findings=["cross-run splice"])

    p, control, arts = standard(end_stamp=False)
    scenario("07-run-end-unanchored", "run_end carries no timestamp: nothing anchors the chain.",
             bundle(control, arts), "run_invalid", {"objects": "warn", "timestamps": "bad", "finalization": "bad"},
             findings=["(run_end): a timestamp is required"])

    p, control, arts = standard(policy=dict(POLICY, everyEvents=2))
    scenario("08-cadence-violated", "The control basis signs everyEvents=2; seq 1 carries no timestamp.",
             bundle(control, arts), "run_invalid", {"objects": "warn", "timestamps": "bad"},
             findings=["seq 1 (tool_call): a timestamp is required"])

    p, control, arts = standard()
    scenario("09-run-only", "The control basis run_start binds is left out: control is bad, so leaving it out "
             "cannot turn an invalid run into a finalized one. The policy is unknown; timestamps warn.",
             bundle(None, arts), "run_invalid", {"objects": "warn", "control": "bad", "timestamps": "warn"},
             binding="run_only", findings=["which was not supplied"])
    p, control, arts = standard(policy=dict(POLICY, everyEvents=2))
    scenario("09b-run-only-hides-cadence", "08-cadence-violated without its control basis: still invalid.",
             bundle(None, arts), "run_invalid", {"objects": "warn", "control": "bad", "timestamps": "warn"},
             binding="run_only", findings=["which was not supplied"])

    p, control, arts = standard()
    other = control_artifact({}, n=2, tweak=lambda e: e["controlSet"].update(version="3"))
    scenario("10-control-swapped", "run_start binds another control basis than the one supplied.",
             bundle(other, arts), "run_invalid", {"objects": "warn", "control": "bad"}, binding="unbound",
             findings=["binds.controlArtifactSignatureSha256"])

    p, control, arts = standard()
    p["urn:example:unsigned"] = b"unsigned content"
    scenario("11-unsigned-payload", "A payload for a URI no artifact signed.", bundle(control, arts, (), p),
             "run_invalid", {"objects": "bad"}, findings=["is not a signed object of any artifact"])

    write_step = {"type": "tool_call", "minute": 3, "consequential": True,
                  "step": {"tool": {"name": "close_ticket", "operation": "write"}},
                  "objects": [("tool-arguments", "application/json", b'{"ticket":"4411"}')]}
    tail = dict(STEPS[2], minute=4)
    p, control, arts = standard(policy=dict(POLICY, consequential=True), steps=STEPS[:2] + [write_step, tail])
    scenario("12-consequential-unanchored", "consequential: true in the policy, but the write carries no "
             "timestamp.", bundle(control, arts), "run_invalid", {"objects": "warn", "timestamps": "bad"},
             findings=["seq 3 (tool_call): a timestamp is required"])
    p, control, arts = standard(policy=dict(POLICY, consequential=True),
                                steps=STEPS[:2] + [dict(write_step, stamp=True), tail])
    scenario("13-consequential-anchored", "consequential: true and the write is timestamped: finalized.",
             bundle(control, arts), "run_finalized", {"objects": "warn"})
    p, control, arts = standard(steps=STEPS[:2] + [write_step, tail])
    scenario("14-consequential-default", "The default policy: a consequential write is sealed B-B and the run "
             "finalizes.", bundle(control, arts), "run_finalized", {"objects": "warn"})

    p, control, arts = standard(start_type="model_output")
    scenario("15-no-run-start", "seq 0 is not a run_start.", bundle(control, arts), "run_invalid",
             {"objects": "warn", "sequence": "bad"}, findings=["The run has no run_start"])

    steps = [STEPS[0], {"type": "run_end", "minute": 2, "stamp": True, "step": {"runDisposition": "completed"}},
             dict(STEPS[1], minute=3), dict(STEPS[2], minute=4)]
    p, control, arts = standard(steps=steps)
    scenario("16-multiple-run-end", "A run_end in the middle and another at the end.", bundle(control, arts),
             "run_invalid", {"objects": "warn", "finalization": "bad"}, findings=["More than one run_end"])

    def wrong_final(seq, e):
        if e["step"]["type"] == "run_end":
            e["step"]["finalSeq"] = seq - 1
    p, control, arts = standard(tweak=wrong_final)
    scenario("17-final-seq-not-own", "run_end's finalSeq names the previous seq instead of its own.",
             bundle(control, arts), "run_invalid", {"objects": "warn", "finalization": "bad"},
             findings=["finalSeq"])

    def bad_tool(seq, e):
        if seq == 1:
            e["step"]["tool"] = "lookup_ticket"
    p, control, arts = standard(tweak=bad_tool)
    scenario("18-schema-violation", "tool_call's tool is a string, not {name, operation}.", bundle(control, arts),
             "run_invalid", {"objects": "warn", "envelope": "bad"}, findings=["step.tool must be of type object"])

    p, control, arts = standard()
    arts[2]["signature"]["x-note"] = "\ud800"
    scenario("19-not-i-json", "seq 2's signature carries a lone surrogate. A verdict, never an exception.",
             bundle(control, arts), "run_invalid",
             {"objects": "bad", "sequence": "bad", "chain": "bad", "envelope": "bad", "signatures": "bad"},
             missing=[2], findings=["not valid I-JSON"], ascii_only=True)

    p, control, arts = standard()
    arts[2]["envelope"]["extensions"] = {"com.example.x": {"count": 2 ** 53 + 1}}
    resign(arts[2], CTY["event"])
    rechain(arts, 3)
    scenario("20-integer-beyond-i-json", "seq 2 carries 2^53+1: not valid I-JSON.", bundle(control, arts),
             "run_invalid", {"objects": "bad", "sequence": "bad", "chain": "bad", "envelope": "bad",
                             "signatures": "bad"}, missing=[2], findings=["not valid I-JSON"])

    p, control, arts = standard(tweak=lambda seq, e: e["activity"].update(correlationId=""))
    scenario("21-empty-correlation", "No event carries a non-empty correlationId.", bundle(control, arts),
             "run_invalid", {"objects": "warn", "correlation": "bad", "envelope": "bad"},
             findings=["no signed correlationId"])

    forged = STEPS[:2] + [{"type": "human_approval", "minute": 3, "stamp": True, "cert": CERT_B,
                           "step": {"decision": "approved", "approver": "urn:example:approver:42"}}]
    p, control, arts = standard(steps=forged, end_cert=CERT_B)
    scenario("22-foreign-signer-appended", "Events after seq 2 are forged and sealed by another certificate; "
             "their links compute.", bundle(control, arts), "run_invalid", {"objects": "warn", "signatures": "bad"},
             findings=["signed by a different certificate than the run"])

    p = {}
    control = control_artifact(p, cert=CERT_B)
    arts = build_run(STEPS, p, control=control)
    scenario("23-control-other-signer", "The control basis is signed by another certificate than the run.",
             bundle(control, arts), "run_invalid", {"objects": "warn", "signatures": "bad"},
             findings=["control artifact: signed by a different certificate than the run"])

    p, control, arts = standard()
    first = arts[2]["signature"]["signatures"][0]
    arts[2]["signature"]["signatures"].append(dict(first, signature=b64u(b"another classical signature")))
    scenario("24-two-classical-signatures", "seq 2 carries two classical signature entries.", bundle(control, arts),
             "run_invalid", {"objects": "warn", "signatures": "bad"}, findings=["exactly one classical signature"])

    dup = copy.deepcopy(STEPS)
    dup[1]["dupAlg"] = True
    p, control, arts = standard(steps=dup)
    scenario("25-duplicate-header-member", "seq 2's protected header repeats \"alg\": no signer can be "
             "established.", bundle(control, arts), "run_invalid", {"objects": "warn", "signatures": "bad"},
             findings=["no readable protected header"])

    stamped = [dict(s, stamp=True) for s in STEPS]
    per_event = dict(POLICY, profile="per-event")
    p, control, arts = standard(policy=per_event, steps=stamped, start_stamp=True)
    scenario("26-per-event", "per-event: every event timestamped.", bundle(control, arts), "run_finalized",
             {"objects": "warn"})
    p, control, arts = standard(policy=per_event, steps=[stamped[0], dict(stamped[1], stamp=False), stamped[2]],
                                start_stamp=True)
    scenario("27-per-event-missing", "per-event, but seq 2 carries no timestamp.", bundle(control, arts),
             "run_invalid", {"objects": "warn", "timestamps": "bad"}, findings=["seq 2 (tool_result): a timestamp"])

    checkpoint = {"type": "checkpoint", "minute": 3, "stamp": True, "step": {"detail": "idle"}}
    p, control, arts = standard(steps=STEPS[:2] + [checkpoint, tail])
    scenario("28-checkpoint", "A checkpoint declares and carries a timestamp.", bundle(control, arts),
             "run_finalized", {"objects": "warn"})

    def declare(seq, e):
        if seq == 1:
            e["step"]["timestamp"] = "required"
    p, control, arts = standard(tweak=declare)
    scenario("29-declared-unstamped", "seq 1 declares timestamp \"required\" but carries none.",
             bundle(control, arts), "run_invalid", {"objects": "warn", "timestamps": "bad"},
             findings=["seq 1 (tool_call): a timestamp is required"])

    late = [STEPS[0], STEPS[1], dict(STEPS[2], minute=5)]
    every = dict(POLICY, everySeconds=300)
    p, control, arts = standard(policy=every, steps=[late[0], late[1], dict(late[2], stamp=True)])
    scenario("30-every-seconds", "everySeconds=300; seq 3 is exactly 300 s after run_start and timestamped.",
             bundle(control, arts), "run_finalized", {"objects": "warn"})
    p, control, arts = standard(policy=every, steps=late)
    scenario("31-every-seconds-unstamped", "everySeconds=300; seq 3 is 300 s later but unstamped.",
             bundle(control, arts), "run_invalid", {"objects": "warn", "timestamps": "bad"},
             findings=["seq 3 (model_output): a timestamp is required"])

    def rebind(seq, e):
        if seq == 2:
            e["binds"] = {"controlArtifactSignatureSha256": "0" * 64}
    p, control, arts = standard(tweak=rebind)
    scenario("32-later-event-binds-other-control", "seq 2 binds another control basis than run_start.",
             bundle(control, arts), "run_invalid", {"objects": "warn", "control": "bad"},
             findings=["binds another control artifact"])

    p = {}
    control = control_artifact(p, policy=None)
    arts = build_run(STEPS, p, control=control)
    scenario("33-control-without-policy", "The control basis signs no timestampPolicy: the defaults apply, with a "
             "warning.", bundle(control, arts), "run_finalized", {"objects": "warn"},
             warnings=["signs no timestampPolicy"])

    p, control, arts = standard(tweak=lambda seq, e: e.update(evidenceId="urn:uuid:" + e["evidenceId"]))
    scenario("34-urn-uuid-accepted", "Events use the urn:uuid: form of evidenceId: accepted.",
             bundle(control, arts), "run_finalized", {"objects": "warn"})

    p, control, arts = standard()
    ev = evaluation(p, control, arts[-1], tweak=lambda e: e["subject"].update(runEndSignatureSha256="0" * 64))
    scenario("35-evaluation-wrong-subject", "The evaluation names another run_end. Evaluations never change the "
             "run verdict.", bundle(control, arts, [ev]), "run_finalized", {"objects": "warn"},
             evaluations=[dict(EVAL_OK, subjectBound=False, valid=False)], warnings=["which is not in the bundle"])
    p, control, arts = standard()
    ev = evaluation(p, control, arts[-1], control_set_bytes=b'{"controls":["ticket-closed"]}')
    scenario("36-evaluation-other-control-set", "The evaluation carries another control set under the same URI.",
             bundle(control, arts, [ev]), "run_finalized", {"objects": "warn"},
             evaluations=[dict(EVAL_OK, controlSetDigestMatches=False, valid=False)])
    p, control, arts = standard()
    ev = evaluation(p, control, arts[-1], baseline_bytes=b'{"ticket":"4411","status":"closed"}')
    scenario("37-evaluation-other-baseline", "The evaluation's baseline differs from the one sealed before the run.",
             bundle(control, arts, [ev]), "run_finalized", {"objects": "warn"},
             evaluations=[dict(EVAL_OK, baselineDigestMatches=False, valid=False)])
    p, control, arts = standard()
    ev = evaluation(p, control, arts[-1], tweak=lambda e: e.update(
        overall="FAIL", controls=[{"id": "ticket-closed", "result": "PASS"},
                                  {"id": "owner-unchanged", "result": "FAIL", "detail": "owner changed"}]))
    scenario("38-evaluation-fail-reported", "A FAIL evaluation is reported unchanged; the run itself finalizes.",
             bundle(control, arts, [ev]), "run_finalized", {"objects": "warn"},
             evaluations=[dict(EVAL_OK, overall="FAIL")])

    p = {}
    control = control_artifact(p, stamp_at=None)
    arts = build_run(STEPS, p, control=control)
    scenario("40-control-unstamped", "The control basis carries no timestamp.", bundle(control, arts), "run_invalid",
             {"objects": "warn", "control": "bad"}, findings=["control artifact: a timestamp is required"])

    p = {}
    control = control_artifact(p, tweak=lambda e: e["activity"].update(
        correlationId="urn:uuid:00000000-0000-4000-9000-000000000002"))
    arts = build_run(STEPS, p, control=control)
    scenario("41-control-other-correlation", "The control basis belongs to another run.", bundle(control, arts),
             "run_invalid", {"objects": "warn", "control": "bad"}, findings=["its signed correlationId is not the run's"])

    p = {}
    control = control_artifact(p, tweak=lambda e: e["agent"].update(id="urn:example:agent:other"))
    arts = build_run(STEPS, p, control=control)
    scenario("42-control-other-agent", "The control basis names another agent than the run's actor.",
             bundle(control, arts), "run_invalid", {"objects": "warn", "control": "bad"},
             findings=["is not the run's actor"])

    p, control, arts = standard(policy=dict(POLICY, profile="fast"))
    scenario("43-malformed-policy", "The signed timestampPolicy names an unknown profile.", bundle(control, arts),
             "run_invalid", {"objects": "warn", "envelope": "bad", "timestamps": "bad"},
             findings=["timestampPolicy.profile must be one of", "the signed timestampPolicy is malformed"])

    p, control, arts = standard(steps=[STEPS[0], dict(STEPS[1], cty=CTY["control"]), STEPS[2]])
    scenario("44-wrong-content-type", "seq 2 is signed under the Control Artifact's content type: one profile "
             "presented as another.", bundle(control, arts), "run_invalid", {"objects": "warn", "signatures": "bad"},
             findings=["seq 2: its signed content type (sigD.ctys[0]) is 'application/vnd.sigill.agent-control+json'"])

    def other_version(seq, e):
        if seq == 2:
            e["actor"]["version"] = "2.5.0"
    p, control, arts = standard(tweak=other_version)
    scenario("45-actor-mismatch", "seq 2 is signed under another agent version than run_start.",
             bundle(control, arts), "run_invalid", {"objects": "warn", "envelope": "bad"},
             findings=["seq 2: signed actor/version"])

    steps = [STEPS[0], {"type": "run_end", "minute": 2, "stamp": True, "step": {"runDisposition": "completed"}},
             dict(STEPS[1], minute=3), dict(STEPS[2], minute=4)]
    p, control, arts = standard(steps=steps, finish=False)
    scenario("46-run-end-not-last", "Events follow the only run_end.", bundle(control, arts), "run_invalid",
             {"objects": "warn", "finalization": "bad"}, findings=["run_end is not the last artifact"])

    def paused(seq, e):
        if e["step"]["type"] == "run_end":
            e["step"]["runDisposition"] = "paused"
    p, control, arts = standard(tweak=paused)
    scenario("47-bad-disposition", "run_end's runDisposition is not completed, aborted or failed.",
             bundle(control, arts), "run_invalid", {"objects": "warn", "envelope": "bad", "finalization": "bad"},
             findings=["carries no valid runDisposition"])

    def wrong_prev(seq, e):
        if e["step"]["type"] == "run_end":
            e["step"]["finalPrevSignatureSha256"] = "0" * 64
    p, control, arts = standard(tweak=wrong_prev)
    scenario("48-final-prev-not-own", "run_end's finalPrevSignatureSha256 is not its own chain link.",
             bundle(control, arts), "run_invalid", {"objects": "warn", "finalization": "bad"},
             findings=["finalPrevSignatureSha256 is not its own"])

    p, control, arts = standard()
    ev = evaluation(p, control, arts[-1], cert=CERT_A)
    scenario("49-evaluation-by-the-run-signer", "The run evaluates itself: a warning, never a failure.",
             bundle(control, arts, [ev]), "run_finalized", {"objects": "warn"},
             warnings=["is signed by the run's own certificate"])

    p = {}
    control = control_artifact(p, policy=per_event, stamp_at="2026-10-01T09:10:00Z")
    arts = build_run([dict(s, stamp=True) for s in STEPS], p, control=control, start_stamp=True)
    scenario("50-control-sealed-after-run", "The control basis was timestamped after run_start: a warning.",
             bundle(control, arts), "run_finalized", {"objects": "warn"},
             warnings=["later than the run's first timestamp", "earlier than the Control Artifact's timestamp"])

    p, control, arts = standard(end_stamp_at="2026-10-01T09:03:00Z")
    scenario("51-event-time-implausible", "run_end claims an eventTime a minute after its own seal time: a warning.",
             bundle(control, arts), "run_finalized", {"objects": "warn"},
             warnings=["later than the timestamp that bounds it"])

    def optional_control(e):
        e["agent"]["identityRef"] = "urn:example:identity:support-triage"
        e["actor"]["displayHint"] = "Production harness"
        e["objects"][0]["encoding"] = "utf-8"
        e["objects"][0]["metadata"] = {"lines": 1}

    def optional_event(seq, e):
        if e["objects"]:
            e["objects"][0]["encoding"] = "binary"
            e["objects"][0]["metadata"] = {"producer": {"version": 1}}
    p = {}
    control = control_artifact(p, tweak=optional_control)
    arts = build_run(STEPS, p, control=control, tweak=optional_event)
    scenario("52-optional-fields", "Every optional field the schemas allow is present and valid.",
             bundle(control, arts, (), p), "run_finalized", {})

    p, control, arts = standard()
    scenario("53-control-only", "A control basis whose run has not started: control_only, run_open.",
             bundle(control, []), "run_open", {"objects": "warn", "timestamps": "warn", "finalization": "warn"},
             binding="control_only")

    p, control, arts = standard()
    ev = evaluation(p, control, arts[-1], tweak=lambda e: e.update(
        overall="FAIL", controls=[{"id": "ticket-closed", "result": "PASS"},
                                  {"id": "owner-unchanged", "result": "FAIL", "detail": "owner changed"}]))
    ev["envelope"]["overall"] = "PASS"
    ev["envelope"]["controls"][1] = {"id": "owner-unchanged", "result": "PASS"}
    scenario("54-evaluation-envelope-edited", "A FAIL evaluation edited to PASS after signing: its signature no longer "
             "covers its envelope, so it is not valid.", bundle(control, arts, [ev]), "run_finalized",
             {"objects": "warn"}, evaluations=[dict(EVAL_OK, signatureValid=False, objectsComplete=False, valid=False)])

    steps = [STEPS[0], dict(STEPS[1], minute=2), {"type": "model_output", "minute": 3, "step": {},
             "objects": [("model-output", "text/plain", b"Done.")]}]
    def far(seq, e):
        if seq == 1:
            e["step"]["eventTime"] = "2031-01-01T00:00:00.000Z"
        if seq == 2:
            e["step"]["eventTime"] = "2020-01-01T00:00:00.000Z"
    p, control, arts = standard(steps=steps, tweak=far)
    scenario("55-event-times-outside-the-window", "Unstamped events claim times in 2031 and 2020: both outside the "
             "window between the control basis and run_end's timestamp.", bundle(control, arts), "run_finalized",
             {"objects": "warn"}, warnings=["earlier than the Control Artifact's timestamp",
                                            "later than the timestamp that bounds it"])

    p, control, arts = standard()
    ev = evaluation(p, control, arts[-1])
    p["urn:example:obj:observed-state"] = b'{"ticket":"4411","status":"closed","note":"all good"}'
    scenario("56-evaluation-observed-state-replaced", "The evaluation's observed state is swapped for other bytes: "
             "the evaluation is not valid; the run is unaffected.", bundle(control, arts, [ev], p), "run_finalized", {},
             evaluations=[dict(EVAL_OK, objectsComplete=False, valid=False)])

    p, control, arts = standard()
    ev = evaluation(p, control, arts[-1], control_set_bytes=b'{"controls":["ticket-closed"]}')
    cs_uri = "urn:example:obj:control-set"
    ev["objectDigests"][cs_uri] = control["objectDigests"][cs_uri]  # unsigned metadata lies; the signed hashV does not
    scenario("57-evaluation-unsigned-basis", "An evaluation signed over another control set, whose unsigned "
             "objectDigests claim the sealed one: only signed digests count.", bundle(control, arts, [ev]),
             "run_finalized", {"objects": "warn"},
             evaluations=[dict(EVAL_OK, controlSetDigestMatches=False, objectsComplete=False, valid=False)])

    p, control, arts = standard()
    reused = arts[0]["envelope"]["objects"][0]["uri"]
    own = arts[1]["envelope"]["objects"][0]["uri"]
    arts[1]["envelope"]["objects"][0]["uri"] = reused
    arts[1]["objectDigests"] = {reused: arts[1]["objectDigests"][own]}
    resign(arts[1], CTY["event"])
    rechain(arts, 2)
    scenario("58-same-uri-different-content", "seq 1 reuses seq 0's object URI for different content.",
             bundle(control, arts), "run_invalid", {"objects": "bad"},
             findings=[f"Object '{reused}' is signed with different content in seq 0 and seq 1"])

    def reorder(a: dict) -> None:
        """Swap the first two signed objects in sigD (pars, hashV, ctys alike), leaving the envelope's order."""
        e = a["signature"]["signatures"][0]
        h = json.loads(base64.urlsafe_b64decode(e["protected"] + "=" * (-len(e["protected"]) % 4)))
        for k in ("pars", "hashV", "ctys"):
            h["sigD"][k][1], h["sigD"][k][2] = h["sigD"][k][2], h["sigD"][k][1]
        e["protected"] = b64u(jcs.canonicalize(h))
        e["signature"] = b64u(hashlib.sha256(e["protected"].encode()).digest())
    p = {}
    control = control_artifact(p)
    reorder(control)
    arts = build_run(STEPS, p, control=control)
    scenario("59-signed-object-order", "The Control Artifact's sigD lists its objects in another order than the "
             "envelope: every URI/digest pair matches, their positions do not.", bundle(control, arts), "run_invalid",
             {"objects": "bad", "control": "bad"}, findings=["sigD.pars is not the envelope followed by objects[] in order"])

    p, control, arts = standard()
    e = arts[-1]["signature"]["signatures"][0]
    h = base64.urlsafe_b64decode(e["protected"] + "=" * (-len(e["protected"]) % 4))
    # Written as a literal: JCS serializes numbers as IEEE doubles and would round 2^53+1 to 2^53.
    e["protected"] = b64u(h.replace(b'{"alg":"ES256"', b'{"alg":"ES256","private":9007199254740993', 1))
    e["signature"] = b64u(hashlib.sha256(e["protected"].encode()).digest())
    scenario("60-header-integer-beyond-i-json", "run_end's protected header carries 2^53+1: the header is not I-JSON, "
             "so no signer can be established.", bundle(control, arts), "run_invalid",
             {"objects": "warn", "signatures": "bad"}, findings=["no readable protected header"])

    def impossible(seq, e):
        if seq == 2:
            e["step"]["eventTime"] = "2026-02-30T09:02:00.000Z"
    p, control, arts = standard(tweak=impossible)
    scenario("61-impossible-date", "seq 2 claims February 30th: not an RFC 3339 date-time.", bundle(control, arts),
             "run_invalid", {"objects": "warn", "envelope": "bad"}, findings=["step.eventTime is not a valid date-time"])

    p, control, arts = standard()
    ev = evaluation(p, control, arts[-1])
    scenario("62-control-only-run-withheld", "A control basis and an evaluation of its finished run, but no events: "
             "the evaluation proves the run exists.", bundle(control, [], [ev]), "run_open",
             {"objects": "warn", "timestamps": "warn", "finalization": "warn"}, binding="control_only",
             evaluations=[dict(EVAL_OK, subjectBound=False, valid=False)], warnings=["which is not in the bundle"])

    p, control, arts = standard()
    deep: dict = {}
    for _ in range(70):
        deep = {"a": deep}
    nested = bundle(control, arts)
    nested["artifacts"][2]["envelope"]["extensions"] = {"com.example.deep": deep}
    write("runs/63-nesting-too-deep.json", {
        "description": "An envelope nests 70 levels deep: beyond the 64 every implementation accepts.",
        "bundleText": json.dumps(nested, separators=(",", ":")),
        "expected": {"parseError": "nests deeper than 64 levels"},
    })

    p, control, arts = standard()
    arts[-1]["signature"]["signatures"][0]["header"]["stubTimestamp"]["trust"] = "untrusted"
    scenario("64-tsa-untrusted", "run_end's timestamp comes from a TSA the signature service does not trust: a "
             "warning, never a verdict change.", bundle(control, arts), "run_finalized", {"objects": "warn"},
             warnings=["TSA trust not established for the timestamps of: seq 4 (trust: untrusted)"])

    p, control, arts = standard()
    text = json.dumps(bundle(control, arts), separators=(",", ":"))
    needle = '"consequential":false'
    assert needle in text
    write("runs/39-duplicate-member.json", {
        "description": "An event repeats \"consequential\". I-JSON forbids duplicate names; parsers disagree on which "
                       "value wins, so the bundle must not parse.",
        "bundleText": text.replace(needle, needle + ',"consequential":true', 1),
        "expected": {"parseError": "duplicate member name"},
    })


if __name__ == "__main__":
    main()
