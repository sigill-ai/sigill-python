# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Reference generator for the AgentExecutionProfileV1 test vectors.

Deterministic: fixed identifiers, times and bytes, so every run produces
byte-identical files. Signatures are produced by the *stub signer* described
in README.md — not real JAdES — so the vectors exercise the profile layer
(chain, sequence, policy, finalization, identity, fingerprint) without
depending on issued certificates.

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
EXT = "ai.sigill.agent-execution"
ENVELOPE_URI = "urn:sigill:envelope"
AGENT_ID = "urn:example:agent:support-triage"
AGENT_VERSION = "2.4.0"
TENANT = "tenant-example"
MODEL = {"provider": "example-ai", "name": "example-model-1"}


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sha256hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def write(name: str, value, *, ascii_only: bool = False) -> None:
    path = HERE / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=ascii_only) + "\n", encoding="utf-8")


# ── Stub signer (see README.md) ─────────────────────────────────────────────

def stub_sign(envelope: dict, digests: dict[str, str], *, timestamp: str | None, valid_ts: bool = True,
              hybrid: bool = False) -> dict:
    pars = [ENVELOPE_URI] + [o["uri"] for o in envelope["objects"]]
    env_hex = sha256hex(jcs.canonicalize(envelope))
    hash_v = [b64u(bytes.fromhex(env_hex))] + [b64u(bytes.fromhex(digests[u])) for u in pars[1:]]
    protected = b64u(jcs.canonicalize({"alg": "ES256", "sigD": {"pars": pars, "hashV": hash_v}}))
    entry: dict = {"protected": protected, "signature": b64u(hashlib.sha256(protected.encode()).digest())}
    if timestamp is not None:
        entry["header"] = {"stubTimestamp": {"genTime": timestamp, "valid": valid_ts}}
    entries = [entry]
    if hybrid:
        pq = b64u(jcs.canonicalize({"alg": "ML-DSA-87"}))
        entries.insert(0, {"protected": pq, "signature": b64u(b"post-quantum signature value")})
    return {"signatures": entries}


def chain_digest(jws: dict) -> str:
    for e in jws["signatures"]:
        alg = json.loads(base64.urlsafe_b64decode(e["protected"] + "=" * (-len(e["protected"]) % 4)))["alg"]
        if alg.upper().startswith("ML-DSA"):
            continue
        return sha256hex(base64.urlsafe_b64decode(e["signature"] + "=" * (-len(e["signature"]) % 4)))
    raise ValueError("no classical signature")


# ── Envelopes ───────────────────────────────────────────────────────────────

def uuid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def envelope(evidence_n: int, at: str, category: str, activity: str, correlation: str | None,
             parent: str | None, objects: list[tuple[str, str, str, str, bytes]], seq: int | None,
             prev: str | None, ext: dict) -> dict:
    activity_node: dict = {"name": activity}
    if correlation is not None:
        activity_node["correlationId"] = correlation
    if parent is not None:
        activity_node["parentEvidenceId"] = parent
    kinds = {}
    objs = []
    for uri, kind, role, ctype, data in objects:
        objs.append({"uri": uri, "role": role, "contentType": ctype, "sizeBytes": len(data)})
        kinds[uri] = kind
    ext = dict(ext)
    ext["objectKinds"] = kinds
    env = {
        "schemaName": "AiEvidenceEnvelope",
        "schemaVersion": "2",
        "evidenceId": uuid(evidence_n),
        "createdAt": at,
        "purpose": {"category": category, "businessContext": "support-triage"},
        "actor": {"type": "agent", "id": AGENT_ID, "tenantId": TENANT},
        "activity": activity_node,
        "model": dict(MODEL),
        "objects": objs,
    }
    if seq is not None:
        chain = {"seq": seq}
        if prev is not None:
            chain["prevSignatureSha256"] = prev
        env["chain"] = chain
    env["extensions"] = {EXT: ext}
    return env


CONFIG = {
    "instruction-set": ("urn:example:obj:instruction-set", "text/plain", b"You triage support tickets. Never close a ticket without approval."),
    "tool-manifest": ("urn:example:obj:tool-manifest", "application/json", b'{"tools":[{"name":"lookup_ticket"},{"name":"close_ticket"}]}'),
    "model-config": ("urn:example:obj:model-config", "application/json", b'{"max_tokens":1024,"temperature":0}'),
    "execution-policy": ("urn:example:obj:execution-policy", "application/json", b'{"allow":["lookup_ticket","close_ticket"],"writeRequiresApproval":true}'),
}
MANIFEST = jcs.canonicalize({"agentId": AGENT_ID, "agentVersion": AGENT_VERSION, "displayName": "Support triage",
                             "model": MODEL})
REGISTRATION = jcs.canonicalize({"action": "agent-registration", "agentId": AGENT_ID, "mode": "automatic-on-first-use",
                                 "registeredAt": "2026-10-01T08:00:00.000Z"})


def config_digest(manifest: bytes, cfg: dict[str, bytes]) -> str:
    return sha256hex(jcs.canonicalize({
        "agentManifest": sha256hex(manifest),
        "instructionSet": sha256hex(cfg["instruction-set"]),
        "toolManifest": sha256hex(cfg["tool-manifest"]),
        "modelConfig": sha256hex(cfg["model-config"]),
        "executionPolicy": sha256hex(cfg["execution-policy"]),
    }))


CONFIG_BYTES = {k: v[2] for k, v in CONFIG.items()}
CONFIG_SHA = config_digest(MANIFEST, CONFIG_BYTES)


def identity_artifact(payloads: dict[str, bytes], *, ext_override: dict | None = None) -> dict:
    objs = [("urn:example:obj:agent-manifest", "agent-manifest", "input", "application/json", MANIFEST)]
    objs += [(uri, kind, "input", ctype, data) for kind, (uri, ctype, data) in CONFIG.items()]
    objs += [("urn:example:obj:registration", "registration-record", "input", "application/json", REGISTRATION)]
    ext = {
        "recordType": "agent-identity", "stepType": "record:agent-identity", "agentId": AGENT_ID,
        "agentVersion": AGENT_VERSION, "configSha256": CONFIG_SHA, "eventTime": "2026-10-01T08:00:00.000Z",
    }
    ext.update(ext_override or {})
    env = envelope(1, "2026-10-01T08:00:00.000Z", "agent-identity", "agent_identity", None, None, objs, None, None, ext)
    digests = {o[0]: sha256hex(o[4]) for o in objs}
    for o in objs:
        payloads[o[0]] = o[4]
    return {"envelope": env, "signature": stub_sign(env, digests, timestamp="2026-10-01T08:00:01Z"),
            "objectDigests": digests}


RUN = "urn:uuid:00000000-0000-4000-9000-000000000001"


def build_run(steps: list[dict], policy, payloads: dict[str, bytes], *, finish: bool = True,
              config_override: dict[str, bytes] | None = None, start_type: str = "run_start",
              start_extra_objects: list | None = None, tweak=None, identity: dict | None = None,
              ) -> tuple[dict, list[dict]]:
    """steps: [{type, minute, objects, consequential, stamp, ext}] after run_start.
    tweak(seq, envelope) edits an envelope before it is signed (producer-side non-conformance)."""
    identity = identity or identity_artifact(payloads)
    artifacts: list[dict] = []
    prev_sig = None
    prev_id = identity["envelope"]["evidenceId"]
    n = 100

    def seal(step_type: str, at: str, objs, ext: dict, stamp: bool, consequential: bool):
        nonlocal prev_sig, prev_id, n
        seq = len(artifacts)
        ext = dict(ext)
        ext.update({"stepType": step_type, "agentVersion": AGENT_VERSION, "eventTime": at,
                    "consequential": consequential, "timestamp": "required" if stamp else "none"})
        env = envelope(n, at, "agent-execution", step_type, RUN, prev_id, objs, seq, prev_sig, ext)
        if tweak is not None:
            tweak(seq, env)
        n += 1
        digests = {o[0]: sha256hex(o[4]) for o in objs}
        for o in objs:
            payloads[o[0]] = o[4]
        sig = stub_sign(env, digests, timestamp=at.replace(".000", "") if stamp else None)
        artifacts.append({"envelope": env, "signature": sig, "objectDigests": digests})
        prev_sig = chain_digest(sig)
        prev_id = env["evidenceId"]

    cfg = dict(CONFIG_BYTES)
    if config_override:
        cfg.update(config_override)
    start_objs = [(CONFIG[k][0] + ":run", k, "input", CONFIG[k][1], cfg[k]) for k in CONFIG]
    start_objs.append(("urn:example:obj:request", "user-request", "prompt", "text/plain", b"Ticket 4411: login fails after reset."))
    start_objs += start_extra_objects or []
    profile = policy["profile"] if isinstance(policy, dict) else "throughput"
    seal(start_type, "2026-10-01T09:00:00.000Z", start_objs, {
        "agentIdentityEvidenceId": identity["envelope"]["evidenceId"],
        "assuranceProfile": profile, "timestampPolicy": policy,
    }, (isinstance(policy, dict) and policy.get("runStart", False)) or profile == "per-event", False)
    for i, s in enumerate(steps):
        objs = [(f"urn:example:obj:step-{i}-{k}", k, role, ctype, data) for k, role, ctype, data in s.get("objects", [])]
        seal(s["type"], f"2026-10-01T09:{s['minute']:02d}:00.000Z", objs, s.get("ext", {}), s["stamp"],
             s.get("consequential", False))
    if finish:
        head = artifacts[-1]
        seal("run_end", f"2026-10-01T09:{steps[-1]['minute'] + 1:02d}:00.000Z", [], {
            "finalSeq": head["envelope"]["chain"]["seq"], "finalPrevSignatureSha256": chain_digest(head["signature"]),
            "runDisposition": "completed", "usage": {"inputTokens": 900, "outputTokens": 120},
        }, True, True)
    return identity, artifacts


THROUGHPUT = {"profile": "throughput", "everyEvents": 10, "everySeconds": 300, "runStart": False,
              "runEnd": True, "consequential": True}

STEPS = [
    {"type": "tool_call", "minute": 1, "ext": {"tool": "lookup_ticket"}, "stamp": False,
     "objects": [("tool-arguments", "input", "application/json", b'{"ticket":"4411"}')]},
    {"type": "tool_result", "minute": 2, "ext": {"tool": "lookup_ticket"}, "stamp": False,
     "objects": [("tool-result", "output", "application/json", b'{"status":"open","product":"web"}')]},
    {"type": "model_output", "minute": 3, "stamp": False,
     "objects": [("model-output", "output", "text/plain", b"Reset the session cache and retry.")]},
]


def bundle(identity, artifacts, payloads=None) -> dict:
    b = {"profile": "AgentExecutionProfileV1", "bundleVersion": "1", "correlationId": RUN,
         "agentIdentity": identity, "artifacts": artifacts}
    if payloads is not None:
        b["payloads"] = {u: base64.b64encode(d).decode() for u, d in sorted(payloads.items())}
    return b


def fingerprint(b: dict) -> str | None:
    try:
        return _fingerprint(b)
    except Exception:  # not valid I-JSON: the fingerprint is undefined (§8.1)
        return None


def _fingerprint(b: dict) -> str:
    def one(a):
        return {"e": sha256hex(jcs.canonicalize(a["envelope"])), "s": sha256hex(jcs.canonicalize(a["signature"])),
                "d": dict(sorted((a.get("objectDigests") or {}).items()))}
    arts = []
    for a in b["artifacts"]:
        seq = (a["envelope"].get("chain") or {}).get("seq", -1)
        arts.append({"seq": seq, **one(a)})
    arts.sort(key=lambda x: (x["seq"], x["e"]))
    ident = one(b["agentIdentity"]) if b.get("agentIdentity") else None
    pls = [{"uri": u, "sha256": sha256hex(base64.b64decode(v))} for u, v in sorted((b.get("payloads") or {}).items())]
    return sha256hex(jcs.canonicalize({"profile": b["profile"], "artifacts": arts, "identity": ident, "payloads": pls}))


def resign(art: dict, timestamp: str | None = "keep") -> None:
    """Re-sign an artifact with the stub after a deliberate edit (a producer-side forgery)."""
    old = art["signature"]["signatures"][-1].get("header", {}).get("stubTimestamp")
    ts = old["genTime"] if (timestamp == "keep" and old) else (None if timestamp == "keep" else timestamp)
    art["signature"] = stub_sign(art["envelope"], art["objectDigests"], timestamp=ts)


ALL_OK = {k: "ok" for k in ("correlation", "sequence", "chain", "envelope", "signatures", "timestamps",
                            "objects", "finalization", "identity")}


def scenario(name: str, description: str, b: dict, verdict: str, checks: dict, missing=None,
             findings_contain=None, ascii_only: bool = False) -> None:
    exp_checks = dict(ALL_OK)
    exp_checks.update(checks)
    write(f"runs/{name}.json", {
        "description": description,
        "bundle": b,
        "expected": {
            "verdict": verdict,
            "checks": exp_checks,
            "missingSeqs": missing or [],
            "fingerprint": fingerprint(b),
            "findingsContain": findings_contain or [],
        },
    }, ascii_only=ascii_only)


def main() -> None:
    # Chain digest vectors.
    env = {"x": 1, "objects": []}
    plain = stub_sign(env, {}, timestamp=None)
    hybrid = stub_sign(env, {}, timestamp="2026-10-01T09:00:00Z", hybrid=True)
    flattened = {"protected": plain["signatures"][0]["protected"], "signature": plain["signatures"][0]["signature"]}
    write("chain-digest.json", [
        {"name": "general-jws", "signature": plain, "expected": chain_digest(plain)},
        {"name": "hybrid-mldsa-first", "description": "The ML-DSA entry is skipped; unprotected headers are ignored.",
         "signature": hybrid, "expected": chain_digest(hybrid)},
        {"name": "flattened-jws", "signature": flattened, "expected": chain_digest(plain)},
    ])

    # Configuration digest vector.
    write("config-digest.json", {
        "agentManifest": base64.b64encode(MANIFEST).decode(),
        "instructionSet": base64.b64encode(CONFIG_BYTES["instruction-set"]).decode(),
        "toolManifest": base64.b64encode(CONFIG_BYTES["tool-manifest"]).decode(),
        "modelConfig": base64.b64encode(CONFIG_BYTES["model-config"]).decode(),
        "executionPolicy": base64.b64encode(CONFIG_BYTES["execution-policy"]).decode(),
        "expected": CONFIG_SHA,
    })

    # 01 — finalized, digests only.
    p: dict = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p)
    scenario("01-finalized-digests-only", "A finalized throughput run verified by digests only: every check passes; "
             "objects is 'warn' because no payload bytes were supplied.",
             bundle(ident, arts), "run_finalized", {"objects": "warn"})

    # 02 — finalized with payloads.
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p)
    scenario("02-finalized-with-payloads", "The same run with every payload supplied: all nine checks are ok.",
             bundle(ident, arts, p), "run_finalized", {})

    # 03 — open run.
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p, finish=False)
    scenario("03-open", "No run_end yet: run_open; finalization and timestamps warn.",
             bundle(ident, arts), "run_open", {"objects": "warn", "finalization": "warn", "timestamps": "warn"})

    # 04 — a step withheld.
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p)
    del arts[2]
    scenario("04-withheld-step", "seq 2 removed from the bundle: the sequence gap is listed and the chain breaks.",
             bundle(ident, arts), "run_invalid",
             {"objects": "warn", "sequence": "bad", "chain": "bad"}, missing=[2],
             findings_contain=["Sequence gap"])

    # 05 — envelope edited after signing.
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p)
    arts[3]["envelope"]["extensions"][EXT]["eventTime"] = "2026-10-01T08:59:00.000Z"
    scenario("05-envelope-edited", "model_output's envelope was edited after signing: the signature no longer "
             "covers it.", bundle(ident, arts), "run_invalid", {"objects": "bad"},
             findings_contain=["the signature does not cover this envelope"])

    # 06 — cross-run splice.
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p)
    arts[2]["envelope"]["activity"]["correlationId"] = "urn:uuid:00000000-0000-4000-9000-000000000002"
    resign(arts[2])
    scenario("06-cross-run-splice", "A validly signed step from another run is spliced in: correlation and chain "
             "fail.", bundle(ident, arts), "run_invalid",
             {"objects": "warn", "correlation": "bad", "chain": "bad"},
             findings_contain=["cross-run splice"])

    # 07 — run_end anchor missing.
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p)
    resign(arts[-1], timestamp=None)
    scenario("07-run-end-unanchored", "run_end carries no timestamp: timestamps and finalization fail.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "timestamps": "bad", "finalization": "bad"},
             findings_contain=["(run_end): a timestamp is required"])

    # 08 — cadence violated.
    policy = dict(THROUGHPUT, everyEvents=2)
    p = {}
    ident, arts = build_run(STEPS, policy, p)
    scenario("08-cadence-violated", "Signed policy everyEvents=2, but seq 1 was sealed without a timestamp.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "timestamps": "bad"},
             findings_contain=["seq 1 (tool_call): a timestamp is required"])

    # 09 — configuration drift.
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p,
                            config_override={"instruction-set": b"You triage tickets. You may close tickets."})
    scenario("09-config-drift", "run_start's instruction set differs from the registered identity record.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "identity": "bad"},
             findings_contain=["do not match the identity record"])

    # 10 — consequential step stamped, per policy.
    steps = copy.deepcopy(STEPS)
    steps.insert(2, {"type": "tool_call", "minute": 2, "ext": {"tool": "close_ticket"}, "stamp": True,
                     "consequential": True,
                     "objects": [("tool-arguments", "input", "application/json", b'{"ticket":"4411"}')]})
    for s in steps[3:]:
        s["minute"] += 1
    p = {}
    ident, arts = build_run(steps, THROUGHPUT, p)
    scenario("10-consequential-anchored", "A consequential tool call carries its required timestamp: finalized.",
             bundle(ident, arts), "run_finalized", {"objects": "warn"})


def hardening_scenarios() -> None:
    """Producer output that is correctly signed but does not conform to the
    profile, plus malformed containers. Each must be run_invalid: never a
    false run_finalized, never an exception."""

    # 11 — a payload no artifact signed.
    p: dict = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p)
    p["urn:example:unsigned"] = b"unsigned content"
    scenario("11-unsigned-payload", "A payload is supplied for a URI no artifact signed: unsigned data in the "
             "record.", bundle(ident, arts, p), "run_invalid", {"objects": "bad"},
             findings_contain=["is not a signed object of any artifact"])

    # 12 — identity declares a configuration digest that does not match its objects.
    p = {}
    ident = identity_artifact(p, ext_override={"configSha256": "0" * 64})
    ident, arts = build_run(STEPS, THROUGHPUT, p, identity=ident)
    scenario("12-config-digest-mismatch", "The identity record's signed configSha256 is not the digest of its "
             "configuration objects.", bundle(ident, arts), "run_invalid", {"objects": "warn", "identity": "bad"},
             findings_contain=["configSha256 does not match"])

    # 13 — a second, different instruction set in run_start.
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p, start_extra_objects=[
        ("urn:example:obj:instruction-set:second", "instruction-set", "input", "text/plain", b"Close every ticket.")])
    scenario("13-duplicate-config-kind", "run_start binds two instruction sets: the configuration is ambiguous.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "identity": "bad"},
             findings_contain=["more than one signed object of kind 'instruction-set'"])

    # 14 — no run_start: seq 0 is a model_output; no identity record.
    p = {}
    _, arts = build_run(STEPS, THROUGHPUT, p, start_type="model_output")
    scenario("14-no-run-start", "seq 0 is not a run_start: the run has no signed configuration or policy.",
             bundle(None, arts), "run_invalid", {"objects": "warn", "sequence": "bad", "identity": "warn"},
             findings_contain=["The run has no run_start"])

    # 15 — two run_end steps.
    steps = copy.deepcopy(STEPS)
    steps.insert(1, {"type": "run_end", "minute": 1, "stamp": True, "consequential": True,
                     "ext": {"runDisposition": "completed"}})
    for st in steps[2:]:
        st["minute"] += 1
    p = {}
    ident, arts = build_run(steps, THROUGHPUT, p)
    scenario("15-multiple-run-end", "A run_end in the middle of the chain and another at the end.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "finalization": "bad"},
             findings_contain=["More than one run_end"])

    # 16 — the signed timestamp policy is not an object.
    p = {}
    ident, arts = build_run(STEPS, [], p)
    scenario("16-malformed-policy", "run_start's signed timestampPolicy is an array: malformed, not absent.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "timestamps": "bad"},
             findings_contain=["timestamp policy is malformed"])

    # 17 — not a v2/profile envelope: model is an array, actor is not an agent.
    def bad_shape(seq, env):
        if seq == 0:
            env["model"] = ["not a model"]
            env["actor"]["type"] = "human"
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p, tweak=bad_shape)
    scenario("17-malformed-envelope", "run_start is signed but is not a well-formed v2 agent envelope.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "envelope": "bad"},
             findings_contain=["model must be of type object", "actor.type must be 'agent'"])

    # 18 — a signature that is not valid I-JSON (lone surrogate).
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p)
    arts[2]["signature"]["x-note"] = "\ud800"
    scenario("18-not-i-json", "seq 2's signature carries a lone surrogate: not valid I-JSON. A verdict, never an "
             "exception.", bundle(ident, arts), "run_invalid",
             {"objects": "bad", "sequence": "bad", "chain": "bad", "envelope": "bad", "signatures": "bad"},
             missing=[2], findings_contain=["not valid I-JSON"], ascii_only=True)


def schema_scenarios() -> None:
    """Optional v2 sections are optional to supply, never exempt from
    validation; and the run identifier must be signed on every step."""

    def full_optional(seq, env):
        if seq == 1:
            env["sourceTrace"] = [{
                "sourceId": "kb-1182", "sourceType": "kb-article", "sourceUri": "urn:example:kb:1182",
                "snapshotHash": {"alg": "SHA-256", "hex": "ab" * 32, "sizeBytes": 2048},
                "retrievedAt": "2026-10-01T09:00:30Z",
            }]
            env["objects"][0]["metadata"] = {"rank": 1, "score": 0.92, "source": "urn:example:kb:1182",
                                             "language": "en", "x-producer-field": "allowed"}
        if seq == 3:
            env["processingMetadata"] = {
                "startedAt": "2026-10-01T09:02:30Z", "completedAt": "2026-10-01T09:03:00.250Z", "durationMs": 30250,
                "tokenUsage": {"input": 900, "output": 120, "total": 1020, "cached": 0},
                "stopReason": "end_turn", "providerRequestId": "req-example-1",
            }
            env["policyMetadata"] = {
                "redactionApplied": True, "redactionPolicy": "pii-redaction-v3", "contentFilters": ["pii"],
                "consent": {"scope": "support", "obtainedAt": "2026-09-30T12:00:00Z", "reference": "urn:example:consent:7"},
            }
            env["model"]["version"] = "2026-09"
            env["model"]["parameters"] = {"max_tokens": 1024, "temperature": 0}
    p: dict = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p, tweak=full_optional)
    scenario("19-optional-sections-valid", "Every optional v2 section present and valid: still finalized.",
             bundle(ident, arts), "run_finalized", {"objects": "warn"})

    negatives = [
        ("20-invalid-source-trace", "sourceTrace is a string, not an array.", 1,
         lambda env: env.__setitem__("sourceTrace", "not an array"), "sourceTrace must be of type array"),
        ("21-invalid-processing-metadata", "processingMetadata.tokenUsage.input is negative.", 3,
         lambda env: env.__setitem__("processingMetadata", {"tokenUsage": {"input": -1}}),
         "processingMetadata.tokenUsage.input must be >= 0"),
        ("22-invalid-policy-metadata", "policyMetadata.redactionApplied is a string, not a boolean.", 3,
         lambda env: env.__setitem__("policyMetadata", {"redactionApplied": "yes"}),
         "policyMetadata.redactionApplied must be of type boolean"),
        ("23-invalid-chain-member", "run_start's chain carries a member the schema does not define.", 0,
         lambda env: env["chain"].__setitem__("unrecognized", True), "chain has unknown member 'unrecognized'"),
    ]
    for name, description, at, edit, finding in negatives:
        p = {}
        ident, arts = build_run(STEPS, THROUGHPUT, p, tweak=lambda seq, env, at=at, edit=edit: edit(env) if seq == at else None)
        scenario(name, description + " Signed, but not a valid v2 envelope.", bundle(ident, arts), "run_invalid",
                 {"objects": "warn", "envelope": "bad"}, findings_contain=[finding])

    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p, tweak=lambda seq, env: env["activity"].pop("correlationId"))
    scenario("24-missing-correlation", "No step carries a signed correlationId: the run identifier is not "
             "signed anywhere.", bundle(ident, arts), "run_invalid", {"objects": "warn", "correlation": "bad"},
             findings_contain=["no signed correlationId"])


if __name__ == "__main__":
    main()
    hardening_scenarios()
    schema_scenarios()
