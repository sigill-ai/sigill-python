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

CERT_A = b"stub signing certificate A (the producer)"
CERT_B = b"stub signing certificate B (someone else)"


def signer_header(cert: bytes) -> dict:
    """x5c / x5t#S256 as real JAdES carries them: thumbprint = b64url(SHA-256(DER x5c[0]))."""
    return {"x5c": [base64.b64encode(cert).decode()], "x5t#S256": b64u(hashlib.sha256(cert).digest())}


def stub_sign(envelope: dict, digests: dict[str, str], *, timestamp: str | None, valid_ts: bool = True,
              hybrid: bool = False, cert: bytes = CERT_A) -> dict:
    pars = [ENVELOPE_URI] + [o["uri"] for o in envelope["objects"]]
    env_hex = sha256hex(jcs.canonicalize(envelope))
    hash_v = [b64u(bytes.fromhex(env_hex))] + [b64u(bytes.fromhex(digests[u])) for u in pars[1:]]
    protected = b64u(jcs.canonicalize({"alg": "ES256", "sigD": {"pars": pars, "hashV": hash_v}, **signer_header(cert)}))
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
    d = {
        "agentManifest": sha256hex(manifest),
        "instructionSet": sha256hex(cfg["instruction-set"]),
        "toolManifest": sha256hex(cfg["tool-manifest"]),
        "executionPolicy": sha256hex(cfg["execution-policy"]),
    }
    if "model-config" in cfg:  # optional (§3.6)
        d["modelConfig"] = sha256hex(cfg["model-config"])
    return sha256hex(jcs.canonicalize(d))


CONFIG_BYTES = {k: v[2] for k, v in CONFIG.items()}
CONFIG_SHA = config_digest(MANIFEST, CONFIG_BYTES)


def identity_artifact(payloads: dict[str, bytes], *, ext_override: dict | None = None,
                      without: tuple = (), cert: bytes = CERT_A) -> dict:
    objs = [("urn:example:obj:agent-manifest", "agent-manifest", "input", "application/json", MANIFEST)]
    objs += [(uri, kind, "input", ctype, data) for kind, (uri, ctype, data) in CONFIG.items() if kind not in without]
    objs += [("urn:example:obj:registration", "registration-record", "input", "application/json", REGISTRATION)]
    cfg = {k: v for k, v in CONFIG_BYTES.items() if k not in without}
    ext = {
        "recordType": "agent-identity", "stepType": "record:agent-identity", "agentId": AGENT_ID,
        "agentVersion": AGENT_VERSION, "configSha256": config_digest(MANIFEST, cfg),
        "eventTime": "2026-10-01T08:00:00.000Z",
    }
    ext.update(ext_override or {})
    env = envelope(1, "2026-10-01T08:00:00.000Z", "agent-identity", "agent_identity", None, None, objs, None, None, ext)
    digests = {o[0]: sha256hex(o[4]) for o in objs}
    for o in objs:
        payloads[o[0]] = o[4]
    return {"envelope": env, "signature": stub_sign(env, digests, timestamp="2026-10-01T08:00:01Z", cert=cert),
            "objectDigests": digests}


RUN = "urn:uuid:00000000-0000-4000-9000-000000000001"


def build_run(steps: list[dict], policy, payloads: dict[str, bytes], *, finish: bool = True,
              config_override: dict[str, bytes] | None = None, start_type: str = "run_start",
              start_extra_objects: list | None = None, tweak=None, identity: dict | None = None,
              start_without: tuple = (), start_stamp: bool | None = None,
              end_cert: bytes = CERT_A) -> tuple[dict, list[dict]]:
    """steps: [{type, minute, objects, consequential, stamp, ext}] after run_start.
    tweak(seq, envelope) edits an envelope before it is signed (producer-side non-conformance)."""
    identity = identity or identity_artifact(payloads)
    artifacts: list[dict] = []
    prev_sig = None
    prev_id = identity["envelope"]["evidenceId"]
    n = 100

    def seal(step_type: str, at: str, objs, ext: dict, stamp: bool, consequential: bool, cert: bytes = CERT_A):
        nonlocal prev_sig, prev_id, n
        seq = len(artifacts)
        ext = copy.deepcopy(ext)  # tweaks must never leak into shared step templates
        ext.update({"stepType": step_type, "agentVersion": AGENT_VERSION, "eventTime": at,
                    "consequential": consequential, "timestamp": "required" if stamp else "none"})
        env = envelope(n, at, "agent-execution", step_type, RUN, prev_id, objs, seq, prev_sig, ext)
        if tweak is not None:
            tweak(seq, env)
        n += 1
        digests = {o[0]: sha256hex(o[4]) for o in objs}
        for o in objs:
            payloads[o[0]] = o[4]
        sig = stub_sign(env, digests, timestamp=at.replace(".000", "") if stamp else None, cert=cert)
        artifacts.append({"envelope": env, "signature": sig, "objectDigests": digests})
        prev_sig = chain_digest(sig)
        prev_id = env["evidenceId"]

    cfg = dict(CONFIG_BYTES)
    if config_override:
        cfg.update(config_override)
    start_objs = [(CONFIG[k][0] + ":run", k, "input", CONFIG[k][1], cfg[k]) for k in CONFIG if k not in start_without]
    start_objs.append(("urn:example:obj:request", "user-turn", "prompt", "text/plain", b"Ticket 4411: login fails after reset."))
    start_objs += start_extra_objects or []
    profile = policy["profile"] if isinstance(policy, dict) else "throughput"
    seal(start_type, "2026-10-01T09:00:00.000Z", start_objs, {
        "agentIdentityEvidenceId": identity["envelope"]["evidenceId"],
        "assuranceProfile": profile, "timestampPolicy": policy,
    }, start_stamp if start_stamp is not None
        else (isinstance(policy, dict) and policy.get("runStart", False)) or profile == "per-event", False)
    for i, s in enumerate(steps):
        objs = [(f"urn:example:obj:step-{i}-{k}", k, role, ctype, data) for k, role, ctype, data in s.get("objects", [])]
        seal(s["type"], f"2026-10-01T09:{s['minute']:02d}:00.000Z", objs, s.get("ext", {}), s["stamp"],
             s.get("consequential", False), s.get("cert", CERT_A))
    if finish:
        head = artifacts[-1]
        seal("run_end", f"2026-10-01T09:{steps[-1]['minute'] + 1:02d}:00.000Z", [], {
            "finalSeq": head["envelope"]["chain"]["seq"], "finalPrevSignatureSha256": chain_digest(head["signature"]),
            "runDisposition": "completed", "usage": {"inputTokens": 900, "outputTokens": 120},
        }, True, True, end_cert)
    return identity, artifacts


THROUGHPUT = {"profile": "throughput", "everyEvents": 10, "everySeconds": 300, "runStart": False,
              "runEnd": True, "consequential": True}

STEPS = [
    {"type": "tool_call", "minute": 1, "stamp": False,
     "ext": {"tool": {"name": "lookup_ticket", "operation": "read"},
             "authorization": {"decision": "allowed", "policyId": "support-tools-v1"}},
     "objects": [("tool-arguments", "input", "application/json", b'{"ticket":"4411"}')]},
    {"type": "tool_result", "minute": 2, "ext": {"tool": {"name": "lookup_ticket"}}, "stamp": False,
     "objects": [("tool-result", "context", "application/json", b'{"status":"open","product":"web"}')]},
    {"type": "model_output", "minute": 3, "stamp": False,
     "objects": [("assistant-reply", "output", "text/plain", b"Reset the session cache and retry.")]},
]


def bundle(identity, artifacts, payloads=None) -> dict:
    b = {"profile": "AgentExecutionProfileV1", "bundleVersion": "1", "correlationId": RUN,
         "agentIdentity": identity, "artifacts": artifacts}
    if payloads is not None:
        b["payloads"] = {u: base64.b64encode(d).decode() for u, d in sorted(payloads.items())}
    return b


def is_i_json(v) -> bool:
    """No integers beyond ±2^53, no lone surrogates (jcs would silently round / fail)."""
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
    arts = b["artifacts"] + ([b["agentIdentity"]] if b.get("agentIdentity") else [])
    if not all(is_i_json(a["envelope"]) and is_i_json(a["signature"]) for a in arts):
        return None  # §8.1: undefined for evidence that is not valid I-JSON
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
        raw = (a["envelope"].get("chain") or {}).get("seq") if isinstance(a["envelope"].get("chain"), dict) else None
        seq = raw if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0 else -1
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
    runs = HERE / "runs"
    if runs.is_dir():  # stale vectors must not survive a regeneration
        for f in runs.glob("*.json"):
            f.unlink()
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
        {"name": "non-base64url-signature", "description": "Characters outside the base64url alphabet: no digest.",
         "signature": {"signatures": [dict(plain["signatures"][0],
                                           signature=plain["signatures"][0]["signature"] + "!!")]},
         "expected": None},
    ])

    # Configuration digest vector.
    write("config-digest.json", {
        "agentManifest": base64.b64encode(MANIFEST).decode(),
        "instructionSet": base64.b64encode(CONFIG_BYTES["instruction-set"]).decode(),
        "toolManifest": base64.b64encode(CONFIG_BYTES["tool-manifest"]).decode(),
        "modelConfig": base64.b64encode(CONFIG_BYTES["model-config"]).decode(),
        "executionPolicy": base64.b64encode(CONFIG_BYTES["execution-policy"]).decode(),
        "expected": CONFIG_SHA,
        "expectedWithoutModelConfig": config_digest(MANIFEST, {k: v for k, v in CONFIG_BYTES.items()
                                                               if k != "model-config"}),
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
    steps.insert(2, {"type": "tool_call", "minute": 2, "stamp": True,
                     "ext": {"tool": {"name": "close_ticket", "operation": "write"},
                             "authorization": {"decision": "allowed", "policyId": "support-tools-v1"}},
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


def step_block_scenarios() -> None:
    """Optional model config, the tool/authorization/approval blocks (§3.4)
    and a human approval flow."""

    # 25 — no model-config on either side: allowed (§3.2, §3.6).
    p: dict = {}
    ident = identity_artifact(p, without=("model-config",))
    ident, arts = build_run(STEPS, THROUGHPUT, p, identity=ident, start_without=("model-config",))
    scenario("25-no-model-config", "The optional model-config is bound on neither side: finalized.",
             bundle(ident, arts), "run_finalized", {"objects": "warn"})

    # 26 — model-config on the identity record only.
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p, start_without=("model-config",))
    scenario("26-model-config-one-side", "The identity record binds a model-config, run_start does not.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "identity": "bad"},
             findings_contain=["do not match the identity record"])

    # 27 — tool block is a bare string.
    def string_tool(seq, env):
        if seq == 1:
            env["extensions"][EXT]["tool"] = "lookup_ticket"
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p, tweak=string_tool)
    scenario("27-invalid-tool-block", "tool_call's tool block is a string, not {name, operation}.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "envelope": "bad"},
             findings_contain=["tool must be an object with a non-empty string name"])

    # 28 — authorization decision outside the vocabulary.
    def odd_decision(seq, env):
        if seq == 1:
            env["extensions"][EXT]["authorization"]["decision"] = "maybe"
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p, tweak=odd_decision)
    scenario("28-invalid-authorization", "tool_call's authorization decision is neither allowed nor denied.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "envelope": "bad"},
             findings_contain=["authorization.decision must be 'allowed' or 'denied'"])

    # 29 — a write guarded by an authorization step and a human approval.
    approval_steps = [
        STEPS[0], STEPS[1],
        {"type": "authorization", "minute": 3, "stamp": False,
         "ext": {"tool": {"name": "close_ticket", "operation": "write"},
                 "authorization": {"decision": "allowed", "policyId": "support-tools-v1",
                                   "reason": "write requires approval"}}},
        {"type": "human_approval", "minute": 4, "stamp": True, "consequential": True,
         "ext": {"approval": {"decision": "approved", "approverRef": "urn:example:approver:42",
                              "actionEvidenceId": uuid(102), "decidedAt": "2026-10-01T09:04:00Z"}},
         "objects": [("approval-receipt", "input", "application/json", b'{"ticket":"4411","decision":"approved"}'),
                     ("identity-assertion", "input", "application/jwt", b"eyJhbGciOiJFUzI1NiJ9.example.sig")]},
        {"type": "tool_call", "minute": 5, "stamp": True, "consequential": True,
         "ext": {"tool": {"name": "close_ticket", "operation": "write"},
                 "authorization": {"decision": "allowed", "policyId": "support-tools-v1"}},
         "objects": [("tool-arguments", "input", "application/json", b'{"ticket":"4411"}')]},
        dict(STEPS[2], minute=6),
    ]
    p = {}
    ident, arts = build_run(approval_steps, THROUGHPUT, p)
    scenario("29-human-approval", "authorization → human_approval (receipt + identity assertion) → "
             "consequential write: finalized.", bundle(ident, arts), "run_finalized", {"objects": "warn"})

    # 30 — human_approval without a decision.
    steps = copy.deepcopy(approval_steps)
    steps[3]["ext"] = {"approval": {"approverRef": "urn:example:approver:42"}}
    p = {}
    ident, arts = build_run(steps, THROUGHPUT, p)
    scenario("30-approval-without-decision", "A human_approval step whose approval block has no decision.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "envelope": "bad"},
             findings_contain=["approval must be an object with a non-empty string decision"])


def signer_and_policy_scenarios() -> None:
    """One signer per run (§4.1), one classical signature per artifact (§4),
    I-JSON and duplicate names (§7), and every §5 coverage branch."""

    # 31 — truncate a real run and append forged steps under another certificate.
    forged = STEPS[:2] + [
        {"type": "human_approval", "minute": 3, "stamp": True, "consequential": True, "cert": CERT_B,
         "ext": {"approval": {"decision": "approved", "approverRef": "urn:example:approver:42"}}},
    ]
    p: dict = {}
    ident, arts = build_run(forged, THROUGHPUT, p, end_cert=CERT_B)
    scenario("31-foreign-signer-appended", "Steps after seq 2 are forged and sealed with a different "
             "certificate; the chain itself links correctly.", bundle(ident, arts), "run_invalid",
             {"objects": "warn", "signatures": "bad"}, findings_contain=["signed by a different certificate than the run"])

    # 32 — an artifact carrying two classical signature entries.
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p)
    first = arts[2]["signature"]["signatures"][0]
    arts[2]["signature"]["signatures"].append(dict(first, signature=b64u(b"another classical signature")))
    scenario("32-two-classical-signatures", "seq 2 carries two classical signature entries: which one the chain "
             "commits to and which one is verified is ambiguous.", bundle(ident, arts), "run_invalid",
             {"objects": "warn", "signatures": "bad"}, findings_contain=["exactly one classical signature"])

    # 33 — an integer beyond I-JSON's ±2^53.
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p,
                            tweak=lambda seq, env: env["extensions"][EXT].update({"x-count": 2 ** 53 + 1}) if seq == 2 else None)
    scenario("33-integer-beyond-i-json", "seq 2's envelope carries 2^53+1: not valid I-JSON; two envelopes could "
             "share a hash. A verdict, never an exception.", bundle(ident, arts), "run_invalid",
             {"objects": "bad", "sequence": "bad", "chain": "bad", "envelope": "bad", "signatures": "bad"},
             missing=[2], findings_contain=["not valid I-JSON"])

    # 34/35 — per-event profile.
    per_event = dict(THROUGHPUT, profile="per-event")
    stamped = [dict(st, stamp=True) for st in STEPS]
    p = {}
    ident, arts = build_run(stamped, per_event, p)
    scenario("34-per-event", "per-event profile, every step timestamped: finalized.", bundle(ident, arts),
             "run_finalized", {"objects": "warn"})
    p = {}
    ident, arts = build_run([stamped[0], dict(stamped[1], stamp=False), stamped[2]], per_event, p)
    scenario("35-per-event-missing", "per-event profile, seq 2 without a timestamp.", bundle(ident, arts),
             "run_invalid", {"objects": "warn", "timestamps": "bad"},
             findings_contain=["seq 2 (tool_result): a timestamp is required"])

    # 36/37 — runStart.
    run_start_policy = dict(THROUGHPUT, runStart=True)
    p = {}
    ident, arts = build_run(STEPS, run_start_policy, p)
    scenario("36-run-start-stamped", "runStart: true and run_start carries its timestamp: finalized.",
             bundle(ident, arts), "run_finalized", {"objects": "warn"})
    p = {}
    ident, arts = build_run(STEPS, run_start_policy, p, start_stamp=False)
    scenario("37-run-start-unstamped", "runStart: true but run_start carries no timestamp.", bundle(ident, arts),
             "run_invalid", {"objects": "warn", "timestamps": "bad"},
             findings_contain=["seq 0 (run_start): a timestamp is required"])

    # 38/39 — checkpoints.
    checkpoint = {"type": "checkpoint", "minute": 3, "stamp": True, "ext": {"checkpoint": {"reason": "idle"}}}
    tail = dict(STEPS[2], minute=4)
    p = {}
    ident, arts = build_run(STEPS[:2] + [checkpoint, tail], THROUGHPUT, p)
    scenario("38-checkpoint", "An idle checkpoint anchors the head: finalized.", bundle(ident, arts),
             "run_finalized", {"objects": "warn"})
    p = {}
    ident, arts = build_run(STEPS[:2] + [dict(checkpoint, stamp=False), tail], THROUGHPUT, p)
    scenario("39-checkpoint-unstamped", "A checkpoint without a timestamp anchors nothing.", bundle(ident, arts),
             "run_invalid", {"objects": "warn", "timestamps": "bad"},
             findings_contain=["seq 3 (checkpoint): a timestamp is required"])

    # 40 — a step declaring timestamp "required" without one.
    def declare_required(seq, env):
        if seq == 1:
            env["extensions"][EXT]["timestamp"] = "required"
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p, tweak=declare_required)
    scenario("40-declared-required-unstamped", "seq 1 declares timestamp \"required\" but carries none.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "timestamps": "bad"},
             findings_contain=["seq 1 (tool_call): a timestamp is required"])

    # 41/42 — everySeconds: a step exactly 300 s after the last anchor.
    late = [STEPS[0], STEPS[1], dict(STEPS[2], minute=5)]
    p = {}
    ident, arts = build_run([late[0], late[1], dict(late[2], stamp=True)], THROUGHPUT, p)
    scenario("41-every-seconds", "seq 3 is exactly everySeconds (300 s) after run_start and is timestamped: "
             "finalized.", bundle(ident, arts), "run_finalized", {"objects": "warn"})
    p = {}
    ident, arts = build_run(late, THROUGHPUT, p)
    scenario("42-every-seconds-unstamped", "seq 3 is exactly 300 s after run_start but carries no timestamp.",
             bundle(ident, arts), "run_invalid", {"objects": "warn", "timestamps": "bad"},
             findings_contain=["seq 3 (model_output): a timestamp is required"])

    # 43 — tool.useId and registeredBy.
    with_ids = copy.deepcopy(STEPS)
    with_ids[0]["ext"]["tool"]["useId"] = "toolu_01"
    with_ids[1]["ext"]["tool"]["useId"] = "toolu_01"
    p = {}
    ident = identity_artifact(p, ext_override={"registeredBy": "urn:example:registrar:7"})
    ident, arts = build_run(with_ids, THROUGHPUT, p, identity=ident)
    scenario("43-use-id-and-registered-by", "tool.useId correlates call and result; the identity record names "
             "its registrar opaquely: finalized.", bundle(ident, arts), "run_finalized", {"objects": "warn"})

    # 44 — a duplicate member name: the bundle does not parse.
    p = {}
    ident, arts = build_run(STEPS, THROUGHPUT, p)
    text = json.dumps(bundle(ident, arts), separators=(",", ":"))
    needle = '"consequential":false'
    assert needle in text
    text = text.replace(needle, needle + ',"consequential":true', 1)
    write("runs/44-duplicate-member.json", {
        "description": "A step's profile block repeats \"consequential\". I-JSON forbids duplicate names; parsers "
                       "disagree on which value wins, so the bundle must not parse at all.",
        "bundleText": text,
        "expected": {"parseError": "duplicate member name"},
    })


if __name__ == "__main__":
    main()
    hardening_scenarios()
    schema_scenarios()
    step_block_scenarios()
    signer_and_policy_scenarios()
