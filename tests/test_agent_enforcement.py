"""Agent Policy Control Set v2 and Agent Enforcement v1 (Execution Evidence v4): validation, digests and the
enforcement view against vector 13; facts v2, the v4 schema and the verifier's enforcement findings against
vector 14; the recorder's tool-call lifecycle and bound approvals. No guard: nothing here denies or halts (the guard
is tested in test_agent_guard.py).
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import json
import threading
import time
import uuid
from datetime import datetime, timezone

import pytest

from sigill_sdk import (
    POLICY_CONTROL_SET_CONTENT_TYPE,
    AgentPolicy,
    AgentRunArtifact,
    AgentRunBundle,
    AgentTimestampPolicy,
    ApprovalCovers,
    signature_sha256,
    verify_agent_run,
)
from sigill_sdk._agent_policy import _cedar_schema_v2_sha256
from sigill_sdk._agent_profiles import (
    CONTROL_ARTIFACT_CONTENT_TYPE,
    EXECUTION_EVIDENCE_CONTENT_TYPE,
    _execution_schema_for,
)
from sigill_sdk._canonical import canonicalize, hash_bytes
from sigill_sdk._schema import validate_profile
from test_agent_policy import _client
from test_agent_run import REPO, StubSealer, _start, stub_sign, stub_verify

V13 = REPO / "spec" / "test-vectors" / "13-policy-control-set-v2"
V14 = REPO / "spec" / "test-vectors" / "14-policy-enforcement"
DOC = (V13 / "control-set.json").read_bytes()
EXPECTED = json.loads((V13 / "expected.json").read_text(encoding="utf-8"))
RUNS = sorted(p.stem for p in (V14 / "runs").glob("*.json"))
FINDINGS = sorted(p.stem for p in (V14 / "findings").glob("*.json"))


def _with_enforcement(enforcement: dict | None) -> bytes:
    doc = json.loads(DOC)
    if enforcement is None:
        del doc["enforcement"]
    else:
        doc["enforcement"] = enforcement
    return json.dumps(doc).encode()


# ── Vector 13: the v2 document ──────────────────────────────────────────────

def test_v2_digests_and_schema_digest_match_the_vector() -> None:
    assert AgentPolicy.validate(DOC) == []
    d = AgentPolicy.compute_digests(DOC)
    assert (d.approval_scope_digest, d.cedar_digest) == (EXPECTED["approvalScopeDigest"], EXPECTED["cedarDigest"])
    assert hash_bytes(DOC) == EXPECTED["objectSha256"]
    spec_schema = json.loads((REPO / "spec" / "agent-policy-cedar-schema-v2.json").read_bytes())
    assert _cedar_schema_v2_sha256() == hash_bytes(canonicalize(spec_schema)) == EXPECTED["schemaSha256"]


@pytest.mark.parametrize("case", json.loads((V13 / "invalid.json").read_text(encoding="utf-8"))["cases"],
                         ids=lambda c: c["name"])
def test_v2_validate_rejects_every_invalid_vector(case: dict) -> None:
    raw = base64.b64decode(case["documentBase64"]) if "documentBase64" in case else case["document"].encode()
    errors = AgentPolicy.validate(raw)
    assert any(case["error"] in e for e in errors), errors
    with pytest.raises(ValueError):
        AgentPolicy.compute_digests(raw)


def test_v1_documents_validate_as_before() -> None:
    v1 = (REPO / "spec" / "test-vectors" / "11-policy-control-set" / "control-set.json").read_bytes()
    assert AgentPolicy.validate(v1) == []
    doc = json.loads(v1)
    doc["cedar"]["policies"]["staticPolicies"]["max-steps"]["annotations"]["severity"] = "high"
    assert AgentPolicy.validate(json.dumps(doc).encode()) == [], "v1 has no annotation rule"


def test_enforcement_view_applies_defaults_and_effective_effects() -> None:
    e = AgentPolicy.enforcement(DOC)
    assert dict(e.rule_effects) == EXPECTED["effects"]
    assert (e.mode, e.default_effect, e.unknown_tools, e.on_rule_error, e.halt_after_denials) == \
        ("enforce", "deny", "deny", "deny", 0)
    assert dict(e.locked_configuration) == {"tool-manifest": hash_bytes(b"tool-manifest v1")}
    with pytest.raises(TypeError):
        e.rule_effects["no-web-search"] = "observe"  # type: ignore[index]

    halt = AgentPolicy.enforcement(_with_enforcement({"mode": "enforce", "defaultEffect": "halt"}))
    assert halt.rule_effects["restricted-needs-bound-approval"] == "halt", "no effect annotation: the default"
    assert (halt.unknown_tools, halt.on_rule_error, halt.halt_after_denials, dict(halt.locked_configuration)) == \
        ("allow", "deny", 0, {})
    for observe in (_with_enforcement({"mode": "observe", "defaultEffect": "halt"}), _with_enforcement(None)):
        o = AgentPolicy.enforcement(observe)
        assert o.mode == "observe" and set(o.rule_effects.values()) == {"observe"}
    v1 = AgentPolicy.enforcement((REPO / "spec" / "test-vectors" / "11-policy-control-set" / "control-set.json")
                                 .read_bytes())
    assert v1.mode == "observe" and set(v1.rule_effects.values()) == {"observe"}
    with pytest.raises(ValueError, match="schemaVersion"):
        AgentPolicy.enforcement(DOC.replace(b'"schemaVersion": "2"', b'"schemaVersion": "1"'))


# ── Vector 14: facts v2 ─────────────────────────────────────────────────────

def _run(name: str, folder: str = "runs") -> dict:
    return json.loads((V14 / folder / f"{name}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", RUNS)
def test_build_facts_v2_is_exact_with_the_vector(name: str) -> None:
    run, expected = _run(name), _run(name, "expected")
    control_set = _with_enforcement(run["enforcement"])
    assert AgentPolicy.compute_digests(control_set).approval_scope_digest == expected["approvalScopeDigest"]
    events = [AgentRunArtifact(e["envelope"], {}, e["objectDigests"]) for e in run["events"]]
    facts = AgentPolicy.build_facts_v2(run["agentId"], run["correlationId"], reversed(events), control_set)
    assert facts.data == (V14 / "expected" / f"{name}.facts.json").read_bytes()
    assert facts.sha256 == expected["factsSha256"]
    doc = json.loads(facts.data)
    want = [{"seq": e["seq"], **e["request"]} for e in expected["events"]] + \
        [{"seq": "run", **expected["runLevel"]["request"]}]
    assert canonicalize(doc["requests"]) == canonicalize(want)
    assert (doc["factsVersion"], doc["throughSeq"], doc["missingSeqs"], doc["runLevel"]) == \
        ("2", len(run["events"]) - 1, [], True)
    assert doc["entities"] == json.loads(DOC)["cedar"]["entities"]


def test_build_facts_v2_refuses_a_v1_control_set() -> None:
    v1 = (REPO / "spec" / "test-vectors" / "11-policy-control-set" / "control-set.json").read_bytes()
    with pytest.raises(ValueError, match="v2 policy control set"):
        AgentPolicy.build_facts_v2("a", "r", [], v1)


# ── Vector 14: the v4 schema ────────────────────────────────────────────────

ENVELOPES = json.loads((V14 / "envelopes.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", ENVELOPES["valid"], ids=lambda c: c["name"])
def test_v4_schema_accepts_the_valid_envelopes(case: dict) -> None:
    env = case["envelope"]
    assert validate_profile(env, _execution_schema_for(env)) == []


@pytest.mark.parametrize("case", ENVELOPES["invalid"], ids=lambda c: c["name"])
def test_schema_of_its_version_rejects_the_invalid_envelopes(case: dict) -> None:
    env = case["envelope"]
    assert validate_profile(env, _execution_schema_for(env)) != []


# ── Vector 14: the verifier's enforcement check ─────────────────────────────

def _bundle(run: dict, control_set: tuple[str, bytes] | None) -> AgentRunBundle:
    """The vector's envelopes, re-chained and sealed with the stub signer under a stub Control Artifact; the
    control-set bytes travel as a payload when given."""
    roles = dict(run.get("configuration") or {})
    roles["control-set"] = hash_bytes(control_set[1] if control_set else DOC)
    objects, digests, payloads = [], {}, {}
    for role, hex_ in roles.items():
        uri = f"objects/{uuid.uuid4()}"
        ctype = (control_set[0] if control_set else POLICY_CONTROL_SET_CONTENT_TYPE) if role == "control-set" \
            else "application/json"
        objects.append({"uri": uri, "role": role, "contentType": ctype})
        digests[uri] = hex_
        if role == "control-set" and control_set:
            payloads[uri] = control_set[1]
    control_env = {
        "schemaName": "AgentControlArtifact", "schemaVersion": "1", "evidenceId": str(uuid.uuid4()),
        "createdAt": "2026-11-02T09:59:59Z", "actor": {"type": "agent", "id": run["agentId"]},
        "activity": {"name": "support-session", "correlationId": run["correlationId"]},
        "agent": {"id": run["agentId"], "version": "1"},
        "controlSet": {"id": "acme-support-agent-controls", "version": "4"},
        "timestampPolicy": AgentTimestampPolicy().to_json(), "objects": objects,
    }
    control = AgentRunArtifact(control_env, stub_sign(
        hash_bytes(canonicalize(control_env)), [(o["uri"], digests[o["uri"]], o["contentType"]) for o in objects],
        CONTROL_ARTIFACT_CONTENT_TYPE, timestamp=True, gen_time="2026-11-02T09:59:59Z"), digests)
    events, prev = [], None
    for e in run["events"]:
        env = copy.deepcopy(e["envelope"])
        if prev is None:
            env["binds"]["controlArtifactSignatureSha256"] = control.signature_sha256
        else:
            env["chain"]["prevSignatureSha256"] = prev
        if env["step"]["type"] == "run_end":
            env["step"]["finalPrevSignatureSha256"] = prev
        sig = stub_sign(hash_bytes(canonicalize(env)),
                        [(o["uri"], e["objectDigests"][o["uri"]], o["contentType"]) for o in env["objects"]],
                        EXECUTION_EVIDENCE_CONTENT_TYPE, timestamp=env["step"]["type"] == "run_end",
                        gen_time="2026-11-02T11:00:00Z")
        events.append(AgentRunArtifact(env, sig, dict(e["objectDigests"])))
        prev = signature_sha256(sig)
    return AgentRunBundle(run["correlationId"], control, events, [], payloads)


@pytest.mark.parametrize("name", RUNS)
def test_every_guard_run_verifies_without_enforcement_findings(name: str) -> None:
    run = _run(name)
    result = verify_agent_run(_bundle(run, (POLICY_CONTROL_SET_CONTENT_TYPE, _with_enforcement(run["enforcement"]))),
                              stub_verify)
    assert result.verdict == "run_finalized", result.findings
    assert result.checks["enforcement"] == "ok" and result.enforcement_findings == []


@pytest.mark.parametrize("name", FINDINGS)
def test_each_findings_run_produces_exactly_its_findings(name: str) -> None:
    run = _run(name, "findings")
    supplied = (run["controlSetContentType"], base64.b64decode(run["controlSetBase64"])) \
        if "controlSetContentType" in run else None
    result = verify_agent_run(_bundle(run, supplied), stub_verify)
    assert [dataclasses.asdict(f) for f in result.enforcement_findings] == run["findings"], result.findings
    v4 = run["events"][0]["envelope"]["schemaVersion"] == "4"  # v1–v3: the check only with its finding
    assert result.checks.get("enforcement") == ("bad" if run["findings"] else "ok" if v4 else None)
    assert result.verdict == ("run_invalid" if run["findings"] else "run_finalized"), result.findings
    for f in run["findings"]:
        assert any(f["code"] in x for x in result.findings)


# ── Recorder: Execution Evidence v4 and the tool-call lifecycle ─────────────

def _v4_run(sealer: StubSealer, **opts):  # noqa: ANN202
    # Vector 13's document in observe mode: an enforcing one needs enforcement= (test_agent_guard.py).
    observe = _with_enforcement({**json.loads(DOC)["enforcement"], "mode": "observe"})
    return _start(_client(sealer), control_set=AgentPolicy.control_set_from_document(observe), **opts)


def test_a_v2_policy_run_seals_v4_and_pairs_calls_with_generated_use_ids() -> None:
    sealer = StubSealer()
    run = _v4_run(sealer)
    call = run.begin_tool_call("crm.read_customer", b'{"customer":"c-1"}', operation="read",
                               definition=b"crm.read_customer definition")
    uuid.UUID(call.use_id)
    assert call.artifact.envelope["step"]["tool"] == {"name": "crm.read_customer", "operation": "read",
                                                      "useId": call.use_id}
    assert [o["role"] for o in call.artifact.envelope["objects"]] == ["tool-arguments", "tool-definition"]
    result = call.complete(b'{"ok":true}')
    assert result.envelope["step"]["tool"] == {"name": "crm.read_customer", "useId": call.use_id}
    plain = run.record_tool_call("search.web", b"{}")
    uuid.UUID(plain.envelope["step"]["tool"]["useId"])
    with run.begin_tool_call("payments.refund", b'{"amount":1}', use_id="call-9", consequential=True) as named:
        assert named.use_id == "call-9"
        named.complete(b"{}")
    bundle = run.finish()
    assert {a.envelope["schemaVersion"] for a in bundle.artifacts} == {"4"}
    result = verify_agent_run(bundle, stub_verify)
    assert result.verdict == "run_finalized", result.findings
    assert result.checks["enforcement"] == "ok"


@pytest.mark.parametrize("bad", ["result without use id", "duplicate use id", "complete twice", "unknown tool name"])
def test_lifecycle_rejections_seal_nothing_and_the_run_stays_usable(bad: str) -> None:
    sealer = StubSealer()
    run = _v4_run(sealer)
    call = run.begin_tool_call("crm.read_customer", b"{}", use_id="call-1")
    call.complete(b"{}")
    before = len(sealer.requests)
    act, error = {
        "result without use id": (lambda: run.record_tool_result("crm.read_customer", b"{}"), ValueError),
        "duplicate use id": (lambda: run.begin_tool_call("crm.read_customer", b"{}", use_id="call-1"), ValueError),
        "complete twice": (lambda: call.complete(b"{}"), RuntimeError),
        "unknown tool name": (lambda: run.begin_tool_call("t" * 256, b"{}"), ValueError),  # v4: at most 255
    }[bad]
    with pytest.raises(error):
        act()
    assert len(sealer.requests) == before
    assert not run.is_broken
    run.begin_tool_call("crm.read_customer", b"{}", use_id="call-2").complete(b"{}")
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"


def test_an_exception_in_the_call_body_seals_no_result() -> None:
    sealer = StubSealer()
    run = _v4_run(sealer)
    with pytest.raises(KeyError):
        with run.begin_tool_call("crm.read_customer", b"{}"):
            raise KeyError("tool failed")
    assert [a.step_type for a in run.artifacts] == ["run_start", "tool_call"]


def test_lifecycle_in_a_v1_run_pairs_with_a_generated_use_id_and_refuses_v4_members() -> None:
    sealer = StubSealer()
    run = _start(_client(sealer))
    call = run.begin_tool_call("lookup_ticket", b"{}")
    assert call.complete(b"{}").envelope["step"]["tool"]["useId"] == call.use_id
    assert run.record_tool_call("lookup_ticket", b"{}").envelope["step"]["tool"] == {"name": "lookup_ticket"}
    before = len(sealer.requests)
    with pytest.raises(RuntimeError):
        run.begin_tool_call("lookup_ticket", b"{}", definition=b"def")
    with pytest.raises(RuntimeError):
        run.record_human_approval("approved", covers=ApprovalCovers.for_arguments("lookup_ticket", b"{}"))
    assert len(sealer.requests) == before
    bundle = run.finish()
    assert {a.envelope["schemaVersion"] for a in bundle.artifacts} == {"1"}
    result = verify_agent_run(bundle, stub_verify)
    assert result.verdict == "run_finalized" and "enforcement" not in result.checks


def test_bound_approvals_are_sealed_and_bind_in_the_facts() -> None:
    sealer = StubSealer()
    run = _v4_run(sealer)
    args = b'{"amount":120,"order":"o-1"}'
    expires = datetime(2030, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)
    approval = run.record_human_approval("approved", approver="urn:example:approver:1",
                                         covers=ApprovalCovers.for_arguments("payments.refund", args, expires))
    assert approval.envelope["step"]["covers"] == {"tool": "payments.refund", "argumentsSha256": hash_bytes(args),
                                                   "expiresAt": "2030-01-01T12:00:00.123Z"}
    first = run.begin_tool_call("payments.refund", args, consequential=True)
    first.complete(b"{}")
    second = run.begin_tool_call("payments.refund", args, consequential=True)
    rejection = run.record_human_approval("rejected", covers=second.covers())
    assert rejection.envelope["step"]["covers"] == {"tool": "payments.refund", "argumentsSha256": hash_bytes(args),
                                                    "useId": second.use_id}
    with pytest.raises(ValueError, match="reserved"):
        run.record("authorization", fields={"decision": "denied", "enforcer": {
            "engine": "cedar-policy@4.14.0", "factsVersion": "2", "reason": "rule"}, "rules": ["no-web-search"]})
    with pytest.raises(ValueError):
        run.finish("halted")
    bundle = run.finish()
    assert verify_agent_run(bundle, stub_verify).verdict == "run_finalized"

    facts = json.loads(AgentPolicy.build_facts_v2("urn:example:agent:triage", run.correlation_id,
                                                  bundle.artifacts, DOC).data)
    calls = [r["context"]["approval"] for r in facts["requests"] if r["action"]["id"] == "tool_call"]
    assert calls == ["bound", "unbound"], "one approval binds one call"


# ── Regressions from the phase-1 security review ────────────────────────────

ENFORCER = {"engine": "cedar-policy@4.14.0", "factsVersion": "2", "reason": "rule"}
F9 = "f9-evidence-version-mismatch"


class _HashlessKey(str):
    """A str whose hash differs from the plain string's: a set intersection misses it, json.dumps writes it."""

    def __hash__(self) -> int:
        return 7

    __eq__ = str.__eq__


class _HidingDict(dict):
    """A dict whose iteration hides 'enforcer'; json.dumps still writes every item."""

    def __iter__(self):  # noqa: ANN204
        return iter([k for k in dict.keys(self) if k != "enforcer"])


@pytest.mark.parametrize("trick", ["str-subclass key", "dict-subclass iteration"])
def test_reserved_members_cannot_be_smuggled_through_record(trick: str) -> None:
    sealer = StubSealer()
    run = _v4_run(sealer)
    run.begin_tool_call("search.web", b'{"q":"x"}', use_id="c1")
    before = len(sealer.requests)
    base = {"decision": "denied", "tool": {"name": "search.web", "useId": "c1"}}
    fields = {**base, _HashlessKey("enforcer"): ENFORCER} if trick == "str-subclass key" \
        else _HidingDict({**base, "enforcer": ENFORCER})
    with pytest.raises(ValueError, match="reserved"):
        run.record("authorization", fields=fields)
    assert len(sealer.requests) == before and not run.is_broken


def test_record_refuses_rules_so_the_recorder_writes_no_guard_looking_denial() -> None:
    sealer = StubSealer()
    run = _v4_run(sealer)
    run.begin_tool_call("search.web", b"{}", use_id="c1")
    before = len(sealer.requests)
    with pytest.raises(ValueError, match="reserved step member\\(s\\): rules"):
        run.record("authorization", fields={"decision": "denied", "rules": ["no-web-search"],
                                            "tool": {"name": "search.web", "useId": "c1"}})
    assert len(sealer.requests) == before


def test_unique_items_is_linear_and_skipped_past_max_items() -> None:
    env = copy.deepcopy(_run("f4-executed-after-denial", "findings")["events"][2]["envelope"])
    env["step"]["rules"] = [f"r{i}" for i in range(50_000)]
    started = time.perf_counter()
    errors = validate_profile(env, _execution_schema_for(env))
    assert time.perf_counter() - started < 2
    assert any("must have at most 256 items" in e for e in errors) and not any("non-unique" in e for e in errors)
    env["step"]["rules"] = ["a", "b", "a"]
    assert any(e.endswith("step.rules has non-unique items") for e in validate_profile(env, _execution_schema_for(env)))


def test_a_deeply_nested_control_set_is_rejected_never_raised() -> None:
    deep = b'{"zz":' + b"[" * 200_000 + b"]" * 200_000 + b"}"
    started = time.perf_counter()
    errors = AgentPolicy.validate(deep)
    assert time.perf_counter() - started < 1, "a linear scan, before any parse"
    assert errors == ["the document exceeds the nesting depth of 64 levels"]
    result = verify_agent_run(_bundle(_run(F9, "findings"), (POLICY_CONTROL_SET_CONTENT_TYPE, deep)), stub_verify)
    assert result.verdict == "run_invalid"
    assert [f.code for f in result.enforcement_findings] == ["evidence_version_mismatch"]


def test_nesting_of_64_levels_is_accepted_and_65_rejected() -> None:
    def nested(levels: int) -> bytes:  # the outermost object is level 1
        return b'{"x":' + b"[" * (levels - 1) + b"]" * (levels - 1) + b"}"
    assert not any("depth" in e for e in AgentPolicy.validate(nested(64)))
    assert any("depth" in e for e in AgentPolicy.validate(nested(65)))
    assert not any("depth" in e for e in AgentPolicy.validate(b'{"x":"' + b"[" * 100 + b'\\"' + b"{" * 100 + b'"}')), \
        "brackets inside strings, escaped quotes included, do not nest"


def test_depth_is_reported_before_i_json_as_in_the_other_port() -> None:
    deep_and_repeated = b'{"x":1,"x":' + b"[" * 64 + b"]" * 64 + b"}"
    assert AgentPolicy.validate(deep_and_repeated) == ["the document exceeds the nesting depth of 64 levels"]
    assert AgentPolicy.validate(b"\xef\xbb\xbf" + deep_and_repeated) == \
        ["the document is not UTF-8 without a byte-order mark"]


@pytest.mark.parametrize("variant", ["dup member", "bigint", "NaN", "BOM", "UTF-16"])
def test_a_policy_control_set_that_does_not_parse_strictly_is_a_version_mismatch(variant: str) -> None:
    doc = {"dup member": DOC.replace(b'"schemaVersion": "2",', b'"schemaVersion": "2", "schemaVersion": "2",', 1),
           "bigint": DOC.replace(b"{", b'{"zz": 9007199254740993,', 1), "NaN": DOC.replace(b"{", b'{"zz": NaN,', 1),
           "BOM": b"\xef\xbb\xbf" + DOC, "UTF-16": DOC.decode().encode("utf-16-le")}[variant]
    assert AgentPolicy.validate(doc), variant
    result = verify_agent_run(_bundle(_run(F9, "findings"), (POLICY_CONTROL_SET_CONTENT_TYPE, doc)), stub_verify)
    assert result.verdict == "run_invalid"
    assert [f.code for f in result.enforcement_findings] == ["evidence_version_mismatch"]


def test_date_times_truncate_fractions_and_cap_offsets_at_14_hours() -> None:
    from sigill_sdk._schema import parse_date_time, validate
    assert parse_date_time("2026-11-02T10:00:01.999999999Z") == datetime(2026, 11, 2, 10, 0, 1, 999999, timezone.utc)
    assert parse_date_time("2026-11-02T10:00:00+14:00") is not None
    assert parse_date_time("2026-11-02T10:00:00-14:00") is not None
    for beyond in ("2026-11-02T10:00:00+14:01", "2026-11-02T10:00:00-23:59"):
        assert parse_date_time(beyond) is None
        assert validate(beyond, {"type": "string", "format": "date-time"}, {}) != []


def _env(seq: int, step: dict, objects=(), event_time: str | None = None) -> AgentRunArtifact:  # noqa: ANN001
    objs = [{"uri": f"objects/{seq}-{i}", "role": r, "contentType": "application/json"}
            for i, (r, _) in enumerate(objects)]
    return AgentRunArtifact({"schemaName": "AgentExecutionEvidence", "schemaVersion": "4", "chain": {"seq": seq},
                             "step": {"eventTime": event_time or f"2026-11-02T10:00:{seq:02d}.000Z", **step},
                             "objects": objs},
                            {}, {f"objects/{seq}-{i}": hash_bytes(b) for i, (_, b) in enumerate(objects)})


ARGS, OTHER = b'{"amount":120}', b'{"amount":121}'


def _approval(seq: int, decision: str = "approved", args: bytes = ARGS, **covers) -> AgentRunArtifact:  # noqa: ANN003
    return _env(seq, {"type": "human_approval", "decision": decision,
                      "covers": {"tool": "payments.refund", "argumentsSha256": hash_bytes(args), **covers}})


def _call(seq: int, use_id, objects=(("tool-arguments", ARGS),), event_time: str | None = None,  # noqa: ANN001
          tool=None) -> AgentRunArtifact:  # noqa: ANN001
    return _env(seq, {"type": "tool_call", "tool": tool if tool is not None else
                      {"name": "payments.refund", "useId": use_id}}, objects, event_time)


def _approvals(events: list) -> list[str]:
    facts = json.loads(AgentPolicy.build_facts_v2("a", "r", [_env(0, {"type": "run_start"})] + events, DOC).data)
    return [r["context"]["approval"] for r in facts["requests"] if r["action"]["id"] == "tool_call"]


EXPIRY = "2026-11-02T10:00:02.000Z"
LAUNDERING = {
    "one approval, two calls": ([_approval(1), _call(2, "u1"), _call(3, "u2")], ["bound", "unbound"]),
    "expiry equals eventTime": ([_approval(1, expiresAt="2026-11-02T10:00:02Z"), _call(2, "u1")], ["unbound"]),
    "expiry 1 ms after": ([_approval(1, expiresAt="2026-11-02T10:00:02.001Z"), _call(2, "u1")], ["bound"]),
    "approval after the call": ([_call(1, "u1"), _approval(2)], ["none"]),
    "rejection sticky by args, new useId": ([_approval(1, "rejected", useId="u0"), _approval(2), _call(3, "u1")],
                                            ["rejected"]),
    "rejection sticky by useId, other args": ([_approval(1, "rejected", args=OTHER, useId="u1"), _approval(2),
                                               _call(3, "u1")], ["rejected"]),
    "covers digest of the tool-definition": ([_approval(1, args=b"def"),
                                              _call(2, "u1", (("tool-arguments", ARGS), ("tool-definition", b"def")))],
                                             ["unbound"]),
    "two tool-arguments": ([_approval(1), _call(2, "u1", (("tool-arguments", ARGS), ("tool-arguments", ARGS)))],
                           ["unbound"]),
    "no tool-arguments": ([_approval(1), _call(2, "u1", ())], ["unbound"]),
    "approval names another useId": ([_approval(1, useId="u9"), _call(2, "u1")], ["unbound"]),
    "expired approval skipped, second binds": ([_approval(1, expiresAt="2026-11-02T10:00:01.500Z"), _approval(2),
                                                _call(3, "u1"), _call(4, "u2")], ["bound", "unbound"]),
    "approval with useId null": ([_approval(1, useId=None), _call(2, "u1")], ["unbound"]),
    "approval with useId null, call without useId": ([_approval(1, useId=None), _call(2, None)], ["unbound"]),
    "approval expiresAt null": ([_approval(1, expiresAt=None), _call(2, "u1")], ["unbound"]),
    "approval expiresAt +01:00 (schema-invalid)": ([_approval(1, expiresAt="2026-11-02T11:00:02.000+01:00"),
                                                    _call(2, "u1")], ["unbound"]),
    "covers without tool, call without name": ([_env(1, {"type": "human_approval", "decision": "approved", "covers": {
        "argumentsSha256": hash_bytes(ARGS)}}), _call(2, None, tool={"useId": "u1"})], ["unbound"]),
    "rejection with useId null, call without useId": ([_approval(1, "rejected", args=OTHER, useId=None),
                                                       _call(2, None, tool={"name": "payments.refund"})], ["unbound"]),
    "tool not an object": ([_approval(1), _call(2, None, tool="payments.refund")], ["unbound"]),
    # Fractions are truncated, never rounded: on both sides of the expiry.
    "event 8 digits before expiry": ([_approval(1, expiresAt=EXPIRY),
                                      _call(2, "u1", event_time="2026-11-02T10:00:01.99999999Z")], ["bound"]),
    "event 9 digits before expiry": ([_approval(1, expiresAt=EXPIRY),
                                      _call(2, "u1", event_time="2026-11-02T10:00:01.999999999Z")], ["bound"]),
    "event 8 digits at expiry": ([_approval(1, expiresAt=EXPIRY),
                                  _call(2, "u1", event_time="2026-11-02T10:00:02.00000001Z")], ["unbound"]),
    "event 9 digits at expiry": ([_approval(1, expiresAt=EXPIRY),
                                  _call(2, "u1", event_time="2026-11-02T10:00:02.000000009Z")], ["unbound"]),
}


@pytest.mark.parametrize("case", list(LAUNDERING))
def test_facts_never_bind_an_uncovered_call(case: str) -> None:
    events, want = LAUNDERING[case]
    assert _approvals(events) == want


def test_a_naive_expiry_is_refused_before_sealing() -> None:
    sealer = StubSealer()
    run = _v4_run(sealer)
    before = len(sealer.requests)
    with pytest.raises(ValueError, match="timezone-aware"):
        run.record_human_approval("approved", covers=ApprovalCovers.for_arguments("x", b"{}", datetime(2030, 1, 1)))
    assert len(sealer.requests) == before and not run.is_broken


def test_a_trailing_newline_never_matches_a_pattern() -> None:
    env = copy.deepcopy(_run("04-approval-laundering")["events"][1]["envelope"])
    assert validate_profile(env, _execution_schema_for(env)) == []
    env["step"]["covers"]["argumentsSha256"] += "\n"
    assert any("argumentsSha256 does not match" in e for e in validate_profile(env, _execution_schema_for(env)))
    doc = json.loads(DOC)
    doc["cedar"]["schemaSha256"] += "\n"
    assert any("schemaSha256" in e for e in AgentPolicy.validate(json.dumps(doc).encode()))


# ── Recorder: results only for open calls, under concurrency ────────────────

def test_concurrent_complete_on_one_call_seals_exactly_one_result() -> None:
    run = _v4_run(StubSealer())
    call = run.begin_tool_call("crm.read_customer", b"{}")
    outcomes: list = []

    def complete() -> None:
        try:
            outcomes.append(call.complete(b"{}"))
        except RuntimeError as e:
            outcomes.append(e)
    threads = [threading.Thread(target=complete) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(isinstance(o, AgentRunArtifact) for o in outcomes) == 1
    assert [a.step_type for a in run.artifacts].count("tool_result") == 1


def test_concurrent_calls_with_one_use_id_seal_exactly_one() -> None:
    run = _v4_run(StubSealer())
    outcomes: list = []

    def begin() -> None:
        try:
            outcomes.append(run.begin_tool_call("crm.read_customer", b"{}", use_id="same"))
        except ValueError as e:
            outcomes.append(e)
    threads = [threading.Thread(target=begin) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(not isinstance(o, ValueError) for o in outcomes) == 1
    assert [a.step_type for a in run.artifacts].count("tool_call") == 1


def test_a_v4_run_refuses_duplicate_orphan_and_second_results_on_every_path() -> None:
    from sigill_sdk import AgentRunObject
    sealer = StubSealer()
    run = _v4_run(sealer)
    tool = {"name": "crm.read_customer", "useId": "c1"}
    run.record("tool_call", [AgentRunObject("tool-arguments", b"{}")], {"tool": tool})
    call = run.begin_tool_call("crm.read_customer", b"{}", use_id="c2")
    before = len(sealer.requests)
    attempts = [
        lambda: run.record("tool_call", [AgentRunObject("tool-arguments", b"{}")], {"tool": tool}),
        lambda: run.record("tool_result", [AgentRunObject("tool-result", b"{}")],
                           {"tool": {"name": "crm.read_customer", "useId": "c9"}}),
        lambda: run.record_tool_result("crm.read_customer", b"{}", use_id="c9"),
    ]
    for attempt in attempts:
        with pytest.raises(ValueError):
            attempt()
    run.record_tool_result("crm.read_customer", b"{}", use_id="c1")
    run.record_tool_result("crm.read_customer", b"{}", use_id="c2")  # the call's result, outside the ToolCall
    for attempt in (lambda: run.record("tool_result", [AgentRunObject("tool-result", b"{}")], {"tool": tool}),
                    lambda: run.record_tool_result("crm.read_customer", b"{}", use_id="c1"),
                    lambda: call.complete(b"{}")):
        with pytest.raises(ValueError, match="already has its result"):
            attempt()
    assert len(sealer.requests) == before + 2 and not run.is_broken
    result = verify_agent_run(run.finish(), stub_verify)
    assert result.verdict == "run_finalized" and result.checks["enforcement"] == "ok"


def test_only_a_v4_parent_records_a_halted_child() -> None:
    v4 = _v4_run(StubSealer())
    child = v4.delegate("urn:example:agent:child").child_correlation_id
    done = v4.complete_delegation(child, "a" * 64, "halted")
    assert done.envelope["step"]["delegation"]["childDisposition"] == "halted"
    sealer = StubSealer()
    v3 = _start(_client(sealer), delegating=True, records_model_calls=True)
    child = v3.delegate("urn:example:agent:child").child_correlation_id
    before = len(sealer.requests)
    with pytest.raises(ValueError):
        v3.complete_delegation(child, "a" * 64, "halted")
    assert len(sealer.requests) == before


@pytest.mark.parametrize("event_time", ["0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-14:00"])
def test_a_date_time_outside_years_1_to_9999_in_utc_is_invalid_and_never_raises(event_time: str) -> None:
    from datetime import timedelta

    from sigill_sdk._schema import parse_date_time, validate
    assert parse_date_time(event_time) is None
    assert validate(event_time, {"type": "string", "format": "date-time"}, {}) != []
    run = copy.deepcopy(_run(F9, "findings"))
    run["events"][1]["envelope"]["step"]["eventTime"] = event_time
    v1 = (REPO / "spec" / "test-vectors" / "11-policy-control-set" / "control-set.json").read_bytes()
    assert verify_agent_run(_bundle(run, (POLICY_CONTROL_SET_CONTENT_TYPE, v1)), stub_verify).verdict == "run_invalid"
    extreme = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=14)))
    with pytest.raises(ValueError, match="outside years"):
        _v4_run(StubSealer()).record_human_approval("approved", covers=ApprovalCovers.for_arguments("x", b"{}", extreme))


def test_a_v4_result_must_name_its_calls_tool() -> None:
    from sigill_sdk import AgentRunObject
    sealer = StubSealer()
    run = _v4_run(sealer)
    run.begin_tool_call("crm.read_customer", b"{}", use_id="c1")
    before = len(sealer.requests)
    text = "The tool_call with use_id 'c1' was made to tool 'crm.read_customer'; its result cannot name another tool."
    for attempt in (lambda: run.record_tool_result("search.web", b"{}", use_id="c1"),
                    lambda: run.record("tool_result", [AgentRunObject("tool-result", b"{}")],
                                       {"tool": {"name": "search.web", "useId": "c1"}})):
        with pytest.raises(ValueError) as e:
            attempt()
        assert str(e.value) == text
    assert len(sealer.requests) == before and not run.is_broken
    run.record_tool_result("crm.read_customer", b"{}", use_id="c1")
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"
