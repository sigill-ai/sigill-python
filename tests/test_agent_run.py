# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""AgentExecutionProfileV1: the cross-language vectors (spec/test-vectors/agent-run)
verified through the stub verifier, and the recorder end-to-end against a
fake sealing endpoint that signs with the same stub. HTTP is faked; hashes
and chain digests are real.

Mirrors the .NET suite one-to-one.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from sigill_sdk import (
    AgentAuthorization,
    AgentConfiguration,
    AgentDefinition,
    AgentModelRef,
    AgentRun,
    AgentRunBundle,
    AgentRunBundleFormatError,
    AgentRunObject,
    AgentTimestampPolicy,
    BlindObjectsVerdict,
    SignatureTimestampInfo,
    SignerCertificateInfo,
    SigillClient,
    SigillError,
    bundle_fingerprint,
    chain_digest,
    configuration_digest,
    register_agent_identity,
    verify_agent_run,
)
from sigill_sdk._canonical import canonicalize

VECTORS = Path(__file__).resolve().parents[1] / "spec" / "test-vectors" / "agent-run"


# ── The stub signer / verifier (spec/test-vectors/agent-run/README.md) ──────

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


CERT_A = b"test signing certificate A"
CERT_B = b"test signing certificate B"


def thumbprint(cert: bytes) -> str:
    return _b64u(hashlib.sha256(cert).digest())


def stub_sign(envelope_hash_hex: str, objects, *, timestamp: bool, gen_time: str = "2026-10-01T09:00:00Z",
              cert: bytes = CERT_A) -> dict:
    pars = ["urn:sigill:envelope"] + [u for u, _ in objects]
    hash_v = [_b64u(bytes.fromhex(envelope_hash_hex))] + [_b64u(bytes.fromhex(h)) for _, h in objects]
    prot = _b64u(canonicalize({"alg": "ES256", "sigD": {"pars": pars, "hashV": hash_v},
                               "x5c": [base64.b64encode(cert).decode()], "x5t#S256": thumbprint(cert)}))
    entry: dict = {"protected": prot, "signature": _b64u(hashlib.sha256(prot.encode()).digest())}
    if timestamp:
        entry["header"] = {"stubTimestamp": {"genTime": gen_time, "valid": True}}
    return {"signatures": [entry]}


def stub_verify(signature: dict, digests) -> BlindObjectsVerdict:
    entry = next(e for e in signature["signatures"]
                 if not json.loads(_b64u_decode(e["protected"]))["alg"].upper().startswith("ML-DSA"))
    prot = entry["protected"]
    sig_d = json.loads(_b64u_decode(prot))["sigD"]
    pars = sig_d["pars"]
    hash_v = [_b64u_decode(h).hex() for h in sig_d["hashV"]]
    valid = entry["signature"] == _b64u(hashlib.sha256(prot.encode()).digest())
    objects = [(p, digests.get(p) == hash_v[i]) for i, p in enumerate(pars)]
    st = (entry.get("header") or {}).get("stubTimestamp")
    return BlindObjectsVerdict(
        signature_valid=valid,
        complete=valid and all(m for _, m in objects),
        objects=objects,
        missing=[p for p in pars if p not in digests],
        unreferenced=[k for k in digests if k not in pars],
        timestamp=SignatureTimestampInfo(st["genTime"], "Stub TSA", st["valid"]) if st else None,
        certificate=SignerCertificateInfo("CN=Stub Signer", "CN=Stub CA", "2030-01-01T00:00:00Z", "issuer_distinct"),
    )


# ── Vectors ─────────────────────────────────────────────────────────────────

def test_chain_digest_matches_vectors() -> None:
    cases = json.loads((VECTORS / "chain-digest.json").read_text(encoding="utf-8"))
    assert len(cases) == 4
    for c in cases:
        assert chain_digest(c["signature"]) == c["expected"], c["name"]


def test_configuration_digest_matches_vector() -> None:
    v = json.loads((VECTORS / "config-digest.json").read_text(encoding="utf-8"))
    b = lambda k: base64.b64decode(v[k])  # noqa: E731
    cfg = AgentConfiguration(instruction_set=b("instructionSet"), tool_manifest=b("toolManifest"),
                             model_config=b("modelConfig"), execution_policy=b("executionPolicy"))
    assert configuration_digest(b("agentManifest"), cfg) == v["expected"]
    without = AgentConfiguration(instruction_set=b("instructionSet"), tool_manifest=b("toolManifest"),
                                 execution_policy=b("executionPolicy"))
    assert configuration_digest(b("agentManifest"), without) == v["expectedWithoutModelConfig"]


RUN_VECTORS = sorted(p.name for p in (VECTORS / "runs").glob("*.json"))


def test_there_are_run_vectors() -> None:
    assert len(RUN_VECTORS) == 44


@pytest.mark.parametrize("name", RUN_VECTORS)
def test_run_vector_reproduces_expected_verdict(name: str) -> None:
    v = json.loads((VECTORS / "runs" / name).read_text(encoding="utf-8"))
    expected = v["expected"]
    if "bundleText" in v:  # a container that must not parse at all
        with pytest.raises(AgentRunBundleFormatError) as ei:
            AgentRunBundle.parse(v["bundleText"])
        assert any(expected["parseError"] in e for e in ei.value.errors), ei.value.errors
        return
    result = verify_agent_run(AgentRunBundle.parse(v["bundle"]), stub_verify)

    assert result.verdict == expected["verdict"], result.findings
    assert len(result.checks) == 9
    for check, state in expected["checks"].items():
        assert result.checks[check] == state, (check, result.findings)
    assert result.missing_seqs == expected["missingSeqs"]
    assert result.fingerprint == expected["fingerprint"]
    for fragment in expected["findingsContain"]:
        assert any(fragment in f for f in result.findings), (fragment, result.findings)
    if result.verdict != "run_invalid":
        assert result.findings == []


def test_bundled_schema_is_a_byte_exact_copy_of_the_spec() -> None:
    repo = Path(__file__).resolve().parents[1]
    bundled = repo / "src" / "sigill_sdk" / "_schemas" / "ai-evidence-envelope-v2.schema.json"
    assert bundled.read_bytes() == (repo / "spec" / "ai-evidence-envelope-v2.schema.json").read_bytes()


def test_bundle_round_trips_through_json() -> None:
    v = json.loads((VECTORS / "runs" / "02-finalized-with-payloads.json").read_text(encoding="utf-8"))
    bundle = AgentRunBundle.parse(v["bundle"])
    again = AgentRunBundle.parse(bundle.to_json())
    assert bundle_fingerprint(again) == v["expected"]["fingerprint"]
    assert len(again.payloads) == len(bundle.payloads)


def test_bundle_parse_is_strict_and_lists_every_problem() -> None:
    bad = {
        "profile": "SomethingElse",
        "artifacts": [
            {"envelope": {}, "signature": {}, "objectDigests": {"urn:x": "ABC"}},
            "not an object",
        ],
        "payloads": {"urn:y": "%%%"},
    }
    with pytest.raises(AgentRunBundleFormatError) as ei:
        AgentRunBundle.parse(bad)
    errors = ei.value.errors
    assert len(errors) == 5
    assert any("unsupported profile" in e for e in errors)
    assert any("unsupported bundleVersion" in e for e in errors)
    assert any("64-char hex" in e for e in errors)
    assert any("artifacts[1]: not an object" in e for e in errors)
    assert any("not valid base64" in e for e in errors)


def test_bundle_parse_reports_every_bad_digest_of_an_artifact() -> None:
    v = json.loads((VECTORS / "runs" / "01-finalized-digests-only.json").read_text(encoding="utf-8"))
    v["bundle"]["artifacts"][0]["objectDigests"] = {"urn:a": "x", "urn:b": "y"}
    with pytest.raises(AgentRunBundleFormatError) as ei:
        AgentRunBundle.parse(v["bundle"])
    assert sum("is not a 64-char hex digest" in e for e in ei.value.errors) == 2


def test_malformed_envelope_is_an_invalid_verdict_never_an_exception() -> None:
    v = json.loads((VECTORS / "runs" / "01-finalized-digests-only.json").read_text(encoding="utf-8"))
    v["bundle"]["artifacts"][1]["envelope"]["chain"] = "seq one"
    result = verify_agent_run(AgentRunBundle.parse(v["bundle"]), stub_verify)
    assert result.verdict == "run_invalid"
    assert result.checks["envelope"] == "bad"
    assert any("chain is not an object" in f for f in result.findings)


def test_boolean_is_never_read_as_an_integer() -> None:
    # Python's bool is an int; the profile's integers must not accept it.
    v = json.loads((VECTORS / "runs" / "01-finalized-digests-only.json").read_text(encoding="utf-8"))
    v["bundle"]["artifacts"][1]["envelope"]["chain"]["seq"] = True
    result = verify_agent_run(AgentRunBundle.parse(v["bundle"]), stub_verify)
    assert result.verdict == "run_invalid"
    assert any("chain.seq missing, negative or not an integer" in f for f in result.findings)


# ── Recorder ────────────────────────────────────────────────────────────────

class StubSealer:
    """A sign-hashes endpoint that signs with the stub and records every request."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.fail_on_call = -1
        self.drop_timestamps = False
        self.cert = CERT_A

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/seal/sign-hashes"
        body = json.loads(request.content)
        self.requests.append(body)
        if len(self.requests) - 1 == self.fail_on_call:
            return httpx.Response(503, text="busy")
        stamp = body.get("timestamp", True) and not self.drop_timestamps
        sig = stub_sign(body["envelopeHashHex"], [(o["uri"], o["hashHex"]) for o in body["objects"]], timestamp=stamp,
                        cert=self.cert)
        return httpx.Response(200, json={
            "signature": sig, "operationId": "0be049c7-0000-0000-0000-000000000000",
            "format": "jades-b-t" if stamp else "jades-b-b", "timestampedBy": "Stub TSA" if stamp else None,
            "qualified": False, "pqc": False,
        })


CERT = "11111111-2222-3333-4444-555555555555"
SECRET = b"customer 4411: Jane Doe cannot log in"


def _agent(instructions: str = "You triage support tickets.") -> AgentDefinition:
    return AgentDefinition(
        agent_id="urn:example:agent:triage",
        agent_version="1.0.0",
        model=AgentModelRef("example-ai", "example-model-1"),
        tenant_id="tenant-example",
        configuration=AgentConfiguration(
            instruction_set=instructions.encode(),
            tool_manifest=b'{"tools":["lookup_ticket","close_ticket"]}',
            model_config=b'{"temperature":0}',
            execution_policy=b'{"allow":["lookup_ticket","close_ticket"]}',
        ),
    )


def _client(sealer: StubSealer) -> SigillClient:
    http = httpx.Client(base_url="https://api.example", headers={"Authorization": "Bearer fake"},
                        transport=httpx.MockTransport(sealer), timeout=5)
    return SigillClient(api_key="fake", http_client=http)


def _clock():
    """A clock that advances one minute per reading."""
    state = {"t": datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)}

    def tick() -> datetime:
        state["t"] += timedelta(minutes=1)
        return state["t"]
    return tick


def test_recorded_run_verifies_as_finalized_and_no_content_ever_travels() -> None:
    sealer = StubSealer()
    client = _client(sealer)
    sealed_steps: list = []
    run = client.start_agent_run(
        _agent(), certificate_id=CERT,
        start_objects=[AgentRunObject("user-turn", "prompt", SECRET, "text/plain")],
        on_artifact_sealed=lambda a: sealed_steps.append(a.step_type), _clock=_clock())
    run.record_tool_call("lookup_ticket", b'{"ticket":"4411"}')
    run.record_tool_result("lookup_ticket", b'{"status":"open"}')
    run.record_tool_call("close_ticket", b'{"ticket":"4411"}', consequential=True)
    run.record_model_output(b"Closed.")
    bundle = run.finish("completed", {"inputTokens": 10})

    result = verify_agent_run(AgentRunBundle.parse(bundle.to_json()), stub_verify)
    assert result.verdict == "run_finalized", result.findings
    assert set(result.checks.values()) <= {"ok", "warn"}
    assert result.checks["objects"] == "warn"  # no payloads retained by default
    assert result.disposition == "completed"
    assert result.identity.linked
    assert sealed_steps == ["run_start", "tool_call", "tool_result", "tool_call", "model_output", "run_end"]

    # Blind contract: one identity seal + six steps, digests and opaque URIs only.
    # (Only strings that cannot occur by chance in a digest or UUID.)
    assert len(sealer.requests) == 7
    wire = "\n".join(json.dumps(r) for r in sealer.requests)
    for s in ("Jane Doe", "ticket", "triage support"):
        assert s not in wire
    assert bundle.payloads == {}
    assert "Jane Doe" not in bundle.to_json()

    # Timestamps: identity, consequential call and run_end stamped; the rest B-B.
    assert [r.get("timestamp", True) for r in sealer.requests] == [True, False, False, False, True, False, True]

    # v2 schema: evidenceId / parentEvidenceId are bare UUIDs.
    import uuid as _uuid
    for a in list(bundle.artifacts) + [bundle.agent_identity]:
        _uuid.UUID(a.envelope["evidenceId"])
        if "parentEvidenceId" in a.envelope["activity"]:
            _uuid.UUID(a.envelope["activity"]["parentEvidenceId"])
        assert a.envelope["actor"]["type"] == "agent"


def test_authorization_and_human_approval_flow_verifies_as_finalized() -> None:
    sealer = StubSealer()
    run = AgentRun.start(_client(sealer), _agent(), certificate_id=CERT, _clock=_clock())
    auth = run.record_authorization(AgentAuthorization("allowed", policy_id="support-tools-v1",
                                                       reason="write requires approval"),
                                    tool="close_ticket", operation="write")
    approval = run.record_human_approval("approved", receipt=b'{"decision":"approved"}',
                                         identity_assertion=b"eyJhbGciOiJFUzI1NiJ9.x.y",
                                         approver_ref="urn:example:approver:42",
                                         action_evidence_id=auth.evidence_id)
    run.record_tool_call("close_ticket", b'{"ticket":"4411"}', operation="write", consequential=True,
                         authorization=AgentAuthorization("allowed", policy_id="support-tools-v1"))
    bundle = run.finish()

    ext = approval.envelope["extensions"]["ai.sigill.agent-execution"]
    assert ext["approval"] == {"decision": "approved", "approverRef": "urn:example:approver:42",
                               "actionEvidenceId": auth.evidence_id}
    assert ext["timestamp"] == "required"  # consequential by default
    assert sorted(ext["objectKinds"].values()) == ["approval-receipt", "identity-assertion"]
    call = bundle.artifacts[3].envelope["extensions"]["ai.sigill.agent-execution"]
    assert call["tool"] == {"name": "close_ticket", "operation": "write"}
    assert call["authorization"] == {"decision": "allowed", "policyId": "support-tools-v1"}
    result = verify_agent_run(bundle, stub_verify)
    assert result.verdict == "run_finalized", result.findings
    assert b"eyJhbGciOiJFUzI1NiJ9" not in json.dumps(sealer.requests).encode()


def test_invalid_authorization_decision_is_rejected_before_sealing() -> None:
    run = AgentRun.start(_client(StubSealer()), _agent(), certificate_id=CERT, _clock=_clock())
    with pytest.raises(ValueError):
        run.record_authorization(AgentAuthorization("maybe"))
    assert not run.is_broken


def test_run_without_model_config_verifies_as_finalized() -> None:
    agent = _agent()
    agent = AgentDefinition(agent_id=agent.agent_id, agent_version=agent.agent_version, model=agent.model,
                            configuration=AgentConfiguration(
                                instruction_set=b"You triage.", tool_manifest=b"{}", execution_policy=b"{}"))
    run = AgentRun.start(_client(StubSealer()), agent, certificate_id=CERT, _clock=_clock())
    kinds = run.artifacts[0].envelope["extensions"]["ai.sigill.agent-execution"]["objectKinds"].values()
    assert "model-config" not in kinds
    result = verify_agent_run(run.finish(), stub_verify)
    assert result.verdict == "run_finalized", result.findings
    assert result.checks["identity"] == "ok"


def _bundle_from_vector(name: str) -> AgentRunBundle:
    return AgentRunBundle.parse(json.loads((VECTORS / "runs" / name).read_text(encoding="utf-8"))["bundle"])


def test_expected_signers_pin_the_run() -> None:
    bundle = _bundle_from_vector("01-finalized-digests-only.json")
    ok = verify_agent_run(bundle, stub_verify)
    assert ok.signer is not None
    assert verify_agent_run(bundle, stub_verify, expected_signers=[ok.signer]).verdict == "run_finalized"
    pinned = verify_agent_run(bundle, stub_verify, expected_signers=["someone-else"])
    assert pinned.verdict == "run_invalid" and pinned.checks["signatures"] == "bad"
    assert any("not among the expected signers" in f for f in pinned.findings)


def test_self_signed_certificate_is_a_warning() -> None:
    def self_signed(signature, digests):
        v = stub_verify(signature, digests)
        return BlindObjectsVerdict(v.signature_valid, v.complete, v.objects, v.missing, v.unreferenced, v.timestamp,
                                   SignerCertificateInfo("CN=x", "CN=x", "2030-01-01T00:00:00Z", "self_signed"))
    r = verify_agent_run(_bundle_from_vector("01-finalized-digests-only.json"), self_signed)
    assert r.verdict == "run_finalized"
    assert any("self-signed" in w for w in r.warnings)


def test_hybrid_commitment_not_verified_fails_signatures() -> None:
    def pqc_failed(signature, digests):
        v = stub_verify(signature, digests)
        return BlindObjectsVerdict(v.signature_valid, v.complete, v.objects, v.missing, v.unreferenced, v.timestamp,
                                   v.certificate, pqc="not_checked")
    r = verify_agent_run(_bundle_from_vector("01-finalized-digests-only.json"), pqc_failed)
    assert r.verdict == "run_invalid" and r.checks["signatures"] == "bad"
    assert any("ML-DSA commitment is 'not_checked'" in f for f in r.findings)


def test_sub_millisecond_times_cannot_split_recorder_and_verifier() -> None:
    times = iter([datetime(2026, 10, 1, 9, 0, 0, 900, tzinfo=timezone.utc),       # identity
                  datetime(2026, 10, 1, 9, 0, 0, 900, tzinfo=timezone.utc),       # run_start  :00.000900
                  datetime(2026, 10, 1, 9, 5, 0, 100, tzinfo=timezone.utc),       # next step  :00.000100, 300 s later
                  datetime(2026, 10, 1, 9, 6, 0, tzinfo=timezone.utc)])
    run = AgentRun.start(_client(StubSealer()), _agent(), certificate_id=CERT, _clock=lambda: next(times))
    step = run.record_model_output(b"x")
    assert step.envelope["extensions"]["ai.sigill.agent-execution"]["timestamp"] == "required"
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"


def test_callback_may_call_back_into_the_run() -> None:
    anchored = []

    def anchor_after_writes(a):
        if a.step_type == "tool_call":
            anchored.append(run.checkpoint("after-write"))

    run = AgentRun.start(_client(StubSealer()), _agent(), certificate_id=CERT, on_artifact_sealed=anchor_after_writes,
                         _clock=_clock())
    run.record_tool_call("close_ticket", b"{}", operation="write")
    assert anchored and anchored[0].step_type == "checkpoint"
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"


@pytest.mark.parametrize("bad", [
    lambda r: r.record_human_approval("approved", action_evidence_id="step-3"),
    lambda r: r.record("custom", [AgentRunObject("x", "weird", b"x")]),
    lambda r: r.record("custom", extension={"finalSeq": 3}),
    lambda r: r.record("custom", extension={"parentRun": {}}),
    lambda r: r.record("record:agent-identity"),
])
def test_recorder_refuses_steps_the_verifier_would_reject_without_breaking_the_run(bad) -> None:
    sealer = StubSealer()
    run = AgentRun.start(_client(sealer), _agent(), certificate_id=CERT, _clock=_clock())
    sealed_before = len(sealer.requests)
    with pytest.raises(ValueError):
        bad(run)
    assert len(sealer.requests) == sealed_before and not run.is_broken
    run.record_model_output(b"still fine")
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"


def test_identity_record_from_another_version_is_rejected() -> None:
    client = _client(StubSealer())
    identity = register_agent_identity(client, _agent(), CERT)
    newer = AgentDefinition(agent_id="urn:example:agent:triage", agent_version="1.1.0",
                            model=AgentModelRef("example-ai", "example-model-1"), tenant_id="tenant-example",
                            configuration=_agent().configuration, manifest=_agent().manifest_bytes())
    with pytest.raises(ValueError, match="different agent, version or configuration"):
        AgentRun.start(client, newer, certificate_id=CERT, identity=identity)


def test_identity_record_from_another_certificate_is_rejected() -> None:
    sealer = StubSealer()
    client = _client(sealer)
    identity = register_agent_identity(client, _agent(), CERT)
    sealer.cert = CERT_B  # the sealing certificate was rotated
    with pytest.raises(SigillError, match="different certificate"):
        AgentRun.start(client, _agent(), certificate_id=CERT, identity=identity)


def test_bundles_built_in_code_reject_non_bytes_payloads() -> None:
    bundle = _bundle_from_vector("01-finalized-digests-only.json")
    with pytest.raises(TypeError):
        bundle.with_payloads({"urn:x": "not bytes"})  # type: ignore[dict-item]


def test_retained_payloads_upgrade_objects_to_ok() -> None:
    sealer = StubSealer()
    run = AgentRun.start(_client(sealer), _agent(), certificate_id=CERT, retain_payloads=True, _clock=_clock())
    run.record_model_output(b"Done.")
    result = verify_agent_run(run.finish(), stub_verify)
    assert result.verdict == "run_finalized", result.findings
    assert set(result.checks.values()) == {"ok"}


def test_every_events_cadence_stamps_the_nth_step() -> None:
    sealer = StubSealer()
    run = AgentRun.start(_client(sealer), _agent(), certificate_id=CERT,
                         timestamp_policy=AgentTimestampPolicy(every_events=3, every_seconds=0), _clock=_clock())
    for i in range(5):
        run.record_model_output(f"x{i}".encode())
    bundle = run.finish()
    # seq: 0 start, 1..5 outputs, 6 end → stamped at seq 2, 5 (cadence) and 6 (run_end).
    assert [a.envelope["extensions"]["ai.sigill.agent-execution"]["timestamp"] for a in bundle.artifacts] == [
        "none", "none", "required", "none", "none", "required", "required"]
    assert verify_agent_run(bundle, stub_verify).verdict == "run_finalized"


def test_sealing_failure_breaks_the_chain_and_the_bundle_is_never_finalized() -> None:
    sealer = StubSealer()
    sealer.fail_on_call = 2  # identity, run_start, then the tool call fails
    run = AgentRun.start(_client(sealer), _agent(), certificate_id=CERT, _clock=_clock())
    with pytest.raises(SigillError):
        run.record_tool_call("lookup_ticket", b"{}")
    assert run.is_broken
    with pytest.raises(RuntimeError):
        run.record_model_output(b"x")
    with pytest.raises(RuntimeError):
        run.finish()
    assert verify_agent_run(run.to_bundle(), stub_verify).verdict == "run_open"


def test_required_timestamp_missing_fails_the_step() -> None:
    sealer = StubSealer()
    run = AgentRun.start(_client(sealer), _agent(), certificate_id=CERT, _clock=_clock())
    sealer.drop_timestamps = True
    with pytest.raises(SigillError, match="timestamp is required"):
        run.finish()
    assert run.is_broken
    assert not run.is_finished


def test_identity_record_is_reused_and_rejected_for_another_configuration() -> None:
    sealer = StubSealer()
    client = _client(sealer)
    identity = register_agent_identity(client, _agent(), CERT)
    run = AgentRun.start(client, _agent(), certificate_id=CERT, identity=identity, _clock=_clock())
    assert len(sealer.requests) == 2  # the identity record is not sealed again
    assert run.identity is identity
    assert verify_agent_run(run.finish(), stub_verify).checks["identity"] == "ok"

    with pytest.raises(ValueError, match="different agent, version or configuration"):
        AgentRun.start(client, _agent("A different instruction set."), certificate_id=CERT, identity=identity)


def test_run_end_callback_failure_still_leaves_the_run_finished() -> None:
    def persist(a):
        if a.step_type == "run_end":
            raise OSError("disk full")

    run = AgentRun.start(_client(StubSealer()), _agent(), certificate_id=CERT, on_artifact_sealed=persist,
                         _clock=_clock())
    with pytest.raises(OSError):
        run.finish()
    assert run.is_finished and not run.is_broken
    with pytest.raises(RuntimeError):
        run.record_model_output(b"after the end")
    with pytest.raises(RuntimeError):
        run.finish()
    bundle = run.to_bundle()
    assert [a.step_type for a in bundle.artifacts].count("run_end") == 1
    assert verify_agent_run(bundle, stub_verify).verdict == "run_finalized"


def test_ordinary_step_callback_failure_leaves_the_run_usable() -> None:
    calls = {"n": 0}

    def persist(a):
        calls["n"] += 1
        if a.step_type == "tool_call":
            raise OSError("disk full")

    run = AgentRun.start(_client(StubSealer()), _agent(), certificate_id=CERT, on_artifact_sealed=persist,
                         _clock=_clock())
    with pytest.raises(OSError):
        run.record_tool_call("lookup_ticket", b"{}")
    assert not run.is_broken and not run.is_finished
    run.record_model_output(b"ok")
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"


def test_reserved_step_types_are_rejected() -> None:
    run = AgentRun.start(_client(StubSealer()), _agent(), certificate_id=CERT, _clock=_clock())
    with pytest.raises(ValueError):
        run.record("run_end")
    assert not run.is_broken


def test_sign_hashes_sends_timestamp_false_only_when_opted_out() -> None:
    sealer = StubSealer()
    client = _client(sealer)
    hex_ = hashlib.sha256(b"envelope").hexdigest()
    client.sign_object_hashes(hex_, [], CERT)
    client.sign_object_hashes(hex_, [], CERT, timestamp=False)
    assert "timestamp" not in sealer.requests[0]
    assert sealer.requests[1]["timestamp"] is False


def test_blind_verdict_maps_the_verify_objects_response() -> None:
    v = BlindObjectsVerdict.from_verify_objects_response({"objects": {
        "signatureValid": True, "complete": True,
        "objects": [{"par": "urn:sigill:envelope", "supplied": True, "hashMatch": True}],
        "missing": [], "unreferenced": [],
        "underlying": {
            "timestamp": {"genTime": "2026-10-01T09:00:00Z", "tsaName": "Example TSA", "signatureValid": True},
            "certificate": {"subject": "CN=Seal", "issuer": "CN=CA", "notAfter": "2028-01-01T00:00:00Z",
                            "isSelfSigned": False},
        },
    }})
    assert v.signature_valid
    assert v.objects == [("urn:sigill:envelope", True)]
    assert v.timestamp == SignatureTimestampInfo("2026-10-01T09:00:00Z", "Example TSA", True)
    assert v.certificate is not None and v.certificate.trust == "issuer_distinct"
