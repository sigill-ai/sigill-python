# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Agent Evidence Profiles v1: the cross-language vectors (spec/test-vectors/agent-run)
verified through the stub verifier, the real sealed run (vector 10), and the
recorder end-to-end against a fake sealing endpoint that signs with the same
stub. HTTP is faked; hashes and binding digests are real.

Mirrors the .NET suite one-to-one.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from sigill_sdk import (
    PER_EVENT,
    AgentAuthorization,
    AgentConfiguration,
    AgentControlSet,
    AgentDefinition,
    AgentRun,
    AgentRunArtifact,
    AgentRunBundle,
    AgentRunBundleFormatError,
    AgentRunObject,
    AgentTimestampPolicy,
    BlindObjectsVerdict,
    ControlEvaluation,
    ControlEvaluationRequest,
    ControlResult,
    SigillClient,
    SigillError,
    SignatureTimestampInfo,
    SignerCertificateInfo,
    bundle_fingerprint,
    signature_sha256,
    verify_agent_run,
)
from sigill_sdk._agent_profiles import (
    CONTROL_ARTIFACT_CONTENT_TYPE,
    CONTROL_EVALUATION_CONTENT_TYPE,
    EXECUTION_EVIDENCE_CONTENT_TYPE,
)
from sigill_sdk._canonical import canonicalize, hash_bytes

REPO = Path(__file__).resolve().parents[1]
VECTORS = REPO / "spec" / "test-vectors" / "agent-run"
VECTOR10 = REPO / "spec" / "test-vectors" / "10-agent-controlled-run"


# ── The stub signer / verifier (spec/test-vectors/agent-run/README.md) ──────

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


CERT_A = b"test signing certificate A"
CERT_B = b"test signing certificate B"
CERT_V = b"test signing certificate V (verifier)"


def thumbprint(cert: bytes) -> str:
    return _b64u(hashlib.sha256(cert).digest())


def stub_sign(envelope_hash_hex: str, objects, cty, *, timestamp: bool, gen_time: str = "2026-10-01T09:00:00Z",
              cert: bytes = CERT_A, with_signer: bool = True) -> dict:
    pars = ["urn:sigill:envelope"] + [u for u, _ in objects]
    hash_v = [_b64u(bytes.fromhex(envelope_hash_hex))] + [_b64u(bytes.fromhex(h)) for _, h in objects]
    sig_d: dict = {"pars": pars, "hashV": hash_v}
    if cty is not None:
        sig_d["ctys"] = [cty]
    header: dict = {"alg": "ES256", "sigD": sig_d}
    if with_signer:
        header.update({"x5c": [base64.b64encode(cert).decode()], "x5t#S256": thumbprint(cert)})
    prot = _b64u(canonicalize(header))
    entry: dict = {"protected": prot, "signature": _b64u(hashlib.sha256(prot.encode()).digest())}
    if timestamp:
        entry["header"] = {"stubTimestamp": {"genTime": gen_time, "valid": True}}
    return {"signatures": [entry]}


def _lenient_header(entry: dict) -> dict:
    """Headers read leniently (a repeated name: last value wins), as a lenient service might."""
    return json.loads(_b64u_decode(entry["protected"]))


def _classical_entry(signature: dict) -> dict:
    return next(e for e in signature["signatures"]
                if not _lenient_header(e)["alg"].upper().startswith("ML-DSA"))


def _match_digests(header: dict, digests):
    pars = header["sigD"]["pars"]
    hash_v = [_b64u_decode(h).hex() for h in header["sigD"]["hashV"]]
    objects = [(p, digests.get(p) == hash_v[i]) for i, p in enumerate(pars)]
    return objects, [p for p in pars if p not in digests], [k for k in digests if k not in pars]


def stub_verify(signature: dict, digests) -> BlindObjectsVerdict:
    entry = _classical_entry(signature)
    prot = entry["protected"]
    valid = entry["signature"] == _b64u(hashlib.sha256(prot.encode()).digest())
    objects, missing, unreferenced = _match_digests(_lenient_header(entry), digests)
    st = (entry.get("header") or {}).get("stubTimestamp")
    return BlindObjectsVerdict(
        signature_valid=valid,
        complete=valid and all(m for _, m in objects),
        objects=objects,
        missing=missing,
        unreferenced=unreferenced,
        timestamp=SignatureTimestampInfo(st["genTime"], "Stub TSA", st["valid"]) if st else None,
        certificate=SignerCertificateInfo("CN=Stub Signer", "CN=Stub CA", "2030-01-01T00:00:00Z", "trusted_chain"),
    )


# ── Vectors ─────────────────────────────────────────────────────────────────

def test_signature_sha256_matches_vectors() -> None:
    cases = json.loads((VECTORS / "signature-sha256.json").read_text(encoding="utf-8"))
    assert len(cases) == 4
    for c in cases:
        assert signature_sha256(c["signature"]) == c["expected"], c["name"]


RUN_VECTORS = sorted(p.name for p in (VECTORS / "runs").glob("*.json"))


def test_run_vectors_are_all_present() -> None:
    assert len(RUN_VECTORS) == 54


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
    assert result.binding == expected["binding"], result.findings
    assert result.missing_seqs == expected["missingSeqs"]
    assert result.fingerprint == expected["fingerprint"], "None when the evidence is not valid I-JSON"
    for f in expected["findingsContain"]:
        assert any(f in x for x in result.findings), (f, result.findings)
    if result.verdict != "run_invalid":
        assert result.findings == []
    for w in expected["warningsContain"]:
        assert any(w in x for x in result.warnings), (w, result.warnings)
    assert len(result.warnings) == expected["warningCount"], result.warnings
    assert result.control_sealed_before_run == expected["controlSealedBeforeRun"]
    assert result.event_times_plausible == expected["eventTimesPlausible"]
    assert len(result.evaluations) == len(expected["evaluations"])
    for e, r in zip(expected["evaluations"], result.evaluations):
        assert r.subject_bound == e["subjectBound"], r.findings
        assert r.control_set_digest_matches == e["controlSetDigestMatches"], r.findings
        assert r.baseline_digest_matches == e["baselineDigestMatches"], r.findings
        assert r.signature_valid == e["signatureValid"], r.findings
        assert r.timestamp_valid == e["timestampValid"], r.findings
        assert r.overall == e["overall"]


def _bundle_from_vector(name: str) -> AgentRunBundle:
    return AgentRunBundle.parse(json.loads((VECTORS / "runs" / name).read_text(encoding="utf-8"))["bundle"])


@pytest.mark.parametrize("name", ["agent-control-artifact-v1", "agent-execution-evidence-v1", "control-evaluation-v1"])
def test_bundled_schema_is_a_byte_exact_copy_of_the_spec(name: str) -> None:
    bundled = REPO / "src" / "sigill_sdk" / "_schemas" / f"{name}.schema.json"
    assert bundled.read_bytes() == (REPO / "spec" / f"{name}.schema.json").read_bytes()


def test_bundle_round_trips_through_json() -> None:
    v = json.loads((VECTORS / "runs" / "02-finalized-with-payloads.json").read_text(encoding="utf-8"))
    bundle = AgentRunBundle.parse(v["bundle"])
    again = AgentRunBundle.parse(bundle.to_json())
    assert bundle_fingerprint(again) == v["expected"]["fingerprint"]
    assert len(again.payloads) == len(bundle.payloads)
    assert len(again.evaluations) == 1
    assert again.control_artifact is not None


def test_bundle_parse_is_strict_and_lists_every_problem() -> None:
    bad = {
        "format": "SomethingElse",
        "artifacts": [
            {"envelope": {}, "signature": {}, "objectDigests": {"urn:x": "ABC"}},
            "not an object",
        ],
        "evaluations": {},
        "payloads": {"urn:y": "%%%"},
    }
    with pytest.raises(AgentRunBundleFormatError) as ei:
        AgentRunBundle.parse(bad)
    errors = ei.value.errors
    assert len(errors) == 6
    assert any("unsupported format" in e for e in errors)
    assert any("unsupported bundleVersion" in e for e in errors)
    assert any("64-char hex" in e for e in errors)
    assert any("artifacts[1]: not an object" in e for e in errors)
    assert any("evaluations is not an array" in e for e in errors)
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
    assert any("chain must be of type object" in f for f in result.findings)


def test_boolean_is_never_read_as_an_integer() -> None:
    # Python's bool is an int; the profile's integers must not accept it.
    v = json.loads((VECTORS / "runs" / "01-finalized-digests-only.json").read_text(encoding="utf-8"))
    v["bundle"]["artifacts"][1]["envelope"]["chain"]["seq"] = True
    result = verify_agent_run(AgentRunBundle.parse(v["bundle"]), stub_verify)
    assert result.verdict == "run_invalid"
    assert any("chain.seq must be of type integer" in f for f in result.findings)
    assert any("no valid chain.seq" in f for f in result.findings)


def test_non_finite_numbers_are_refused_in_bundles() -> None:
    text = (VECTORS / "runs" / "01-finalized-digests-only.json").read_text(encoding="utf-8")
    bundle_text = json.dumps(json.loads(text)["bundle"]).replace('"consequential": false', '"consequential": NaN', 1)
    with pytest.raises(AgentRunBundleFormatError):
        AgentRunBundle.parse(bundle_text)


def test_bundle_accepts_payloads_none() -> None:
    b = _bundle_from_vector("01-finalized-digests-only.json")
    assert AgentRunBundle(b.correlation_id, b.control_artifact, b.artifacts, None, None).payloads == {}  # type: ignore[arg-type]


def test_bundles_built_in_code_reject_non_bytes_payloads() -> None:
    b = _bundle_from_vector("01-finalized-digests-only.json")
    with pytest.raises(TypeError):
        AgentRunBundle(b.correlation_id, b.control_artifact, b.artifacts, [], {"urn:x": "text"})  # type: ignore[dict-item]


def test_expected_signers_pin_the_run_and_the_evaluation_separately() -> None:
    bundle = _bundle_from_vector("01-finalized-digests-only.json")
    ok = verify_agent_run(bundle, stub_verify)
    assert ok.signer is not None
    evaluation_signer = ok.evaluations[0].signer
    assert evaluation_signer is not None and evaluation_signer != ok.signer
    assert verify_agent_run(bundle, stub_verify, expected_signers=[ok.signer],
                            expected_evaluation_signers=[evaluation_signer]).verdict == "run_finalized"

    pinned = verify_agent_run(bundle, stub_verify, expected_signers=["someone-else"])
    assert pinned.verdict == "run_invalid"
    assert pinned.checks["signatures"] == "bad"
    assert any("not among the expected signers" in f for f in pinned.findings)

    eval_pinned = verify_agent_run(bundle, stub_verify, expected_evaluation_signers=[ok.signer])
    assert eval_pinned.verdict == "run_finalized", "an evaluation never changes the run verdict"
    assert not eval_pinned.evaluations[0].signature_valid


def test_self_signed_certificate_is_a_warning() -> None:
    def self_signed(signature, digests):
        return dataclasses.replace(stub_verify(signature, digests),
                                   certificate=SignerCertificateInfo("CN=x", "CN=x", "2030-01-01T00:00:00Z",
                                                                     "self_signed"))
    r = verify_agent_run(_bundle_from_vector("01-finalized-digests-only.json"), self_signed)
    assert r.verdict == "run_finalized"
    assert any("trust: self_signed" in w for w in r.warnings)


def test_untrusted_chain_warns_unless_signers_are_pinned() -> None:
    def untrusted(signature, digests):
        return dataclasses.replace(stub_verify(signature, digests), certificate=SignerCertificateInfo(
            "CN=Sigill Seal", "CN=Attacker CA", "2030-01-01T00:00:00Z", "valid_untrusted_chain"))
    bundle = _bundle_from_vector("01-finalized-digests-only.json")
    open_ = verify_agent_run(bundle, untrusted)
    assert open_.verdict == "run_finalized"
    assert any("valid_untrusted_chain" in w and "does not establish who produced it" in w for w in open_.warnings)
    pinned = verify_agent_run(bundle, untrusted, expected_signers=[open_.signer],
                              expected_evaluation_signers=[open_.evaluations[0].signer])
    assert not any("trusted root" in w for w in pinned.warnings)


def test_hybrid_commitment_not_verified_fails_signatures() -> None:
    def pqc_failed(signature, digests):
        return dataclasses.replace(stub_verify(signature, digests), pqc="not_checked")
    r = verify_agent_run(_bundle_from_vector("01-finalized-digests-only.json"), pqc_failed)
    assert r.verdict == "run_invalid"
    assert r.checks["signatures"] == "bad"
    assert any("ML-DSA commitment is 'not_checked'" in f for f in r.findings)


def test_control_only_bundle_is_reported_as_such() -> None:
    b = _bundle_from_vector("01-finalized-digests-only.json")
    r = verify_agent_run(AgentRunBundle(b.correlation_id, b.control_artifact, []), stub_verify)
    assert r.binding == "control_only"
    assert r.verdict == "run_open"


# ── Vector 10: one run sealed for real ──────────────────────────────────────

def test_vector10_canonical_bytes_and_envelope_hashes_are_reproduced() -> None:
    for f in sorted((VECTOR10 / "artifacts").glob("*.json")):
        name = f.name.split(".")[0]
        canonical = canonicalize(json.loads(f.read_text(encoding="utf-8"))["envelope"])
        assert canonical == (VECTOR10 / "canonical" / f"{name}.canonical.json").read_bytes(), name
        assert hash_bytes(canonical) == (VECTOR10 / "canonical" / f"{name}.envelope-hash.txt").read_text().strip(), name


def _gen_time_of(der: bytes):
    """The first GeneralizedTime in a timestamp token is TSTInfo.genTime (it
    precedes the certificates). Enough for this offline check."""
    for i in range(len(der) - 2):
        n = der[i + 1]
        if der[i] != 0x18 or not 15 <= n <= 23 or i + 2 + n > len(der):
            continue
        try:
            s = der[i + 2:i + 2 + n].decode("ascii")
        except UnicodeDecodeError:
            continue
        if not (s.startswith("20") and s.endswith("Z")):
            continue
        base, _, frac = s[:-1].partition(".")
        try:
            t = datetime.strptime(base, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        t += timedelta(milliseconds=int((frac + "000")[:3]) if frac else 0)
        return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"
    return None


def digests_only_verify(signature: dict, digests) -> BlindObjectsVerdict:
    """Offline and NOT cryptographic: checks every hashV against the supplied
    digests and reads the timestamp's genTime, but treats signature values and
    timestamp tokens as valid without checking them — that needs the blind
    endpoint (:func:`remote_verifier`) or a TS 119 182-1 validator."""
    entry = _classical_entry(signature)
    objects, missing, unreferenced = _match_digests(_lenient_header(entry), digests)
    ts = None
    for u in (entry.get("header") or {}).get("etsiU") or []:
        item = json.loads(_b64u_decode(u))
        tokens = (item.get("sigTst") or {}).get("tstTokens")
        if tokens:
            ts = SignatureTimestampInfo(_gen_time_of(base64.b64decode(tokens[0]["val"])), "TSA", True)
    return BlindObjectsVerdict(
        signature_valid=True, complete=all(m for _, m in objects), objects=objects, missing=missing,
        unreferenced=unreferenced, timestamp=ts,
        certificate=SignerCertificateInfo("CN=test tenant", "CN=CA", "2030-01-01T00:00:00Z", "trusted_chain"))


def test_vector10_real_sealed_run_profile_layer_holds_offline_signatures_assumed() -> None:
    def load(f: Path) -> AgentRunArtifact:
        a = json.loads(f.read_text(encoding="utf-8"))
        return AgentRunArtifact(a["envelope"], a["signature"], {})
    files = sorted((VECTOR10 / "artifacts").glob("*.json"))
    payloads = {uri: (VECTOR10 / path).read_bytes()
                for uri, path in json.loads((VECTOR10 / "objects.json").read_text(encoding="utf-8")).items()}
    bundle = AgentRunBundle(
        None,
        load(next(f for f in files if "control-artifact" in f.name)),
        [load(f) for f in files if f.name.endswith(".agent-execution.json")],
        [load(f) for f in files if f.name.endswith(".control-evaluation.json")],
        payloads)

    r = verify_agent_run(bundle, digests_only_verify)
    expected = json.loads((VECTOR10 / "expected-result.json").read_text(encoding="utf-8"))
    assert r.verdict == expected["runVerdict"], r.findings
    assert r.binding == expected["binding"]
    assert set(r.checks.values()) == {"ok"}
    assert r.disposition == expected["runDisposition"]
    assert r.artifacts[-1].seq == expected["finalSeq"]
    assert r.control_sealed_before_run == expected["controlSealedBeforeRun"]
    assert r.event_times_plausible == expected["eventTimesPlausible"]
    assert any("signs no timestampPolicy" in w for w in r.warnings)
    e = expected["evaluations"][0]
    (ev,) = r.evaluations
    assert ev.verifier_id == e["verifier"]
    assert ev.verifier_version == e["verifierVersion"]
    assert ev.overall == e["overall"]
    assert ev.subject_bound == e["subjectBound"]
    assert ev.control_set_digest_matches == e["controlSetDigestMatches"]
    assert ev.baseline_digest_matches == e["baselineDigestMatches"]
    assert any(c.result == "FAIL" for c in ev.controls)


# ── Recorder ────────────────────────────────────────────────────────────────

class StubSealer:
    """A sign-hashes endpoint that signs with the stub and records every request."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.fail_on_call = -1
        self.drop_timestamps = False
        self.cert = CERT_A
        self.omit_signer = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/seal/sign-hashes"
        body = json.loads(request.content)
        self.requests.append(body)
        if len(self.requests) - 1 == self.fail_on_call:
            return httpx.Response(503, text="busy")
        stamp = body.get("timestamp", True) and not self.drop_timestamps
        sig = stub_sign(body["envelopeHashHex"], [(o["uri"], o["hashHex"]) for o in body["objects"]],
                        body.get("envelopeContentType"), timestamp=stamp, cert=self.cert,
                        with_signer=not self.omit_signer)
        return httpx.Response(200, json={
            "signature": sig, "operationId": "0be049c7-0000-0000-0000-000000000000",
            "format": "jades-b-t" if stamp else "jades-b-b", "timestampedBy": "Stub TSA" if stamp else None,
            "qualified": False, "pqc": False,
        })


CERT = "11111111-2222-3333-4444-555555555555"
VERIFIER_CERT = "66666666-7777-8888-9999-000000000000"
SECRET = b"customer 4411: Jane Doe cannot log in"


def _agent() -> AgentDefinition:
    return AgentDefinition(
        agent_id="urn:example:agent:triage",
        agent_version="1.0.0",
        tenant_id="tenant-example",
        configuration=AgentConfiguration(
            instruction_set=b"You triage support tickets.",
            tool_manifest=b'{"tools":["lookup_ticket","close_ticket"]}',
            model_config=b'{"temperature":0}',
            execution_policy=b'{"allow":["lookup_ticket","close_ticket"]}',
        ),
    )


def _options(policy: AgentTimestampPolicy | None = None, **extra) -> dict:
    opts = {
        "certificate_id": CERT,
        "activity": "support-ticket-close",
        "control_set": AgentControlSet("ticket-close-v2", "2", b'{"controls":["ticket-closed","owner-unchanged"]}'),
        "baseline_state": b'{"ticket":"4411","status":"open","owner":"team-a"}',
        "timestamp_policy": policy or AgentTimestampPolicy(),
    }
    opts.update(extra)
    return opts


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


def _start(client: SigillClient, **opts) -> AgentRun:
    o = _options(**opts)
    o.setdefault("_clock", _clock())
    return AgentRun.start(client, _agent(), **o)


def _stamped(request: dict) -> bool:
    return request.get("timestamp", True)


def test_recorded_run_with_evaluation_verifies_with_three_timestamps_and_no_content_travels() -> None:
    sealer = StubSealer()
    client = _client(sealer)
    sealed_order: list = []
    run = _start(client, start_objects=[AgentRunObject("model-input", SECRET, "text/plain")],
                 on_artifact_sealed=lambda a: sealed_order.append(a.step_type or a.schema_name))
    run.record_tool_call("lookup_ticket", b'{"ticket":"4411"}', operation="read", use_id="call-1")
    run.record_tool_result("lookup_ticket", b'{"status":"open"}', use_id="call-1")
    run.record_tool_call("close_ticket", b'{"ticket":"4411"}', operation="write", consequential=True)
    run.record_model_output(b"Closed.")
    bundle = run.finish("completed")

    sealer.cert = CERT_V  # the evaluating verifier seals with its own certificate
    evaluation = ControlEvaluation.seal(client, ControlEvaluationRequest(
        certificate_id=VERIFIER_CERT, verifier_id="urn:example:verifier:ticket-state", verifier_version="1.3.0",
        control_artifact=run.control_artifact, run_end=bundle.artifacts[-1],
        observed_state=[AgentRunObject.json("observed-state", {"ticket": "4411", "status": "closed"})],
        controls=[ControlResult("ticket-closed", "PASS"), ControlResult("owner-unchanged", "PASS")],
        overall="PASS"), _clock=_clock())
    bundle = bundle.with_evaluations(evaluation)

    result = verify_agent_run(AgentRunBundle.parse(bundle.to_json()), stub_verify)
    assert result.verdict == "run_finalized", result.findings
    assert result.binding == "bound"
    assert set(result.checks.values()) <= {"ok", "warn"}
    assert result.checks["objects"] == "warn", "no payloads retained by default"
    assert result.checks["timestamps"] == "ok"
    assert result.disposition == "completed"
    assert result.timestamps.policy_signed
    (ev,) = result.evaluations
    assert ev.subject_bound, ev.findings
    assert ev.control_set_digest_matches and ev.baseline_digest_matches
    assert ev.signature_valid and ev.timestamp_valid
    assert ev.signer == thumbprint(CERT_V) != result.signer
    assert sealed_order == ["AgentControlArtifact", "run_start", "tool_call", "tool_result", "tool_call",
                            "model_output", "run_end"]

    # Seal every event, timestamp to wrap up: control, run_end and the evaluation — three for the whole run.
    assert [_stamped(r) for r in sealer.requests] == [True, False, False, False, False, False, True, True]
    assert [r["envelopeContentType"] for r in sealer.requests] == \
        [CONTROL_ARTIFACT_CONTENT_TYPE] + [EXECUTION_EVIDENCE_CONTENT_TYPE] * 6 + [CONTROL_EVALUATION_CONTENT_TYPE]

    # Blind contract: digests and opaque URIs only (strings that cannot occur by chance in a digest or UUID).
    wire = "\n".join(json.dumps(r) for r in sealer.requests)
    for needle in ("Jane Doe", "ticket", "triage support", "tool_call"):
        assert needle not in wire
    assert bundle.payloads == {}
    assert "Jane Doe" not in bundle.to_json()

    # run_end closes on its own seq and its own link.
    end = bundle.artifacts[-1].envelope
    assert end["step"]["finalSeq"] == end["chain"]["seq"]
    assert end["step"]["finalPrevSignatureSha256"] == end["chain"]["prevSignatureSha256"]
    import uuid
    for a in [*bundle.artifacts, bundle.control_artifact, evaluation]:
        uuid.UUID(a.evidence_id)  # a bare UUID


def test_authorization_and_human_approval_flow_verifies_as_finalized() -> None:
    sealer = StubSealer()
    run = _start(_client(sealer))
    auth = run.record_authorization(AgentAuthorization("allow_with_human_approval", policy_id="support-tools-v1",
                                                       detail="write requires approval"))
    approval = run.record_human_approval("approved", receipt=b'{"decision":"approved"}',
                                         identity_assertion=b"eyJhbGciOiJFUzI1NiJ9.x.y",
                                         approver="urn:example:approver:42")
    run.record_tool_call("close_ticket", b'{"ticket":"4411"}', operation="write", consequential=True)
    bundle = run.finish()

    assert auth.envelope["step"]["decision"] == "allow_with_human_approval"
    assert auth.envelope["step"]["policyId"] == "support-tools-v1"
    assert approval.envelope["step"]["approver"] == "urn:example:approver:42"
    assert [o["role"] for o in approval.envelope["objects"]] == ["approval-receipt", "identity-assertion"]
    result = verify_agent_run(bundle, stub_verify)
    assert result.verdict == "run_finalized", result.findings
    assert "eyJhbGciOiJFUzI1NiJ9" not in "\n".join(json.dumps(r) for r in sealer.requests)


def test_consequential_policy_stamps_the_write() -> None:
    sealer = StubSealer()
    run = _start(_client(sealer), policy=AgentTimestampPolicy(consequential=True))
    write = run.record_tool_call("close_ticket", b"{}", operation="write", consequential=True)
    assert write.envelope["step"]["timestamp"] == "required"
    assert _stamped(sealer.requests[-1])
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"


def test_per_event_policy_stamps_every_event() -> None:
    sealer = StubSealer()
    run = _start(_client(sealer), policy=PER_EVENT)
    run.record_model_output(b"x")
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"
    assert all(_stamped(r) for r in sealer.requests)


def test_checkpoint_and_require_timestamp_stamp_events_the_policy_would_not() -> None:
    sealer = StubSealer()
    run = _start(_client(sealer))
    checkpoint = run.checkpoint("idle")
    assert checkpoint.step_type == "checkpoint"
    assert checkpoint.envelope["step"]["timestamp"] == "required"
    assert _stamped(sealer.requests[-1])
    run.record("retrieval", require_timestamp=True)
    assert _stamped(sealer.requests[-1])
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"


def test_recorder_refuses_a_signature_whose_signer_cannot_be_established() -> None:
    sealer = StubSealer()
    sealer.omit_signer = True
    with pytest.raises(SigillError, match="signer cannot be established"):
        _start(_client(sealer))


def test_certificate_rotated_mid_run_breaks_the_run() -> None:
    sealer = StubSealer()
    run = _start(_client(sealer))
    sealer.cert = CERT_B
    with pytest.raises(SigillError, match="different certificate"):
        run.record_model_output(b"x")
    assert run.is_broken
    assert len(run.artifacts) == 1, "the foreign-signed event is never appended"


def test_control_artifact_without_timestamp_fails_the_start() -> None:
    sealer = StubSealer()
    sealer.drop_timestamps = True
    with pytest.raises(SigillError, match="Control Artifact must be timestamped"):
        _start(_client(sealer))


def test_sub_millisecond_times_cannot_split_recorder_and_verifier() -> None:
    times = iter([
        datetime(2026, 10, 1, 8, 59, tzinfo=timezone.utc),                     # control artifact
        datetime(2026, 10, 1, 9, 0, 0, 900, tzinfo=timezone.utc),              # run_start :00.0009
        datetime(2026, 10, 1, 9, 5, 0, 100, tzinfo=timezone.utc),              # 300 s later, :00.0001
        datetime(2026, 10, 1, 9, 6, tzinfo=timezone.utc),
    ])
    run = _start(_client(StubSealer()), policy=AgentTimestampPolicy(every_seconds=300), _clock=lambda: next(times))
    step = run.record_model_output(b"x")
    assert step.envelope["step"]["timestamp"] == "required"
    assert step.envelope["step"]["eventTime"] == "2026-10-01T09:05:00.000Z"
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"


def test_callbacks_arrive_in_chain_order_even_when_events_are_recorded_concurrently() -> None:
    delivered: list = []

    def persist(a):
        if a.seq == 1:
            time.sleep(0.3)  # the first event's persistence is slow
        delivered.append(a.seq if a.seq is not None else -1)

    run = _start(_client(StubSealer()), on_artifact_sealed=persist)
    t1 = threading.Thread(target=lambda: run.record_model_output(b"a"))
    t1.start()
    time.sleep(0.05)
    t2 = threading.Thread(target=lambda: run.record_model_output(b"b"))
    t2.start()
    t1.join(5)
    t2.join(5)
    assert delivered == [-1, 0, 1, 2]


def test_callback_may_call_back_into_the_run() -> None:
    anchored: list = []
    holder: dict = {}

    def anchor_after_writes(a):
        if a.step_type == "tool_call":
            anchored.append(holder["run"].checkpoint("after-write"))

    run = _start(_client(StubSealer()), on_artifact_sealed=anchor_after_writes)
    holder["run"] = run
    done = threading.Event()
    threading.Thread(target=lambda: (run.record_tool_call("close_ticket", b"{}", operation="write"), done.set()),
                     daemon=True).start()
    assert done.wait(10), "a callback must not deadlock the run"
    assert len(anchored) == 1 and anchored[0].step_type == "checkpoint"
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"


@pytest.mark.parametrize("bad", [
    "approval decision outside approved/rejected", "object with an unknown role", "reserved step member",
    "unknown step member", "unknown step type", "run_end through record", "non-finite number",
])
def test_recorder_refuses_events_the_verifier_would_reject_without_breaking_the_run(bad: str) -> None:
    sealer = StubSealer()
    run = _start(_client(sealer))
    before = len(sealer.requests)
    act = {
        "approval decision outside approved/rejected": lambda: run.record_human_approval("maybe"),
        "object with an unknown role": lambda: run.record("retrieval", [AgentRunObject("weird", b"\x01")]),
        "reserved step member": lambda: run.record("retrieval", fields={"finalSeq": 3}),
        "unknown step member": lambda: run.record("retrieval", fields={"parentRun": "x"}),
        "unknown step type": lambda: run.record("custom"),
        "run_end through record": lambda: run.record("run_end"),
        "non-finite number": lambda: run.record("retrieval", fields={"detail": float("nan")}),
    }[bad]
    with pytest.raises(ValueError):
        act()
    assert len(sealer.requests) == before
    assert not run.is_broken
    run.record_model_output(b"still fine")
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"


def test_artifact_rejects_none_parts() -> None:
    with pytest.raises(TypeError):
        AgentRunArtifact({}, {}, None)  # type: ignore[arg-type]


def test_retained_payloads_upgrade_objects_to_ok() -> None:
    run = _start(_client(StubSealer()), retain_payloads=True)
    run.record_model_output(b"Done.")
    bundle = run.finish()
    assert set(run.control_artifact.object_digests) <= set(bundle.payloads)
    result = verify_agent_run(bundle, stub_verify)
    assert result.verdict == "run_finalized", result.findings
    assert set(result.checks.values()) == {"ok"}


def test_every_events_cadence_stamps_the_nth_event() -> None:
    run = _start(_client(StubSealer()), policy=AgentTimestampPolicy(every_events=3))
    for i in range(5):
        run.record_model_output(f"x{i}".encode())
    bundle = run.finish()
    # seq: 0 start, 1..5 outputs, 6 end → stamped at seq 2, 5 (cadence) and 6 (run_end).
    assert [a.envelope["step"]["timestamp"] for a in bundle.artifacts] == \
        ["none", "none", "required", "none", "none", "required", "required"]
    assert verify_agent_run(bundle, stub_verify).verdict == "run_finalized"


def test_sealing_failure_breaks_the_chain_and_the_bundle_is_never_finalized() -> None:
    sealer = StubSealer()
    sealer.fail_on_call = 2  # control, run_start, then the tool call fails
    run = _start(_client(sealer))
    with pytest.raises(SigillError):
        run.record_tool_call("lookup_ticket", b"{}")
    assert run.is_broken
    with pytest.raises(RuntimeError):
        run.record_model_output(b"x")
    with pytest.raises(RuntimeError):
        run.finish()
    assert verify_agent_run(run.to_bundle(), stub_verify).verdict == "run_open"


def test_required_timestamp_missing_fails_the_event() -> None:
    sealer = StubSealer()
    run = _start(_client(sealer))
    sealer.drop_timestamps = True
    with pytest.raises(SigillError, match="timestamp is required"):
        run.finish()
    assert run.is_broken and not run.is_finished


def test_run_end_callback_failure_still_leaves_the_run_finished() -> None:
    def persist(a):
        if a.step_type == "run_end":
            raise OSError("disk full")

    run = _start(_client(StubSealer()), on_artifact_sealed=persist)
    with pytest.raises(OSError):
        run.finish()
    assert run.is_finished and not run.is_broken
    with pytest.raises(RuntimeError):
        run.record_model_output(b"after the end")
    bundle = run.to_bundle()
    assert sum(1 for a in bundle.artifacts if a.step_type == "run_end") == 1
    assert verify_agent_run(bundle, stub_verify).verdict == "run_finalized"


def test_ordinary_event_callback_failure_leaves_the_run_usable() -> None:
    def persist(a):
        if a.step_type == "tool_call":
            raise OSError("disk full")

    run = _start(_client(StubSealer()), on_artifact_sealed=persist)
    with pytest.raises(OSError):
        run.record_tool_call("lookup_ticket", b"{}")
    assert not run.is_broken
    run.record_model_output(b"ok")
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"


def test_control_evaluation_refuses_anything_but_a_run_end() -> None:
    client = _client(StubSealer())
    run = _start(client)
    with pytest.raises(ValueError, match="run_end"):
        client.seal_control_evaluation(ControlEvaluationRequest(
            certificate_id=VERIFIER_CERT, verifier_id="urn:example:verifier", verifier_version="1",
            control_artifact=run.control_artifact, run_end=run.artifacts[0],
            observed_state=[AgentRunObject.text("observed-state", "x")],
            controls=[ControlResult("c", "PASS")], overall="PASS"))


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
