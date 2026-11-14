"""ControlEvaluation v3 and the enforcement comparison (``spec/control-evaluation-v3.md``) against vector 15: every
expected ``enforcement`` member byte for byte, the facts, the results, the schema's envelopes, and the evaluations a
verifier must reject. Tests that need the Cedar core are skipped, with the reason, without the 'policy' extra.
"""

from __future__ import annotations

import copy
import json
import uuid
from dataclasses import replace

import pytest

from sigill_sdk import (
    POLICY_CONTROL_SET_CONTENT_TYPE,
    AgentPolicy,
    AgentRunArtifact,
    CedarEngine,
    ControlEvaluation,
    PolicyEngineError,
    PolicyEvaluationRequest,
    verify_agent_run,
)
from sigill_sdk._canonical import canonicalize, hash_bytes
from sigill_sdk._schema import validate_profile
from test_agent_enforcement import V14, _bundle, _with_enforcement
from test_agent_policy import _client
from test_agent_run import CERT_V, REPO, VERIFIER_CERT, StubSealer, _clock, stub_verify

V15 = REPO / "spec" / "test-vectors" / "15-policy-enforcement-evaluation"
EXPECTED = sorted(p.stem for p in (V15 / "expected").glob("*.json") if not p.stem.endswith(".facts"))
REJECTED = sorted(p.stem for p in (V15 / "invalid-evaluations").glob("*.json"))
ENVELOPES = json.loads((V15 / "envelopes.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def engine() -> CedarEngine:
    try:
        return CedarEngine()
    except ImportError as e:
        pytest.skip(str(e))


def _load(name: str) -> tuple[dict, bytes]:
    """The run and its control-set bytes: vector 14's runs as ``14-<case>``, else vector 15's."""
    if name.startswith("14-"):
        run = json.loads((V14 / "runs" / f"{name[3:]}.json").read_text(encoding="utf-8"))
        return run, _with_enforcement(run["enforcement"])
    run = json.loads((V15 / "runs" / f"{name}.json").read_text(encoding="utf-8"))
    variant = run["controlSet"]
    return run, (_with_enforcement(run["enforcement"]) if variant == "13"
                 else (V15 / f"control-set-{variant}.json").read_bytes())


def _artifacts(run: dict, doc: bytes) -> tuple[AgentRunArtifact, list[AgentRunArtifact]]:
    """The Control Artifact and the events as an index holds them: envelopes and object digests, no payloads."""
    objects, digests = [], {}
    for i, (role, hex_) in enumerate({**run["configuration"], "control-set": hash_bytes(doc)}.items()):
        objects.append({"uri": f"objects/control-{i}", "role": role, "contentType": "application/json"})
        digests[f"objects/control-{i}"] = hex_
    control = AgentRunArtifact({"agent": {"id": run["agentId"]}, "objects": objects,
                                "activity": {"name": "support-session", "correlationId": run["correlationId"]}},
                               {}, digests)
    return control, [AgentRunArtifact(e["envelope"], {}, e["objectDigests"]) for e in run["events"]]


def test_vector_15_is_complete() -> None:
    assert (len(EXPECTED), len(REJECTED)) == (95, 15)
    assert sum(n.startswith("14-") for n in EXPECTED) == 35


@pytest.mark.parametrize("name", EXPECTED)
def test_the_comparison_is_the_vectors_byte_for_byte(name: str, engine: CedarEngine) -> None:
    want = json.loads((V15 / "expected" / f"{name}.json").read_text(encoding="utf-8"))
    run, doc = _load(name)
    control, events = _artifacts(run, doc)
    member = AgentPolicy.compare_enforcement(control, reversed(events), doc, engine)  # any order
    assert canonicalize(member) == canonicalize(want["enforcement"])
    facts = AgentPolicy.build_facts_v2(run["agentId"], run["correlationId"], events, doc)
    assert facts.sha256 == want["factsSha256"]
    if not name.startswith("14-"):
        assert facts.data == (V15 / "expected" / f"{name}.facts.json").read_bytes()
    ev = AgentPolicy.evaluate(doc, facts, engine)
    got = {r.id: {"id": r.id, "result": r.result, **({"where": list(r.where)} if r.where else {})} for r in ev.rules}
    assert got == {c["id"]: c for c in want["controls"]} and ev.overall == want["overall"]
    d = AgentPolicy.compute_digests(doc)
    assert (d.approval_scope_digest, d.cedar_digest) == (want["approvalScopeDigest"], want.get("cedarDigest"))


@pytest.mark.parametrize("case", ENVELOPES["valid"], ids=lambda c: c["name"])
def test_the_v3_schema_accepts(case: dict) -> None:
    assert validate_profile(case["envelope"], "ControlEvaluation/3") == []


@pytest.mark.parametrize("case", ENVELOPES["invalid"], ids=lambda c: c["name"])
def test_the_v3_schema_rejects(case: dict) -> None:
    assert validate_profile(case["envelope"], "ControlEvaluation/3") != []


# ── Sealed evaluations, verified ─────────────────────────────────────────────

def _patched(env: dict, patch: list[dict]) -> dict:
    """RFC 6902 add, replace and remove, as the vector's edits use them."""
    env = copy.deepcopy(env)
    for op in patch:
        *parents, last = op["path"].lstrip("/").split("/")
        node = env
        for p in parents:
            node = node[int(p)] if isinstance(node, list) else node[p]
        key = int(last) if isinstance(node, list) else last
        if op["op"] == "remove":
            del node[key]
        else:
            node[key] = copy.deepcopy(op["value"])
    return env


def _evaluated(name: str, engine: CedarEngine, patch: list[dict] | None = None):  # noqa: ANN202
    """The run sealed with the stub signer, and its policy evaluation (ControlEvaluation v3), optionally edited."""
    run, doc = _load(name)
    bundle = _bundle(run, (POLICY_CONTROL_SET_CONTENT_TYPE, doc))
    facts = AgentPolicy.build_facts_v2(run["agentId"], run["correlationId"], bundle.artifacts, doc)
    rules = AgentPolicy.evaluate(doc, facts, engine)
    prefix = [a for a in bundle.artifacts if a.seq is not None and a.seq <= facts.through_seq]
    member = AgentPolicy.compare_enforcement(bundle.control_artifact, bundle.artifacts, doc, engine)
    prepared = ControlEvaluation.prepare_policy(PolicyEvaluationRequest(
        certificate_id=VERIFIER_CERT, evaluator_id="urn:example:policy-evaluator", evaluator_version="1.0.0",
        control_artifact=bundle.control_artifact, control_set_document=doc, events=prefix, rules=rules.rules,
        policy_status="unapproved", engine=rules.engine, missing_seqs=facts.missing_seqs, enforcement=member,
        private_controls_reported="reported"), _clock=_clock())
    assert prepared.envelope["schemaVersion"] == "3" and prepared.envelope["policy"]["evaluator"]["factsVersion"] == "2"
    if patch:
        env = _patched(prepared.envelope, patch)
        prepared = replace(prepared, envelope=env, envelope_hash_hex=hash_bytes(canonicalize(env)))
    sealer = StubSealer()
    sealer.cert = CERT_V
    evaluation = ControlEvaluation.seal(_client(sealer), prepared, VERIFIER_CERT)
    return bundle.with_evaluations(evaluation).with_payloads(prepared.payloads), prepared


@pytest.mark.parametrize("name", ["14-02-denied-by-rule", "14-24-deny-and-halt-one-call", "e01-refusal-missing",
                                  "e23-engine-not-available", "c01-executed-after-denial", "e39-no-rules-refused",
                                  "e25-open-refusal-pending", "e28-gap"])
def test_an_honest_v3_evaluation_verifies_and_its_comparison_recomputes(name: str, engine: CedarEngine) -> None:
    bundle, _ = _evaluated(name, engine)
    e = verify_agent_run(bundle, stub_verify, engine=engine).evaluations[0]
    assert e.valid and e.schema_version == "3" and e.facts_match and e.results_recomputed, e.findings
    member = bundle.evaluations[0].envelope["policy"]["enforcement"]
    assert (e.enforcement_comparison, e.enforcement_result) == (member["comparison"], member.get("result"))
    assert e.enforcement_recomputed == (member["comparison"] == "performed"), "not_performed is never recomputed"
    without = verify_agent_run(bundle, stub_verify).evaluations[0]
    assert without.valid and not without.enforcement_recomputed


WHY = {  # the finding that names each vector's reason
    "x01-recorded-not-from-chain": "decision 1: recorded does not follow from the chain",
    "x02-comparison-does-not-recompute": "its enforcement comparison does not recompute with cedar-policy@4.14.0",
    "x03-result-not-from-decisions": "policy.enforcement.result does not follow from its decisions",
    "x04-performed-with-another-core": "is performed, but the run gives not performed (engine_unavailable)",
    "x05-engine-unavailable-with-the-same-core": "is not performed (engine_unavailable), but the run gives performed",
    "x06-decisions-not-ascending": "policy.enforcement.decisions do not ascend by seq",
    "x07-finding-of-the-wrong-class": "decision 1: its findings do not fit its outcome",
    "x08-no-finding-of-the-outcomes-class": "decision 5: its findings do not fit its outcome",
    "x09-inconsistent-chain-compared": "is performed, but the run gives not performed (chain_inconsistent)",
    "x10-chain-inconsistent-claimed": "is not performed (chain_inconsistent), but the run gives performed",
    "x11-cedar-digest-without-cedar": "approvalScopeDigest or cedarDigest does not recompute from its control set",
    "x11-controls-empty-with-rules": "rule 'export-weight' is not reported",
    "x13-recorded-outcome-without-decision": "the event at seq 1 has a recorded outcome but no decision",
    "x14-not-checkable-without-unavailable": "decision 1: not_checkable, but the record after it does not say unavailable",
    "x15-as-required-where-due-is-not-recorded": "decision 1: as_required, but what is due is not what the chain records",
}


@pytest.mark.parametrize("name", REJECTED)
def test_the_verifier_rejects_for_the_vectors_reason(name: str, engine: CedarEngine) -> None:
    x = json.loads((V15 / "invalid-evaluations" / f"{name}.json").read_text(encoding="utf-8"))
    bundle, _ = _evaluated(x["run"], engine, x["patch"])
    checks = [verify_agent_run(bundle, stub_verify, engine=engine).evaluations[0]]
    if not x["needsEngine"]:
        checks.append(verify_agent_run(bundle, stub_verify).evaluations[0])
    for e in checks:
        assert not e.valid, x["because"]
        assert any(WHY[name] in f for f in e.findings), (x["because"], e.findings)
        if not name.startswith("x11"):  # the x11 members are honest: the evaluation is wrong elsewhere
            assert not e.enforcement_recomputed


# ── Prepare, determinism, the engine ─────────────────────────────────────────

def test_prepare_refuses_an_enforcement_member_that_does_not_fit_the_run(engine: CedarEngine) -> None:
    run, doc = _load("e01-refusal-missing")
    bundle = _bundle(run, (POLICY_CONTROL_SET_CONTENT_TYPE, doc))
    facts = AgentPolicy.build_facts_v2(run["agentId"], run["correlationId"], bundle.artifacts, doc)
    rules = AgentPolicy.evaluate(doc, facts, engine)
    member = AgentPolicy.compare_enforcement(bundle.control_artifact, bundle.artifacts, doc, engine)
    request = PolicyEvaluationRequest(
        certificate_id=VERIFIER_CERT, evaluator_id="e", evaluator_version="1", control_artifact=bundle.control_artifact,
        control_set_document=doc, events=bundle.artifacts, rules=rules.rules, policy_status="unapproved",
        engine=rules.engine, enforcement=member, private_controls_reported="reported")
    ControlEvaluation.prepare_policy(request)
    with pytest.raises(ValueError, match="enforcement does not fit this run"):
        ControlEvaluation.prepare_policy(replace(request, enforcement={**member, "result": "as_required"}))
    with pytest.raises(ValueError, match="required exactly when the control set is a v2 one"):
        ControlEvaluation.prepare_policy(replace(request, enforcement=None))


def test_the_member_is_byte_stable_across_two_sealings(engine: CedarEngine) -> None:
    run, doc = _load("e21-refused-call-consumes-approval")
    one, two = (_bundle(run, (POLICY_CONTROL_SET_CONTENT_TYPE, doc)) for _ in range(2))
    a = AgentPolicy.compare_enforcement(one.control_artifact, one.artifacts, doc, engine)
    b = AgentPolicy.compare_enforcement(two.control_artifact, list(reversed(two.artifacts)), doc, engine)
    assert canonicalize(a) == canonicalize(b)


class _Engine:
    """A stand-in core: another version, or one that refuses every request."""

    def __init__(self, version: str, refuse: bool = False) -> None:
        self.version, self.refuse, self.asked = version, refuse, 0

    def authorize(self, call: dict) -> dict:
        self.asked += 1
        if self.refuse:
            return {"type": "failure", "errors": [{"message": "refused"}]}
        return {"type": "success", "response": {"decision": "allow", "diagnostics": {"reason": [], "errors": []}}}

    def validate(self, call: dict) -> dict:
        return {"type": "success", "validationErrors": []}


def test_another_core_is_never_used_for_the_comparison() -> None:
    run, doc = _load("14-02-denied-by-rule")
    control, events = _artifacts(run, doc)
    other = _Engine("4.13.0")
    assert AgentPolicy.compare_enforcement(control, events, doc, other) == {
        "comparison": "not_performed", "notPerformed": "engine_unavailable", "recordedEngine": "cedar-policy@4.14.0"}
    assert other.asked == 0, "a comparison that is not performed asks the engine nothing"
    run, doc = _load("e01-refusal-missing")  # no record: the evaluator's own core
    control, events = _artifacts(run, doc)
    assert AgentPolicy.compare_enforcement(control, events, doc, other)["comparison"] == "performed"
    with pytest.raises(PolicyEngineError):
        AgentPolicy.compare_enforcement(control, events, doc, _Engine("4.14.0", refuse=True))


def test_the_comparison_refuses_a_v1_or_unsealed_control_set(engine: CedarEngine) -> None:
    run, doc = _load("e01-refusal-missing")
    control, events = _artifacts(run, doc)
    v1 = (REPO / "spec" / "test-vectors" / "11-policy-control-set" / "control-set.json").read_bytes()
    with pytest.raises(ValueError, match="v2 policy control set"):
        AgentPolicy.compare_enforcement(control, events, v1, engine)
    with pytest.raises(ValueError, match="not the one the Control Artifact seals"):
        AgentPolicy.compare_enforcement(control, events, _with_enforcement({"mode": "observe"}), engine)


def test_a_v1_control_set_still_yields_control_evaluation_v2_unchanged(monkeypatch: pytest.MonkeyPatch,
                                                                      engine: CedarEngine) -> None:
    """The same request as before this version gives the same bytes: pinned with fixed ids and a fixed clock."""
    from sigill_sdk import _agent_run
    from test_policy_engine import _PolicyRun
    counter = iter(range(1000))
    monkeypatch.setattr(_agent_run.uuid, "uuid4", lambda: uuid.UUID(int=next(counter)))
    monkeypatch.setattr(_agent_run, "new_object_uri", lambda: f"objects/{next(counter)}")
    p = _PolicyRun()
    ev = AgentPolicy.evaluate(p.doc, p.facts, engine)
    prepared = ControlEvaluation.prepare_policy(PolicyEvaluationRequest(
        certificate_id=VERIFIER_CERT, evaluator_id="urn:example:policy-evaluator", evaluator_version="1.0.0",
        control_artifact=p.run.control_artifact, control_set_document=p.doc, events=p.bundle.artifacts,
        rules=ev.rules, policy_status="unapproved", engine=ev.engine, private_controls_reported="reported"),
        _clock=_clock())
    env = prepared.envelope
    assert env["schemaVersion"] == "2" and "enforcement" not in env["policy"]
    assert hash_bytes(canonicalize(env)) == V1_EVALUATION_SHA256, hash_bytes(canonicalize(env))


V1_EVALUATION_SHA256 = "caeac0401f6c6a38748328361097b28082a1a5914c2c4b6926b54a738c032c95"  # as 0.15.0 seals it


# ── Input errors (the comparison makes no statement) ──────────────────────────

def _e01() -> tuple[AgentRunArtifact, list[AgentRunArtifact], bytes]:
    run, doc = _load("e01-refusal-missing")
    control, events = _artifacts(run, doc)
    return control, events, doc


@pytest.mark.parametrize("order", ["as given", "reversed"])
def test_a_repeated_or_missing_seq_is_an_input_error(order: str, engine: CedarEngine) -> None:
    control, events, doc = _e01()
    twin = AgentRunArtifact(copy.deepcopy(events[2].envelope), {}, dict(events[2].object_digests))
    twin.envelope["chain"]["seq"] = 1
    both = events + [twin] if order == "as given" else [twin] + events
    with pytest.raises(ValueError, match="^two events claim seq 1$"):
        AgentPolicy.compare_enforcement(control, both, doc, engine)
    seqless = AgentRunArtifact(copy.deepcopy(events[1].envelope), {}, dict(events[1].object_digests))
    del seqless.envelope["chain"]["seq"]
    with pytest.raises(ValueError, match="^an event has no chain.seq$"):
        AgentPolicy.compare_enforcement(control, events + [seqless], doc, engine)


def test_a_record_without_engine_and_a_bad_control_artifact_are_input_errors(engine: CedarEngine) -> None:
    run, doc = _load("14-02-denied-by-rule")
    control, events = _artifacts(run, doc)
    del events[2].envelope["step"]["enforcer"]["engine"]
    with pytest.raises(ValueError, match="has no enforcer.engine"):
        AgentPolicy.compare_enforcement(control, events, doc, engine)
    control, events, doc = _e01()
    nameless = AgentRunArtifact(copy.deepcopy(control.envelope), {}, dict(control.object_digests))
    del nameless.envelope["activity"]["correlationId"]
    with pytest.raises(ValueError, match="no agent or correlationId"):
        AgentPolicy.compare_enforcement(nameless, events, doc, engine)
    twice = AgentRunArtifact(copy.deepcopy(control.envelope), {}, {**control.object_digests, "objects/extra": "0" * 64})
    twice.envelope["objects"].append({"uri": "objects/extra", "role": "control-set", "contentType": "application/json"})
    with pytest.raises(ValueError, match="exactly one control-set object"):
        AgentPolicy.compare_enforcement(twice, events, doc, engine)


class _Raising(_Engine):
    """Raises for the run-level request only."""

    def authorize(self, call: dict) -> dict:
        if call["action"]["id"] == "run":
            raise RuntimeError("trapped")
        return super().authorize(call)


def test_an_engine_that_raises_anything_is_a_policy_engine_error() -> None:
    control, events, doc = _e01()
    with pytest.raises(PolicyEngineError, match="^The policy engine failed: trapped$"):
        AgentPolicy.compare_enforcement(control, events, doc, _Raising("4.14.0"))


def test_prepare_refuses_enforcement_for_a_v1_control_set(engine: CedarEngine) -> None:
    from test_policy_engine import _PolicyRun
    p = _PolicyRun()
    ev = AgentPolicy.evaluate(p.doc, p.facts, engine)
    with pytest.raises(ValueError, match="required exactly when the control set is a v2 one"):
        ControlEvaluation.prepare_policy(PolicyEvaluationRequest(
            certificate_id=VERIFIER_CERT, evaluator_id="e", evaluator_version="1", control_artifact=p.run.control_artifact,
            control_set_document=p.doc, events=p.bundle.artifacts, rules=ev.rules, policy_status="unapproved",
            engine=ev.engine, private_controls_reported="reported",
            enforcement={"comparison": "performed", "decisions": [], "result": "as_required"}))


def test_recomputed_only_with_the_core_the_evaluation_names(engine: CedarEngine) -> None:
    switched_off, _ = _evaluated("e23-engine-not-available", engine)  # not_performed: engine_unavailable
    e = verify_agent_run(switched_off, stub_verify, engine=engine).evaluations[0]
    assert e.valid and not e.enforcement_recomputed
    assert (e.enforcement_comparison, e.enforcement_result) == ("not_performed", None)
    performed, _ = _evaluated("e01-refusal-missing", engine)
    assert verify_agent_run(performed, stub_verify, engine=engine).evaluations[0].enforcement_recomputed
    assert not verify_agent_run(performed, stub_verify).evaluations[0].enforcement_recomputed
    other = verify_agent_run(performed, stub_verify, engine=_Engine("4.13.0")).evaluations[0]
    assert not other.enforcement_recomputed and other.enforcement_result == "let_through"


@pytest.mark.parametrize("bad", [
    {"decisions": 5}, {"decisions": [{"seq": 1, "due": "refused", "dueReason": "rule", "dueRules": [1, "a"],
                                      "recorded": "none", "outcome": "let_through", "findings": ["refusal_missing"]}]},
    {"decisions": [{"seq": 1, "due": "refused", "dueReason": "rule", "dueRules": [{}, {}], "recorded": "none",
                    "outcome": "let_through", "findings": ["refusal_missing"]}]},
    {"decisions": [{"seq": 1, "due": "refused", "outcome": ["x"]}]}, {"result": {"x": 1}},
    {"decisions": [{"seq": "1", "due": "none", "outcome": "as_required"}]},
    {"decisions": [{"seq": 1, "due": "refused", "dueReason": "rule", "dueRules": ["a"], "recorded": "none",
                    "outcome": "let_through", "findings": [["refusal_missing"]]}]},
], ids=lambda b: json.dumps(b)[:40])
def test_a_malformed_signed_member_is_an_invalid_evaluation_never_an_exception(bad: dict, engine: CedarEngine) -> None:
    patch = [{"op": "replace", "path": f"/policy/enforcement/{k}", "value": v} for k, v in bad.items()]
    bundle, _ = _evaluated("e01-refusal-missing", engine, patch)
    for e in (verify_agent_run(bundle, stub_verify, engine=engine).evaluations[0],
              verify_agent_run(bundle, stub_verify).evaluations[0]):
        assert not e.valid and not e.enforcement_recomputed and e.findings


def test_a_duplicated_locked_role_is_an_input_error(engine: CedarEngine) -> None:
    control, events, doc = _e01()
    uri = next(o["uri"] for o in control.envelope["objects"] if o["role"] == "tool-manifest")
    twice = AgentRunArtifact(copy.deepcopy(control.envelope), {}, {**control.object_digests, "objects/again": "0" * 64})
    twice.envelope["objects"].append({"uri": "objects/again", "role": "tool-manifest", "contentType": "application/json"})
    assert uri in twice.object_digests
    with pytest.raises(ValueError, match="more than one tool-manifest object"):
        AgentPolicy.compare_enforcement(twice, events, doc, engine)


def test_a_non_string_engine_is_an_input_error(engine: CedarEngine) -> None:
    run, doc = _load("14-02-denied-by-rule")
    control, events = _artifacts(run, doc)
    events[2].envelope["step"]["enforcer"]["engine"] = 4
    with pytest.raises(ValueError, match="has no enforcer.engine"):
        AgentPolicy.compare_enforcement(control, events, doc, engine)


@pytest.mark.parametrize("patch", [
    [{"op": "replace", "path": "/policy/enforcement/decisions/0/outcome", "value": "as_required"},
     {"op": "remove", "path": "/policy/enforcement/decisions/0/findings"},
     {"op": "replace", "path": "/policy/enforcement/result", "value": "as_required"}],
    [{"op": "replace", "path": "/policy/enforcement/decisions", "value": "oops"}],
    [{"op": "replace", "path": "/policy/enforcement/decisions", "value": []},  # caught by recomputation only
     {"op": "replace", "path": "/policy/enforcement/result", "value": "as_required"}],
], ids=["relabelled", "malformed", "recomputation"])
def test_a_rejected_evaluation_reports_no_comparison(patch: list, engine: CedarEngine) -> None:
    bundle, _ = _evaluated("e01-refusal-missing", engine, patch)
    e = verify_agent_run(bundle, stub_verify, engine=engine).evaluations[0]
    assert not e.valid and (e.enforcement_comparison, e.enforcement_result) == (None, None)


def test_an_engine_whose_version_fails_fails_the_comparison() -> None:
    class Broken(_Engine):
        @property
        def version(self) -> str:
            raise RuntimeError("no module")

        @version.setter
        def version(self, v: str) -> None:
            pass
    control, events, doc = _e01()
    with pytest.raises(PolicyEngineError, match="^The policy engine failed: no module$"):
        AgentPolicy.compare_enforcement(control, events, doc, Broken("4.14.0"))


def test_the_core_free_path_refuses_what_compare_refuses() -> None:
    from sigill_sdk._agent_compare import member_problems
    control, events, _ = _e01()
    pairs = [(a.envelope, a.object_digests) for a in events]
    member = {"comparison": "performed", "decisions": [], "result": "as_required"}
    twice = AgentRunArtifact(copy.deepcopy(control.envelope), {}, dict(control.object_digests))
    twice.envelope["objects"].append({"uri": "objects/extra", "role": "control-set", "contentType": "application/json"})
    nameless = AgentRunArtifact(copy.deepcopy(control.envelope), {}, dict(control.object_digests))
    del nameless.envelope["activity"]["correlationId"]
    for bad, text in ((twice, "exactly one control-set object"), (nameless, "no agent or correlationId")):
        with pytest.raises(ValueError, match=text):  # the verifier turns these into findings
            member_problems(member, bad, pairs, "cedar-policy@4.14.0")


def test_a_non_conforming_member_is_reported_once(engine: CedarEngine) -> None:
    bundle, _ = _evaluated("e01-refusal-missing", engine, [{"op": "replace", "path": "/policy/enforcement/decisions",
                                                           "value": 5}])
    e = verify_agent_run(bundle, stub_verify, engine=engine).evaluations[0]
    about = [f for f in e.findings if "decisions" in f]
    assert not e.valid and len(about) == 1, about
