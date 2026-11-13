"""The policy engine: the bundled Cedar core in Wasmtime (CedarEngine), strict validation against vectors 11 and 13,
evaluation against vectors 12 and 14, and the verifier's recomputation of policy evaluations (Control Evaluation v2
§4.6). Tests that need the engine are skipped, with the reason, when the 'policy' extra (wasmtime) is not installed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import replace

import pytest

from sigill_sdk import (
    AgentPolicy,
    AgentRunBundle,
    CedarEngine,
    ControlEvaluation,
    PolicyEngineError,
    PolicyEvaluationRequest,
    PolicyRuleResult,
    verify_agent_run,
)
from sigill_sdk import _agent_verify, _policy_engine
from sigill_sdk._agent_policy import _BASELINE, BASELINE_PERMIT, _cedar_schema
from sigill_sdk._canonical import canonicalize, hash_bytes
from test_agent_enforcement import DOC as V13_DOC
from test_agent_enforcement import RUNS, V14, _run, _with_enforcement
from test_agent_policy import DOC as V11_DOC
from test_agent_policy import FACTS as V12
from test_agent_policy import _client
from test_agent_run import CERT_V, REPO, VERIFIER_CERT, StubSealer, _clock, _start, stub_verify


@pytest.fixture(scope="module")
def engine() -> CedarEngine:
    try:
        return CedarEngine()
    except ImportError as e:
        pytest.skip(str(e))


def _mutate(raw: bytes, change) -> bytes:  # noqa: ANN001
    doc = json.loads(raw)
    change(doc)
    return json.dumps(doc).encode()


def _rules(d: dict) -> dict:
    return d["cedar"]["policies"]["staticPolicies"]


def _calls(control_set: bytes, facts: bytes) -> list[dict]:
    """The authorize call of every request of a facts document, as the evaluator builds it."""
    doc, f = json.loads(control_set), json.loads(facts)
    version = 2 if "schemaVersion" in doc else 1
    base = {"schema": _cedar_schema(version), "validateRequest": True,
            "policies": {"staticPolicies": {**_rules(doc), BASELINE_PERMIT: _BASELINE}},
            "entities": f.get("entities", [])}
    return [{**{k: r[k] for k in ("principal", "action", "resource", "context")}, **base} for r in f["requests"]]


def _as_json(controls) -> list[dict]:  # noqa: ANN001
    return [{"id": c.id, "result": c.result, **({"where": list(c.where)} if c.where else {})} for c in controls]


# ── The module ──────────────────────────────────────────────────────────────

def test_the_bundled_module_is_the_pinned_file() -> None:
    data = (REPO / "src" / "sigill_sdk" / "_policy" / "sigill_cedar.wasm").read_bytes()
    assert hashlib.sha256(data).hexdigest() == _policy_engine.MODULE_SHA256 \
        == "a0cd395067e77a157116f6b25bcdb612d34c61d1a4446918d75da1a07c80d1f3"
    assert len(data) == 3_855_655
    assert _policy_engine._module_bytes() == data, "the installed package carries the same file"


def test_the_engine_reports_the_pinned_cedar_version(engine: CedarEngine) -> None:
    assert engine.version == _policy_engine.CEDAR_VERSION == "4.14.0"


def test_a_tampered_module_is_refused(engine: CedarEngine, monkeypatch: pytest.MonkeyPatch) -> None:
    data = bytearray(_policy_engine._module_bytes())
    data[-1] ^= 1
    monkeypatch.setattr(_policy_engine, "_module_bytes", lambda: bytes(data))
    tampered = CedarEngine()
    for _ in range(2):  # and stays refused
        with pytest.raises(PolicyEngineError, match="SHA-256"):
            tampered.authorize({})


def test_without_wasmtime_the_engine_names_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "wasmtime", None)  # import wasmtime now raises ImportError
    with pytest.raises(ImportError, match=r"sigill-sdk\[policy\]"):
        CedarEngine()


def test_importing_the_sdk_does_not_import_wasmtime() -> None:
    code = "import sys, sigill_sdk; sigill_sdk.CedarEngine; sys.exit('wasmtime' in sys.modules)"
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"))
    assert subprocess.run([sys.executable, "-c", code], env=env).returncode == 0


def test_a_malformed_call_is_a_failure_answer_not_an_exception(engine: CedarEngine) -> None:
    assert engine.authorize({})["type"] == "failure"
    assert engine.validate({"policies": 1})["type"] == "failure"


def test_the_memory_cap_traps_as_a_policy_engine_error_and_the_engine_recovers(
        engine: CedarEngine, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _policy_engine._MEMORY_LIMIT == 256 * 1024 * 1024
    monkeypatch.setattr(_policy_engine, "_MEMORY_LIMIT", 32 * 1024 * 1024)  # the same mechanism, a cheaper test
    capped = CedarEngine()
    call = _calls(V11_DOC, (V12 / "expected" / "02-rogue.facts.json").read_bytes())[0]
    before = capped.authorize(call)
    padded = {"pad": "x" * (40 * 1024 * 1024)}  # the input alone exceeds the cap
    assert engine.authorize(padded)["type"] == "failure", "under the default cap the same call is only malformed"
    with pytest.raises(PolicyEngineError, match="cedar_authorize"):
        capped.authorize(padded)
    assert capped.authorize(call) == before, "a fresh instance serves the next call"


def test_concurrent_use_gives_the_same_answers(engine: CedarEngine) -> None:
    calls = []
    for name in ("10-rule-error", "24-deny-and-halt-one-call", "35-two-approvals-two-calls"):
        calls += _calls(_with_enforcement(_run(name)["enforcement"]), (V14 / "expected" / f"{name}.facts.json").read_bytes())
    expected = [engine.authorize(c) for c in calls]
    got: dict = {}

    def work(i: int) -> None:
        got[i] = [engine.authorize(c) for c in calls]
    threads = [threading.Thread(target=work, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(got) == 16 and all(g == expected for g in got.values())


def test_an_evaluation_of_2000_requests(engine: CedarEngine) -> None:
    facts = json.loads((V12 / "expected" / "02-rogue.facts.json").read_bytes())
    single = AgentPolicy.evaluate(V11_DOC, json.dumps(facts).encode(), engine)
    source = facts["requests"]
    facts["requests"] = [dict(source[i % len(source)], seq=i) for i in range(2000)]
    started = time.perf_counter()
    big = AgentPolicy.evaluate(V11_DOC, json.dumps(facts).encode(), engine)
    elapsed = time.perf_counter() - started
    print(f"\n2000-request evaluation: {elapsed:.2f} s ({elapsed / 2:.2f} ms per request)")
    assert len(big.requests) == 2000
    assert [(r.reason, r.errors) for r in big.requests] == \
        [(single.requests[i % len(source)].reason, single.requests[i % len(source)].errors) for i in range(2000)]
    assert big.overall == single.overall


# ── Strict validation (vectors 11 and 13) ───────────────────────────────────

def test_the_vector_control_sets_validate_strictly(engine: CedarEngine) -> None:
    assert AgentPolicy.validate_strict(V11_DOC, engine) == [], "v1 against Cedar schema v1"
    assert AgentPolicy.validate_strict(V13_DOC, engine) == [], "v2 policies and entities against Cedar schema v2"


def _approval_gt(n: int) -> list:
    return [{"kind": "when", "body": {">": {"left": {".": {"left": {"Var": "context"}, "attr": "approval"}},
                                            "right": {"Value": n}}}}]


_CALL_ON_STEP = {"effect": "forbid", "principal": {"op": "All"},
                 "action": {"op": "==", "entity": {"type": "Action", "id": "tool_call"}},
                 "resource": {"op": "==", "entity": {"type": "Step", "id": "0"}}, "conditions": [],
                 "annotations": {"id": "call-on-step"}}
# The same cases in both ports. (name, document, whether validate() alone finds it, the exact problems
# validate_strict adds)
STRICT_CASES = [
    ("a-v1-type-error-in-condition",
     _mutate(V11_DOC, lambda d: _rules(d)["max-steps"].update(conditions=_approval_gt(20))),
     False, ["policy 'max-steps' does not validate against Cedar schema v1 in strict mode: for policy `max-steps`, "
             "unexpected type: expected Long but saw String"]),
    ("b-v2-type-error-in-condition",
     _mutate(V13_DOC, lambda d: _rules(d)["no-web-search"].update(conditions=_approval_gt(3))),
     False, ["policy 'no-web-search' does not validate against Cedar schema v2 in strict mode: for policy "
             "`no-web-search`, unexpected type: expected Long but saw String"]),
    ("c-v2-entity-violates-schema",
     _mutate(V13_DOC, lambda d: d["cedar"]["entities"][2]["attrs"].update(consequential="yes")),
     True, ["cedar.entities do not conform to Cedar schema v2: entity does not conform to the schema: in attribute "
            "`consequential` on `Tool::\"crm.read_customer\"`, type mismatch: value was expected to have type bool, but "
            "it actually has type string: `\"yes\"`"]),
    ("d-v1-schema-digest-of-schema-v2",
     _mutate(V11_DOC, lambda d: d["cedar"].update(schemaSha256=json.loads(
         (REPO / "spec" / "test-vectors" / "13-policy-control-set-v2" / "expected.json").read_bytes())["schemaSha256"])),
     False, ["cedar.schemaSha256 must be the SHA-256 of JCS(agent-policy-cedar-schema-v1.json)"]),
    ("e-v2-rules-in-a-v1-document",
     _mutate(V11_DOC, lambda d: d["cedar"].update(policies=json.loads(V13_DOC)["cedar"]["policies"])),
     False, [
         "policy 'export-weight' does not validate against Cedar schema v1 in strict mode: for policy `export-weight`, "
         "attribute `toolCallsSoFar` in context for Action::\"tool_call\" not found",
         "policy 'halt-refund-loop' does not validate against Cedar schema v1 in strict mode: for policy `halt-refund-loop`, "
         "attribute `callsOfThisTool` in context for Action::\"tool_call\" not found",
         "policy 'halt-retrieval-after-denial' does not validate against Cedar schema v1 in strict mode: for policy `halt-retrieval-after-denial`, "
         "attribute `denialsSoFar` in context for Action::\"retrieval\" not found",
         "policy 'no-web-search' does not validate against Cedar schema v1 in strict mode: for policy `no-web-search`, "
         "unrecognized entity type `AgentGroup`",
         "policy 'preview-weight' does not validate against Cedar schema v1 in strict mode: for policy `preview-weight`, "
         "attribute `toolCallsSoFar` in context for Action::\"tool_call\" not found",
         "policy 'read-loop-limit' does not validate against Cedar schema v1 in strict mode: for policy `read-loop-limit`, "
         "attribute `callsOfThisTool` in context for Action::\"tool_call\" not found",
         "policy 'restricted-needs-bound-approval' does not validate against Cedar schema v1 in strict mode: for policy `restricted-needs-bound-approval`, "
         "unrecognized entity type `ToolGroup`",
         "policy 'shadow-repeat-read' does not validate against Cedar schema v1 in strict mode: for policy `shadow-repeat-read`, "
         "attribute `callsOfThisTool` in context for Action::\"tool_call\" not found",
     ]),
    # Only warnings in the core (no applicable action; an impossible policy): strict validation fails on errors only.
    ("f-v1-warnings-only-rule-passes",
     _mutate(V11_DOC, lambda d: _rules(d).update({"call-on-step": _CALL_ON_STEP})),
     False, []),
    # run_start applies only to Step resources, which have no attribute consequential (Tool has).
    ("g-v2-attribute-the-actions-resource-type-lacks",
     _mutate(V13_DOC, lambda d: _rules(d)["no-web-search"].update(
         action={"op": "==", "entity": {"type": "Action", "id": "run_start"}}, resource={"op": "All"},
         conditions=[{"kind": "when", "body": {".": {"left": {"Var": "resource"}, "attr": "consequential"}}}])),
     False, ["policy 'no-web-search' does not validate against Cedar schema v2 in strict mode: for policy "
             "`no-web-search`, attribute `consequential` on entity type `Step` not found"]),
]


@pytest.mark.parametrize("name,document,structural,added", STRICT_CASES, ids=[c[0] for c in STRICT_CASES])
def test_strict_validation_rejects(engine: CedarEngine, name: str, document: bytes, structural: bool,
                                   added: list[str]) -> None:
    plain = AgentPolicy.validate(document)
    assert bool(plain) == structural
    assert AgentPolicy.validate_strict(document, engine) == plain + added


# ── Evaluation (vectors 12 and 14) ──────────────────────────────────────────

@pytest.mark.parametrize("run", sorted(p.stem for p in (V12 / "runs").glob("*.json")))
def test_evaluation_gives_vector_12s_results(engine: CedarEngine, run: str) -> None:
    expected = json.loads((V12 / "expected" / f"{run}.results.json").read_text(encoding="utf-8"))
    ev = AgentPolicy.evaluate(V11_DOC, (V12 / "expected" / f"{run}.facts.json").read_bytes(), engine)
    assert (ev.engine, _as_json(ev.rules), ev.overall) == \
        (expected["engine"], expected["controls"], expected["overall"])


@pytest.mark.parametrize("name", RUNS)
def test_evaluation_gives_vector_14s_diagnostics(engine: CedarEngine, name: str) -> None:
    run, expected = _run(name), _run(name, "expected")
    control_set = _with_enforcement(run["enforcement"])
    facts = (V14 / "expected" / f"{name}.facts.json").read_bytes()
    ev = AgentPolicy.evaluate(control_set, facts, engine)
    events = expected["events"] + [dict(expected["runLevel"], seq="run")]
    assert [(r.seq, {"reason": list(r.reason), "errors": list(r.errors)}) for r in ev.requests] == \
        [(str(e["seq"]), e["diagnostics"]) for e in events]
    assert (ev.engine, _as_json(sorted(ev.rules, key=lambda c: c.id)), ev.overall) == \
        (expected["engine"], expected["controls"], expected["overall"])
    # Rule errors are the core's Long overflows, reported as errors, never a trap.
    for call, e in zip(_calls(control_set, facts), events):
        if e["diagnostics"]["errors"]:
            errors = engine.authorize(call)["response"]["diagnostics"]["errors"]
            assert errors and all(x["error"]["message"].startswith("integer overflow") for x in errors)


def test_vector_14_has_rule_errors_where_its_readme_says(engine: CedarEngine) -> None:
    with_errors = {n for n in RUNS if any(e["diagnostics"]["errors"] for e in _run(n, "expected")["events"])}
    assert {"10-rule-error", "25-erroring-observe-rule", "27-on-rule-error-allow", "32-rule-error-halt-rule"} <= with_errors


def test_a_request_the_engine_refuses_fails_the_evaluation(engine: CedarEngine) -> None:
    facts = json.loads((V12 / "expected" / "01-clean.facts.json").read_bytes())
    del facts["requests"][1]["context"]["approval"]  # no longer a request of the schema
    with pytest.raises(PolicyEngineError, match="refused request 1: .*approval"):
        AgentPolicy.evaluate(V11_DOC, json.dumps(facts).encode(), engine)


def test_evaluate_refuses_facts_of_the_other_version(engine: CedarEngine) -> None:
    with pytest.raises(ValueError, match="factsVersion 2"):
        AgentPolicy.evaluate(V13_DOC, (V12 / "expected" / "01-clean.facts.json").read_bytes(), engine)


# ── The verifier recomputes (Control Evaluation v2 §4.6) ────────────────────

class _PolicyRun:
    """A stub-sealed run under a v1 policy control set, and sealed policy evaluations of it."""

    def __init__(self, doc: bytes = V11_DOC) -> None:
        self.doc, sealer = doc, StubSealer()
        self.client = _client(sealer)
        self.run = _start(self.client, control_set=AgentPolicy.control_set_from_document(doc))
        self.run.record_tool_call("crm.read_customer", b"{}", operation="read", use_id="c1")
        self.run.record_tool_result("crm.read_customer", b"{}", use_id="c1")
        self.run.record_tool_call("crm.delete_customer", b"{}", operation="delete", consequential=True, use_id="c2")
        self.run.record_tool_result("crm.delete_customer", b"{}", use_id="c2")
        self.bundle = self.run.finish("completed")
        env = self.run.control_artifact.envelope
        self.facts = AgentPolicy.build_facts(env["agent"]["id"], env["activity"]["correlationId"],
                                             [a.envelope for a in self.bundle.artifacts])
        sealer.cert = CERT_V
        self.payloads: dict = {}

    def evaluation(self, rules, named: str = "cedar-policy@4.14.0", mutate=None):  # noqa: ANN001, ANN201
        prepared = ControlEvaluation.prepare_policy(PolicyEvaluationRequest(
            certificate_id=VERIFIER_CERT, evaluator_id="urn:example:policy-evaluator", evaluator_version="1.0.0",
            control_artifact=self.run.control_artifact, control_set_document=self.doc, events=self.bundle.artifacts,
            rules=rules, policy_status="unapproved", engine=named, private_controls_reported="reported"),
            _clock=_clock())
        if mutate is not None:  # an evaluator that signs what prepare_policy would refuse
            env = copy.deepcopy(prepared.envelope)
            mutate(env)
            prepared = replace(prepared, envelope=env, envelope_hash_hex=hash_bytes(canonicalize(env)))
        self.payloads.update(prepared.payloads)
        return ControlEvaluation.seal(self.client, prepared, VERIFIER_CERT)

    def with_evaluations(self, *evaluations) -> AgentRunBundle:  # noqa: ANN002
        return self.bundle.with_evaluations(*evaluations).with_payloads(self.payloads)


def _control(rule) -> dict:  # noqa: ANN001
    return {"id": rule.id, "result": rule.result, **({"where": list(rule.where)} if rule.where else {})}


def test_the_verifier_recomputes_a_policy_evaluation(engine: CedarEngine) -> None:
    p = _PolicyRun()
    ev = AgentPolicy.evaluate(V11_DOC, p.facts, engine)
    assert ev.overall == "FAIL" and ev.rules[0].id == "allowed-tools" and ev.rules[0].result == "FAIL"
    honest = p.evaluation(ev.rules)
    lying = p.evaluation([replace(ev.rules[0], result="PASS", where=None), *ev.rules[1:]])
    other = p.evaluation(ev.rules, "cedar-policy@4.13.0")
    full = p.with_evaluations(honest, lying, other)

    today = verify_agent_run(full, stub_verify)
    assert [(e.valid, e.results_recomputed) for e in today.evaluations] == [(True, False)] * 3, \
        "without an engine the results are the evaluator's"
    assert not any("recomputed" in n for n in today.notes)

    checked = verify_agent_run(full, stub_verify, engine=engine)
    assert checked.verdict == today.verdict == "run_finalized" and checked.checks == today.checks
    h, lie, o = checked.evaluations
    assert h.valid and h.results_recomputed, h.findings
    assert not lie.valid and not lie.results_recomputed
    assert "evaluation 1: its results do not recompute: rule 'allowed-tools' is FAIL at 3 with cedar-policy@4.14.0, " \
           "not PASS." in lie.findings
    assert o.valid and not o.results_recomputed
    assert checked.notes == today.notes + [
        "evaluation 2: its results were not recomputed: it names the engine cedar-policy@4.13.0, the verifier has "
        "cedar-policy@4.14.0."]


def test_a_tampered_where_or_overall_does_not_recompute(engine: CedarEngine) -> None:
    p = _PolicyRun()
    ev = AgentPolicy.evaluate(V11_DOC, p.facts, engine)
    fails = [i for i, r in enumerate(ev.rules) if r.result == "FAIL"]
    i = fails[0]

    def other_where(env: dict) -> None:
        env["controls"][i]["where"] = ["run"] if ev.rules[i].where != ("run",) else ["0"]
    result = verify_agent_run(p.with_evaluations(p.evaluation(ev.rules, mutate=other_where),
                                                 p.evaluation(ev.rules, mutate=lambda e: e.update(overall="PASS"))),
                              stub_verify, engine=engine)
    where, overall = result.evaluations
    assert not where.valid and not where.results_recomputed
    assert any(f.startswith(f"evaluation 0: its results do not recompute: rule '{ev.rules[i].id}' is FAIL at ")
               for f in where.findings), where.findings
    assert not overall.valid and not overall.results_recomputed
    assert "evaluation 1: its results do not recompute: overall is FAIL with cedar-policy@4.14.0, not PASS." \
        in overall.findings


@pytest.mark.parametrize("true_first", [True, False])
def test_a_repeated_control_id_is_never_recomputed(engine: CedarEngine, true_first: bool) -> None:
    p = _PolicyRun()
    ev = AgentPolicy.evaluate(V11_DOC, p.facts, engine)
    true0, false0 = ev.rules[0], replace(ev.rules[0], result="PASS", where=None)
    pair = [_control(true0), _control(false0)] if true_first else [_control(false0), _control(true0)]

    def repeat(env: dict) -> None:
        env["controls"] = pair + [c for c in env["controls"] if c["id"] != true0.id]
    result = verify_agent_run(p.with_evaluations(p.evaluation(ev.rules, mutate=repeat)), stub_verify, engine=engine)
    e = result.evaluations[0]
    assert not e.valid and not e.results_recomputed
    assert not any("recompute" in f for f in e.findings) and not any("recomputed" in n for n in result.notes)


_UNPARSABLE = _mutate(V11_DOC, lambda d: _rules(d).update({"nonsense": {
    "effect": "forbid", "principal": {"op": "All"}, "action": {"op": "All"}, "resource": {"op": "All"},
    "conditions": [{"kind": "when", "body": {"nonsense": {}}}], "annotations": {"id": "nonsense"}}}))
_UNPARSABLE_MESSAGE = ("failed to parse policy with id `nonsense` from JSON: error deserializing a policy/template "
                       "from JSON: unknown variant `nonsense`, expected one of `Value`, `Var`, `Slot`, `!`, `neg`, "
                       "`==`, `!=`, `in`, `<`, `<=`, `>`, `>=`, `&&`, `||`, `+`, `-`, `*`, `contains`, `containsAll`, "
                       "`containsAny`, `isEmpty`, `getTag`, `hasTag`, `.`, `has`, `like`, `is`, `if-then-else`, `Set`, "
                       "`Record`")


def test_a_request_the_named_engine_refuses_makes_the_evaluation_invalid(engine: CedarEngine) -> None:
    assert AgentPolicy.validate(_UNPARSABLE) == []
    assert AgentPolicy.validate_strict(_UNPARSABLE, engine) == [
        "cedar.policies cannot be validated against Cedar schema v1: " + _UNPARSABLE_MESSAGE]
    p = _PolicyRun(_UNPARSABLE)
    with pytest.raises(PolicyEngineError) as refused:
        AgentPolicy.evaluate(_UNPARSABLE, p.facts, engine)
    assert refused.value.refused and str(refused.value) == f"The policy engine refused request 0: {_UNPARSABLE_MESSAGE}"
    rules = [PolicyRuleResult(r, "PASS") for r in _rules(json.loads(_UNPARSABLE))]
    e = verify_agent_run(p.with_evaluations(p.evaluation(rules)), stub_verify, engine=engine).evaluations[0]
    assert not e.valid and not e.results_recomputed
    assert e.findings == [f"evaluation 0: its results cannot be recomputed: The policy engine refused request 0: "
                          f"{_UNPARSABLE_MESSAGE}."]


class _FailingEngine:
    version = "4.14.0"

    def __init__(self, error: Exception) -> None:
        self.error = error

    def authorize(self, call: dict) -> dict:
        raise self.error

    def validate(self, call: dict) -> dict:
        raise self.error


@pytest.mark.parametrize("error", [PolicyEngineError("The policy engine failed (cedar_authorize): trap."),
                                   RuntimeError("disposed")], ids=["engine-error", "unrelated-exception"])
def test_a_failing_engine_is_a_note_and_never_raises(engine: CedarEngine, error: Exception) -> None:
    p = _PolicyRun()
    ev = AgentPolicy.evaluate(V11_DOC, p.facts, engine)
    result = verify_agent_run(p.with_evaluations(p.evaluation(ev.rules)), stub_verify, engine=_FailingEngine(error))
    e = result.evaluations[0]
    assert e.valid and not e.results_recomputed, e.findings
    assert result.notes[-1] == f"evaluation 0: its results were not recomputed: {str(error).rstrip('.')}."


def test_one_recomputation_budget_per_verification(engine: CedarEngine, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _agent_verify.RECOMPUTE_BUDGET == 536_870_912
    p = _PolicyRun()
    ev = AgentPolicy.evaluate(V11_DOC, p.facts, engine)
    cost = len(V11_DOC) * len(json.loads(p.facts.data)["requests"])
    monkeypatch.setattr(_agent_verify, "RECOMPUTE_BUDGET", cost + cost // 2)  # one evaluation, not two
    bundle = p.with_evaluations(p.evaluation(ev.rules), p.evaluation(ev.rules))
    for _ in range(2):  # each verification has its own budget
        result = verify_agent_run(bundle, stub_verify, engine=engine)
        assert [(e.valid, e.results_recomputed) for e in result.evaluations] == [(True, True), (True, False)]
        assert result.notes[-1] == ("evaluation 1: its results were not recomputed: the recomputation budget of this "
                                    "verification is used up.")


def test_a_non_conforming_evaluation_is_not_recomputed(engine: CedarEngine) -> None:
    p = _PolicyRun()
    ev = AgentPolicy.evaluate(V11_DOC, p.facts, engine)
    result = verify_agent_run(p.with_evaluations(p.evaluation(ev.rules, mutate=lambda e: e.update(extra=1))),
                              stub_verify, engine=_FailingEngine(RuntimeError("must not be called")))
    assert not result.evaluations[0].results_recomputed and not any("recomputed" in n for n in result.notes)


# ── Regression tests from the security review ───────────────────────────────

def test_the_module_imports_only_the_five_wasi_functions(engine: CedarEngine) -> None:
    import wasmtime
    module = wasmtime.Module(wasmtime.Engine(), _policy_engine._module_bytes())
    assert sorted((i.module, i.name) for i in module.imports) == sorted(
        ("wasi_snapshot_preview1", n) for n in ("environ_get", "environ_sizes_get", "fd_write", "proc_exit", "random_get"))


def test_the_engine_writes_nothing_to_stdio_even_when_it_traps(engine: CedarEngine) -> None:
    code = ("import sigill_sdk._policy_engine as p; p._MEMORY_LIMIT = 32 << 20; e = p.CedarEngine()\n"
            "e.authorize({}); e.validate({'x': 1})\n"
            "try: e.authorize({'pad': 'x' * (40 << 20)})\n"
            "except p.PolicyEngineError: pass\n"
            "else: raise SystemExit(3)\n"
            "assert e.version == '4.14.0'")
    env = {k: v for k, v in os.environ.items() if k != "RUST_LOG"}
    env.update(PYTHONPATH=str(REPO / "src"), RUST_BACKTRACE="full", SECRET="host-environment")
    child = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, timeout=300)
    assert (child.returncode, child.stdout, child.stderr) == (0, b"", b"")


def test_fresh_instances_give_the_same_problem_lists(engine: CedarEngine) -> None:
    doc = _mutate(V11_DOC, lambda d: _rules(d).update({f"bad{i}": {
        "effect": "forbid", "principal": {"op": "All"}, "action": {"op": "==", "entity": {"type": "Action", "id": f"u{i}"}},
        "resource": {"op": "All"}, "conditions": [], "annotations": {"id": f"bad{i}"}} for i in range(12)}))
    lists = {json.dumps(AgentPolicy.validate_strict(doc, CedarEngine())) for _ in range(4)}
    assert len(lists) == 1 and len(json.loads(lists.pop())) == 12


def test_concurrent_calls_with_traps_keep_answers_apart(monkeypatch: pytest.MonkeyPatch, engine: CedarEngine) -> None:
    monkeypatch.setattr(_policy_engine, "_MEMORY_LIMIT", 32 * 1024 * 1024)
    capped = CedarEngine()
    plain = _calls(V11_DOC, (V12 / "expected" / "01-clean.facts.json").read_bytes())[1]
    secret = dict(plain, context=dict(plain["context"], operation="tenant-a-secret-op"))
    expected = json.dumps(capped.authorize(plain))
    pad = {"pad": "x" * (34 * 1024 * 1024)}
    problems: list = []

    def worker(i: int) -> None:
        for j in range(10):
            try:
                if (i + j) % 7 == 0:
                    with pytest.raises(PolicyEngineError):
                        capped.authorize(pad)
                elif (i + j) % 2:
                    a = json.dumps(capped.authorize(plain))
                    if a != expected:
                        problems.append(a[:200])
                else:
                    capped.authorize(secret)
            except BaseException as e:  # noqa: BLE001
                problems.append(repr(e)[:200])
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []


def test_a_call_too_deep_to_serialise_is_an_engine_error(engine: CedarEngine) -> None:
    deep: dict = {"Value": True}
    for _ in range(5000):
        deep = {"&&": {"left": deep, "right": {"Value": True}}}
    with pytest.raises(PolicyEngineError, match="cedar_authorize"):
        engine.authorize({"policies": {"staticPolicies": {"deep": deep}}})
    assert engine.authorize({})["type"] == "failure"


def test_facts_too_deep_to_parse_are_not_facts(engine: CedarEngine) -> None:
    with pytest.raises(ValueError, match="factsVersion 1"):
        AgentPolicy.evaluate(V11_DOC, b'{"factsVersion":"1","requests":' + b"[" * 100000 + b"]" * 100000 + b"}", engine)


@pytest.mark.parametrize("seq", ["0", 1.0, True, None, "Run"])
def test_a_request_seq_must_be_an_integer_or_run(engine: CedarEngine, seq: object) -> None:
    facts = json.loads((V12 / "expected" / "01-clean.facts.json").read_bytes())
    facts["requests"][0]["seq"] = seq
    with pytest.raises(ValueError, match=r"^The facts are not a factsVersion 1 document \(a v1 control set\)\.$"):
        AgentPolicy.evaluate(V11_DOC, json.dumps(facts).encode(), engine)


def test_v2_entities_come_from_the_control_set(engine: CedarEngine) -> None:
    name = "13-group-rule"
    control_set = _with_enforcement(_run(name)["enforcement"])
    facts = json.loads((V14 / "expected" / f"{name}.facts.json").read_bytes())
    facts["entities"] = [e for e in facts["entities"] if e["uid"]["id"] != "payments"]
    with pytest.raises(ValueError, match=r"^The facts carry other entities than the control set\.$"):
        AgentPolicy.evaluate(control_set, json.dumps(facts).encode(), engine)


# The reviewer's number and string corpus: 11 control sets, each strictly validated and evaluated over two facts
# documents (33 inputs), against the reference evaluator's answers (@cedar-policy/cedar-wasm 4.14.0 on the parsed
# JavaScript values).
_V11_TEXT = V11_DOC.decode()
_OP = {".": {"left": {"Var": "context"}, "attr": "operation"}}
_EMOJI = "\U0001F600"


def _number(text: str) -> bytes:
    assert '"Value": 20' in _V11_TEXT
    return _V11_TEXT.replace('"Value": 20', f'"Value": {text}', 1).encode()


def _with_rule(rid: str, cond: dict) -> bytes:
    d = json.loads(V11_DOC)
    _rules(d)[rid] = {"effect": "forbid", "principal": {"op": "All"}, "action": {"op": "All"}, "resource": {"op": "All"},
                      "conditions": [{"kind": "when", "body": cond}], "annotations": {"id": rid}}
    return json.dumps(d, ensure_ascii=False).encode()  # raw UTF-8


_ESC = _with_rule("esc", {"==": {"left": _OP, "right": {"Value": "delete"}}})
_EMO = _with_rule("emoji", {"==": {"left": {"Var": "resource"}, "right": {"Value": {"__entity": {"type": "Tool", "id": _EMOJI}}}}})
_MAX = 9007199254740991
CORPUS = {  # name: (document, {facts: {rule: where} for every rule that is not PASS (all FAIL here)})
    "v11": (V11_DOC, {"01-clean": {}, "ops": {"allowed-tools": ["2"]}}),
    "num_neg0": (_number("-0"), {"01-clean": {"max-steps": ["1", "2", "3", "4", "run"]},
                                 "ops": {"allowed-tools": ["2"], "max-steps": ["1", "2"]}}),
    "num_20.0": (_number("20.0"), {"01-clean": {}, "ops": {"allowed-tools": ["2"]}}),
    "num_2e1": (_number("2e1"), {"01-clean": {}, "ops": {"allowed-tools": ["2"]}}),
    "num_max_safe": (_number(str(_MAX)), {"01-clean": {}, "ops": {"allowed-tools": ["2"]}}),
    "num_min_safe": (_number(str(-_MAX)), {"01-clean": {"max-steps": ["0", "1", "2", "3", "4", "run"]},
                                           "ops": {"allowed-tools": ["2"], "max-steps": ["1", "2"]}}),
    "str_escaped": (_ESC.replace(b'"delete"', b'"d\\u0065lete"'), {"01-clean": {}, "ops": {"allowed-tools": ["2"], "esc": ["1"]}}),
    "str_raw": (_ESC, {"01-clean": {}, "ops": {"allowed-tools": ["2"], "esc": ["1"]}}),
    "str_non_bmp_tool": (_EMO, {"01-clean": {}, "ops": {"allowed-tools": ["2"], "emoji": ["2"]}}),
    "str_non_bmp_escaped": (_EMO.replace(_EMOJI.encode(), b"\\ud83d\\ude00"),
                            {"01-clean": {}, "ops": {"allowed-tools": ["2"], "emoji": ["2"]}}),
    "long_overflow": (_with_rule("ovf", {">": {"left": {"+": {"left": {"Value": _MAX}, "right": {"Value": _MAX}}},
                                               "right": {"Value": 0}}}),
                      {"01-clean": {"ovf": ["0", "1", "2", "3", "4", "run"]}, "ops": {"allowed-tools": ["2"], "ovf": ["1", "2"]}}),
}


def _corpus_facts() -> dict:
    clean = (V12 / "expected" / "01-clean.facts.json").read_bytes()
    first = json.loads(clean)
    call = next(r for r in first["requests"] if r["action"]["id"] == "tool_call")
    ops = dict(first, requests=[dict(call, seq=1, context=dict(call["context"], operation="delete")),
                                dict(call, seq=2, resource={"type": "Tool", "id": _EMOJI})])
    return {"01-clean": clean, "ops": canonicalize(ops)}


@pytest.mark.parametrize("name", CORPUS)
def test_numbers_and_strings_reach_the_core_as_the_reference_reads_them(engine: CedarEngine, name: str) -> None:
    doc, expected = CORPUS[name]
    assert AgentPolicy.validate_strict(doc, engine) == []
    for facts_name, facts in _corpus_facts().items():
        ev = AgentPolicy.evaluate(doc, facts, engine)
        failing = expected[facts_name]
        assert {r.id: list(r.where) for r in ev.rules if r.result != "PASS"} == failing, facts_name
        assert all(r.result in ("PASS", "FAIL") for r in ev.rules)
        assert ev.overall == ("FAIL" if failing else "PASS")


def test_a_fraction_is_still_refused_as_by_the_reference(engine: CedarEngine) -> None:
    with pytest.raises(PolicyEngineError) as e:
        AgentPolicy.evaluate(_number("1.5"), (V12 / "expected" / "01-clean.facts.json").read_bytes(), engine)
    assert e.value.refused
