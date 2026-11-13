"""The guard (Agent Policy Control Set v2 §7, Agent Enforcement v1 §4): vector 14 driven end to end through the
public API with the real Cedar core, and the guard's behaviour with a stub engine (no wasmtime needed): denials,
halts, the start gate, engine and sealing failures, concurrency, the event budget, callbacks, the examples.
Tests that need the Cedar core are skipped, with the reason, when the 'policy' extra (wasmtime) is not installed.
"""

from __future__ import annotations

import copy
import json
import sys
import threading
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from sigill_sdk import (
    POLICY_CONTROL_SET_CONTENT_TYPE,
    AgentConfiguration,
    AgentControlSet,
    AgentDefinition,
    AgentPolicy,
    AgentRun,
    ApprovalCovers,
    CedarEngine,
    Enforcement,
    ModelCallTransport,
    PolicyDenied,
    PolicyEngineError,
    RunHalted,
    SigillError,
    StartRefused,
    verify_agent_run,
)
from sigill_sdk import _agent_run
from sigill_sdk._canonical import canonicalize, hash_bytes
from test_agent_enforcement import DOC, V14, _run, _with_enforcement
from test_agent_policy import DOC as V11_DOC
from test_agent_policy import _client
from test_agent_run import CERT, REPO, StubSealer, _clock, _start, stub_verify

sys.path.insert(0, str(REPO / "examples"))

CASES = {c["name"]: c for c in json.loads((V14 / "cases.json").read_text(encoding="utf-8"))["cases"]}
ARGUMENTS = json.loads((V14 / "cases.json").read_text(encoding="utf-8"))["arguments"]
AGENT_ID = "urn:example:agent:support"
T0 = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)
DEFINED = {e["uid"]["id"] for e in json.loads(DOC)["cedar"]["entities"] if "definitionSha256" in e["attrs"]}
SECRET = b'{"card":"4111 1111 1111 1111"}'


def _agent(tool_manifest: bytes = b"tool-manifest v1") -> AgentDefinition:
    return AgentDefinition(AGENT_ID, "1", AgentConfiguration(instruction_set=b"instruction-set v1",
                                                             tool_manifest=tool_manifest,
                                                             execution_policy=b"execution-policy v1"))


@pytest.fixture(scope="module")
def engine() -> CedarEngine:
    try:
        return CedarEngine()
    except ImportError as e:
        pytest.skip(str(e))


class StubEngine:
    """A stand-in for the Cedar core: some of vector 13's rules as predicates over the request."""

    RULES = {
        "no-web-search": lambda a, r, c: a == "tool_call" and r == "search.web",
        "restricted-needs-bound-approval": lambda a, r, c: a == "tool_call" and r == "payments.refund"
        and c["approval"] != "bound",
        "rejected-is-final": lambda a, r, c: a == "tool_call" and c["approval"] == "rejected",
        "shadow-repeat-read": lambda a, r, c: a == "tool_call" and r == "crm.read_customer" and c["callsOfThisTool"] > 1,
        "read-loop-limit": lambda a, r, c: a == "tool_call" and r == "crm.read_customer" and c["callsOfThisTool"] > 3,
        "halt-retrieval-after-denial": lambda a, r, c: a == "retrieval" and c["denialsSoFar"] > 0,
        "no-delegation": lambda a, r, c: a == "delegation",
        "halt-fs-wipe": lambda a, r, c: a == "tool_call" and r == "fs.wipe",
    }

    def __init__(self, dead: bool = False) -> None:
        self.dead, self.fail, self.calls = dead, False, []

    @property
    def version(self) -> str:
        if self.dead:
            raise PolicyEngineError("The policy engine could not be loaded: stub")
        return "4.14.0"

    def authorize(self, call: dict) -> dict:
        self.calls.append(call)
        if self.dead or self.fail:
            raise PolicyEngineError("The policy engine failed (cedar_authorize): stub")
        a, r, c = call["action"]["id"], call["resource"]["id"], call["context"]
        rules = call["policies"]["staticPolicies"]
        reason = sorted(k for k, f in self.RULES.items() if k in rules and f(a, r, c))
        return {"type": "success", "response": {"decision": "deny" if reason else "allow",
                                                 "diagnostics": {"reason": reason, "errors": []}}}

    def validate(self, call: dict) -> dict:
        if self.dead:
            raise PolicyEngineError("The policy engine could not be loaded: stub")
        return {"type": "success", "validationErrors": [], "validationWarnings": []}


class _Wrapped:
    """The real engine, failing where a vector case says so; records every request it is asked."""

    def __init__(self, inner: object, dead: bool) -> None:
        self.inner, self.dead, self.fail_next, self.requests = inner, dead, False, []

    @property
    def version(self) -> str:
        if self.dead:
            raise PolicyEngineError("The policy engine could not be loaded: modelled by the case")
        return self.inner.version

    def authorize(self, call: dict) -> dict:
        if call["principal"]["id"] != "strict-validation":
            self.requests.append({k: call[k] for k in ("principal", "action", "resource", "context")})
        if self.dead or self.fail_next:
            raise PolicyEngineError("The policy engine failed: modelled by the case")
        return self.inner.authorize(call)

    def validate(self, call: dict) -> dict:
        if self.dead:
            raise PolicyEngineError("The policy engine could not be loaded: modelled by the case")
        return self.inner.validate(call)


def _vector_clock():  # noqa: ANN202 — the Control Artifact one second before T0, then event seq k at T0 + k s
    state = {"n": -1}

    def tick() -> datetime:
        state["n"] += 1
        return T0 + timedelta(seconds=state["n"] - 1)
    return tick


# ── Vector 14, end to end ───────────────────────────────────────────────────

def _drive(name: str, engine: object) -> dict:
    """Drives the recorder with what the case's producer attempts; returns what happened."""
    case, run_file = CASES[name], _run(name)
    config = {"tool-manifest": "tool-manifest v1", **case.get("configuration", {})}
    doc = _with_enforcement(run_file["enforcement"])
    wrapped, events = _Wrapped(engine, case.get("engineFailsAtStart", False)), []
    out: dict = {"doc": doc, "wrapped": wrapped, "events": events, "denied": {}, "not_executed": [], "discarded": 0}
    try:
        run = AgentRun.start(_client(StubSealer()), _agent(config["tool-manifest"].encode()), certificate_id=CERT,
                             activity="support-session", control_set=AgentPolicy.control_set_from_document(doc),
                             correlation_id=run_file["correlationId"], delegating=True,
                             enforcement=Enforcement(wrapped, events.append), _clock=_vector_clock())
    except StartRefused as e:
        out["refused"], run = e, e.run
    out["run"], calls = run, {}
    for a in case["actions"]:
        wrapped.fail_next = a.get("engineFails", False)
        before, t = len(run.artifacts), a["type"]
        try:
            if t == "tool_call":
                definition = a["definition"] if "definition" in a else \
                    f"{a['tool']} definition" if a["tool"] in DEFINED else None
                calls[a["useId"]] = run.begin_tool_call(
                    a["tool"], ARGUMENTS[a["args"]].encode(), use_id=a["useId"],
                    consequential=a.get("consequential", False),
                    definition=None if definition is None else definition.encode())
            elif t == "tool_result":
                if a["useId"] in calls:
                    calls[a["useId"]].complete(b'{"ok":true}')
                else:
                    run.record_tool_result(a["tool"], b'{"ok":true}', use_id=a["useId"])
            elif t == "human_approval":
                c = a["covers"]
                expires = datetime.fromisoformat(c["expiresAt"].replace("Z", "+00:00")) if "expiresAt" in c else None
                run.record_human_approval(a["decision"], approver="urn:example:approver:1",
                                          receipt=b'{"receipt":%d}' % before, covers=ApprovalCovers(
                                              c["tool"], hash_bytes(ARGUMENTS[c["args"]].encode()), c.get("useId"),
                                              expires))
            elif t == "retrieval":
                run.record_retrieval(b"retrieved context")
            elif t == "model_output":
                run.record_model_output(b"model output")
            elif t == "delegation":
                run.delegate(a["childAgentId"], b'{"task":"review"}')
            elif t == "delegation_result":
                run.complete_delegation(run.outstanding_delegations[0], "a" * 64, "completed")
            else:
                assert t == "run_end"
                out["bundle"] = run.finish()
                if len(run.artifacts) == before:
                    out["discarded"] += 1  # the halted run is closed: nothing sealed
        except PolicyDenied as e:
            out["denied"][e.use_id] = e
        except RunHalted:
            if len(run.artifacts) == before:
                out["discarded"] += 1
        except ValueError as e:
            assert str(e) == f"The tool_call with use_id '{a['useId']}' was denied; it has no result."
            assert len(run.artifacts) == before
            out["not_executed"].append(a["useId"])
    out.setdefault("bundle", run.to_bundle())
    return out


def _record_view(step: dict) -> dict:
    return {"decision": step["decision"], "tool": step.get("tool"), "rules": step.get("rules"),
            "reason": step["enforcer"]["reason"], "engine": step["enforcer"]["engine"],
            "factsVersion": step["enforcer"]["factsVersion"]}


@pytest.mark.parametrize("name", sorted(CASES))
def test_vector_14_driven_through_the_recorder(name: str, engine: CedarEngine) -> None:
    run_file, expected = _run(name), _run(name, "expected")
    out = _drive(name, engine)
    bundle, mine = out["bundle"], out["bundle"].artifacts
    theirs = [e["envelope"] for e in run_file["events"]]

    # The same chain of step types, the same records, the same disposition.
    assert [a.step_type for a in mine] == [e["step"]["type"] for e in theirs]
    for a, e in zip(mine, theirs):
        if e["step"]["type"] == "authorization":
            assert _record_view(a.envelope["step"]) == _record_view(e["step"])
    assert mine[-1].envelope["step"]["runDisposition"] == theirs[-1]["step"]["runDisposition"]

    # Denied calls raised PolicyDenied with the record's reason and rules; a refused start raised StartRefused.
    decided = [e for e in expected["events"] if e["sealedBy"] == "producer" and e.get("outcome") in ("denied", "halted")]
    want = {theirs[e["seq"]]["step"]["tool"]["useId"]: e for e in decided if e["type"] == "tool_call"}
    assert set(out["denied"]) == set(want)
    for use_id, e in want.items():
        d = out["denied"][use_id]
        assert (d.reason, d.rules, d.halted, d.seq) == (e["reason"], tuple(e.get("rules", ())),
                                                        e["outcome"] == "halted", e["seq"])
        assert d.record.envelope == mine[e["seq"] + 1].envelope
    if expected["events"][0].get("outcome") == "halted":
        assert out["refused"].reason == expected["events"][0]["reason"] and out["refused"].run.halted
    else:
        assert "refused" not in out
    assert out["not_executed"] == expected["notExecuted"]
    assert out["discarded"] == expected["discarded"]

    # What the guard reported, in seal order.
    report = []
    for e in expected["events"]:
        if e["sealedBy"] != "producer" or e["type"] == "run_end":
            continue
        tool = theirs[e["seq"]]["step"].get("tool") or {}
        if e["outcome"] in ("denied", "halted"):
            kind = "start_refused" if e["type"] == "run_start" else e["outcome"]
            report.append((kind, e["reason"], tuple(e.get("rules", ())), tool.get("name"), tool.get("useId"), e["seq"]))
        elif e["diagnostics"]["reason"]:
            report.append(("observed", None, tuple(e["diagnostics"]["reason"]), tool.get("name"), tool.get("useId"),
                           e["seq"]))
    assert [(x.kind, x.reason, x.rules, x.tool, x.use_id, x.seq) for x in out["events"]] == report

    # Incremental facts: each request the guard evaluated is the vector's, and the run's facts are the vector's bytes.
    asked = [e["request"] for e in expected["events"] if e["sealedBy"] == "producer" and e["type"] != "run_end"
             and not (e["type"] == "run_start" and e["outcome"] == "halted")]
    assert canonicalize(out["wrapped"].requests) == canonicalize(asked)
    facts = AgentPolicy.build_facts_v2(AGENT_ID, run_file["correlationId"], mine, out["doc"])
    assert facts.data == (V14 / "expected" / f"{name}.facts.json").read_bytes()

    # The run produced verifies, with the engine.
    result = verify_agent_run(bundle, stub_verify, engine=engine)
    assert result.verdict == "run_finalized", result.findings
    assert result.checks["enforcement"] == "ok" and result.enforcement_findings == []


# ── The guard with a stub engine ────────────────────────────────────────────

def _doc(**enforcement: object) -> bytes:
    return _with_enforcement({**json.loads(DOC)["enforcement"], **enforcement})


def _enforced(sealer: StubSealer, doc: bytes = DOC, engine: object = None, on_event=None,  # noqa: ANN001
              agent: AgentDefinition | None = None, **opts: object) -> AgentRun:
    return AgentRun.start(_client(sealer), agent or _agent(), certificate_id=CERT, activity="support-session",
                          control_set=AgentPolicy.control_set_from_document(doc),
                          enforcement=Enforcement(engine or StubEngine(), on_event), _clock=_clock(), **opts)


def _types(run: AgentRun) -> list:
    return [a.step_type for a in run.artifacts]


def test_enforce_mode_without_enforcement_is_a_caller_error_and_seals_nothing() -> None:
    sealer = StubSealer()
    with pytest.raises(ValueError) as e:
        AgentRun.start(_client(sealer), _agent(), certificate_id=CERT, activity="a",
                       control_set=AgentPolicy.control_set_from_document(DOC))
    assert str(e.value) == "The control set enforces its policy: pass enforcement with a policy engine."
    assert sealer.requests == []


def test_strict_validation_runs_before_anything_is_sealed() -> None:
    class Strict(StubEngine):
        def validate(self, call: dict) -> dict:
            return {"type": "success", "validationErrors": [{"policyId": "no-web-search",
                                                             "error": {"message": "unknown attribute"}}]}
    sealer = StubSealer()
    with pytest.raises(ValueError, match="^Invalid policy control set: policy 'no-web-search' does not validate"):
        _enforced(sealer, engine=Strict())
    assert sealer.requests == []


@pytest.mark.parametrize("control_set", ["observe", "v1", "not a policy"])
def test_observe_mode_and_other_control_sets_never_deny_and_seal_no_record(control_set: str) -> None:
    stub, events = StubEngine(), []
    cs = {"observe": AgentPolicy.control_set_from_document(_doc(mode="observe")),
          "v1": AgentPolicy.control_set_from_document(V11_DOC),
          "not a policy": AgentControlSet("plain", "1", b'{"controls":[]}')}[control_set]
    run = AgentRun.start(_client(StubSealer()), _agent(), certificate_id=CERT, activity="a", control_set=cs,
                         enforcement=Enforcement(stub, events.append), _clock=_clock())
    run.record_tool_call("search.web", b"{}")
    run.record_tool_call("payments.refund", b"{}")
    run.record_retrieval(b"r")
    bundle = run.finish()
    assert "authorization" not in _types(run) and not run.halted
    assert verify_agent_run(bundle, stub_verify).verdict == "run_finalized"
    if control_set == "observe":
        assert [(e.kind, e.reason, e.rules, e.tool) for e in events] == [
            ("observed", None, ("no-web-search",), "search.web"),
            ("observed", None, ("restricted-needs-bound-approval",), "payments.refund")]
    else:
        assert events == []
    assert bool(stub.calls) == (control_set != "not a policy")


@pytest.mark.parametrize("control_set", ["observe", "v1"])
def test_a_broken_engine_at_start_of_a_run_that_is_not_enforced_is_raised(control_set: str) -> None:
    doc = _doc(mode="observe") if control_set == "observe" else V11_DOC
    sealer = StubSealer()
    with pytest.raises(PolicyEngineError):
        _enforced(sealer, doc, engine=StubEngine(dead=True))
    assert sealer.requests == []

    stub, events = StubEngine(), []  # later engine failures in a run that is not enforced stay silent
    run = _enforced(sealer, doc, engine=stub, on_event=events.append)
    stub.fail = True
    run.record_tool_call("search.web", b"{}", use_id="u1")
    assert events == [] and not run.halted and "authorization" not in _types(run)


def test_an_observed_call_carries_its_tool_and_use_id() -> None:
    events = []
    run = _enforced(StubSealer(), _doc(mode="observe"), on_event=events.append)
    run.record_tool_call("search.web", b"{}", use_id="u1")
    assert [(e.kind, e.reason, e.rules, e.tool, e.use_id, e.seq) for e in events] == [
        ("observed", None, ("no-web-search",), "search.web", "u1", 1)]


def test_a_shadow_rule_is_reported_through_on_event_only() -> None:
    events = []
    run = _enforced(StubSealer(), on_event=events.append)
    for _ in range(2):
        run.invoke_tool("crm.read_customer", b"{}", lambda: b"{}", definition=b"crm.read_customer definition")
    assert "authorization" not in _types(run)
    assert [(e.kind, e.rules, e.seq) for e in events] == [("observed", ("shadow-repeat-read",), 3)]


def test_approval_flow_denied_approved_with_covers_and_retried() -> None:
    sealer = StubSealer()
    run, args, ran = _enforced(sealer), b'{"amount":120}', []
    with pytest.raises(PolicyDenied) as e:
        run.invoke_tool("payments.refund", args, lambda: ran.append(1) or b"{}", consequential=True, use_id="call-1")
    d = e.value
    assert (d.reason, d.rules, d.tool, d.use_id, d.seq, d.halted) == \
        ("rule", ("restricted-needs-bound-approval",), "payments.refund", "call-1", 1, False)
    assert d.record.envelope["step"]["tool"] == {"name": "payments.refund", "useId": "call-1"}
    assert ran == [] and not run.halted
    before = len(sealer.requests)
    with pytest.raises(ValueError) as refused:
        run.record_tool_result("payments.refund", b"{}", use_id="call-1")
    assert str(refused.value) == "The tool_call with use_id 'call-1' was denied; it has no result."
    assert len(sealer.requests) == before
    run.record_human_approval("approved", approver="urn:example:approver:1",
                              covers=ApprovalCovers.for_arguments("payments.refund", args))
    assert run.invoke_tool("payments.refund", args, lambda: b'{"ok":true}', consequential=True) == b'{"ok":true}'
    assert _types(run) == ["run_start", "tool_call", "authorization", "human_approval", "tool_call", "tool_result"]
    result = verify_agent_run(run.finish(), stub_verify)
    assert result.verdict == "run_finalized" and result.checks["enforcement"] == "ok"


def test_halt_after_denials_then_every_call_raises_and_finish_returns_the_bundle() -> None:
    sealer = StubSealer()
    run = _enforced(sealer, _doc(haltAfterDenials=2))
    with pytest.raises(PolicyDenied) as first:
        run.begin_tool_call("search.web", b"{}")
    assert not first.value.halted and not run.halted
    with pytest.raises(PolicyDenied) as second:
        run.begin_tool_call("search.web", b"{}")
    assert second.value.halted and run.halted
    assert _types(run)[-3:] == ["tool_call", "authorization", "run_end"]
    assert run.artifacts[-1].envelope["step"]["runDisposition"] == "halted"
    before = len(sealer.requests)
    for attempt in (lambda: run.record_model_output(b"x"), lambda: run.begin_tool_call("crm.read_customer", b"{}"),
                    lambda: run.delegate("urn:example:agent:child"), run.checkpoint):
        with pytest.raises(RunHalted) as halted:
            attempt()
        assert (halted.value.reason, halted.value.rules, halted.value.seq) == ("rule", ("no-web-search",), 3)
        assert halted.value.record.envelope == run.artifacts[4].envelope
    bundle = run.finish("completed")
    assert len(sealer.requests) == before and bundle.artifacts == run.artifacts
    assert run.to_bundle().artifacts == bundle.artifacts
    result = verify_agent_run(bundle, stub_verify)
    assert result.verdict == "run_finalized" and result.enforcement_findings == []


def test_halt_on_a_non_tool_event() -> None:
    events = []
    run = _enforced(StubSealer(), on_event=events.append)
    with pytest.raises(PolicyDenied):
        run.begin_tool_call("search.web", b"{}")
    with pytest.raises(RunHalted) as e:
        run.record_retrieval(b"context")
    assert (e.value.reason, e.value.rules, e.value.seq) == ("rule", ("halt-retrieval-after-denial",), 3)
    assert "tool" not in e.value.record.envelope["step"]
    assert _types(run) == ["run_start", "tool_call", "authorization", "retrieval", "authorization", "run_end"]
    assert [(x.kind, x.seq) for x in events] == [("denied", 1), ("halted", 3)]
    assert verify_agent_run(run.finish(), stub_verify).checks["enforcement"] == "ok"


def test_a_halt_rule_on_delegation_and_a_refused_child_start() -> None:
    sealer = StubSealer()
    run = _enforced(sealer)
    with pytest.raises(RunHalted) as e:
        run.delegate("urn:example:agent:reviewer", b"task")
    assert e.value.rules == ("no-delegation",)
    assert _types(run) == ["run_start", "delegation", "authorization", "run_end"]
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"

    # A delegation made before the parent was halted: its child is not started afterwards.
    doc = json.loads(_doc())
    doc["cedar"]["policies"]["staticPolicies"]["no-delegation"]["annotations"]["effect"] = "observe"
    parent = _enforced(sealer, json.dumps(doc).encode())
    delegation = parent.delegate("urn:example:agent:reviewer", b"task")
    with pytest.raises(PolicyDenied):
        parent.begin_tool_call("search.web", b"{}")
    with pytest.raises(RunHalted):
        parent.record_retrieval(b"context")
    before = len(sealer.requests)
    with pytest.raises(RunHalted):
        AgentRun.start_child(_client(sealer), AgentDefinition("urn:example:agent:reviewer", "1"), delegation,
                             certificate_id=CERT, activity="review",
                             control_set=AgentControlSet("plain", "1", b'{"controls":[]}'))
    assert len(sealer.requests) == before


@pytest.mark.parametrize("why", ["configuration_locked", "unavailable"])
def test_start_refused(why: str) -> None:
    sealer, events = StubSealer(), []
    with pytest.raises(StartRefused) as e:
        _enforced(sealer, engine=StubEngine(dead=why == "unavailable"), on_event=events.append,
                  agent=_agent(b"tool-manifest v2" if why == "configuration_locked" else b"tool-manifest v1"))
    run = e.value.run
    assert e.value.reason == why and run.halted
    assert _types(run) == ["run_start", "authorization", "run_end"]
    record = run.artifacts[1].envelope["step"]
    assert record["enforcer"] == {"engine": "cedar-policy@4.14.0", "factsVersion": "2", "reason": why}
    assert "tool" not in record and "rules" not in record
    assert [(x.kind, x.reason, x.seq) for x in events] == [("start_refused", why, 0)]
    with pytest.raises(RunHalted):
        run.record_tool_call("crm.read_customer", b"{}")
    bundle = run.finish()
    assert len(bundle.artifacts) == 3
    assert verify_agent_run(bundle, stub_verify).verdict == "run_finalized"


@pytest.mark.parametrize("event", ["tool_call", "model_output"])
def test_an_engine_failure_mid_run_is_unavailable_and_halts(event: str) -> None:
    stub = StubEngine()
    run = _enforced(StubSealer(), engine=stub)
    run.invoke_tool("crm.read_customer", b"{}", lambda: b"{}", definition=b"crm.read_customer definition")
    stub.fail = True
    if event == "tool_call":
        with pytest.raises(PolicyDenied) as e:
            run.begin_tool_call("crm.read_customer", b"{}", use_id="u2", definition=b"crm.read_customer definition")
        assert (e.value.reason, e.value.rules, e.value.halted) == ("unavailable", (), True)
        assert e.value.record.envelope["step"]["tool"] == {"name": "crm.read_customer", "useId": "u2"}
    else:
        with pytest.raises(RunHalted) as e:
            run.record_model_output(b"x")
        assert (e.value.reason, e.value.rules) == ("unavailable", ())
        assert "tool" not in e.value.record.envelope["step"]
    assert run.halted and _types(run)[-2:] == ["authorization", "run_end"]
    assert verify_agent_run(run.finish(), stub_verify).checks["enforcement"] == "ok"


@pytest.mark.parametrize("failing", ["tool_call", "record", "halt"])
def test_a_sealing_failure_breaks_the_run_and_the_tool_does_not_run(failing: str) -> None:
    sealer, ran = StubSealer(), []
    run = _enforced(sealer, _doc(haltAfterDenials=1) if failing == "halt" else DOC)
    sealer.fail_on_call = len(sealer.requests) + {"tool_call": 0, "record": 1, "halt": 2}[failing]
    with pytest.raises(Exception) as e:
        run.invoke_tool("search.web", b"{}", lambda: ran.append(1) or b"{}")
    assert not isinstance(e.value, (PolicyDenied, RunHalted))
    assert ran == [] and run.is_broken and not run.halted
    assert _types(run) == {"tool_call": ["run_start"], "record": ["run_start", "tool_call"],
                           "halt": ["run_start", "tool_call", "authorization"]}[failing]
    with pytest.raises(RuntimeError, match="broken"):
        run.record_model_output(b"x")
    assert verify_agent_run(run.to_bundle(), stub_verify).verdict != "run_finalized"


def test_32_concurrent_calls_each_decision_directly_follows_its_call() -> None:
    run, outcomes, lock = _enforced(StubSealer()), [], threading.Lock()
    barrier = threading.Barrier(32)

    def call(i: int) -> None:
        barrier.wait()
        try:
            tool = "search.web" if i % 2 else "crm.read_customer"
            run.invoke_tool(tool, b"{}", lambda: b"{}", definition=None if i % 2 else b"crm.read_customer definition")
            result = "allowed"
        except PolicyDenied as e:
            result = e.use_id
        with lock:
            outcomes.append(result)
    threads = [threading.Thread(target=call, args=(i,)) for i in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    bundle = run.finish()
    events = [a.envelope for a in bundle.artifacts]
    records = [i for i, e in enumerate(events) if e["step"]["type"] == "authorization"]
    assert len(records) == sum(o != "allowed" for o in outcomes) == 16 + 13  # every search, and reads after the 3rd
    for i in records:
        assert events[i - 1]["step"]["type"] == "tool_call"
        assert events[i - 1]["step"]["tool"]["useId"] == events[i]["step"]["tool"]["useId"]
    result = verify_agent_run(bundle, stub_verify)
    assert result.verdict == "run_finalized" and result.enforcement_findings == []


def test_the_event_budget_keeps_room_for_a_record_and_the_halt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_agent_run, "MAX_ARTIFACTS", 8)
    sealer = StubSealer()
    run = _enforced(sealer)
    with pytest.raises(PolicyDenied):
        run.begin_tool_call("search.web", b"{}")       # seq 1, its record seq 2
    run.record_model_output(b"x")                       # 3
    run.record_model_output(b"x")                       # 4
    before = len(sealer.requests)
    with pytest.raises(RuntimeError, match="reserved for run_end, the guard's enforcement record"):
        run.begin_tool_call("crm.read_customer", b"{}")  # it and its record would leave no room for a halt
    assert len(sealer.requests) == before and not run.is_broken
    with pytest.raises(RunHalted):
        run.record_retrieval(b"r")                      # 5, its record 6, the halting run_end 7: exactly 8
    assert len(run.artifacts) == 8 and run.halted


def test_callbacks_in_seal_order_and_a_failing_callback_never_hides_the_denial() -> None:
    log: list = []

    def on_event(e: object) -> None:
        log.append(("event", e.seq))
        raise KeyError("callback failed")
    run = AgentRun.start(_client(StubSealer()), _agent(), certificate_id=CERT, activity="a",
                         control_set=AgentPolicy.control_set_from_document(DOC),
                         enforcement=Enforcement(StubEngine(), on_event), _clock=_clock(),
                         on_artifact_sealed=lambda a: log.append(("sealed", a.seq)))
    with pytest.raises(PolicyDenied) as e:
        run.begin_tool_call("search.web", b"{}")
    assert isinstance(e.value.__cause__, KeyError)
    assert log == [("sealed", None), ("sealed", 0), ("sealed", 1), ("sealed", 2), ("event", 1)]
    run.invoke_tool("crm.read_customer", b"{}", lambda: b"{}", definition=b"crm.read_customer definition")
    assert not run.is_broken and log[-2:] == [("sealed", 3), ("sealed", 4)]


def test_messages_and_attributes_carry_no_arguments_or_results() -> None:
    events = []
    run = _enforced(StubSealer(), _doc(haltAfterDenials=2), on_event=events.append)
    with pytest.raises(PolicyDenied) as denied:
        run.begin_tool_call("search.web", SECRET)
    run.invoke_tool("crm.read_customer", SECRET, lambda: SECRET, definition=b"crm.read_customer definition")
    with pytest.raises(PolicyDenied) as halted:
        run.begin_tool_call("search.web", SECRET)
    with pytest.raises(RunHalted) as later:
        run.record_model_output(SECRET)
    secret = SECRET.decode()
    for e in (denied.value, halted.value, later.value):
        assert secret not in str(e)
        assert secret not in repr({k: v for k, v in vars(e).items() if k != "record"})
    assert str(denied.value) == f"The policy denied the call of tool 'search.web' (use_id '{denied.value.use_id}', " \
        "seq 1): reason rule, rules no-web-search."
    assert str(later.value) == "The policy halted the run at seq 5: reason rule, rules no-web-search."
    assert all(secret not in repr(e) for e in events)
    for a in run.artifacts:
        if a.step_type == "authorization":
            assert secret not in json.dumps(a.envelope) and a.envelope["objects"] == []


def test_invoke_tool_never_runs_a_denied_tool() -> None:
    run, ran = _enforced(StubSealer()), []
    with pytest.raises(PolicyDenied):
        run.invoke_tool("fs.wipe", b"{}", lambda: ran.append(1) or b"{}")  # unknown tool, and a halt rule
    assert ran == [] and run.halted


def test_the_model_call_transport_does_not_swallow_a_halt() -> None:
    stub, sent = StubEngine(), []

    def provider(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={"id": "msg_1", "model": "claude-x", "usage": {"input_tokens": 1}})
    run = _enforced(StubSealer(), engine=stub, records_model_calls=True)
    http = httpx.Client(transport=ModelCallTransport(run, httpx.MockTransport(provider)))
    http.post("https://api.anthropic.com/v1/messages", json={"model": "claude-x"})
    stub.fail = True
    with pytest.raises(RunHalted):
        http.post("https://api.anthropic.com/v1/messages", json={"model": "claude-x"})
    assert run.halted and len(sent) == 2
    with pytest.raises(RunHalted):
        http.post("https://api.anthropic.com/v1/messages", json={"model": "claude-x"})
    assert len(sent) == 2, "a halted run makes no more model calls"
    assert _types(run) == ["run_start", "model_output", "model_output", "authorization", "run_end"]


# ── Review fixes: regressions (the security proofs, ported) ──────────────────

class _Shaped(StubEngine):
    """Answers a call of search.web (forbidden by no-web-search) with ``shape``; everything else as the stub."""

    def __init__(self, shape: object) -> None:
        super().__init__()
        self.shape = shape

    def authorize(self, call: dict) -> dict:
        if call["action"]["id"] == "tool_call" and call["resource"]["id"] == "search.web":
            return copy.deepcopy(self.shape)
        return super().authorize(call)


def _answer(decision: object = None, **diagnostics: object) -> dict:
    """An isAuthorized answer; its decision agrees with ``reason`` unless one is given."""
    response = {"decision": decision or ("deny" if diagnostics.get("reason") else "allow"), "diagnostics": diagnostics}
    return {"type": "success", "response": response if decision != "missing" else {"diagnostics": diagnostics}}


MALFORMED = {
    "reason as a string": _answer(reason="no-web-search", errors=[]),
    "reason as an object": _answer(reason={"no-web-search": 1}, errors=[]),
    "reason with a non-string": _answer(reason=["no-web-search", 5], errors=[]),
    "reason missing": _answer(errors=[]),
    "errors as a string": _answer(reason=[], errors="no-web-search"),
    "errors as a list of strings": _answer(reason=[], errors=["no-web-search"]),
    "errors with a non-string policyId": _answer(reason=[], errors=[{"policyId": 5}]),
    "errors without policyId": _answer(reason=[], errors=[{"error": "x"}]),
    "diagnostics missing": {"type": "success", "response": {"decision": "deny"}},
    "response missing": {"type": "success"},
    "type ok": {**_answer(reason=["no-web-search"], errors=[]), "type": "ok"},
    "type Success": {**_answer(reason=["no-web-search"], errors=[]), "type": "Success"},
    "type failure": {"type": "failure", "errors": [{"message": "refused"}]},
    "answer a list": [],
    "answer null": None,
    "decision missing": _answer("missing", reason=["no-web-search"], errors=[]),
    "decision permit": _answer("permit", reason=["no-web-search"], errors=[]),
    "decision deny with an empty reason": _answer("deny", reason=[], errors=[]),
    "decision allow with a rule in reason": _answer("allow", reason=["no-web-search"], errors=[]),
    "reason names an unknown policy, decision deny": _answer("deny", reason=["nonexistent-rule"], errors=[]),
    "reason names an unknown policy, decision allow": _answer(
        "allow", reason=["nonexistent-rule", "sigill:baseline-permit"], errors=[]),
    "errors name an unknown policy": _answer(reason=[], errors=[{"policyId": "nonexistent-rule",
                                                                 "error": {"message": "x"}}]),
}


@pytest.mark.parametrize("shape", list(MALFORMED))
def test_h1_any_malformed_engine_answer_is_unavailable_and_halts(shape: str) -> None:
    run, ran = _enforced(StubSealer(), engine=_Shaped(MALFORMED[shape])), []
    with pytest.raises(PolicyDenied) as e:
        run.invoke_tool("search.web", SECRET, lambda: ran.append(1) or b"{}")
    assert (e.value.reason, e.value.rules, e.value.halted) == ("unavailable", (), True)
    assert ran == [] and run.halted and _types(run) == ["run_start", "tool_call", "authorization", "run_end"]
    assert verify_agent_run(run.finish(), stub_verify).checks["enforcement"] == "ok"


@pytest.mark.parametrize("shape", list(MALFORMED))
def test_h1_evaluate_uses_the_same_answer_check(shape: str) -> None:
    facts = AgentPolicy.build_facts_v2(AGENT_ID, "urn:uuid:r", _enforced(StubSealer()).to_bundle().artifacts, DOC)

    class Malformed(StubEngine):
        def authorize(self, call: dict) -> dict:
            return copy.deepcopy(MALFORMED[shape])
    answer = MALFORMED[shape]
    refused = isinstance(answer, dict) and answer.get("type") != "success"  # phase 2: a refused request
    with pytest.raises(PolicyEngineError, match="^The policy engine refused request 0" if refused else
                       "^The policy engine's answer is not an isAuthorized answer.$"):
        AgentPolicy.evaluate(DOC, facts, Malformed())


@pytest.mark.parametrize("variant", ["validate raises", "version raises", "version 4.14", "version with a newline"])
def test_h2_an_engine_failing_at_start_refuses_an_enforced_start(variant: str) -> None:
    class Broken(StubEngine):
        @property
        def version(self) -> str:
            if variant == "version raises":
                raise PolicyEngineError("cannot load")
            return {"version 4.14": "4.14", "version with a newline": "4.14.0\n"}.get(variant, "4.14.0")

        def validate(self, call: dict) -> dict:
            if variant == "validate raises":
                raise PolicyEngineError("validate trapped")
            return super().validate(call)
    with pytest.raises(StartRefused) as e:
        _enforced(StubSealer(), engine=Broken())
    assert e.value.reason == "unavailable" and e.value.run.halted
    assert _types(e.value.run) == ["run_start", "authorization", "run_end"]


@pytest.mark.parametrize("manifest", [b"tool-manifest v2", None, b"", b"Tool-manifest v1"])
def test_the_start_gate_refuses_any_other_or_missing_locked_object(manifest: bytes | None) -> None:
    with pytest.raises(StartRefused) as e:
        _enforced(StubSealer(), agent=_agent(manifest))
    assert e.value.reason == "configuration_locked"


def test_w1_a_bytearray_configuration_changed_during_the_seal_is_judged_on_the_sealed_bytes() -> None:
    manifest, sealer, calls = bytearray(b"tool-manifest v2"), StubSealer(), []

    def handler(request: httpx.Request) -> httpx.Response:
        if not calls:
            manifest[:] = b"tool-manifest v1"  # after the Control Artifact's digests were taken
        calls.append(1)
        return sealer(request)
    with pytest.raises(StartRefused) as e:
        AgentRun.start(_client(handler), _agent(manifest), certificate_id=CERT, activity="a",
                       control_set=AgentPolicy.control_set_from_document(DOC),
                       enforcement=Enforcement(StubEngine()), _clock=_clock())
    assert e.value.reason == "configuration_locked"


@pytest.mark.parametrize("where", ["on_artifact_sealed", "on_event"])
def test_w2_a_base_exception_in_a_callback_does_not_wedge_the_run(where: str) -> None:
    def interrupt(x: object) -> None:
        if getattr(x, "step_type", None) == "authorization" or getattr(x, "kind", None) == "denied":
            raise KeyboardInterrupt
    run = AgentRun.start(_client(StubSealer()), _agent(), certificate_id=CERT, activity="a",
                         control_set=AgentPolicy.control_set_from_document(DOC),
                         enforcement=Enforcement(StubEngine(), interrupt if where == "on_event" else None),
                         on_artifact_sealed=interrupt if where == "on_artifact_sealed" else None, _clock=_clock())
    returned = []
    with pytest.raises(KeyboardInterrupt):
        returned.append(run.begin_tool_call("search.web", b"{}", use_id="s1"))
    assert returned == []
    done = []
    t = threading.Thread(target=lambda: done.append(run.record_model_output(b"x")), daemon=True)
    t.start()
    t.join(5)
    assert done, "the next recording call returned"
    with pytest.raises(ValueError, match="was denied"):
        run.record_tool_result("search.web", b"{}", use_id="s1")


def test_w2_a_base_exception_in_the_engine_breaks_the_run() -> None:
    class Interrupting(StubEngine):
        def authorize(self, call: dict) -> dict:
            if call["resource"]["id"] == "search.web":
                raise KeyboardInterrupt
            return super().authorize(call)
    run = _enforced(StubSealer(), engine=Interrupting())
    with pytest.raises(KeyboardInterrupt):
        run.begin_tool_call("search.web", b"{}", use_id="s1")
    assert run.is_broken
    with pytest.raises(RuntimeError, match="broken"):
        run.record_tool_result("search.web", b"{}", use_id="s1")


def test_w3_an_engine_that_changes_its_input_does_not_change_a_later_decision() -> None:
    class Mutating(StubEngine):
        def authorize(self, call: dict) -> dict:
            answer = super().authorize(call)
            call["policies"]["staticPolicies"].pop("no-web-search", None)
            return answer
    run = _enforced(StubSealer(), engine=Mutating())
    for use_id in ("s1", "s2"):
        with pytest.raises(PolicyDenied):
            run.begin_tool_call("search.web", b"{}", use_id=use_id)


def test_halted_run_every_entry_point_raises_run_halted() -> None:
    from sigill_sdk import AgentAuthorization, ModelCall
    run = _enforced(StubSealer(), _doc(haltAfterDenials=1))
    with pytest.raises(PolicyDenied):
        run.begin_tool_call("search.web", b"{}", use_id="s1")
    attempts = [lambda: run.begin_tool_call("crm.read_customer", b"{}"),
                lambda: run.record_tool_call("crm.read_customer", b"{}"),
                lambda: run.record_tool_result("search.web", b"{}", use_id="s1"),
                lambda: run.invoke_tool("crm.read_customer", b"{}", lambda: b"{}"),
                lambda: run.record("retrieval"), lambda: run.record_retrieval(b"r"),
                lambda: run.record_authorization(AgentAuthorization("allowed")),
                lambda: run.record_human_approval("approved", covers=ApprovalCovers.for_arguments("x", b"{}")),
                lambda: run.record_model_output(b"x"), lambda: run.record_model_call(ModelCall()), run.checkpoint,
                lambda: run.delegate("urn:example:agent:child"),
                lambda: run.complete_delegation("urn:uuid:x", "a" * 64, "completed")]
    for attempt in attempts:
        with pytest.raises(RunHalted) as e:
            attempt()
        assert (e.value.reason, e.value.rules, e.value.seq) == ("rule", ("no-web-search",), 1)
    errors: list = []

    def concurrent() -> None:
        try:
            run.begin_tool_call("crm.read_customer", b"{}")
        except RunHalted as e:
            errors.append(e)
    threads = [threading.Thread(target=concurrent) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(errors) == 16
    for disposition in ("completed", "failed", "aborted"):
        assert run.finish(disposition).artifacts == run.artifacts
    with pytest.raises(ValueError):
        run.finish("halted")
    assert _types(run)[-1] == "run_end" and len(run.artifacts) == 4


def _delegate_from_a_callback(run_box: list, when: object):  # noqa: ANN202
    """A callback that halts the run (no-delegation) while a tool_call that was allowed is being delivered."""
    def callback(x: object) -> None:
        if when(x) and not run_box[0].halted:
            with pytest.raises(RunHalted):
                run_box[0].delegate("urn:example:agent:child")
    return callback


class _PreviewObserved(StubEngine):
    """ledger.preview (known, no definition) is allowed; preview-weight (an observe rule) matches it."""

    def authorize(self, call: dict) -> dict:
        if call["action"]["id"] == "tool_call" and call["resource"]["id"] == "ledger.preview":
            return _answer(reason=["preview-weight"], errors=[])
        return super().authorize(call)


@pytest.mark.parametrize("entry", ["invoke_tool", "begin_tool_call", "record_tool_call"])
@pytest.mark.parametrize("via", ["on_artifact_sealed", "on_event"])
def test_r2_no_tool_starts_after_a_callback_halted_the_run(entry: str, via: str) -> None:
    box: list = [None]
    cb = _delegate_from_a_callback(box, (lambda a: getattr(a, "step_type", None) == "tool_call")
                                   if via == "on_artifact_sealed" else (lambda e: e.kind == "observed"))
    run = box[0] = AgentRun.start(
        _client(StubSealer()), _agent(), certificate_id=CERT, activity="a",
        control_set=AgentPolicy.control_set_from_document(DOC), _clock=_clock(),
        enforcement=Enforcement(_PreviewObserved(), cb if via == "on_event" else None),
        on_artifact_sealed=cb if via == "on_artifact_sealed" else None)
    ran, returned = [], []
    with pytest.raises(RunHalted) as e:
        if entry == "invoke_tool":
            run.invoke_tool("ledger.preview", b"{}", lambda: ran.append(1) or b"{}", use_id="r9")
        elif entry == "begin_tool_call":
            returned.append(run.begin_tool_call("ledger.preview", b"{}", use_id="r9"))
        else:
            returned.append(run.record_tool_call("ledger.preview", b"{}", use_id="r9"))
    assert ran == [] and returned == []
    with pytest.raises(RunHalted) as again:
        run.record_tool_result("ledger.preview", b"{}", use_id="r9")
    assert (e.value.reason, e.value.rules, e.value.seq, e.value.record.envelope) == \
        (again.value.reason, again.value.rules, again.value.seq, again.value.record.envelope)
    assert e.value.rules == ("no-delegation",)
    assert _types(run)[-4:] == ["tool_call", "delegation", "authorization", "run_end"]
    result = verify_agent_run(run.finish(), stub_verify)
    assert result.verdict == "run_finalized" and result.checks["enforcement"] == "ok"
    assert result.enforcement_findings == [] and result.findings == []


def test_r2_a_call_held_in_its_callback_while_another_thread_halts_the_run() -> None:
    held, outcome = threading.Event(), {}
    box: list = [None]

    def on_sealed(a: object) -> None:
        if getattr(a, "step_type", None) == "tool_call" and threading.current_thread().name == "A":
            held.set()
            for _ in range(500):  # until thread B has sealed the halt
                if box[0].halted:
                    return
                threading.Event().wait(0.01)
    run = box[0] = AgentRun.start(
        _client(StubSealer()), _agent(), certificate_id=CERT, activity="a",
        control_set=AgentPolicy.control_set_from_document(DOC), _clock=_clock(),
        enforcement=Enforcement(StubEngine()), on_artifact_sealed=on_sealed)

    def a() -> None:
        try:
            outcome["a"] = run.begin_tool_call("crm.read_customer", b"{}", definition=b"crm.read_customer definition")
        except RunHalted as e:
            outcome["a"] = e

    def b() -> None:
        held.wait(5)
        try:
            run.delegate("urn:example:agent:child")
        except RunHalted as e:
            outcome["b"] = e
    threads = [threading.Thread(target=a, name="A"), threading.Thread(target=b, name="B")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert isinstance(outcome["a"], RunHalted) and isinstance(outcome["b"], RunHalted)
    assert outcome["a"].seq == outcome["b"].seq == 2
    assert _types(run) == ["run_start", "tool_call", "delegation", "authorization", "run_end"]
    result = verify_agent_run(run.finish(), stub_verify)
    assert result.verdict == "run_finalized" and result.enforcement_findings == []


_PROBE_OK = {"type": "success", "response": {"decision": "deny", "diagnostics": {"reason": [], "errors": []}}}
STRICT_MALFORMED = {
    "validate: validationErrors missing": ("validate", {"type": "success"}),
    "validate: validationErrors a string": ("validate", {"type": "success", "validationErrors": "not-an-array"}),
    "validate: validationErrors with a string": ("validate", {"type": "success", "validationErrors": ["x"]}),
    "validate: an entry without policyId": ("validate", {"type": "success", "validationErrors": [
        {"error": {"message": "m"}}]}),
    "validate: an entry whose error is a string": ("validate", {"type": "success", "validationErrors": [
        {"policyId": "no-web-search", "error": "m"}]}),
    "validate: type ok": ("validate", {"type": "ok", "validationErrors": []}),
    "validate: a list": ("validate", []),
    "probe: no response": ("probe", {"type": "success"}),
    "probe: reason a string": ("probe", {"type": "success", "response": {"decision": "deny", "diagnostics": {
        "reason": "no-web-search", "errors": []}}}),
    "probe: a non-empty reason": ("probe", {"type": "success", "response": {"decision": "deny", "diagnostics": {
        "reason": ["no-web-search"], "errors": []}}}),
}


class _StrictShaped(StubEngine):
    def __init__(self, case: str) -> None:
        super().__init__()
        self.where, self.answer = STRICT_MALFORMED[case]

    def validate(self, call: dict) -> dict:
        return copy.deepcopy(self.answer) if self.where == "validate" else super().validate(call)

    def authorize(self, call: dict) -> dict:
        if call["principal"]["id"] == "strict-validation":
            return copy.deepcopy(self.answer if self.where == "probe" else _PROBE_OK)
        return super().authorize(call)


@pytest.mark.parametrize("case", list(STRICT_MALFORMED))
def test_r4_strict_validation_fails_closed_on_a_malformed_answer(case: str) -> None:
    text = "The policy engine's answer is not " + ("a validate answer." if case.startswith("validate")
                                                   else "an isAuthorized answer.")
    with pytest.raises(PolicyEngineError) as e:
        AgentPolicy.validate_strict(DOC, _StrictShaped(case))
    assert str(e.value) == text
    sealer = StubSealer()
    with pytest.raises(StartRefused) as refused:
        _enforced(sealer, engine=_StrictShaped(case))
    assert refused.value.reason == "unavailable"
    assert _types(refused.value.run) == ["run_start", "authorization", "run_end"] and len(sealer.requests) == 4
    with pytest.raises(PolicyEngineError, match="^" + text.replace(".", "\\.") + "$"):  # not enforced: the error
        _enforced(StubSealer(), _doc(mode="observe"), engine=_StrictShaped(case))


@pytest.mark.parametrize("swap", ["observe to enforce", "enforce to observe"])
def test_r5_a_control_set_buffer_changed_during_validation_is_one_document(swap: str) -> None:
    first, second = (_doc(mode="observe"), DOC) if swap == "observe to enforce" else (DOC, _doc(mode="observe"))
    buffer = bytearray(first)

    class Swapping(StubEngine):
        def validate(self, call: dict) -> dict:
            buffer[:] = second  # the caller's buffer changes while the engine validates
            return super().validate(call)
    control_set = AgentControlSet("acme-support-agent-controls", "4", buffer, POLICY_CONTROL_SET_CONTENT_TYPE)
    run = AgentRun.start(_client(StubSealer()), _agent(), certificate_id=CERT, activity="a", control_set=control_set,
                         enforcement=Enforcement(Swapping()), _clock=_clock())
    sealed = next(run.control_artifact.object_digests[o["uri"]] for o in run.control_artifact.envelope["objects"]
                  if o["role"] == "control-set")
    assert sealed == hash_bytes(first)
    assert run._guard.settings == AgentPolicy.enforcement(first)  # the guard's settings came from those bytes
    if swap == "observe to enforce":
        run.invoke_tool("search.web", b"{}", lambda: b"{}")
    else:
        with pytest.raises(PolicyDenied):
            run.invoke_tool("search.web", b"{}", lambda: b"{}")
    assert verify_agent_run(run.finish(), stub_verify).verdict == "run_finalized"


@pytest.mark.parametrize("failing", ["the record after the model call", "the model call's own event"])
@pytest.mark.parametrize("mode", ["enforce", "observe", "no guard"])
def test_r6_the_model_call_transport_lets_no_enforced_agent_go_on_after_a_failure(failing: str, mode: str) -> None:
    stub, sealer, sent, errors = StubEngine(), StubSealer(), [], []

    def provider(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={"id": "msg_1", "model": "claude-x", "usage": {"input_tokens": 1}})
    if mode == "no guard":
        run = AgentRun.start(_client(sealer), _agent(), certificate_id=CERT, activity="a", _clock=_clock(),
                             control_set=AgentControlSet("plain", "1", b'{"controls":[]}'), records_model_calls=True)
    else:
        run = _enforced(sealer, DOC if mode == "enforce" else _doc(mode="observe"), engine=stub,
                        records_model_calls=True)
    http = httpx.Client(transport=ModelCallTransport(run, httpx.MockTransport(provider), errors.append))
    post = lambda: http.post("https://api.anthropic.com/v1/messages", json={"model": "claude-x"})  # noqa: E731
    if failing == "the record after the model call":
        stub.fail, sealer.fail_on_call = True, len(sealer.requests) + 1  # unavailable, then its record fails
    else:
        sealer.fail_on_call = len(sealer.requests)
    if mode == "enforce":
        with pytest.raises(SigillError) as e:
            post()
        assert errors == [e.value] and run.is_broken and not run.halted
        with pytest.raises(RuntimeError, match="broken"):
            post()
        assert len(sent) == 1, "nothing is sent for a broken enforced run"
    else:  # today's behaviour: the response is returned, the failure goes to on_error, the next request is sent
        assert post().status_code == 200
        assert len(errors) == (1 if failing == "the model call's own event" else 0)
        assert post().status_code == 200 and len(sent) == 2


@pytest.mark.parametrize("where", ["the returned artifact", "on_artifact_sealed"])
def test_r7_editing_an_approval_artifact_changes_no_decision(where: str, engine: CedarEngine) -> None:
    one, thousand = b'{"amount":1}', b'{"amount":1000}'

    def edit(a: object) -> None:
        if where == "on_artifact_sealed" and getattr(a, "step_type", None) == "human_approval":
            a.envelope["step"]["covers"]["argumentsSha256"] = hash_bytes(thousand)
    run = AgentRun.start(_client(StubSealer()), _agent(), certificate_id=CERT, activity="a",
                         control_set=AgentPolicy.control_set_from_document(DOC), _clock=_clock(),
                         enforcement=Enforcement(engine), on_artifact_sealed=edit)
    approval = run.record_human_approval("approved", approver="urn:example:approver:1",
                                         covers=ApprovalCovers.for_arguments("payments.refund", one))
    if where == "the returned artifact":
        approval.envelope["step"]["covers"]["argumentsSha256"] = hash_bytes(thousand)
    ran = []
    with pytest.raises(PolicyDenied) as e:
        run.invoke_tool("payments.refund", thousand, lambda: ran.append(1) or b"{}", consequential=True)
    assert (e.value.reason, e.value.rules, ran) == ("rule", ("restricted-needs-bound-approval",), [])
    approval.envelope["step"]["covers"]["argumentsSha256"] = hash_bytes(one)  # restored: still what was sealed
    assert run.invoke_tool("payments.refund", one, lambda: b'{"ok":true}', consequential=True) == b'{"ok":true}'


def test_r7_a_parent_records_the_childs_sealed_run_end_not_an_edited_artifact() -> None:
    sealer = StubSealer()
    parent = _start(_client(sealer), delegating=True)
    child = AgentRun.start_child(_client(sealer), AgentDefinition("urn:example:agent:child", "1"),
                                 parent.delegate("urn:example:agent:child"), certificate_id=CERT, activity="a",
                                 control_set=AgentControlSet("plain", "1", b'{"controls":[]}'), _clock=_clock())
    end = child.finish("completed").artifacts[-1]
    signature = end.signature_sha256
    end.envelope["step"]["runDisposition"] = "failed"
    end.signature["signatures"][0]["signature"] = "edited"
    result = parent.complete_delegation(child).envelope["step"]["delegation"]
    assert (result["childDisposition"], result["childRunEndSignatureSha256"]) == ("completed", signature)


def test_r7_the_guard_decides_on_its_own_copy_of_the_event() -> None:
    box: list = [None]

    class Reaching(StubEngine):  # caller code that runs while the event is decided, on the deciding thread
        def authorize(self, call: dict) -> dict:
            if call["action"]["id"] == "tool_call" and box[0] is not None:
                event = box[0].artifacts[-1].envelope
                event["objects"] = [o for o in event["objects"] if o["role"] != "tool-definition"]
            return super().authorize(call)
    run = box[0] = _enforced(StubSealer(), engine=Reaching())
    run.invoke_tool("crm.read_customer", b"{}", lambda: b"{}", definition=b"crm.read_customer definition")
    assert "authorization" not in _types(run), "allowed, not denied tool_changed"


def test_vector_14_is_complete() -> None:
    from test_agent_enforcement import FINDINGS, RUNS
    assert (len(RUNS), len(FINDINGS)) == (35, 15) and set(RUNS) == set(CASES)


def test_t1_a_halt_rule_on_the_producers_run_end_has_no_effect() -> None:
    doc = json.loads(DOC)
    rule = copy.deepcopy(doc["cedar"]["policies"]["staticPolicies"]["no-delegation"])
    rule["action"]["entity"]["id"], rule["annotations"]["id"] = "run_end", "halt-at-end"
    doc["cedar"]["policies"]["staticPolicies"]["halt-at-end"] = rule
    stub = StubEngine()
    run = _enforced(StubSealer(), json.dumps(doc).encode(), engine=stub)
    bundle = run.finish()
    assert not run.halted and bundle.artifacts[-1].envelope["step"]["runDisposition"] == "completed"
    assert [c["action"]["id"] for c in stub.calls if c["principal"]["id"] != "strict-validation"] == ["run_start"]


def test_t2_an_observed_event_on_a_tool_result_carries_the_call() -> None:
    class Results(StubEngine):
        def authorize(self, call: dict) -> dict:
            if call["action"]["id"] == "tool_result":
                return _answer(reason=["shadow-repeat-read"], errors=[])
            return super().authorize(call)
    events = []
    run = _enforced(StubSealer(), engine=Results(), on_event=events.append)
    run.invoke_tool("crm.read_customer", b"{}", lambda: b"{}", use_id="r1",
                    definition=b"crm.read_customer definition")
    assert [(e.kind, e.reason, e.rules, e.tool, e.use_id, e.seq) for e in events] == [
        ("observed", None, ("shadow-repeat-read",), "crm.read_customer", "r1", 2)]


def test_t3_a_rule_less_enforcing_control_set_denies_every_tool_as_unknown() -> None:
    doc = json.loads(DOC)
    del doc["cedar"]
    run = _enforced(StubSealer(), json.dumps(doc).encode())
    for tool in ("crm.read_customer", "search.web"):
        with pytest.raises(PolicyDenied) as e:
            run.begin_tool_call(tool, b"{}")
        assert (e.value.reason, e.value.rules, e.value.halted) == ("unknown_tool", (), False)
    assert verify_agent_run(run.finish(), stub_verify).checks["enforcement"] == "ok"


def test_32_threads_every_decision_equals_its_recomputation(engine: CedarEngine) -> None:
    doc = json.loads(DOC)
    for rule in doc["cedar"]["policies"]["staticPolicies"].values():
        if rule["annotations"].get("effect") == "halt":
            rule["annotations"]["effect"] = "deny"  # a long run: no halts
    nohalt = json.dumps(doc).encode()
    effects = AgentPolicy.enforcement(nohalt).rule_effects
    run, outcomes, refund = _enforced(StubSealer(), nohalt, engine=engine), [], ARGUMENTS["A"].encode()

    def worker(i: int) -> None:
        for k in [(i * 7 + j * 3) % 4 for j in range(6)]:
            try:
                if k == 0:
                    run.invoke_tool("ledger.preview", ARGUMENTS["L"].encode(), lambda: b"{}")
                elif k == 1:
                    run.invoke_tool("search.web", b'{"q":"x"}', lambda: b"{}")
                    outcomes.append("RAN-FORBIDDEN")
                elif k == 2:
                    run.record_human_approval("approved", approver="urn:example:approver:1",
                                              covers=ApprovalCovers.for_arguments("payments.refund", refund))
                else:
                    run.invoke_tool("payments.refund", refund, lambda: b"{}", consequential=True)
                    outcomes.append("refund-ran")
            except PolicyDenied:
                pass
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    bundle = run.finish()
    arts = bundle.artifacts
    facts = AgentPolicy.build_facts_v2(AGENT_ID, run.correlation_id, arts, nohalt)
    by_seq = {int(r.seq): r for r in AgentPolicy.evaluate(nohalt, facts, engine).requests if r.seq != "run"}
    for a in arts:
        if a.step_type == "tool_call":
            due = any(effects.get(x) in ("deny", "halt") for x in by_seq[a.seq].reason)
            assert due == (arts[a.seq + 1].step_type == "authorization"), a.seq
    assert "RAN-FORBIDDEN" not in outcomes
    assert outcomes.count("refund-ran") <= sum(a.step_type == "human_approval" for a in arts)
    result = verify_agent_run(bundle, stub_verify)
    assert result.verdict == "run_finalized" and result.checks["enforcement"] == "ok"


# ── The examples, against the stub signer ───────────────────────────────────

def test_example_loop_until_halted(engine: CedarEngine) -> None:
    import loop_until_halted
    bundle = loop_until_halted.scenario(_client(StubSealer()), CERT, engine)
    steps = [a.envelope["step"] for a in bundle.artifacts]
    assert [s.get("enforcer", {}).get("reason") for s in steps if s["type"] == "authorization"] == ["rule"] * 3
    assert steps[-1]["runDisposition"] == "halted"
    result = verify_agent_run(bundle, stub_verify, engine=engine)
    assert result.verdict == "run_finalized" and result.checks["enforcement"] == "ok"


def test_example_graph_agent(engine: CedarEngine) -> None:
    import graph_agent
    parent, child = graph_agent.scenario(_client(StubSealer()), CERT, engine)
    types = [a.step_type for a in parent.artifacts]
    assert types.count("authorization") == 1 and types.count("tool_result") == 2
    assert types[-2:] == ["delegation_result", "run_end"]
    for b in (parent, child):
        result = verify_agent_run(b, stub_verify, engine=engine)
        assert result.verdict == "run_finalized" and result.checks["enforcement"] == "ok", result.findings


def test_example_approval_flow(engine: CedarEngine) -> None:
    import approval_flow
    bundle = approval_flow.scenario(_client(StubSealer()), CERT, engine)
    assert [a.step_type for a in bundle.artifacts] == [
        "run_start", "tool_call", "authorization", "human_approval", "tool_call", "tool_result", "run_end"]
    assert verify_agent_run(bundle, stub_verify, engine=engine).verdict == "run_finalized"


def test_the_control_set_of_the_examples_is_strictly_valid(engine: CedarEngine) -> None:
    assert AgentPolicy.validate_strict((REPO / "examples" / "control-set.json").read_bytes(), engine) == []
