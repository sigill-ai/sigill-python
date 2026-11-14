"""deliver_run: a run's artifacts uploaded to the organisation's evidence index in chain order, the outcome of every
answer the index can give, and the catch-up `SigillClient.deliver_agent_run`. The index and the sealing service are
faked on one httpx.MockTransport; nothing leaves the process.
"""

from __future__ import annotations

import base64
import json
import threading

import httpx
import pytest

from sigill_sdk import (
    AgentPolicy,
    AgentRun,
    AgentRunBundle,
    Enforcement,
    PolicyDenied,
    SigillClient,
)
from test_agent_enforcement import DOC, _with_enforcement
from test_agent_guard import StubEngine, _agent
from test_agent_policy import DOC as V11
from test_agent_policy import _client
from test_agent_run import CERT, StubSealer, _clock, _start

INDEX = "/api/agent-evidence/artifacts"


class Index:
    """The evidence index: 201 for a new artifact, 200 for one it holds; ``script`` overrides the next answers with
    (status, JSON body or text) or an exception to raise."""

    def __init__(self) -> None:
        self.sealer, self.uploads, self.script, self.held = StubSealer(), [], [], set()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path != INDEX:
            return self.sealer(request)
        body = json.loads(request.content)
        self.uploads.append({**body, "_timeout": request.extensions["timeout"]["read"]})
        if self.script:
            answer = self.script.pop(0)
            if isinstance(answer, Exception):
                raise answer
            status, payload = answer
            return httpx.Response(status, json=payload) if isinstance(payload, dict) else \
                httpx.Response(status, text=payload, headers={"content-type": "text/html"})
        key = body["envelope"]["evidenceId"]
        new = key not in self.held
        self.held.add(key)
        return httpx.Response(201 if new else 200, json={"status": "indexed" if new else "exists", "runId": "r-1",
                                                          "artifactId": key})

    def order(self) -> list:
        """What was uploaded: "control" for the Control Artifact, else the event's seq."""
        return [u["envelope"].get("chain", {}).get("seq", "control") for u in self.uploads]


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _run(index: Index, clock: Clock | None = None, **opts) -> AgentRun:  # noqa: ANN003
    return _start(_client(index), deliver_run=True, _index_clock=clock or Clock(), **opts)


def _enforced(index: Index, doc: bytes = DOC, **opts) -> AgentRun:  # noqa: ANN003
    return AgentRun.start(_client(index), _agent(), certificate_id=CERT, activity="a", _clock=_clock(),
                          control_set=AgentPolicy.control_set_from_document(doc), enforcement=Enforcement(StubEngine()),
                          deliver_run=True, _index_clock=Clock(), **opts)


def test_uploads_in_chain_order_with_the_guards_record_and_the_halted_run_end() -> None:
    index = Index()
    run = _enforced(index, _with_enforcement({**json.loads(DOC)["enforcement"], "haltAfterDenials": 1}))
    run.invoke_tool("crm.read_customer", b"{}", lambda: b"{}", definition=b"crm.read_customer definition")
    with pytest.raises(PolicyDenied):
        run.begin_tool_call("search.web", b"{}")
    bundle = run.finish()
    assert index.order() == ["control", 0, 1, 2, 3, 4, 5]
    assert [u["envelope"]["step"]["type"] for u in index.uploads[1:]] == \
        ["run_start", "tool_call", "tool_result", "tool_call", "authorization", "run_end"]
    assert index.uploads[-1]["envelope"]["step"]["runDisposition"] == "halted"
    for u, a in zip(index.uploads, [bundle.control_artifact, *bundle.artifacts]):
        assert (u["envelope"], u["signature"], u["objectDigests"]) == (a.envelope, a.signature, a.object_digests)
        assert "controlSet" not in u and u["_timeout"] == 10.0
    assert run.delivery.__dict__ == {"status": "delivered", "delivered": 7, "pending": 0, "run_id": "r-1",
                                     "error": None}


def test_off_uploads_nothing_and_disclose_alone_is_unchanged() -> None:
    index = Index()
    run = _start(_client(index))
    run.record_model_output(b"x")
    run.finish()
    assert index.uploads == [] and run.delivery is None
    run = _start(_client(index), control_set=AgentPolicy.control_set_from_document(V11), disclose_policy=True)
    run.record_tool_call("lookup_ticket", b"{}", use_id="c1")
    run.finish()
    assert index.order() == ["control"] and base64.b64decode(index.uploads[0]["controlSet"]) == V11
    assert run.policy_disclosure.succeeded and run.delivery is None


def test_disclose_with_deliver_sends_the_document_on_the_control_artifacts_upload_only() -> None:
    index = Index()
    run = _run(index, control_set=AgentPolicy.control_set_from_document(
        _with_enforcement({**json.loads(DOC)["enforcement"], "mode": "observe"})), disclose_policy=True)
    run.record_tool_call("lookup_ticket", b"{}", use_id="c1")
    run.finish()
    assert index.order() == ["control", 0, 1, 2]
    assert "controlSet" in index.uploads[0] and all("controlSet" not in u for u in index.uploads[1:])
    assert run.policy_disclosure.succeeded and run.policy_disclosure.run_id == "r-1"


@pytest.mark.parametrize("answers, status", [
    ([(409, {"code": "conflict", "message": "retry"})], "delivered"),
    ([(409, {"code": "conflict", "message": "retry"})] * 2, "pending"),
    ([(409, {"code": "seq_conflict", "message": "no"})], "rejected"),
    ([(409, "<html><body>Conflict</body></html>")], "rejected"),
])
def test_conflicts(answers: list, status: str) -> None:
    index = Index()
    run = _run(index)
    index.script = list(answers)
    run.record_model_output(b"x")  # seq 1
    assert run.delivery.status == status
    if status == "delivered":
        assert index.order() == ["control", 0, 1, 1], "a first conflict is retried at once"
    else:
        assert run.delivery.error.startswith("seq 1: 409") and run.delivery.delivered == 2
    assert not run.is_broken
    run.finish()


def test_a_503_holds_the_run_goes_on_and_the_cursor_resumes_after_the_back_off() -> None:
    index, clock = Index(), Clock()
    run = _run(index, clock)
    index.script = [(503, {"code": "unavailable", "message": "down"})]
    run.record_model_output(b"x")  # seq 1: held
    assert (run.delivery.status, run.delivery.delivered, run.delivery.error) == \
        ("pending", 2, "seq 1: 503 unavailable")
    run.record_model_output(b"x")  # seq 2: within the back-off, nothing is tried
    assert len(index.uploads) == 3 and run.delivery.pending == 2
    clock.now += 5.0
    run.record_model_output(b"x")  # seq 3: the back-off has passed
    assert index.order() == ["control", 0, 1, 1, 2, 3] and run.delivery.status == "delivered"
    index.script = [(503, {"code": "unavailable"})] * 2
    run.record_model_output(b"x")  # seq 4 fails: back-off 5 s again
    clock.now += 5.0
    run.record_model_output(b"x")  # seq 5: seq 4 fails again: back-off 10 s
    clock.now += 9.0
    run.record_model_output(b"x")  # seq 6: not yet
    assert run.delivery.status == "pending" and index.order()[-2:] == [4, 4]
    bundle = run.finish()  # the run_end turn ignores the back-off
    assert index.order()[-4:] == [4, 5, 6, 7] and run.delivery.status == "delivered"
    assert len(bundle.artifacts) == 8


def test_a_422_rejects_and_a_transport_failure_never_raises() -> None:
    index = Index()
    run = _run(index)
    index.script = [(422, {"code": "run_limit", "message": "full"})]
    run.record_model_output(b"x")
    run.record_model_output(b"x")
    run.finish()
    assert index.order() == ["control", 0, 1] and run.delivery.status == "rejected"
    assert (run.delivery.delivered, run.delivery.pending, run.delivery.error) == (2, 3, "seq 1: 422 run_limit")

    index = Index()
    run = _run(index)
    index.script = [httpx.ConnectError("refused")]
    run.record_model_output(b"x")
    assert run.delivery.status == "pending" and run.delivery.error == "seq 1: ConnectError: refused"
    run.finish()  # the last attempt delivers what is left
    assert run.delivery.status == "delivered" and not run.is_broken


def test_enforce_mode_still_raises_the_denial_while_the_index_is_down() -> None:
    index = Index()
    run = _enforced(index)
    index.script = [(503, {"code": "unavailable"})] * 10
    with pytest.raises(PolicyDenied):
        run.begin_tool_call("search.web", b"{}")
    assert not run.is_broken and not run.halted and run.delivery.status == "pending"
    run.finish()


def test_a_refused_policy_document_does_not_block_the_steps() -> None:
    index = Index()
    observe = _with_enforcement({**json.loads(DOC)["enforcement"], "mode": "observe"})
    index.script = [(422, {"code": "control_set_invalid", "message": "no"})]
    run = _run(index, control_set=AgentPolicy.control_set_from_document(observe), disclose_policy=True)
    run.finish()
    assert index.order() == ["control", "control", 0, 1]
    assert "controlSet" in index.uploads[0] and "controlSet" not in index.uploads[1]
    assert run.policy_disclosure.status == "failed" and "control_set_invalid" in run.policy_disclosure.error
    assert run.delivery.status == "delivered"


def test_concurrent_threads_and_an_event_recorded_inside_a_hook_stay_in_chain_order() -> None:
    index, box = Index(), [None]

    def hook(a: object) -> None:
        if a.step_type == "tool_call" and a.envelope["step"]["tool"]["name"] == "nested":
            box[0].record_model_output(b"from the hook")
    run = box[0] = _run(index, on_artifact_sealed=hook)
    threads = [threading.Thread(target=lambda i=i: run.record_tool_call("nested" if i % 5 == 0 else "t", b"{}"))
               for i in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    bundle = run.finish()
    assert index.order() == ["control", *range(len(bundle.artifacts))]


def test_catch_up_is_idempotent_works_on_a_partial_bundle_skips_evaluations_and_stops_at_a_failure() -> None:
    index = Index()
    run = _start(_client(index))
    run.record_model_output(b"x")
    bundle = run.finish()
    client = _client(index)
    first = client.deliver_agent_run(bundle)
    second = client.deliver_agent_run(bundle)
    assert first == second and first.__dict__ == {"status": "delivered", "delivered": 4, "pending": 0,
                                                  "run_id": "r-1", "error": None}
    assert index.order() == ["control", 0, 1, 2] * 2

    index.uploads.clear()
    partial = AgentRunBundle(bundle.correlation_id, None, [bundle.artifacts[2], bundle.artifacts[0]],
                             [bundle.artifacts[1]])  # an "evaluation" is never sent
    assert client.deliver_agent_run(partial).delivered == 2 and index.order() == [0, 2]

    index.uploads.clear()
    index.script = [(201, {"status": "indexed", "runId": "r-1"}), (503, {"code": "unavailable"})]
    stopped = client.deliver_agent_run(bundle)
    assert stopped.__dict__ == {"status": "pending", "delivered": 1, "pending": 3, "run_id": "r-1",
                                "error": "seq 0: 503 unavailable"}
    assert index.order() == ["control", 0]


def test_deliver_run_with_a_foreign_client_is_refused_before_anything_is_sealed() -> None:
    class Foreign:
        calls: list = []

        def sign_object_hashes(self, *a: object, **k: object) -> None:
            self.calls.append(a)
    foreign = Foreign()
    with pytest.raises(ValueError, match="^deliver_run requires a SigillClient"):
        _start(foreign, deliver_run=True)
    assert foreign.calls == []
    assert isinstance(_client(Index()), SigillClient)


def test_finish_on_a_halted_run_makes_one_last_attempt_past_the_back_off() -> None:
    index = Index()
    run = _enforced(index, _with_enforcement({**json.loads(DOC)["enforcement"], "haltAfterDenials": 1}))
    index.script = [(503, {"code": "unavailable"})] * 2  # the call's turn, then the halt's run_end turn
    with pytest.raises(PolicyDenied):
        run.begin_tool_call("search.web", b"{}")
    assert run.halted and run.delivery.status == "pending"
    run.finish()
    assert run.delivery.status == "delivered" and index.order()[-3:] == [1, 2, 3]
