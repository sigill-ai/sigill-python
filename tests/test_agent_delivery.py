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
RID = "0e0e0e0e-0000-4000-8000-000000000001"


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
        answer = self.script.pop(0) if self.script else None  # None: the ordinary answer
        if answer is not None:
            if isinstance(answer, Exception):
                raise answer
            status, payload = answer
            return httpx.Response(status, json=payload) if isinstance(payload, dict) else \
                httpx.Response(status, text=payload, headers={"content-type": "text/html"})
        key = body["envelope"]["evidenceId"]
        new = key not in self.held
        self.held.add(key)
        return httpx.Response(201 if new else 200, json={"status": "indexed" if new else "exists", "runId": RID,
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
        assert "controlSet" not in u and 9.0 < u["_timeout"] <= 10.0
    assert run.delivery.__dict__ == {"status": "delivered", "delivered": 7, "pending": 0, "run_id": RID,
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
    assert run.policy_disclosure.succeeded and run.policy_disclosure.run_id == RID


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
    assert run.delivery.status == "pending" and run.delivery.error == "seq 1: ConnectError"
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
    assert run.policy_disclosure.status == "failed"
    assert run.policy_disclosure.error == "control artifact: 422 control_set_invalid"
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
                                                  "run_id": RID, "error": None}
    assert index.order() == ["control", 0, 1, 2] * 2

    index.uploads.clear()
    partial = AgentRunBundle(bundle.correlation_id, None, [bundle.artifacts[2], bundle.artifacts[0]],
                             [bundle.artifacts[1]])  # an "evaluation" is never sent
    assert client.deliver_agent_run(partial).delivered == 2 and index.order() == [0, 2]

    index.uploads.clear()
    index.script = [(201, {"status": "indexed", "runId": RID}), (503, {"code": "unavailable"})]
    stopped = client.deliver_agent_run(bundle)
    assert stopped.__dict__ == {"status": "pending", "delivered": 1, "pending": 3, "run_id": RID,
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


# ── What counts as accepted, the budgets, untrusted answers ─────────────────

@pytest.mark.parametrize("answer", [
    (200, "<html>Sign in to continue</html>"), (204, ""), (202, {"status": "queued"}),
    (200, {"code": "rejected", "message": "not stored"}), (201, {"status": "indexed", "runId": "../../x"}),
    (201, {"status": "indexed"}), (200, {"status": "stored", "runId": RID}),
])
def test_only_an_answer_that_accepts_the_artifact_counts(answer: tuple) -> None:
    index = Index()
    run = _run(index)
    index.script = [answer]
    run.record_retrieval(b"r")
    run.finish()
    assert run.delivery.__dict__ == {"status": "rejected", "delivered": 2, "pending": 2, "run_id": RID,
                                     "error": f"seq 1: {answer[0]} unexpected_response"}


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_a_redirect_is_not_followed_and_rejects(status: int) -> None:
    index, elsewhere = Index(), []

    def transport(request: httpx.Request) -> httpx.Response:
        if request.url.host != "api.example":
            elsewhere.append(request)
            return httpx.Response(201, json={"status": "indexed", "runId": RID})
        if request.url.path == INDEX:
            return httpx.Response(status, headers={"Location": "https://elsewhere.example/steal"})
        return index(request)
    run = _start(_client(transport), deliver_run=True, _index_clock=Clock())
    assert run.delivery.status == "rejected" and run.delivery.error == f"control artifact: {status} unexpected_response"
    assert _client(transport).deliver_agent_run(run.to_bundle()).status == "rejected"
    assert elsewhere == []


def test_disclosure_follows_the_same_rule() -> None:
    index = Index()
    index.script = [(200, "<html></html>")]
    run = _start(_client(index), control_set=AgentPolicy.control_set_from_document(V11), disclose_policy=True)
    assert (run.policy_disclosure.status, run.policy_disclosure.error) == ("failed", "200 unexpected_response")
    index.script = [(200, "<html></html>")]
    observe = _with_enforcement({**json.loads(DOC)["enforcement"], "mode": "observe"})
    run = _run(index, control_set=AgentPolicy.control_set_from_document(observe), disclose_policy=True)
    assert run.policy_disclosure.error == "control artifact: 200 unexpected_response"


def test_the_status_is_derived_inside_a_hook_and_after_an_unreadable_answer() -> None:
    seen, box = [], [None]
    run = box[0] = _run(Index(), on_artifact_sealed=lambda a: seen.append(box[0].delivery)
                        if a.step_type == "model_output" else None)
    run.record_model_output(b"x")
    assert (seen[0].status, seen[0].pending) == ("pending", 1), "sealed, not yet delivered"
    assert run.delivery.status == "delivered"

    index, clock = Index(), Clock()
    run = _run(index, clock)
    index.script = [(503, "[" * 60_000), (200, "[" * 60_000)]  # nested too deep to parse, within 64 KiB
    run.record_retrieval(b"r")
    assert (run.delivery.status, run.delivery.pending, run.delivery.error) == ("pending", 1, "seq 1: 503")
    assert _client(index).deliver_agent_run(run.to_bundle()).status == "rejected"  # a 200 that does not parse
    index.script = [(503, "<html>" + "x" * 100 * 1024 + "</html>")]  # over 64 KiB: the status still decides
    clock.now += 5.0
    run.record_retrieval(b"r")
    assert (run.delivery.status, run.delivery.error) == ("pending", "seq 1: 503")


class SlowIndex(Index):
    """Each upload costs ``cost`` seconds of the injected clock."""

    def __init__(self, clock: Clock, cost: float) -> None:
        super().__init__()
        self.clock, self.cost = clock, cost

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == INDEX:
            self.clock.now += self.cost
        return super().__call__(request)


def test_every_turn_has_a_total_budget() -> None:
    clock = Clock()
    index = SlowIndex(clock, 0.0)
    run = _run(index, clock)
    index.script = [(503, {"code": "unavailable"})]
    for _ in range(40):
        run.record_model_output(b"x")  # a backlog of 40 within the back-off
    clock.now += 6
    index.cost = 4.0
    t0 = clock.now
    run.record_model_output(b"x")  # one ordinary call: its uploads share 10 s
    assert clock.now - t0 <= 10.0 + 4.0 and run.delivery.status == "pending"
    assert run.delivery.error.endswith(": time budget used up")
    t0 = clock.now
    run.finish()  # the final turn: 30 s, then the rest stays pending
    assert clock.now - t0 <= 30.0 + 4.0
    assert run.delivery.status == "pending" and run.delivery.pending > 0
    assert run.delivery.error.endswith(": time budget used up")


def test_server_strings_never_reach_the_error() -> None:
    index = Index()
    run = _run(index)
    index.script = [(422, {"code": "x\r\n\x1b[2K" + "A" * 100_000, "message": "status=delivered"})]
    run.record_retrieval(b"r")
    assert run.delivery.error == "seq 1: 422"  # no usable code: the status alone
    index = Index()
    run = _run(index)
    index.script = [httpx.ConnectError("refused by 10.0.0.1 secret-host")]
    run.record_retrieval(b"r")
    assert run.delivery.error == "seq 1: ConnectError"


class RawServer:
    """A local HTTP server on a socket: ``answer(conn)`` writes the response."""

    def __init__(self, answer) -> None:  # noqa: ANN001
        import socket
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}"
        self.answer = answer
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                data = b""
                while b"\r\n\r\n" not in data:
                    data += conn.recv(65536)
                head, _, body = data.partition(b"\r\n\r\n")
                length = next((int(x.split(b":")[1]) for x in head.split(b"\r\n")
                               if x.lower().startswith(b"content-length:")), 0)
                while len(body) < length:
                    body += conn.recv(65536)
                self.answer(conn)
            except OSError:
                pass
            finally:
                conn.close()


def test_a_trickling_index_is_cut_off_at_the_deadline() -> None:
    import time

    def trickle(conn) -> None:  # noqa: ANN001
        conn.sendall(b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 4000\r\n\r\n")
        for _ in range(20):  # one byte every 0.5 s: each read is well inside a per-read timeout
            time.sleep(0.5)
            conn.sendall(b" ")
    server = RawServer(trickle)
    run = _start(_client(Index()))
    started = time.monotonic()
    with SigillClient("k", base_url=server.url) as client:  # closed: no socket is left open
        answer = client._index_send(run.control_artifact, None, 1.0)
    assert time.monotonic() - started < 2.5
    assert (answer.outcome, answer.error) == ("pending", "TimeoutError")


def test_a_body_over_64_kib_is_not_read_on() -> None:
    def big(conn) -> None:  # noqa: ANN001
        conn.sendall(b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 52428800\r\n\r\n")
        for _ in range(50):
            conn.sendall(b" " * (1024 * 1024))
    server = RawServer(big)
    run = _start(_client(Index()))
    with SigillClient("k", base_url=server.url) as client:
        answer = client._index_send(run.control_artifact, None, 10.0)
    assert (answer.outcome, answer.error) == ("rejected", "201 unexpected_response")


def test_an_index_that_never_answers_costs_one_attempt_until_the_back_off_passes() -> None:
    index = Index()
    run = _run(index)
    index.script = [httpx.ReadTimeout("no answer")] * 10
    before = len(index.uploads)
    for _ in range(4):
        run.record_model_output(b"x")
    assert len(index.uploads) - before == 1 and run.delivery.error == "seq 1: ReadTimeout"


def test_an_attempt_cut_short_by_the_turn_budget_starts_no_back_off() -> None:
    clock = Clock()
    index = SlowIndex(clock, 0.0)
    run = _run(index, clock)
    index.script = [(503, {"code": "unavailable"})]
    run.record_model_output(b"x")  # seq 1 held
    run.record_model_output(b"x")  # seq 2 held (back-off)
    clock.now += 5.0
    index.cost, index.script = 7.0, [None, httpx.ReadTimeout("cut")]
    run.record_model_output(b"x")  # seq 1 delivered (7 s), seq 2 gets the 3 s left and times out
    assert run.delivery.error == "seq 2: time budget used up" and run.delivery.pending == 2
    index.cost = 0.0
    run.record_model_output(b"x")  # no back-off: the next turn goes on at once
    assert run.delivery.status == "delivered"


@pytest.mark.parametrize("status", [307, 308])
def test_a_redirect_is_not_followed_even_by_a_client_that_follows_redirects(status: int) -> None:
    other = RawServer(lambda conn: conn.sendall(
        b'HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 64\r\n\r\n'
        b'{"status":"indexed","runId":"0e0e0e0e-0000-4000-8000-000000000001"}'))
    received: list = []
    other.answer = lambda conn, f=other.answer: (received.append(1), f(conn))
    server = RawServer(lambda conn: conn.sendall(b"HTTP/1.1 %d Moved\r\nLocation: %s/steal\r\nContent-Length: 0\r\n\r\n"
                                                 % (status, other.url.encode())))
    http = httpx.Client(base_url=server.url, follow_redirects=True, timeout=5)
    run = _start(_client(Index()))
    with http:
        answer = SigillClient("k", http_client=http)._index_send(run.control_artifact)
    assert (answer.outcome, answer.error) == ("rejected", f"{status} unexpected_response") and received == []


def test_with_the_real_clock_an_index_that_never_answers_costs_one_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    from sigill_sdk import _agent_run
    monkeypatch.setattr(_agent_run, "_INDEX_TIMEOUT", 0.3)
    monkeypatch.setattr(_agent_run, "_INDEX_TURN_BUDGET", 0.3)
    index = Index()
    run = _start(_client(index), deliver_run=True, _index_clock=time.monotonic)
    index.script = [httpx.ReadTimeout("no answer")] * 10
    before = len(index.uploads)
    for _ in range(4):
        run.record_model_output(b"x")
    assert len(index.uploads) - before == 1, "the first attempt had the full limit: a back-off runs"
    assert run.delivery.error == "seq 1: ReadTimeout" and run._index.backoff > 0
