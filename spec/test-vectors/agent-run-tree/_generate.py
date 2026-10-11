# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Reference generator for the Agent Delegation v1 run-tree vectors.

Deterministic: fixed identifiers, times and bytes. Signatures come from the stub signer of
../agent-run (README.md there), reused unchanged. Expected results are declared here, never
derived from an SDK: the tree verdict, every run's verdict, every edge's binding and
completion state, the finding codes, the open reasons and the tree fingerprint.

    pip install jcs
    python _generate.py
"""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
from pathlib import Path

import jcs

HERE = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("agent_run_vectors", HERE.parent / "agent-run" / "_generate.py")
ar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ar)

CERT_A, CERT_B, CERT_V, CTY = ar.CERT_A, ar.CERT_B, ar.CERT_V, ar.CTY
ACTIVITY = "pr-review"
AGENTS = {
    "review": "urn:example:agent:pr-review",
    "security": "urn:example:agent:security-reviewer",
    "tests": "urn:example:agent:test-runner",
}


def corr(n: int) -> str:
    return f"urn:uuid:00000000-0000-4000-a000-{n:012d}"


P, A, B, G, Q, X = corr(1), corr(2), corr(3), corr(4), corr(5), corr(6)


class Clock:
    """One clock for the whole tree, one second per sealed artifact, so every run's times are plausible."""

    def __init__(self):
        self.t = 0

    def tick(self) -> str:
        self.t += 1
        return f"2026-10-01T10:{self.t // 60:02d}:{self.t % 60:02d}.000Z"


def stamp(t: str) -> str:
    return t.replace(".000", "")


class Run:
    """Builds one run with the stub signer. Methods seal in call order, like a producer."""

    _ids = 0

    def __init__(self, clock: Clock, correlation: str, agent: str, *, parent: tuple | None = None,
                 version: str = "2", cert: bytes = CERT_A, start_binds: dict | None = None):
        self.clock, self.corr, self.agent, self.version, self.cert = clock, correlation, agent, version, cert
        self.arts: list = []
        self.payloads: dict = {}
        self.evaluations: list = []
        t = clock.tick()
        env = {
            "schemaName": "AgentControlArtifact", "schemaVersion": "1", "evidenceId": self._id(),
            "createdAt": t, "actor": {"type": "system", "id": "urn:example:harness:ci"},
            "activity": {"name": ACTIVITY, "correlationId": correlation},
            "agent": {"id": agent, "version": "1.0.0"},
            "controlSet": {"id": "ticket-close-v2", "version": "2"},
            "timestampPolicy": ar.POLICY,
            "objects": ar.objects_block(ar.CONTROL_OBJS),
        }
        self.control = ar.artifact(env, ar.CONTROL_OBJS, CTY["control"], stamp_at=stamp(t), cert=cert)
        binds = {"controlArtifactSignatureSha256": ar.signature_sha256(self.control["signature"])}
        if parent is not None:
            binds["parentDelegationSignatureSha256"], binds["parentCorrelationId"] = parent
        if start_binds is not None:
            binds.update(start_binds)
        self.seal("run_start", objs=[("model-input", "text/plain", f"review request for {correlation}".encode())],
                  binds=binds)

    def _id(self) -> str:
        Run._ids += 1
        return ar.uuid(5000 + Run._ids)

    def seal(self, step_type: str, *, fields: dict | None = None, objs=(), binds: dict | None = None,
             stamped: bool = False, version: str | None = None) -> dict:
        seq = len(self.arts)
        t = self.clock.tick()
        uris = [(f"urn:example:obj:{self.corr[-4:]}-s{seq}-{role}", role, ctype, data) for role, ctype, data in objs]
        step = {"type": step_type, "eventTime": t, "consequential": False, "timestamp": "required" if stamped else "none"}
        step.update(copy.deepcopy(fields or {}))
        env = {
            "schemaName": "AgentExecutionEvidence", "schemaVersion": version or self.version, "evidenceId": self._id(),
            "createdAt": t, "actor": {"type": "agent", "id": self.agent, "version": "1.0.0"},
            "activity": {"name": ACTIVITY, "correlationId": self.corr},
            "chain": {"seq": seq}, "step": step, "objects": ar.objects_block(uris),
        }
        if seq > 0:
            env["chain"]["prevSignatureSha256"] = ar.signature_sha256(self.arts[-1]["signature"])
        if step_type == "run_end":
            step["finalSeq"] = seq
            step["finalPrevSignatureSha256"] = env["chain"]["prevSignatureSha256"]
        if binds is not None:
            env["binds"] = binds
        for uri, _, _, data in uris:
            self.payloads[uri] = data
        a = ar.artifact(env, uris, CTY["event"], stamp_at=stamp(t) if stamped else None, cert=self.cert)
        self.arts.append(a)
        return a

    def tool(self, name: str = "read_diff") -> None:
        self.seal("tool_call", fields={"tool": {"name": name, "operation": "read"}},
                  objs=[("tool-arguments", "application/json", b'{"path":"src/"}')])

    def delegate(self, child: str, agent: str) -> tuple:
        a = self.seal("delegation", fields={"delegation": {"childCorrelationId": child, "childAgentId": agent,
                                                            "useId": f"toolu_{child[-4:]}"}},
                      objs=[("delegation-input", "text/plain", f"instruction for {child}".encode())])
        return ar.signature_sha256(a["signature"]), self.corr

    def result(self, child: "Run | str", *, run_end_sig: str | None = None, disposition: str | None = None) -> None:
        cid = child if isinstance(child, str) else child.corr
        sig = run_end_sig or (None if isinstance(child, str) else child.run_end_sig)
        disp = disposition or (None if isinstance(child, str) else child.disposition)
        self.seal("delegation_result", fields={"delegation": {"childCorrelationId": cid,
                                                              "childRunEndSignatureSha256": sig,
                                                              "childDisposition": disp}})

    def end(self, disposition: str = "completed") -> "Run":
        self.seal("run_end", fields={"runDisposition": disposition}, stamped=True)
        return self

    @property
    def run_end_sig(self) -> str:
        assert self.arts[-1]["envelope"]["step"]["type"] == "run_end"
        return ar.signature_sha256(self.arts[-1]["signature"])

    @property
    def disposition(self) -> str:
        return self.arts[-1]["envelope"]["step"]["runDisposition"]

    def evaluate(self) -> None:
        cs = next(o for o in ar.CONTROL_OBJS if o[1] == "control-set")
        bl = next(o for o in ar.CONTROL_OBJS if o[1] == "baseline-state")
        objs = [(f"urn:example:obj:{self.corr[-4:]}-observed", "observed-state", "application/json", b'{"ok":true}'),
                (cs[0], "control-set", cs[2], cs[3]), (bl[0], "baseline-state", bl[2], bl[3])]
        t = self.clock.tick()
        env = {
            "schemaName": "ControlEvaluation", "schemaVersion": "1", "evidenceId": self._id(), "createdAt": t,
            "actor": {"type": "verifier", "id": "urn:example:verifier:review-state", "version": "1.0.0"},
            "activity": {"name": ACTIVITY, "correlationId": self.corr},
            "subject": {"runEndSignatureSha256": self.run_end_sig,
                        "controlArtifactSignatureSha256": ar.signature_sha256(self.control["signature"])},
            "controlSet": {"id": "ticket-close-v2", "version": "2"},
            "controls": [{"id": "ticket-closed", "result": "PASS"}],
            "overall": "PASS", "evaluatedAt": t, "objects": ar.objects_block(objs),
        }
        self.evaluations.append(ar.artifact(env, objs, CTY["evaluation"], stamp_at=stamp(t), cert=CERT_V))

    def bundle(self) -> dict:
        b = {"format": "AgentRunBundle", "bundleVersion": "1", "correlationId": self.corr,
             "controlArtifact": self.control, "artifacts": self.arts}
        if self.evaluations:
            b["evaluations"] = self.evaluations
        return b


def tree(runs: list, root_hint: str | None = P) -> dict:
    return {"format": "AgentRunTreeBundle", "bundleVersion": "1", "rootCorrelationId": root_hint,
            "runs": [r.bundle() if isinstance(r, Run) else r for r in runs]}


def utf16(s: str) -> bytes:
    """§6.8 order: unsigned UTF-16 code units (big-endian bytes compare the same way), not code points."""
    return s.encode("utf-16-be")


def tree_fingerprint(t: dict, root: str | None) -> str | None:
    """§6.8, with the root declared by the scenario."""
    if root is None:
        return None
    runs = []
    for b in t["runs"]:
        f = ar.fingerprint(b)
        if f is None:
            return None
        start = next(a for a in b["artifacts"] if a["envelope"]["step"]["type"] == "run_start")
        runs.append({"c": start["envelope"]["activity"]["correlationId"], "f": f})
    runs.sort(key=lambda r: (utf16(r["c"]), utf16(r["f"])))
    return ar.sha256hex(jcs.canonicalize({"format": "AgentRunTreeBundle", "bundleVersion": "1", "root": root, "runs": runs}))


def edge(parent, child, binding, completion):
    return {"parent": parent, "child": child, "binding": binding, "completion": completion}


def scenario(name, description, t, verdict, *, runs=None, edges=(), findings=(), open_reasons=(), root=P,
             options=None, affiliations=None):
    expected = {
        "verdict": verdict,
        "root": root,
        "runs": runs or {},
        "edges": sorted(edges, key=lambda e: (e["parent"], e["child"], e["binding"])),
        "findings": sorted(set(findings)),
        "openReasons": sorted(set(open_reasons)),
        "fingerprint": None if "limit_exceeded" in findings else tree_fingerprint(t, root),
    }
    if affiliations:
        expected["affiliations"] = affiliations
    v = {"description": description, "tree": t, "expected": expected}
    if options:
        v["options"] = options
    path = HERE / "trees" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(v, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def thumb(cert: bytes) -> str:
    return ar.signer_header(cert)["x5t#S256"]


# ── Scenarios ───────────────────────────────────────────────────────────────

def finalized_two_children():
    c = Clock()
    p = Run(c, P, AGENTS["review"])
    p.tool()
    a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"]))
    b = Run(c, B, AGENTS["tests"], parent=p.delegate(B, AGENTS["tests"]))
    a.tool("repo.read_file"); b.tool("run_tests")
    a.end(); b.end()
    p.result(a); p.result(b)
    p.seal("model_output", objs=[("model-output", "text/plain", b"LGTM with two notes.")])
    p.end()
    return c, p, a, b


def main() -> None:
    for old in (HERE / "trees").glob("*.json"):
        old.unlink()
    FIN = {P: "run_finalized", A: "run_finalized", B: "run_finalized"}
    BOUND = [edge(P, A, "mutually_bound", "result_bound"), edge(P, B, "mutually_bound", "result_bound")]

    # 1. States
    _, p, a, b = finalized_two_children()
    scenario("01-finalized", "A root delegates to two children; both close, both results are bound. Three anchors: each run's run_end.",
             tree([p, a, b]), "tree_finalized", runs=FIN, edges=BOUND)
    scenario("70-reordered", "01 with runs[] reversed and no root hint: identical result and fingerprint (the order is not signed).",
             tree([b, a, p], root_hint=None), "tree_finalized", runs=FIN, edges=BOUND)

    c = Clock(); p = Run(c, P, AGENTS["review"]); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"])); a.tool()
    scenario("02-child-open", "The child is still running and the parent waits: open, not invalid.",
             tree([p, a]), "tree_open", runs={P: "run_open", A: "run_open"},
             edges=[edge(P, A, "mutually_bound", "no_result")], open_reasons=["run_open", "delegation_pending"])

    c = Clock(); p = Run(c, P, AGENTS["review"]); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"])); a.end()
    scenario("03-child-closed-no-result-yet", "The child closed; the parent has not recorded the result yet.",
             tree([p, a]), "tree_open", runs={P: "run_open", A: "run_finalized"},
             edges=[edge(P, A, "mutually_bound", "no_result")], open_reasons=["run_open", "delegation_pending"])

    c = Clock(); p = Run(c, P, AGENTS["review"]); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"])); a.end(); p.end()
    scenario("04-completed-with-unresolved", "The parent closed 'completed' without the child's result (§4 rule 5).",
             tree([p, a]), "tree_invalid", runs={P: "run_finalized", A: "run_finalized"},
             edges=[edge(P, A, "mutually_bound", "no_result")])

    c = Clock(); p = Run(c, P, AGENTS["review"]); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"])); a.tool(); p.end("aborted")
    scenario("05-aborted-with-unresolved", "The parent aborted while the child ran: open with 'parent terminated', never finalized.",
             tree([p, a]), "tree_open", runs={P: "run_finalized", A: "run_open"},
             edges=[edge(P, A, "mutually_bound", "no_result")], open_reasons=["run_open", "parent_terminated"])

    _, p, a, b = finalized_two_children()
    scenario("06-withheld-child", "Child B is left out of the bundle, but the parent recorded its result: withheld evidence.",
             tree([p, a]), "tree_invalid", runs={P: "run_finalized", A: "run_finalized"},
             edges=[edge(P, A, "mutually_bound", "result_bound"), edge(P, B, "child_missing", "result_unresolved")])

    c = Clock(); p = Run(c, P, AGENTS["review"]); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"])); a.end("failed"); p.result(a); p.end()
    scenario("07-child-failed", "The child failed and the parent recorded that: the record is complete, so the tree is finalized.",
             tree([p, a]), "tree_finalized", runs={P: "run_finalized", A: "run_finalized"},
             edges=[edge(P, A, "mutually_bound", "result_bound")])

    # 2. Structure
    c = Clock(); p = Run(c, P, AGENTS["review"]); p.result(X, run_end_sig="ab" * 32, disposition="completed"); p.end()
    scenario("10-orphan-result", "A result for a child the run never delegated to.",
             tree([p]), "tree_invalid", runs={P: "run_finalized"}, findings=["orphan_result"])

    c = Clock(); p = Run(c, P, AGENTS["review"]); p.result(A, run_end_sig="ab" * 32, disposition="completed")
    a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"])); a.end(); p.end("aborted")
    scenario("11-result-before-delegation", "The result for A is sealed before A's delegation.",
             tree([p, a]), "tree_invalid", runs={P: "run_finalized", A: "run_finalized"},
             edges=[edge(P, A, "mutually_bound", "no_result")], findings=["result_before_delegation"])

    c = Clock(); p = Run(c, P, AGENTS["review"]); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"])); a.end()
    p.result(a); p.result(a); p.end()
    scenario("12-duplicate-result", "Two results for one delegation.",
             tree([p, a]), "tree_invalid", runs={P: "run_finalized", A: "run_finalized"},
             edges=[edge(P, A, "mutually_bound", "result_bound")], findings=["duplicate_result"])

    _, p, a, b = finalized_two_children()
    scenario("13-duplicate-run", "Child A is supplied twice.",
             tree([p, a, b, a]), "tree_invalid", runs={P: "run_finalized", A: "run_finalized", B: "run_finalized"},
             edges=BOUND, findings=["duplicate_run"])

    _, p, a, b = finalized_two_children()
    scenario("14-no-root", "Only the children are supplied: no root, and both name a parent that is not there.",
             tree([a, b], root_hint=None), "tree_invalid", runs={A: "run_finalized", B: "run_finalized"},
             edges=[edge(P, A, "parent_missing", "no_result"), edge(P, B, "parent_missing", "no_result")],
             findings=["no_root"], root=None)

    _, p, a, b = finalized_two_children()
    c = Clock(); q = Run(c, Q, AGENTS["review"]).end()
    scenario("15-two-roots", "An unrelated root run is added.",
             tree([p, a, b, q]), "tree_invalid", runs={**FIN, Q: "run_finalized"}, edges=BOUND,
             findings=["multiple_roots"], root=None)

    _, p, a, b = finalized_two_children()
    c = Clock(); x = Run(c, X, AGENTS["tests"], parent=("cd" * 32, corr(99))).end()
    scenario("16-disconnected-run", "A run bound to a parent outside the tree is added: unreachable, and its parent is missing.",
             tree([p, a, b, x]), "tree_invalid", runs={**FIN, X: "run_finalized"},
             edges=BOUND + [edge(corr(99), X, "parent_missing", "no_result")], findings=["unreachable_run"])

    c = Clock(); p = Run(c, P, AGENTS["review"]); p.delegate(P, AGENTS["review"]); p.end("aborted")
    scenario("17-self-delegation", "A run declares itself as its own child.",
             tree([p]), "tree_invalid", runs={P: "run_finalized"},
             edges=[edge(P, P, "unbound", "no_result")], findings=["self_delegation"])

    c = Clock()
    a = Run(c, A, AGENTS["security"], parent=("11" * 32, B)).end()
    b = Run(c, B, AGENTS["tests"], parent=("22" * 32, A)).end()
    scenario("18-cycle", "Two runs name each other as parent: no root, and a cycle.",
             tree([a, b], root_hint=None), "tree_invalid", runs={A: "run_finalized", B: "run_finalized"},
             edges=[edge(B, A, "unbound", "no_result"), edge(A, B, "unbound", "no_result")],
             findings=["no_root", "cycle"], root=None)

    c = Clock(); p = Run(c, P, AGENTS["review"])
    a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"]))
    b = Run(c, B, AGENTS["tests"], parent=p.delegate(B, AGENTS["tests"]))
    x = Run(c, X, AGENTS["tests"], parent=a.delegate(X, AGENTS["tests"]))
    b.delegate(X, AGENTS["tests"])
    x.end(); a.result(x); a.end(); b.end("aborted"); p.result(a); p.result(b); p.end()
    scenario("19-child-two-parents", "Two different runs declare the same child.",
             tree([p, a, b, x]), "tree_invalid",
             runs={P: "run_finalized", A: "run_finalized", B: "run_finalized", X: "run_finalized"},
             edges=[edge(P, A, "mutually_bound", "result_bound"), edge(P, B, "mutually_bound", "result_bound"),
                    edge(A, X, "mutually_bound", "result_bound"), edge(B, X, "unbound", "no_result")],
             findings=["child_two_parents"])

    c = Clock(); p = Run(c, P, AGENTS["review"])
    a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"])); p.delegate(A, AGENTS["security"])
    a.end(); p.result(a); p.end("aborted")
    scenario("20-duplicate-delegation", "One parent declares the same child twice.",
             tree([p, a]), "tree_invalid", runs={P: "run_finalized", A: "run_finalized"},
             edges=[edge(P, A, "mutually_bound", "result_bound"), edge(P, A, "unbound", "result_bound")],
             findings=["duplicate_delegation"])

    # 3. Binding
    c = Clock(); p = Run(c, P, AGENTS["review"]); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"])); a.end(); p.result(a); p.end()
    c2 = Clock(); q = Run(c2, Q, AGENTS["review"]); q.delegate(A, AGENTS["security"]); q.result(a); q.end()
    scenario("30-delegation-replayed", "Child A, delegated by P, is presented under a new parent Q that declares it too.",
             tree([q, a], root_hint=Q), "tree_invalid", runs={Q: "run_finalized", A: "run_finalized"},
             edges=[edge(Q, A, "unbound", "result_bound"), edge(P, A, "parent_missing", "no_result")], root=Q)

    c = Clock(); p = Run(c, P, AGENTS["review"]); sig, _ = p.delegate(A, AGENTS["security"])
    a = Run(c, A, AGENTS["security"], parent=(sig, corr(98))).end(); p.result(a); p.end()
    scenario("31-wrong-parent-correlation", "The child references the right delegation signature but another parent correlationId.",
             tree([p, a]), "tree_invalid", runs={P: "run_finalized", A: "run_finalized"},
             edges=[edge(P, A, "unbound", "result_bound"), edge(corr(98), A, "parent_missing", "no_result")])

    c = Clock(); p = Run(c, P, AGENTS["review"]); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"]))
    a.delegate(G, AGENTS["tests"]); g = Run(c, G, AGENTS["tests"], parent=("ef" * 32, A)).end()
    a.result(g); a.end(); p.result(a); p.end()
    scenario("32-broken-grandchild", "A sound child edge with a broken grandchild edge beneath it.",
             tree([p, a, g]), "tree_invalid", runs={P: "run_finalized", A: "run_finalized", G: "run_finalized"},
             edges=[edge(P, A, "mutually_bound", "result_bound"), edge(A, G, "unbound", "result_bound")])

    c = Clock(); p = Run(c, P, AGENTS["review"]); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["tests"])); a.end(); p.result(a); p.end()
    scenario("33-agent-mismatch", "The parent delegated to the test runner; the child is the security reviewer.",
             tree([p, a]), "tree_invalid", runs={P: "run_finalized", A: "run_finalized"},
             edges=[edge(P, A, "unbound", "result_bound")], findings=["agent_mismatch"])

    c = Clock(); p = Run(c, P, AGENTS["review"]); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"])); a.end()
    p.result(A, run_end_sig="01" * 32, disposition="completed"); p.end()
    scenario("34-result-wrong-run-end", "The result names another run_end than the child's.",
             tree([p, a]), "tree_invalid", runs={P: "run_finalized", A: "run_finalized"},
             edges=[edge(P, A, "mutually_bound", "result_mismatch")])

    c = Clock(); p = Run(c, P, AGENTS["review"]); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"])); a.end("failed")
    p.result(A, run_end_sig=a.run_end_sig, disposition="completed"); p.end()
    scenario("35-result-wrong-disposition", "The child failed; the parent's result says completed.",
             tree([p, a]), "tree_invalid", runs={P: "run_finalized", A: "run_finalized"},
             edges=[edge(P, A, "mutually_bound", "result_mismatch")])

    # 4. Run level
    _, p, a, b = finalized_two_children()
    a.arts[1]["envelope"]["step"]["tool"]["name"] = "repo.write_file"  # edited after sealing
    scenario("40-child-edited", "One of child A's events is edited after sealing: A is invalid, so the tree is.",
             tree([p, a, b]), "tree_invalid", runs={P: "run_finalized", A: "run_invalid", B: "run_finalized"}, edges=BOUND)

    c = Clock(); p = Run(c, P, AGENTS["review"]); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"]))
    a.seal("tool_call", fields={"tool": {"name": "repo.read_file", "operation": "read"}}, version="1",
           objs=[("tool-arguments", "application/json", b'{"path":"README.md"}')])
    a.end(); p.result(a); p.end()
    scenario("41-mixed-versions", "Child A seals one event as schemaVersion 1 inside a version 2 run.",
             tree([p, a]), "tree_invalid", runs={P: "run_finalized", A: "run_invalid"},
             edges=[edge(P, A, "mutually_bound", "result_bound")])

    c = Clock(); p = Run(c, P, AGENTS["review"], version="1"); a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"])); a.end(); p.result(a); p.end()
    scenario("42-v1-root-delegates", "The root delegates under schemaVersion 1, which has no delegation steps.",
             tree([p, a]), "tree_invalid", runs={P: "run_invalid", A: "run_finalized"},
             edges=[edge(P, A, "mutually_bound", "result_bound")])

    # 5. Attribution
    _, p, a, b = finalized_two_children()
    scenario("50-unexpected-root", "The relying party expected another root.",
             tree([p, a, b]), "tree_invalid", runs=FIN, edges=BOUND, findings=["unexpected_root"],
             options={"expectedRootCorrelationId": Q})
    scenario("51-expected-signer-met", "An attribution policy names the producer's certificate for all three agents.",
             tree([p, a, b]), "tree_finalized", runs=FIN, edges=BOUND,
             options={"expectedRootCorrelationId": P, "expectedSigners": {v: [thumb(CERT_A)] for v in AGENTS.values()}},
             affiliations={P: "confirmed", A: "confirmed", B: "confirmed"})

    c = Clock(); p = Run(c, P, AGENTS["review"])
    a = Run(c, A, AGENTS["security"], parent=p.delegate(A, AGENTS["security"]), cert=CERT_B); a.end(); p.result(a); p.end()
    scenario("52-expected-signer-not-met", "Child A is signed by another certificate than the policy expects for its agent.",
             tree([p, a]), "tree_invalid", runs={P: "run_finalized", A: "run_invalid"},
             edges=[edge(P, A, "mutually_bound", "result_bound")],
             options={"expectedSigners": {AGENTS["security"]: [thumb(CERT_A)]}},
             affiliations={P: "unknown", A: "mismatch"})

    # 6. Not covered by the anchor
    _, p, a, b = finalized_two_children()
    a.evaluate()
    scenario("60-later-evaluation", "01 plus a Control Evaluation on child A: same verdict, different fingerprint.",
             tree([p, a, b]), "tree_finalized", runs=FIN, edges=BOUND)

    # 8. Limits
    def chain(depth: int):
        c = Clock()
        ids = [corr(100 + i) for i in range(depth + 1)]
        runs = [Run(c, ids[0], AGENTS["review"])]
        for i in range(1, depth + 1):
            runs.append(Run(c, ids[i], AGENTS["review"], parent=runs[-1].delegate(ids[i], AGENTS["review"])))
        for i in range(depth, 0, -1):
            runs[i].end()
            runs[i - 1].result(runs[i])
        runs[0].end()
        return ids, runs

    ids, runs = chain(8)
    scenario("80-depth-8", "A chain of delegations 8 levels deep: at the limit.", tree(runs, root_hint=ids[0]),
             "tree_finalized", runs={i: "run_finalized" for i in ids},
             edges=[edge(ids[i - 1], ids[i], "mutually_bound", "result_bound") for i in range(1, 9)], root=ids[0])
    ids, runs = chain(9)
    scenario("81-depth-9", "9 levels deep: over the limit; verification stops.", tree(runs, root_hint=ids[0]),
             "tree_invalid", findings=["limit_exceeded"], root=ids[0])

    c = Clock(); single = Run(c, P, AGENTS["review"]).bundle()
    scenario("82-runs-257", "257 runs: over the limit; verification stops before any run is checked.",
             tree([single] * 257), "tree_invalid", findings=["limit_exceeded"], root=None)


    # 7b. Order of the fingerprint (§6.8): UTF-16 code units, not code points. U+10000 is the surrogate
    # pair D800 DC00, so it sorts BEFORE U+E000 by code units but AFTER it by code points.
    UP, UA, UB = "urn:example:run:\ue000", "urn:example:run:\U00010000", "urn:example:run:z"
    assert sorted([UP, UA]) != sorted([UP, UA], key=utf16)
    c = Clock(); p = Run(c, UP, AGENTS["review"])
    a = Run(c, UA, AGENTS["security"], parent=p.delegate(UA, AGENTS["security"]))
    b = Run(c, UB, AGENTS["tests"], parent=p.delegate(UB, AGENTS["tests"]))
    a.end(); b.end(); p.result(a); p.result(b); p.end()
    scenario("71-utf16-order", "Correlation ids with U+E000 and U+10000, supplied out of order: the fingerprint sorts by "
             "UTF-16 code units, where U+10000 precedes U+E000.", tree([b, p, a], root_hint=None), "tree_finalized",
             runs={UP: "run_finalized", UA: "run_finalized", UB: "run_finalized"},
             edges=[edge(UP, UA, "mutually_bound", "result_bound"), edge(UP, UB, "mutually_bound", "result_bound")],
             root=UP)

if __name__ == "__main__":
    main()
