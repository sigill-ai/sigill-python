# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""The enforcement comparison (``spec/control-evaluation-v3.md`` §4–§6): for each event of a run under a v2 control
set, what the control set required the guard to do against what the chain records. It reads typed envelope fields and
signed object digests only — never payload content — so it works on what an evidence index holds.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Mapping, Optional, Sequence

from sigill_sdk._agent_guard import _configuration_locked, _due
from sigill_sdk._agent_policy import AgentPolicy, _build_facts, _is_record, _parse
from sigill_sdk._agent_profiles import CONTROL_EVALUATION_SCHEMA_V3, _int, _obj, _str
from sigill_sdk._agent_types import AgentRunArtifact
from sigill_sdk._policy_engine import PolicyEngineError
from sigill_sdk._schema import profile_schema, validate
from sigill_sdk._canonical import hash_bytes

_CHAIN_FINDINGS = ("executed_after_denial", "misplaced_decision", "unrecorded_halt", "duplicate_use_id",
                   "continued_after_halt", "evidence_version_mismatch")  # §5.1 reason 1
_LET_THROUGH = ("refusal_missing", "unknown_tool_allowed", "configuration_not_enforced", "halt_missing")
_OVER_ENFORCED = ("unfounded_record", "unfounded_halt", "reason_mismatch", "rules_mismatch")
_FINDINGS = _LET_THROUGH + _OVER_ENFORCED  # the order of §5.5's table
_RESULTS = ("let_through", "over_enforced", "not_checkable", "pending")  # §6: the first that is some outcome


def _step(e: dict) -> dict:
    return _obj(e.get("step")) or {}


class _Prefix:
    """The evaluated prefix: the events seq 0…T in order, and whether it holds run_end. Each seq is taken at most
    once: a repeated seq or an event without one is an input error (as for the facts), never a finding."""

    def __init__(self, events: Sequence[tuple[dict, Mapping[str, str]]]) -> None:
        by_seq: dict[int, tuple[dict, Mapping[str, str]]] = {}
        for env, digests in events:
            s = _int((_obj(env.get("chain")) or {}).get("seq"))
            if s is None:
                raise ValueError("an event has no chain.seq")
            if s in by_seq:
                raise ValueError(f"two events claim seq {s}")
            by_seq[s] = (env, digests)
        t = -1
        while t + 1 in by_seq:
            t += 1
        self.through = t
        self.events = [by_seq[s][0] for s in range(t + 1)]
        self.digests = [by_seq[s][1] for s in range(t + 1)]
        self.has_run_end = any(_step(e).get("type") == "run_end" for e in self.events)

    def at(self, s: int) -> Optional[dict]:
        return self.events[s] if 0 <= s <= self.through else None

    def open(self, s: int) -> bool:
        """§5.4: what follows the event is not yet known."""
        if self.has_run_end:
            return False
        return s == self.through or (s == self.through - 1 and _is_record(_step(self.events[self.through])))


def _chain_inconsistent(p: _Prefix) -> bool:
    """§5.1 reason 1, over the prefix alone; a record at T of a prefix without run_end is not continued_after_halt."""
    from sigill_sdk._agent_verify import _enforcement_findings  # the verifier's own findings, one definition
    # The control set is a v2 one (the comparison needs it), so the verifier's evidence_version_mismatch applies as it
    # does when it is given the control-set bytes: any event of the prefix that is not schemaVersion 4.
    findings = _enforcement_findings(p.events, None)
    if any(e.get("schemaVersion") != "4" for e in p.events):
        return True
    for f in findings:
        if f.code in _CHAIN_FINDINGS and not (f.code == "continued_after_halt" and not p.has_run_end
                                              and f.seqs == [p.through]):
            return True
    return False


def _recorded_engines(p: _Prefix) -> list:
    engines: list = []
    for e in p.events:
        if _is_record(_step(e)):
            name = (_obj(_step(e).get("enforcer")) or {}).get("engine")
            if not isinstance(name, str):
                raise ValueError(f"the enforcement record at seq {_int((_obj(e.get('chain')) or {}).get('seq'))} has no "
                                 f"enforcer.engine")
            if name not in engines:
                engines.append(name)
    return engines


def _recorded(p: _Prefix, s: int) -> tuple[str, Optional[str], tuple[str, ...]]:
    """§5.3: the recorded outcome of the event at s, read by position, with the record's reason and rules."""
    nxt = p.at(s + 1)
    if nxt is None or not _is_record(_step(nxt)):
        return "none", None, ()
    end = p.at(s + 2)
    halted = end is not None and _step(end).get("type") == "run_end" and _step(end).get("runDisposition") == "halted"
    record = _step(nxt)
    rules = record.get("rules") if isinstance(record.get("rules"), list) else []
    return ("halted" if halted else "refused"), _str((_obj(record.get("enforcer")) or {}).get("reason")), \
        tuple(sorted({r for r in rules if isinstance(r, str)}))


def _expected_state(p: _Prefix, evaluator_engine: Callable[[], str]) -> tuple[Optional[str], Optional[str]]:
    """(notPerformed reason or None, recordedEngine or None): what follows from the chain without a core (§5.1).
    ``evaluator_engine`` is asked only when the records name one core."""
    engines = _recorded_engines(p)
    recorded = engines[0] if len(engines) == 1 else None
    if _chain_inconsistent(p):
        return "chain_inconsistent", recorded
    if len(engines) > 1:
        return "engine_inconsistent", None
    if recorded is not None and recorded != evaluator_engine():
        return "engine_unavailable", recorded
    return None, recorded


def _decisions(p: _Prefix, control: AgentRunArtifact, document: bytes,
               diagnostics: Callable[[int], tuple[tuple[str, ...], tuple[str, ...], int]]) -> list[dict]:
    """§5.2–§5.5 for every event of the prefix: the listed events with their outcome and findings."""
    settings = AgentPolicy.enforcement(document)
    doc = _parse(document)
    entities = (_obj(doc.get("cedar")) or {}).get("entities") or []
    tools = {e["uid"]["id"]: e["attrs"] for e in entities if e["uid"]["type"] == "Tool"}
    out = []
    for s, e in enumerate(p.events):
        step, type_ = _step(e), _str(_step(e).get("type"))
        due = None
        if not (_is_record(step) or type_ == "run_end") and settings.mode == "enforce":
            if type_ == "run_start" and _configuration_locked(settings, control):
                due = ("configuration_locked", (), True)
            else:
                reason, errors, denials = diagnostics(s)
                tool = _obj(step.get("tool")) or {}
                uris = [_str(o.get("uri")) for o in e.get("objects") or []
                        if isinstance(o, dict) and o.get("role") == "tool-definition"]
                definition = p.digests[s].get(uris[0]) if len(uris) == 1 and uris[0] is not None else None
                due = _due(type_ or "", _str(tool.get("name")), definition, reason, errors, settings, tools, denials,
                           at_least=True)
        due_out = "none" if due is None else "halted" if due[2] else "refused"
        is_open, unknown = p.open(s), p.open(s) and s == p.through
        rec_out, rec_reason, rec_rules = _recorded(p, s)
        if due_out == "none" and (unknown or rec_out == "none"):
            continue  # not listed
        d: dict = {"seq": s, "due": due_out}
        if due is not None:
            d["dueReason"] = due[0]
            if due[0] in ("rule", "rule_error"):
                d["dueRules"] = list(due[1])
        if not unknown:
            d["recorded"] = rec_out
        if is_open:
            d["outcome"] = "pending"
        elif rec_out != "none" and rec_reason == "unavailable" and (due is None or due[0] != "configuration_locked"):
            d["outcome"] = "not_checkable"
        else:
            reason_of = due[0] if due else None
            both = due_out != "none" and rec_out != "none"
            applies = {
                "refusal_missing": type_ == "tool_call" and due_out != "none" and reason_of != "unknown_tool"
                and rec_out == "none",
                "unknown_tool_allowed": type_ == "tool_call" and reason_of == "unknown_tool" and rec_out == "none",
                "configuration_not_enforced": reason_of == "configuration_locked" and rec_out != "halted",
                "halt_missing": due_out == "halted" and reason_of != "configuration_locked" and rec_out != "halted",
                "unfounded_record": due_out == "none" and rec_out != "none",
                "unfounded_halt": due_out == "refused" and rec_out == "halted",
                "reason_mismatch": both and rec_reason != reason_of,
                "rules_mismatch": both and rec_reason == reason_of and set(rec_rules) != set(due[1] if due else ()),
            }
            findings = [f for f in _FINDINGS if applies[f]]
            d["outcome"] = "let_through" if any(f in _LET_THROUGH for f in findings) \
                else "over_enforced" if findings else "as_required"
            if findings:
                d["findings"] = findings
        out.append(d)
    return out


def _result(decisions: Sequence[dict]) -> str:
    outcomes = {d.get("outcome") for d in decisions}
    return next((r for r in _RESULTS if r in outcomes), "as_required")


def _check_control(control: AgentRunArtifact) -> None:
    """The Control Artifact the comparison reads: one control-set object, an agent and a correlationId, and each role
    ``lockedConfiguration`` can lock at most once (otherwise which digest the start gate compares would depend on the
    reader). Raises ValueError: an input error."""
    objects = control.envelope.get("objects") if isinstance(control.envelope.get("objects"), list) else []
    if sum(1 for o in objects if isinstance(o, dict) and o.get("role") == "control-set") != 1:
        raise ValueError("The Control Artifact must carry exactly one control-set object.")
    if _str((_obj(control.envelope.get("agent")) or {}).get("id")) is None \
            or _str((_obj(control.envelope.get("activity")) or {}).get("correlationId")) is None:
        raise ValueError("The Control Artifact names no agent or correlationId.")
    roles = [o.get("role") for o in objects if isinstance(o, dict)]
    for role in ("instruction-set", "tool-manifest", "execution-policy", "model-config"):
        if roles.count(role) > 1:
            raise ValueError(f"The Control Artifact carries more than one {role} object.")


def compare(control: AgentRunArtifact, events: Sequence[AgentRunArtifact], document: bytes, engine: Any) -> dict:
    """The ``enforcement`` member (§6) for the contiguous prefix of ``events``. ``engine`` is the evaluator's core."""
    problems = AgentPolicy.validate(document)
    if problems:
        raise ValueError("Invalid policy control set: " + "; ".join(problems))
    if _parse(document).get("schemaVersion") != "2":
        raise ValueError("The enforcement comparison needs a v2 policy control set (schemaVersion \"2\").")
    if control is None:
        raise ValueError("control_artifact is required.")
    _check_control(control)
    objects = control.envelope.get("objects")
    sealed = [control.object_digests.get(o.get("uri")) for o in objects
              if isinstance(o, dict) and o.get("role") == "control-set"]
    if sealed != [hash_bytes(document)]:
        raise ValueError("The control set is not the one the Control Artifact seals.")
    agent_id = _str(control.envelope["agent"]["id"])
    correlation_id = _str(control.envelope["activity"]["correlationId"])
    p = _Prefix([(a.envelope, a.object_digests) for a in events])
    engine = _Surfaced(engine)
    mine = f"cedar-policy@{engine.version}"  # read up front: an engine whose version fails fails the comparison
    not_performed, recorded = _expected_state(p, lambda: mine)
    return _compare(p, control, document, engine, not_performed, recorded, agent_id, correlation_id)


class _Surfaced:
    """The engine, with whatever it raises surfaced as :class:`PolicyEngineError` — the run-level request included."""

    def __init__(self, engine: Any) -> None:
        self._engine = engine

    def _call(self, f: Callable[[], Any]) -> Any:
        try:
            return f()
        except PolicyEngineError:
            raise
        except Exception as e:  # noqa: BLE001
            raise PolicyEngineError(f"The policy engine failed: {e}") from e

    @property
    def version(self) -> str:
        return self._call(lambda: self._engine.version)

    def authorize(self, call: dict) -> dict:
        return self._call(lambda: self._engine.authorize(call))

    def validate(self, call: dict) -> dict:
        return self._call(lambda: self._engine.validate(call))


def _compare(p: _Prefix, control: AgentRunArtifact, document: bytes, engine: Any, not_performed: Optional[str],
             recorded: Optional[str], agent_id: str, correlation_id: str) -> dict:
    member: dict = {"comparison": "not_performed" if not_performed else "performed"}
    if not_performed:
        member["notPerformed"] = not_performed
    if recorded is not None:
        member["recordedEngine"] = recorded
    if not_performed:
        return member
    doc = _parse(document)
    entities = (_obj(doc.get("cedar")) or {}).get("entities") or []
    facts = _build_facts(agent_id, correlation_id, p.events, None, (dict(enumerate(p.digests)), entities))
    per_seq = {r.seq: r for r in AgentPolicy.evaluate(document, facts, engine).requests}  # §4: every request
    requests = {q["seq"]: q for q in json.loads(facts.data)["requests"]}

    def diagnostics(s: int) -> tuple[tuple[str, ...], tuple[str, ...], int]:
        r = per_seq[str(s)]
        return r.reason, r.errors, requests[s]["context"]["denialsSoFar"]
    member["decisions"] = _decisions(p, control, document, diagnostics)
    member["result"] = _result(member["decisions"])
    return member


def member_problems(member: Any, control: AgentRunArtifact, events: Sequence[tuple[dict, Mapping[str, str]]],
                    evaluator_engine: Optional[str]) -> list[str]:
    """§7: what an evaluation's ``enforcement`` member must satisfy that follows from the chain without a core."""
    out: list[str] = []
    m = _obj(member)
    if m is None:
        return ["policy.enforcement is missing"]
    schema = profile_schema(CONTROL_EVALUATION_SCHEMA_V3)
    shape = validate(m, schema["properties"]["policy"]["properties"]["enforcement"], schema, "policy.enforcement")
    if shape:  # a malformed member is reported, never read further (it must not raise)
        return shape
    _check_control(control)
    p = _Prefix(events)
    not_performed, recorded = _expected_state(p, lambda: evaluator_engine or "")
    if _str(m.get("recordedEngine")) != recorded:
        out.append("policy.enforcement.recordedEngine does not follow from the run's enforcement records")
    claimed = _str(m.get("notPerformed")) if m.get("comparison") == "not_performed" else None
    if claimed != not_performed:
        out.append(f"policy.enforcement is {'not performed (' + claimed + ')' if claimed else 'performed'}, but the "
                   f"run gives {'not performed (' + not_performed + ')' if not_performed else 'performed'}")
    if m.get("comparison") != "performed":
        return out
    decisions = [d for d in m.get("decisions") or [] if isinstance(d, dict)]
    seqs = [_int(d.get("seq")) for d in decisions]
    if any(s is None or not 0 <= s <= p.through for s in seqs):
        out.append("a decision names an event outside the evaluated prefix")
        return out
    if any(a >= b for a, b in zip(seqs, seqs[1:])):
        out.append("policy.enforcement.decisions do not ascend by seq")
    for d, s in zip(decisions, seqs):
        rules = d.get("dueRules")
        if isinstance(rules, list) and rules != sorted(rules):
            out.append(f"decision {s}: dueRules are not sorted")
        unknown = p.open(s) and s == p.through
        if unknown != ("recorded" not in d) or (not unknown and d.get("recorded") != _recorded(p, s)[0]):
            out.append(f"decision {s}: recorded does not follow from the chain")
        if (d.get("outcome") == "pending") != p.open(s):
            out.append(f"decision {s}: pending exactly when the event is open")
        findings = d.get("findings") if isinstance(d.get("findings"), list) else []
        if findings != [f for f in _FINDINGS if f in findings] or len(set(findings)) != len(findings):
            out.append(f"decision {s}: findings are not in the order of the comparison's table")
        let = any(f in _LET_THROUGH for f in findings)
        if (d.get("outcome") == "let_through" and not let) or (d.get("outcome") == "over_enforced" and let):
            out.append(f"decision {s}: its findings do not fit its outcome")
        rec_out, rec_reason, rec_rules = _recorded(p, s)
        if d.get("outcome") == "not_checkable" and (rec_out == "none" or rec_reason != "unavailable"):
            out.append(f"decision {s}: not_checkable, but the record after it does not say unavailable")
        if d.get("outcome") == "as_required" and (
                d.get("due") != rec_out or d.get("dueReason") != rec_reason
                or set(d.get("dueRules") or ()) != set(rec_rules)):
            out.append(f"decision {s}: as_required, but what is due is not what the chain records")
    for s in range(p.through + 1):  # a decision for every event the chain records an outcome after
        if not (p.open(s) and s == p.through) and _recorded(p, s)[0] != "none" and s not in seqs:
            out.append(f"the event at seq {s} has a recorded outcome but no decision")
    if m.get("result") != _result(decisions):
        out.append("policy.enforcement.result does not follow from its decisions")
    return out
