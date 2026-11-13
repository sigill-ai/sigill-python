# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""The guard (``spec/agent-policy-control-set-v2.md`` §7, ``spec/agent-enforcement-v1.md`` §4): decides each event a
run's producer records, after it is sealed, and tells the recorder what to seal directly after it — one enforcement
record, then the halting ``run_end`` when one is due. The recorder seals both under its lock.

Messages and attributes carry the tool alias, the use id, rule ids, the reason and seqs — never arguments, results or
definitions.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

from sigill_sdk._agent_policy import (
    _BASELINE,
    BASELINE_PERMIT,
    POLICY_CONTROL_SET_CONTENT_TYPE,
    AgentPolicy,
    _cedar_schema,
    _diagnostics,
    _Facts,
    _parse,
)
from sigill_sdk._agent_types import AgentControlSet, AgentRunArtifact
from sigill_sdk._errors import SigillError
from sigill_sdk._policy_engine import CEDAR_VERSION, PolicyEngine, PolicyEngineError


@dataclass(frozen=True)
class EnforcementEvent:
    """What the guard did, reported to :attr:`Enforcement.on_event` after the evidence is sealed."""

    kind: str
    """``denied`` (a tool call refused, the run goes on), ``halted`` (the run was halted, after a tool call or any
    other event), ``start_refused`` (the run was halted at its start) or ``observed`` (rules matched; nothing was
    sealed)."""
    reason: Optional[str]
    """The enforcement record's reason (``rule``, ``rule_error``, ``unknown_tool``, ``tool_changed``, ``unavailable``,
    ``configuration_locked``); None for ``observed``."""
    rules: tuple[str, ...]
    """The record's rule ids; for ``observed``, the rules that matched."""
    tool: Optional[str]
    """The tool of the decided ``tool_call`` (or the ``tool_result`` observed); else None."""
    use_id: Optional[str]
    """That call's use id; else None."""
    seq: int
    """The seq of the decided event."""


@dataclass(frozen=True)
class Enforcement:
    """Switches the guard on for a run (``start_agent_run(..., enforcement=Enforcement(engine))``). Required by a v2
    policy control set with ``enforcement.mode: "enforce"``; with any other control set the engine only evaluates
    and reports matching rules as ``observed``."""

    engine: PolicyEngine
    """The Cedar core the guard evaluates each event with (e.g. :class:`CedarEngine`)."""
    on_event: Optional[Callable[[EnforcementEvent], None]] = None
    """Called outside the run's lock, in seal order, after the evidence is sealed and before the exception reaches
    the caller. A failing callback never breaks the run and never hides a denial."""

    def __post_init__(self) -> None:
        if self.engine is None:
            raise ValueError("enforcement.engine is required.")


class PolicyDenied(SigillError):
    """The guard denied a tool call: its ``tool_call`` and the enforcement record (and, when :attr:`halted`, the
    halting ``run_end``) are sealed. The tool must not be executed; the call gets no result."""

    def __init__(self, reason: str, rules: tuple[str, ...], tool: str, use_id: str, seq: int,
                 record: AgentRunArtifact, halted: bool) -> None:
        super().__init__(f"The policy denied the call of tool '{tool}' (use_id '{use_id}', seq {seq}): reason "
                         f"{reason}{_rules_text(rules)}" + ("; the run is halted." if halted else "."))
        self.reason, self.rules, self.tool, self.use_id, self.seq = reason, rules, tool, use_id, seq
        self.record = record
        """The sealed enforcement record."""
        self.halted = halted


class RunHalted(SigillError):
    """The guard halted the run: the enforcement record and the halting ``run_end`` are sealed. Raised by the call
    that recorded the event it halted on, and by every recording call after."""

    def __init__(self, reason: str, rules: tuple[str, ...], seq: int, record: AgentRunArtifact) -> None:
        super().__init__(f"The policy halted the run at seq {seq}: reason {reason}{_rules_text(rules)}.")
        self.reason, self.rules, self.seq = reason, rules, seq
        self.record = record
        """The sealed enforcement record."""


class StartRefused(SigillError):
    """The guard refused the run's start: the Control Artifact, ``run_start``, one enforcement record and the
    halting ``run_end`` are sealed. :attr:`run` is the closed run (``run.finish()`` / ``run.to_bundle()`` give its
    bundle)."""

    def __init__(self, reason: str, run: Any) -> None:
        super().__init__(f"The policy refused the start of the run: reason {reason}.")
        self.reason = reason
        self.run = run


def _rules_text(rules: tuple[str, ...]) -> str:
    return f", rules {', '.join(rules)}" if rules else ""


@dataclass(frozen=True)
class _Outcome:
    reason: Optional[str]           # None: observed only, nothing to seal
    rules: tuple[str, ...]
    halt: bool
    tool: Optional[dict]            # the decided call's {name, useId}, on its record


_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


def _guard_for(control_set: AgentControlSet, enforcement: Optional[Enforcement], agent_id: str,
               is_child_run: bool) -> Optional["_Guard"]:
    """Before anything is sealed: the run's guard, or None. Raises ValueError for an enforcing control set without
    ``enforcement`` and for a control set that fails strict validation."""
    if control_set.content_type != POLICY_CONTROL_SET_CONTENT_TYPE:
        return None
    settings = AgentPolicy.enforcement(control_set.content)
    if enforcement is None:
        if settings.mode == "enforce":
            raise ValueError("The control set enforces its policy: pass enforcement with a policy engine.")
        return None
    try:
        problems = AgentPolicy.validate_strict(control_set.content, enforcement.engine)
        if settings.mode != "enforce":
            enforcement.engine.version  # noqa: B018 — loads the engine
    except Exception as e:  # noqa: BLE001
        if settings.mode != "enforce":  # not enforced: a broken engine would look like "no rule ever matched"
            if isinstance(e, PolicyEngineError):
                raise
            raise PolicyEngineError(f"The policy engine failed: {e}") from e
        problems, engine_failed = [], True  # enforced: the start gate refuses the run, reason unavailable (§7.4)
    else:
        engine_failed = False
    if problems:
        raise ValueError("Invalid policy control set: " + "; ".join(problems))
    return _Guard(enforcement, control_set.content, settings, agent_id, is_child_run, engine_failed)


class _Guard:
    """One run's guard. Not thread-safe: the recorder calls it under the run's lock, once per sealed event in seq
    order."""

    def __init__(self, enforcement: Enforcement, document: bytes, settings: Any, agent_id: str,
                 is_child_run: bool, engine_failed: bool = False) -> None:
        doc = _parse(document)
        v2 = doc.get("schemaVersion") == "2"
        cedar = doc.get("cedar") if isinstance(doc.get("cedar"), dict) else {}
        rules = cedar.get("policies", {}).get("staticPolicies") or {}
        entities = cedar.get("entities", []) if v2 else []
        self.engine = enforcement.engine
        self.settings = settings
        self.enforcing = settings.mode == "enforce"
        self.engine_name = f"cedar-policy@{CEDAR_VERSION}"  # the version the engine reports, once loaded at start
        self.tools = {e["uid"]["id"]: e["attrs"] for e in entities if e["uid"]["type"] == "Tool"}
        self.facts = _Facts(agent_id, is_child_run, v2)
        # The engine call without its request, built once (§7.1: the baseline permit, as an evaluator calls it).
        self.call = {"schema": _cedar_schema(2 if v2 else 1), "validateRequest": True,
                     "policies": {"staticPolicies": {**rules, BASELINE_PERMIT: _BASELINE}}, "entities": entities}
        self.evaluates = self.enforcing or bool(rules)
        self.engine_failed = engine_failed  # strict validation could not run: never start unvalidated

    def after(self, artifact: AgentRunArtifact, producer: bool, control: AgentRunArtifact) -> Optional[_Outcome]:
        """Counts the sealed event into the facts; for a producer's event (never the guard's own, never ``run_end``)
        evaluates it and returns what is due, or None."""
        env = artifact.envelope
        request = self.facts.next(artifact.seq, env, artifact.object_digests)
        step = env["step"]
        type_ = step["type"]
        if not producer or type_ == "run_end" or not self.evaluates:
            return None
        if not self.enforcing:
            diagnostics = self._evaluate(request)
            return _Outcome(None, diagnostics[0], False, None) if diagnostics and diagnostics[0] else None
        # An enforcing control set is v2, so the run is v4: every tool_call carries a use id.
        call = {"name": step["tool"]["name"], "useId": step["tool"]["useId"]} if type_ == "tool_call" else None
        if type_ == "run_start":  # §7.4: the start gate, then run_start like any other event
            reason = self._gate(control)
            if reason is not None:
                return _Outcome(reason, (), True, None)
        diagnostics = self._evaluate(request)
        if diagnostics is None:  # §7.5
            return _Outcome("unavailable", (), True, call)
        reason, errors = diagnostics
        effect = self.settings.rule_effects.get
        halting = tuple(r for r in reason if effect(r) == "halt")
        observed = _Outcome(None, reason, False, None) if reason else None
        if call is None:  # §7.3
            return _Outcome("rule", halting, True, None) if halting else observed
        blocking_errors = tuple(r for r in errors if effect(r) in ("deny", "halt"))
        blocking = tuple(r for r in reason if effect(r) in ("deny", "halt"))
        attrs = self.tools.get(call["name"])
        if attrs is None and self.settings.unknown_tools == "deny":
            denial: Optional[tuple] = ("unknown_tool", ())
        elif attrs is not None and "definitionSha256" in attrs \
                and self._definition(artifact) != attrs["definitionSha256"]:
            denial = ("tool_changed", ())
        elif blocking_errors and self.settings.on_rule_error == "deny":
            denial = ("rule_error", blocking_errors)
        elif blocking:
            denial = ("rule", blocking)
        else:
            return observed
        # §7.2: a matching halt rule always halts, whatever reason won the record; so does the denial count.
        limit = self.settings.halt_after_denials
        halt = bool(halting) or (limit > 0 and self.facts.denials + 1 == limit)
        return _Outcome(denial[0], denial[1], halt, call)

    def _gate(self, control: AgentRunArtifact) -> Optional[str]:
        digests = {o.get("role"): control.object_digests.get(o.get("uri")) for o in control.envelope["objects"]}
        if any(digests.get(role) != hex_ for role, hex_ in self.settings.locked_configuration.items()):
            return "configuration_locked"
        if self.engine_failed:
            return "unavailable"
        try:
            version = self.engine.version
        except Exception:  # noqa: BLE001 — the core cannot be loaded
            return "unavailable"
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            return "unavailable"
        self.engine_name = f"cedar-policy@{version}"
        return None

    def _evaluate(self, request: dict) -> Optional[tuple[tuple[str, ...], tuple[str, ...]]]:
        """(matching rules, erroring rules), each sorted; None when the engine fails or refuses the request."""
        try:  # a fresh copy each time: an engine that changes its input cannot change a later decision
            return _diagnostics(self.engine.authorize(copy.deepcopy(
                {**{k: request[k] for k in ("principal", "action", "resource", "context")}, **self.call})))
        except Exception:  # noqa: BLE001 — a raising, trapping or malformed answer is an unavailable engine
            return None

    @staticmethod
    def _definition(artifact: AgentRunArtifact) -> Optional[str]:
        """The signed digest of the call's one ``tool-definition`` object; None without exactly one."""
        uris = [o.get("uri") for o in artifact.envelope.get("objects") or [] if o.get("role") == "tool-definition"]
        return artifact.object_digests.get(uris[0]) if len(uris) == 1 else None
