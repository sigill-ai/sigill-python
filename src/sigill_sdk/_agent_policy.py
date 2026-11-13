# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Declared agent policies (``spec/agent-policy-control-set-v1.md``, ``spec/agent-policy-control-set-v2.md``).

A control-set document with the content type
``application/vnd.sigill.control-set+json`` that carries forbid-only Cedar rules,
private controls and a coverage contract; a v2 document (``"schemaVersion": "2"``)
adds the entities the rules refer to and what a guard does with them. Keep the
approved document as a file and pass the same bytes to every run.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Optional, Sequence

from sigill_sdk._agent_profiles import MAX_DEPTH, _int, _obj, _reject_constant, _reject_duplicates, _str
from sigill_sdk._agent_types import AgentControlSet, AgentRunArtifact
from sigill_sdk._canonical import canonicalize, hash_bytes
from sigill_sdk._schema import parse_date_time

POLICY_CONTROL_SET_CONTENT_TYPE = "application/vnd.sigill.control-set+json"
FACTS_VERSION = "1"
"""The facts version this SDK builds (``spec/agent-policy-control-set-v1.md`` §5)."""

_MEMBERS = {"id", "version", "controls", "cedar", "privateControls", "coverage"}
_MEMBERS_V2 = _MEMBERS | {"schemaVersion", "enforcement"}
_ENFORCEMENT_MEMBERS = ("mode", "defaultEffect", "lockedConfiguration", "unknownTools", "onRuleError",
                        "haltAfterDenials")
_LOCKED_ROLES = ("instruction-set", "tool-manifest", "execution-policy", "model-config")
_EFFECTS = ("observe", "deny", "halt")
# v2 §5: each entity type and the types its parents may have.
_ENTITY_PARENTS = {"Tool": ("ToolGroup",), "ToolGroup": ("ToolGroup",), "Agent": ("AgentGroup",), "AgentGroup": ()}
_MAX_POLICIES = 256
_MAX_ENTITIES = 1024
_RULE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}\Z")  # \Z: `$` would also match before a final newline
_HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
_MAX_SAFE_INTEGER = 2 ** 53 - 1
# I-JSON also covers §4 rule 4: integers beyond ±2^53-1 are refused anywhere in the document.
_NOT_I_JSON = ("the document is not an I-JSON object (no repeated names, integers within ±2^53-1, no lone "
               "surrogates)")
_NOT_UTF8 = "the document is not UTF-8 without a byte-order mark"
_TOO_DEEP = "the document exceeds the nesting depth of 64 levels"


@dataclass(frozen=True)
class PolicyDigests:
    """The two identities of a policy control set (§3)."""

    approval_scope_digest: str
    """SHA-256 of JCS(document without ``id`` and ``version``): what an owner approves."""
    cedar_digest: Optional[str]
    """SHA-256 of JCS(``cedar``), or None without Cedar rules: the rules alone."""


@dataclass(frozen=True)
class PolicyFacts:
    """A run's facts document (``spec/control-evaluation-v2.md`` §4.5)."""

    data: bytes
    """The exact JCS bytes: the ``evaluation-facts`` object of a policy evaluation."""
    sha256: str
    """Lowercase hex SHA-256 of :attr:`data`."""
    through_seq: int
    """Last seq of the contiguous prefix that was evaluated (−1 without seq 0)."""
    missing_seqs: list[int]
    """Seqs missing below the highest received one."""
    run_level: bool
    """Whether the run-level request is present (run_end in, nothing missing)."""


@dataclass(frozen=True)
class PolicyEnforcement:
    """What a guard does with a policy control set (``spec/agent-policy-control-set-v2.md`` §6, §4 rule 7), every
    default applied. A v1 document, or one without ``enforcement``, is ``observe`` with the defaults."""

    mode: str
    """``observe`` (the guard never denies or halts) or ``enforce``."""
    default_effect: str
    """``deny`` or ``halt``: the effect of a rule without an ``effect`` annotation."""
    locked_configuration: Mapping[str, str]
    """Control Artifact role → the SHA-256 its object must have."""
    unknown_tools: str
    """``deny`` or ``allow``: a ``tool_call`` of a tool the entities do not declare."""
    on_rule_error: str
    """``deny`` or ``allow``: a ``deny`` or ``halt`` rule that errors on a ``tool_call``."""
    halt_after_denials: int
    """Halt at the denial that brings the run's enforcement records to this number; 0 = never."""
    rule_effects: Mapping[str, str]
    """The effective effect of every rule id: ``observe``, ``deny`` or ``halt`` (all ``observe`` unless the mode is
    ``enforce``)."""


@lru_cache(maxsize=None)
def _cedar_schema_v2_sha256() -> str:
    """SHA-256 of JCS(``agent-policy-cedar-schema-v2.json``), from the byte-exact copy shipped with the SDK."""
    raw = resources.files("sigill_sdk").joinpath("_schemas/agent-policy-cedar-schema-v2.json").read_bytes()
    return hash_bytes(canonicalize(json.loads(raw)))


def _is_v2(document: bytes) -> bool:
    """The document declares itself a v2 control set (v2 §1); validity is checked elsewhere."""
    doc = _parse(document)
    return doc is not None and doc.get("schemaVersion") == "2"


def _i_json_values(v: Any) -> bool:
    """Integers within ±(2^53 − 1), finite numbers, no lone surrogates in strings or names. Iterative."""
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, bool) or x is None:
            continue
        if isinstance(x, int):
            if abs(x) > _MAX_SAFE_INTEGER:
                return False
        elif isinstance(x, float):
            if not math.isfinite(x):
                return False
        elif isinstance(x, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in x):
                return False
        elif isinstance(x, list):
            stack.extend(x)
        elif isinstance(x, dict):
            for k, y in x.items():
                stack.extend((k, y))
        else:
            return False
    return True


def _too_deep(text: str) -> bool:
    """A linear scan: brackets and braces outside strings nest deeper than 64 (the outermost one is level 1)."""
    depth, in_string, escaped = 0, False, False
    for c in text:
        if in_string:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                return True
        elif c in "]}":
            depth -= 1
    return False


def _strict_json(document: Any) -> Any:
    """The one strict parse of a control set, used by validation, the facts builder and the verifier: UTF-8
    without a byte-order mark, I-JSON (no repeated names, integers within ±(2^53 − 1), no NaN or Infinity, no lone
    surrogates, raw or escaped), nested at most 64 levels. Raises :class:`ValueError` for anything else, never
    another exception. Depth counts the outermost object or array as level 1."""
    not_utf8 = ValueError(_NOT_UTF8)
    if not isinstance(document, (bytes, bytearray)) or bytes(document[:3]) == b"\xef\xbb\xbf":
        raise not_utf8
    try:
        text = bytes(document).decode("utf-8")
    except UnicodeDecodeError:
        raise not_utf8 from None
    if _too_deep(text):  # before any parse: a deep document never reaches the recursive reader
        raise ValueError(_TOO_DEEP)
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
    except (ValueError, RecursionError):  # malformed JSON, a repeated name, NaN or Infinity
        raise ValueError(_NOT_I_JSON) from None
    if not _i_json_values(value):
        raise ValueError(_NOT_I_JSON)
    return value


def _parse_checked(document: bytes) -> tuple[Optional[dict], Optional[str]]:
    """(the document, None), or (None, why it is not a strictly parsed JSON object)."""
    try:
        doc = _strict_json(document)
    except ValueError as e:
        return None, str(e)
    return (doc, None) if isinstance(doc, dict) else (None, _NOT_I_JSON)


def _parse(document: bytes) -> Optional[dict]:
    return _parse_checked(document)[0]


def _non_empty_str(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def _validate_cedar(cedar: Any, errors: list[str], v2: bool = False) -> None:
    if not isinstance(cedar, dict):
        errors.append("cedar must be an object")
        return
    sha = cedar.get("schemaSha256")
    if not isinstance(sha, str) or not _HEX64.match(sha):
        errors.append("cedar.schemaSha256 must be a lowercase hex SHA-256")
    elif v2 and sha != _cedar_schema_v2_sha256():
        errors.append("cedar.schemaSha256 must be the SHA-256 of JCS(agent-policy-cedar-schema-v2.json)")
    if v2:
        errors.extend(f"cedar has unknown member '{k}'" for k in cedar if k not in ("policies", "schemaSha256", "entities"))
    if v2 and "entities" in cedar:
        _validate_entities(cedar["entities"], errors)
    pset = cedar.get("policies")
    if not isinstance(pset, dict):
        errors.append("cedar.policies must be a Cedar JSON policy set")
        return
    if isinstance(pset.get("templates"), dict) and pset["templates"]:
        errors.append("cedar.policies must not contain templates")
    if isinstance(pset.get("templateLinks"), list) and pset["templateLinks"]:
        errors.append("cedar.policies must not contain template links")
    policies = pset.get("staticPolicies")
    if not isinstance(policies, dict) or not policies:
        errors.append("cedar.policies.staticPolicies must hold at least one policy")
        return
    if v2 and len(policies) > _MAX_POLICIES:
        errors.append(f"cedar.policies holds {len(policies)} policies; at most {_MAX_POLICIES} are allowed")
    for key, p in policies.items():
        if not isinstance(p, dict):
            errors.append(f"policy '{key}' is not an object")
            continue
        if not _RULE_ID.match(key):
            errors.append(f"policy id '{key}' must be 1-64 characters of A-Z a-z 0-9 . _ -")
        if p.get("effect") != "forbid":
            errors.append(f"policy '{key}' must be forbid (step 1 is tripwire mode)")
        annotations = p.get("annotations")
        if not isinstance(annotations, dict) or annotations.get("id") != key:
            errors.append(f"policy '{key}' must carry @id(\"{key}\")")
        if v2 and isinstance(annotations, dict):
            errors.extend(f"policy '{key}' has annotation '{name}'; only id and effect are allowed"
                          for name in annotations if name not in ("id", "effect"))
            if "effect" in annotations and annotations["effect"] not in _EFFECTS:
                errors.append(f"policy '{key}': its effect annotation must be observe, deny or halt")


def _uid(v: Any) -> Optional[tuple[str, str]]:
    """A v2 §5 entity uid: exactly ``{type, id}``, both strings, the id 1-255 characters."""
    if not isinstance(v, dict) or set(v) != {"type", "id"}:
        return None
    t, i = v["type"], v["id"]
    return (t, i) if isinstance(t, str) and isinstance(i, str) and 1 <= len(i) <= 255 else None


def _validate_entities(entities: Any, errors: list[str]) -> None:
    """v2 §5 without a Cedar engine: size, members, types, unique uids, attributes and the parent hierarchy."""
    if not isinstance(entities, list):
        errors.append("cedar.entities must be an array")
        return
    if len(entities) > _MAX_ENTITIES:
        errors.append(f"cedar.entities holds {len(entities)} entities; at most {_MAX_ENTITIES} are allowed")
    declared: dict[tuple[str, str], tuple[int, list[tuple[str, str]]]] = {}
    for i, e in enumerate(entities):
        where = f"cedar.entities[{i}]"
        if not isinstance(e, dict) or set(e) != {"uid", "attrs", "parents"}:
            errors.append(f"{where} must have exactly uid, attrs and parents")
            continue
        uid = _uid(e["uid"])
        if uid is None:
            errors.append(f"{where}.uid must be exactly {{type, id}}, strings, the id 1-255 characters")
            continue
        type_ = uid[0]
        if type_ not in _ENTITY_PARENTS:
            errors.append(f"{where} has type '{type_}'; only Tool, ToolGroup, Agent and AgentGroup are allowed")
            continue
        if uid in declared:
            errors.append(f"cedar.entities declares {type_}::\"{uid[1]}\" more than once")
            continue
        attrs = e["attrs"]
        if not isinstance(attrs, dict):
            errors.append(f"{where}.attrs must be an object")
        elif type_ == "Tool":
            for name, value in attrs.items():
                if not ((name == "consequential" and isinstance(value, bool))
                        or (name == "definitionSha256" and isinstance(value, str) and _HEX64.match(value))):
                    errors.append(f"{where} (Tool) has attribute '{name}'; a Tool may carry only consequential "
                                  f"(boolean) and definitionSha256 (lowercase hex SHA-256)")
        elif attrs:
            errors.append(f"{where} ({type_}) must have no attributes")
        allowed = _ENTITY_PARENTS[type_]
        parents: list[tuple[str, str]] = []
        if not isinstance(e["parents"], list):
            errors.append(f"{where}.parents must be an array")
        for p in e["parents"] if isinstance(e["parents"], list) else []:
            puid = _uid(p)
            if puid is None or puid[0] not in allowed:
                errors.append(f"{where}.parents: a {type_} may have only {' or '.join(allowed)} parents" if allowed
                              else f"{where}.parents: a {type_} has no parents")
            elif puid in parents:
                errors.append(f"{where}.parents lists {puid[0]}::\"{puid[1]}\" twice")
            else:
                parents.append(puid)
        declared[uid] = (i, parents)
    for i, parents in declared.values():
        for p in parents:
            if p not in declared:
                errors.append(f"cedar.entities[{i}].parents: {p[0]}::\"{p[1]}\" is not an entity of the array")
    # Acyclic: peel off entities whose declared parents are all peeled; whatever remains hangs on a cycle.
    remaining = set(declared)
    while remaining:
        free = {u for u in remaining if not any(p in remaining for p in declared[u][1])}
        if not free:
            errors.append("cedar.entities parents form a cycle")
            break
        remaining -= free


def _validate_enforcement(enforcement: Any, errors: list[str]) -> None:
    """v2 §6: members, values and ranges."""
    if not isinstance(enforcement, dict):
        errors.append("enforcement must be an object")
        return
    errors.extend(f"enforcement has unknown member '{k}'" for k in enforcement if k not in _ENFORCEMENT_MEMBERS)
    if enforcement.get("mode") not in ("observe", "enforce"):
        errors.append("enforcement.mode is required: observe or enforce")
    for name, allowed in (("defaultEffect", ("deny", "halt")), ("unknownTools", ("deny", "allow")),
                          ("onRuleError", ("deny", "allow"))):
        if name in enforcement and enforcement[name] not in allowed:
            errors.append(f"enforcement.{name} must be {' or '.join(allowed)}")
    if "lockedConfiguration" in enforcement:
        locked = enforcement["lockedConfiguration"]
        if not isinstance(locked, dict):
            errors.append("enforcement.lockedConfiguration must be an object")
        for role, hex_ in locked.items() if isinstance(locked, dict) else ():
            if role not in _LOCKED_ROLES:
                errors.append(f"enforcement.lockedConfiguration has unknown role '{role}'")
            elif not isinstance(hex_, str) or not _HEX64.match(hex_):
                errors.append(f"enforcement.lockedConfiguration['{role}'] must be a lowercase hex SHA-256")
    halt = enforcement.get("haltAfterDenials", 0)
    if isinstance(halt, bool) or not isinstance(halt, int) or halt < 0:
        errors.append("enforcement.haltAfterDenials must be an integer >= 0")


def _context(consequential: bool, operation: str, steps_so_far: int, approval: str, is_child_run: bool,
             total_steps: int, consequential_count: int, unpaired_consequential: int) -> dict:
    return {
        "consequential": consequential,
        "operation": operation,
        "stepsSoFar": steps_so_far,
        "approval": approval,
        "isChildRun": is_child_run,
        "totalSteps": total_steps,
        "consequentialCount": consequential_count,
        "unpairedConsequential": unpaired_consequential,
    }


def _is_record(step: dict) -> bool:
    """An enforcement record: an ``authorization`` with an ``enforcer`` (Agent Enforcement v1 §3.4)."""
    return step.get("type") == "authorization" and "enforcer" in step


def _approval_v2(step: dict, arguments_sha256: Optional[str], approvals: list[tuple[int, dict]],
                 consumed: set[int]) -> str:
    """v2 §8.1 for one ``tool_call``, given the earlier ``human_approval`` steps (seq order) and the approvals earlier
    calls consumed; a ``bound`` call consumes the lowest-seq approval that matches it."""
    tool = _obj(step.get("tool")) or {}
    u, t, a = _str(tool.get("useId")), _str(tool.get("name")), arguments_sha256
    for _, s in approvals:
        c = _obj(s.get("covers"))
        if s.get("decision") == "rejected" and c is not None and (
                (_str(c.get("useId")) is not None and c.get("useId") == u)
                or (t is not None and c.get("tool") == t and a is not None and c.get("argumentsSha256") == a)):
            return "rejected"
    event_time = parse_date_time(step.get("eventTime"))
    for seq, s in approvals:
        c = _obj(s.get("covers"))
        if s.get("decision") != "approved" or c is None or seq in consumed or t is None or c.get("tool") != t \
                or a is None or c.get("argumentsSha256") != a \
                or ("useId" in c and (u is None or c.get("useId") != u)):  # a malformed restriction never binds
            continue
        if "expiresAt" in c:
            expires = parse_date_time(c.get("expiresAt"))
            if expires is None or event_time is None or not event_time < expires:
                continue
        consumed.add(seq)
        return "bound"
    return "unbound" if approvals else "none"


def _build_facts(agent_id: str, correlation_id: str, events: Iterable[dict],
                 claimed_missing: Optional[Sequence[int]],
                 v2: Optional[tuple[Mapping[int, Mapping[str, str]], list]] = None) -> PolicyFacts:
    """With ``claimed_missing``, ``events`` is an evaluator's contiguous prefix and the gaps it reported above it
    are taken as given: what a verifier rebuilds (``control-evaluation-v2.md`` §4.5). With ``v2`` = (each event's
    object digests by seq, ``cedar.entities``) the facts are factsVersion 2 (``agent-policy-control-set-v2.md`` §8)."""
    by_seq: dict[int, dict] = {}
    for e in events:
        seq = _int((_obj(e.get("chain")) or {}).get("seq"))
        if seq is None:
            raise ValueError("an event has no chain.seq")
        if seq in by_seq:
            raise ValueError(f"two events claim seq {seq}")
        by_seq[seq] = e
    max_seq = max(by_seq) if by_seq else -1
    missing = [s for s in range(max_seq + 1) if s not in by_seq]
    through_seq = missing[0] - 1 if missing else max_seq
    if claimed_missing is not None:
        if missing:
            raise ValueError(f"the prefix is not contiguous (seq {missing[0]} missing)")
        missing = list(claimed_missing)
    prefix = [(s, by_seq[s]) for s in sorted(by_seq) if s <= through_seq]

    def step(e: dict) -> dict:
        return _obj(e.get("step")) or {}

    def step_type(e: dict) -> str:
        return _str(step(e).get("type")) or ""

    def consequential_of(e: dict) -> bool:
        return step(e).get("consequential") is True

    def tool(e: dict, name: str) -> Optional[str]:
        return _str((_obj(step(e).get("tool")) or {}).get(name))

    def principal() -> dict:
        return {"type": "Agent", "id": agent_id}

    first = by_seq.get(0)
    is_child_run = first is not None and step_type(first) == "run_start" \
        and bool(_str((_obj(first.get("binds")) or {}).get("parentCorrelationId")))
    requests: list[dict] = []
    consequential_count = 0
    approvals: list[tuple[int, dict]] = []  # earlier human_approval steps
    consumed: set[int] = set()
    tool_calls = denials = 0
    calls_of: dict[Optional[str], int] = {}
    for seq, e in prefix:
        type_ = step_type(e)
        consequential = consequential_of(e)
        if consequential:
            consequential_count += 1
        context = _context(consequential, tool(e, "operation") or "", seq,
                           "unbound" if approvals else "none", is_child_run, 0, consequential_count, 0)
        if v2 is not None:
            if type_ == "tool_call":
                tool_calls += 1
                calls_of[tool(e, "name")] = calls_of.get(tool(e, "name"), 0) + 1
                objs = e.get("objects")
                args = [o for o in (objs if isinstance(objs, list) else [])
                        if isinstance(o, dict) and o.get("role") == "tool-arguments"]
                digest = v2[0].get(seq, {}).get(_str(args[0].get("uri")) or "") if len(args) == 1 else None
                context["approval"] = _approval_v2(step(e), digest, approvals, consumed)
            context["toolCallsSoFar"] = tool_calls
            # An absent tool name equals nothing, not even another absent one.
            context["callsOfThisTool"] = calls_of.get(tool(e, "name"), 0) \
                if type_ in ("tool_call", "tool_result") and tool(e, "name") is not None else 0
            context["denialsSoFar"] = denials
            if _is_record(step(e)):
                denials += 1
        requests.append({
            "seq": seq,
            "principal": principal(),
            "action": {"type": "Action", "id": type_},
            "resource": {"type": "Tool", "id": tool(e, "name") or ""} if type_ in ("tool_call", "tool_result")
            else {"type": "Step", "id": str(seq)},
            "context": context,
        })
        if type_ == "human_approval":
            approvals.append((seq, step(e)))

    run_end = next(((s, e) for s, e in prefix if step_type(e) == "run_end"), None)
    run_level = run_end is not None and not missing
    if run_level:
        final_seq = _int(step(run_end[1]).get("finalSeq"))
        if final_seq is None:
            final_seq = run_end[0]
        calls = [(s, e) for s, e in prefix if step_type(e) == "tool_call"]
        uses: dict[str, int] = {}
        for _, c in calls:
            u = tool(c, "useId")
            if u is not None:
                uses[u] = uses.get(u, 0) + 1

        def unpaired(s: int, c: dict) -> bool:
            # §5: a call without useId, or whose useId another call also uses, counts as unpaired.
            u = tool(c, "useId")
            paired = u is not None and uses[u] == 1 and any(
                step_type(x) == "tool_result" and xs > s and tool(x, "useId") == u for xs, x in prefix)
            # v2 §8: a call a later enforcement record names was denied, never executed: not unpaired.
            denied = v2 is not None and u is not None and any(
                xs > s and _is_record(step(x)) and tool(x, "useId") == u for xs, x in prefix)
            return not paired and not denied and consequential_of(c)
        context = _context(False, "", final_seq, "none", is_child_run, final_seq, consequential_count,
                           sum(1 for s, c in calls if unpaired(s, c)))
        if v2 is not None:
            context.update(toolCallsSoFar=tool_calls, callsOfThisTool=0, denialsSoFar=denials)
        requests.append({
            "seq": "run",
            "principal": principal(),
            "action": {"type": "Action", "id": "run"},
            "resource": {"type": "Run", "id": correlation_id},
            "context": context,
        })

    facts: dict = {
        "factsVersion": FACTS_VERSION if v2 is None else "2",
        "throughSeq": through_seq,
        "missingSeqs": missing,
        "runLevel": run_level,
        "requests": requests,
    }
    if v2 is not None:
        facts["entities"] = v2[1]  # v2 §8: the entities input of every request
    data = canonicalize(facts)
    return PolicyFacts(data, hash_bytes(data), through_seq, missing, run_level)


class AgentPolicy:
    """Declared agent policies: build, identify and check a policy control set."""

    CONTROL_SET_CONTENT_TYPE = POLICY_CONTROL_SET_CONTENT_TYPE
    FACTS_VERSION = FACTS_VERSION

    @staticmethod
    def build_facts(agent_id: str, correlation_id: str, events: Iterable[dict]) -> PolicyFacts:
        """The facts a run is evaluated on (``spec/agent-policy-control-set-v1.md`` §5, factsVersion 1), as the
        facts document of ``spec/control-evaluation-v2.md`` §4.5: one Cedar request per event of the contiguous
        prefix seq 0…k, plus the run-level request when ``run_end`` is in and nothing is missing.

        :param agent_id: the Control Artifact's signed ``agent.id``.
        :param correlation_id: the run's ``activity.correlationId``.
        :param events: the run's Agent Execution Evidence envelopes, any order. Only typed fields are read.
        :raises ValueError: an event has no seq, or two claim the same one (the chain is not valid)."""
        return _build_facts(agent_id, correlation_id, events, None)

    @staticmethod
    def build_facts_v2(agent_id: str, correlation_id: str, events: Iterable[AgentRunArtifact],
                       control_set_document: bytes) -> PolicyFacts:
        """The facts of a run under a v2 policy control set (``spec/agent-policy-control-set-v2.md`` §8,
        factsVersion 2): the requests of :meth:`build_facts` with ``toolCallsSoFar``, ``callsOfThisTool``,
        ``denialsSoFar``, the ``approval`` of a ``tool_call`` from ``covers`` (§8.1) and denied calls excluded from
        ``unpairedConsequential``, plus the control set's ``cedar.entities`` (the ``entities`` input of every
        request) as the document's ``entities`` member.

        :param events: the run's events, any order, each with its object digests: ``approval`` compares a call's
            signed ``tool-arguments`` digest. Only typed fields and digests are read.
        :param control_set_document: the run's v2 policy control set, exact bytes.
        :raises ValueError: the control set is not a valid v2 policy control set, or an event has no seq, or two
            claim the same one."""
        errors = AgentPolicy.validate(control_set_document)
        if errors:
            raise ValueError("Invalid policy control set: " + "; ".join(errors))
        doc = _parse(control_set_document)
        if doc.get("schemaVersion") != "2":
            raise ValueError("Facts v2 need a v2 policy control set (schemaVersion \"2\").")
        events = list(events)
        digests: dict = {}
        for a in events:  # the first event at a seq is the one (two at one seq are refused below anyway)
            digests.setdefault(_int((_obj(a.envelope.get("chain")) or {}).get("seq")), a.object_digests)
        entities = (_obj(doc.get("cedar")) or {}).get("entities") or []
        return _build_facts(agent_id, correlation_id, [a.envelope for a in events], None, (digests, entities))

    @staticmethod
    def enforcement(document: bytes) -> PolicyEnforcement:
        """The document's :class:`PolicyEnforcement`: its ``enforcement`` member with every default applied and the
        effective effect of each rule (``spec/agent-policy-control-set-v2.md`` §4 rule 7, §6). Raises
        :class:`ValueError` listing the problems when :meth:`validate` finds any."""
        errors = AgentPolicy.validate(document)
        if errors:
            raise ValueError("Invalid policy control set: " + "; ".join(errors))
        doc = _parse(document)
        e = doc.get("enforcement") or {}
        mode, default = e.get("mode", "observe"), e.get("defaultEffect", "deny")
        policies = (_obj((_obj(doc.get("cedar")) or {}).get("policies")) or {}).get("staticPolicies") or {}
        effects = {rid: p["annotations"].get("effect", default) if mode == "enforce" else "observe"
                   for rid, p in policies.items()}
        return PolicyEnforcement(mode, default, MappingProxyType(dict(e.get("lockedConfiguration") or {})),
                                 e.get("unknownTools", "allow"), e.get("onRuleError", "deny"),
                                 e.get("haltAfterDenials", 0), MappingProxyType(effects))

    @staticmethod
    def validate(document: bytes) -> list[str]:
        """Structural checks of v1 §2 and §4 rules 1–4 (rule 4 through I-JSON); for a v2 document
        (``"schemaVersion": "2"``) also v2 §1–§6: annotations and effects, at most 256 policies, the
        entities and their hierarchy, ``enforcement``, and ``schemaSha256`` naming Cedar schema v2. Strict
        validation against the Cedar schema needs a Cedar engine and is not done here.
        An empty list means valid."""
        doc, problem = _parse_checked(document)
        if doc is None:
            return [problem]
        v2 = "schemaVersion" in doc  # v2 §1: without it the document is v1, unchanged
        errors = [f"unknown member '{k}'" for k in doc if k not in (_MEMBERS_V2 if v2 else _MEMBERS)]
        if v2 and doc["schemaVersion"] != "2":
            errors.append("schemaVersion must be \"2\" (a v1 document carries none)")
        if not _non_empty_str(doc.get("id")):
            errors.append("id must be a non-empty string")
        if not _non_empty_str(doc.get("version")):
            errors.append("version must be a non-empty string")
        controls = doc.get("controls")
        if not isinstance(controls, list):
            errors.append("controls must be an array")
        elif any(not _non_empty_str(c) and not (isinstance(c, dict) and _non_empty_str(c.get("id"))) for c in controls):
            errors.append("each control is a string or an object with a string id")
        if "privateControls" in doc:
            pc = doc["privateControls"]
            if not isinstance(pc, list) or any(not isinstance(p, dict) or not _non_empty_str(p.get("id")) for p in pc):
                errors.append("privateControls must be an array of objects with a string id")
            elif len({p["id"] for p in pc}) != len(pc):
                errors.append("privateControls ids must be unique")
        if "coverage" in doc:
            cov = doc["coverage"]
            if not isinstance(cov, dict):
                errors.append("coverage must be an object")
            else:
                if not _non_empty_str(cov.get("sourceProfile")):
                    errors.append("coverage.sourceProfile must be a non-empty string")
                if not _non_empty_str(cov.get("scope")):
                    errors.append("coverage.scope must be a non-empty string")
                idle = cov.get("idleSeconds")
                if isinstance(idle, bool) or not isinstance(idle, int) or idle < 0:
                    errors.append("coverage.idleSeconds must be an integer >= 0")
        if "cedar" in doc:
            _validate_cedar(doc["cedar"], errors, v2)
        if v2 and "enforcement" in doc:
            _validate_enforcement(doc["enforcement"], errors)
        return errors

    @staticmethod
    def compute_digests(document: bytes) -> PolicyDigests:
        """The document's :class:`PolicyDigests`. Digests are defined for valid policy control sets only,
        so this raises :class:`ValueError` listing the problems when :meth:`validate` finds any."""
        errors = AgentPolicy.validate(document)
        if errors:
            raise ValueError("Invalid policy control set: " + "; ".join(errors))
        doc = _parse(document)
        scope = {k: v for k, v in doc.items() if k not in ("id", "version")}
        cedar = hash_bytes(canonicalize(doc["cedar"])) if isinstance(doc.get("cedar"), dict) else None
        return PolicyDigests(hash_bytes(canonicalize(scope)), cedar)

    @staticmethod
    def control_set_from_document(document: bytes) -> AgentControlSet:
        """The control set for ``control_set=``: the document's bytes unchanged, its ``id`` and
        ``version``, and the policy content type. Raises :class:`ValueError` listing every
        problem when the document is not a valid policy control set."""
        errors = AgentPolicy.validate(document)
        if errors:
            raise ValueError("Invalid policy control set: " + "; ".join(errors))
        doc = json.loads(document)
        return AgentControlSet(doc["id"], doc["version"], bytes(document), POLICY_CONTROL_SET_CONTENT_TYPE)
