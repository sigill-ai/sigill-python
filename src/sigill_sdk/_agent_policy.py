# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Declared agent policies (``spec/agent-policy-control-set-v1.md``).

A control-set document with the content type
``application/vnd.sigill.control-set+json`` that carries forbid-only Cedar rules,
private controls and a coverage contract. Keep the approved document as a file
and pass the same bytes to every run.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence

from sigill_sdk._agent_profiles import _int, _is_i_json, _obj, _reject_constant, _reject_duplicates, _str
from sigill_sdk._agent_types import AgentControlSet
from sigill_sdk._canonical import canonicalize, hash_bytes

POLICY_CONTROL_SET_CONTENT_TYPE = "application/vnd.sigill.control-set+json"
FACTS_VERSION = "1"
"""The facts version this SDK builds (``spec/agent-policy-control-set-v1.md`` §5)."""

_MEMBERS = {"id", "version", "controls", "cedar", "privateControls", "coverage"}
_RULE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# I-JSON also covers §4 rule 4: integers beyond ±2^53-1 are refused anywhere in the document.
_NOT_I_JSON = "the document is not an I-JSON object (no repeated names, integers within ±2^53-1)"


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


def _parse(document: bytes) -> Optional[dict]:
    try:
        doc = json.loads(document, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError):  # a repeated name raises a ValueError subclass too
        return None
    return doc if isinstance(doc, dict) and _is_i_json(doc) else None


def _non_empty_str(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def _validate_cedar(cedar: Any, errors: list[str]) -> None:
    if not isinstance(cedar, dict):
        errors.append("cedar must be an object")
        return
    sha = cedar.get("schemaSha256")
    if not isinstance(sha, str) or not _HEX64.match(sha):
        errors.append("cedar.schemaSha256 must be a lowercase hex SHA-256")
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


def _build_facts(agent_id: str, correlation_id: str, events: Iterable[dict],
                 claimed_missing: Optional[Sequence[int]]) -> PolicyFacts:
    """With ``claimed_missing``, ``events`` is an evaluator's contiguous prefix and the gaps it reported above it
    are taken as given: what a verifier rebuilds (``control-evaluation-v2.md`` §4.5)."""
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
    saw_approval = False
    for seq, e in prefix:
        type_ = step_type(e)
        consequential = consequential_of(e)
        if consequential:
            consequential_count += 1
        requests.append({
            "seq": seq,
            "principal": principal(),
            "action": {"type": "Action", "id": type_},
            "resource": {"type": "Tool", "id": tool(e, "name") or ""} if type_ in ("tool_call", "tool_result")
            else {"type": "Step", "id": str(seq)},
            "context": _context(consequential, tool(e, "operation") or "", seq,
                                "unbound" if saw_approval else "none", is_child_run, 0, consequential_count, 0),
        })
        if type_ == "human_approval":
            saw_approval = True

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
            return not paired and consequential_of(c)
        requests.append({
            "seq": "run",
            "principal": principal(),
            "action": {"type": "Action", "id": "run"},
            "resource": {"type": "Run", "id": correlation_id},
            "context": _context(False, "", final_seq, "none", is_child_run, final_seq, consequential_count,
                                sum(1 for s, c in calls if unpaired(s, c))),
        })

    data = canonicalize({
        "factsVersion": FACTS_VERSION,
        "throughSeq": through_seq,
        "missingSeqs": missing,
        "runLevel": run_level,
        "requests": requests,
    })
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
    def validate(document: bytes) -> list[str]:
        """Structural checks of §2 and §4 rules 1–4 (rule 4 through I-JSON). Strict validation
        against the Cedar schema (rule 5) needs a Cedar engine and is not done here.
        An empty list means valid."""
        doc = _parse(document)
        if doc is None:
            return [_NOT_I_JSON]
        errors = [f"unknown member '{k}'" for k in doc if k not in _MEMBERS]
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
            _validate_cedar(doc["cedar"], errors)
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
