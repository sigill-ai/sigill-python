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
from typing import Any, Optional

from sigill_sdk._agent_profiles import _is_i_json, _reject_constant, _reject_duplicates
from sigill_sdk._agent_types import AgentControlSet
from sigill_sdk._canonical import canonicalize, hash_bytes

POLICY_CONTROL_SET_CONTENT_TYPE = "application/vnd.sigill.control-set+json"

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


class AgentPolicy:
    """Declared agent policies: build, identify and check a policy control set."""

    CONTROL_SET_CONTENT_TYPE = POLICY_CONTROL_SET_CONTENT_TYPE

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
