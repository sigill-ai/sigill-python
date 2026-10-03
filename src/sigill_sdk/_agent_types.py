# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Agent Evidence Profiles v1 — the public types and the run bundle (§7)."""

from __future__ import annotations

import base64
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Optional, Sequence

from sigill_sdk._agent_profiles import (
    BUNDLE_FORMAT,
    BUNDLE_VERSION,
    MAX_ARTIFACTS,
    MAX_EVALUATIONS,
    MAX_PAYLOADS,
    MAX_DEPTH,
    _DuplicateMember,
    _int,
    _obj,
    _reject_constant,
    _reject_duplicates,
    _str,
    signature_sha256,
)
from sigill_sdk._canonical import canonicalize
from sigill_sdk._errors import SigillError

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


@dataclass(frozen=True)
class AgentConfiguration:
    """The agent's configuration, bound into the Control Artifact
    (``spec/agent-control-artifact-v1.md`` §3). Every part is optional. The
    bytes stay local; only their digests are sealed. They are usually
    confidential — share them only with parties entitled to read them."""

    instruction_set: Optional[bytes] = None
    """The stable instruction set (system prompt), without per-run context. Role ``instruction-set``."""
    tool_manifest: Optional[bytes] = None
    """Which tools exist and their schemas. Role ``tool-manifest``."""
    execution_policy: Optional[bytes] = None
    """What the agent is allowed to do: scope, allowlists, approval rules, limits. Role ``execution-policy``."""
    model_config: Optional[bytes] = None
    """Model configuration (model, sampling parameters, limits). Role ``model-config``."""


@dataclass(frozen=True)
class AgentDefinition:
    """The agent whose runs are recorded."""

    agent_id: str
    """Stable, opaque agent identifier (``actor.id`` of every event). Not a display name, no personal data."""
    agent_version: str
    """The agent configuration version that runs (``actor.version``, ``agent.version``)."""
    configuration: AgentConfiguration = field(default_factory=AgentConfiguration)
    identity_ref: Optional[str] = None
    """Optional reference to an identity assertion the producer holds (``agent.identityRef``)."""
    tenant_id: Optional[str] = None
    """Optional ``actor.tenantId`` on every event."""


@dataclass(frozen=True)
class AgentControlSet:
    """The control set the run will be evaluated against (role ``control-set``).
    A Control Evaluation later refers to this same object by URI and digest."""

    id: str
    version: str
    content: bytes
    content_type: str = "application/json"


@dataclass(frozen=True)
class AgentRunActor:
    """Who seals the Control Artifact (its ``actor``), e.g. the harness that starts the agent."""

    type: str
    id: str
    version: Optional[str] = None


@dataclass(frozen=True)
class AgentRunObject:
    """One detached object of an event: what the agent read, called or
    produced. The bytes are hashed locally and never transmitted."""

    role: str
    """The profile role, e.g. ``model-input``, ``tool-arguments``, ``model-output``."""
    data: bytes
    content_type: str = "application/octet-stream"
    uri: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    """Opaque URI; generated as ``urn:uuid:`` when omitted. No personal data."""

    @classmethod
    def text(cls, role: str, text: str, content_type: str = "text/plain") -> "AgentRunObject":
        """A UTF-8 text object."""
        return cls(role, text.encode("utf-8"), content_type)

    @classmethod
    def json(cls, role: str, value: Any) -> "AgentRunObject":
        """A JSON object, serialized in canonical (JCS) form so equal values hash equally."""
        return cls(role, canonicalize(value), "application/json")


@dataclass(frozen=True)
class AgentAuthorization:
    """A policy decision taken before an action (an ``authorization`` event)."""

    decision: str
    """The decision, in the producer's vocabulary: e.g. ``allowed``, ``allow_with_human_approval``, ``denied``."""
    policy_id: Optional[str] = None
    detail: Optional[str] = None
    """Optional free text (``step.detail``). No personal data."""


@dataclass(frozen=True)
class AgentTimestampPolicy:
    """The signed timestamp policy (common rules §4), locked in the Control
    Artifact. The default seals every event B-B and timestamps only to wrap
    up: the Control Artifact, ``run_end`` and each Control Evaluation."""

    profile: str = "throughput"
    """``throughput`` (default) or ``per-event``."""
    every_events: int = 0
    """Require a timestamp on the N-th event since the last one. 0 = off."""
    every_seconds: int = 0
    """Require a timestamp on the first event this many seconds after the last one. 0 = off."""
    consequential: bool = False
    """Timestamp every event marked consequential."""

    def to_json(self) -> dict:
        return {"profile": self.profile, "everyEvents": self.every_events, "everySeconds": self.every_seconds,
                "consequential": self.consequential}

    @classmethod
    def _from_json(cls, node: Any) -> Optional["AgentTimestampPolicy"]:
        """The policy a signed ``timestampPolicy`` member states, or None when it is malformed."""
        if not isinstance(node, dict) or len(node) != 4:
            return None
        ee, es = _int(node.get("everyEvents")), _int(node.get("everySeconds"))
        if (node.get("profile") not in ("throughput", "per-event") or ee is None or ee < 0 or es is None or es < 0
                or not isinstance(node.get("consequential"), bool)):
            return None
        return cls(node["profile"], ee, es, node["consequential"])


PER_EVENT = AgentTimestampPolicy(profile="per-event")
"""Every event timestamped: for low-volume, high-consequence agents."""


@dataclass(frozen=True)
class AgentRunArtifact:
    """One sealed artifact of any of the three profiles: the v2
    ``{envelope, signature}`` pair plus each object's SHA-256, keyed by URI."""

    envelope: dict
    signature: dict
    object_digests: dict[str, str]

    def __post_init__(self) -> None:
        if self.envelope is None or self.signature is None or self.object_digests is None:
            raise TypeError("envelope, signature and object_digests are required")

    @property
    def schema_name(self) -> Optional[str]:
        """``AgentControlArtifact``, ``AgentExecutionEvidence`` or ``ControlEvaluation``."""
        return _str(self.envelope.get("schemaName"))

    @property
    def seq(self) -> Optional[int]:
        """``chain.seq`` of an event; None for the other profiles."""
        return _int((_obj(self.envelope.get("chain")) or {}).get("seq"))

    @property
    def step_type(self) -> Optional[str]:
        """``step.type`` of an event; None for the other profiles."""
        return _str((_obj(self.envelope.get("step")) or {}).get("type"))

    @property
    def evidence_id(self) -> Optional[str]:
        return _str(self.envelope.get("evidenceId"))

    @property
    def signature_sha256(self) -> Optional[str]:
        """The binding digest other artifacts refer to this one by (common rules §2)."""
        return signature_sha256(self.signature)

    def to_dict(self) -> dict:
        return {
            "envelope": json.loads(json.dumps(self.envelope)),
            "signature": json.loads(json.dumps(self.signature)),
            "objectDigests": dict(self.object_digests),
        }


@dataclass(frozen=True)
class ControlResult:
    """One control's result in a Control Evaluation."""

    id: str
    result: str
    detail: Optional[str] = None


@dataclass(frozen=True)
class ControlEvaluationRequest:
    """What an independent verifier observed after a run, and how each control
    came out (``spec/control-evaluation-v1.md``). See :meth:`ControlEvaluation.seal`."""

    certificate_id: str
    """The verifier's own seal certificate — SHOULD differ from the run's."""
    verifier_id: str
    """Stable identifier of the verifier component (``actor.id``)."""
    verifier_version: str
    control_artifact: AgentRunArtifact
    """The run's Control Artifact; its control set (and baseline) are referred to by URI and digest."""
    run_end: AgentRunArtifact
    """The run's ``run_end`` artifact."""
    observed_state: Sequence[AgentRunObject]
    """The state read after the run (role ``observed-state``); at least one."""
    controls: Sequence[ControlResult]
    overall: str
    """PASS, FAIL or INDETERMINATE — asserted by the verifier, never derived."""
    evaluated_at: Optional[datetime] = None
    """When the state was read. Default: now."""
    include_baseline: bool = True
    """Also bind the Control Artifact's ``baseline-state``, when it has one."""
    qualified: bool = False


class AgentRunBundleFormatError(SigillError):
    """A bundle failed strict parsing; ``errors`` lists every problem found."""

    def __init__(self, errors: list[str]):
        super().__init__("Malformed agent run bundle: " + "; ".join(errors))
        self.errors = errors


def _depth(v: Any) -> int:
    """Nesting depth: a scalar is 0, an object or array one more than its deepest member.
    Iterative, so arbitrarily deep input cannot exhaust the stack."""
    deepest, stack = 0, [(v, 0)]
    while stack:
        node, level = stack.pop()
        if isinstance(node, (dict, list)):
            level += 1
            deepest = max(deepest, level)
            stack.extend((x, level) for x in (node.values() if isinstance(node, dict) else node))
    return deepest


@dataclass(frozen=True)
class AgentRunBundle:
    """The portable form of a controlled agent run (common rules §7): the
    Control Artifact, every event, any Control Evaluations, each object's
    digest, and optionally the payload bytes. Without payloads it reveals no
    content."""

    correlation_id: Optional[str]
    """An index for humans; verifiers take the run identifier only from the signed envelopes."""
    control_artifact: Optional[AgentRunArtifact]
    """The run's Control Artifact; None for a run-only bundle."""
    artifacts: list[AgentRunArtifact]
    """The Execution Evidence events."""
    evaluations: list[AgentRunArtifact] = field(default_factory=list)
    payloads: dict[str, bytes] = field(default_factory=dict)
    """Payload bytes keyed by object URI. Empty for a digests-only bundle."""

    def __post_init__(self) -> None:
        if self.payloads is None:
            object.__setattr__(self, "payloads", {})
        if self.evaluations is None:
            object.__setattr__(self, "evaluations", [])
        if not all(isinstance(a, AgentRunArtifact) for a in list(self.artifacts) + list(self.evaluations)):
            raise TypeError("artifacts and evaluations must be AgentRunArtifact instances")
        if self.control_artifact is not None and not isinstance(self.control_artifact, AgentRunArtifact):
            raise TypeError("control_artifact must be an AgentRunArtifact")
        for uri, data in self.payloads.items():
            if not isinstance(uri, str) or not isinstance(data, (bytes, bytearray)):
                raise TypeError("payloads must map str URIs to bytes")
        # The limits are properties of a bundle (§7), not only of its parser: a bundle built here must parse again.
        if len(self.artifacts) > MAX_ARTIFACTS:
            raise ValueError(f"more than {MAX_ARTIFACTS} artifacts")
        if len(self.evaluations) > MAX_EVALUATIONS:
            raise ValueError(f"more than {MAX_EVALUATIONS} evaluations")
        if len(self.payloads) > MAX_PAYLOADS:
            raise ValueError(f"more than {MAX_PAYLOADS} payloads")

    def with_payloads(self, payloads: Optional[Mapping[str, bytes]]) -> "AgentRunBundle":
        """The same bundle with (other) payload bytes, e.g. to share content with an auditor."""
        return AgentRunBundle(self.correlation_id, self.control_artifact, list(self.artifacts),
                              list(self.evaluations), dict(payloads or {}))

    def with_evaluations(self, *evaluations: AgentRunArtifact) -> "AgentRunBundle":
        """The same bundle with Control Evaluations added."""
        return AgentRunBundle(self.correlation_id, self.control_artifact, list(self.artifacts),
                              list(self.evaluations) + list(evaluations), dict(self.payloads))

    def to_dict(self) -> dict:
        out: dict = {
            "format": BUNDLE_FORMAT,
            "bundleVersion": BUNDLE_VERSION,
            "correlationId": self.correlation_id,
            "controlArtifact": self.control_artifact.to_dict() if self.control_artifact else None,
            "artifacts": [a.to_dict() for a in self.artifacts],
        }
        if self.evaluations:
            out["evaluations"] = [a.to_dict() for a in self.evaluations]
        if self.payloads:
            out["payloads"] = {u: base64.b64encode(d).decode() for u, d in sorted(self.payloads.items())}
        return out

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def parse(cls, value: Any) -> "AgentRunBundle":
        """Strict parse (§7) of a JSON string, bytes or already-parsed dict.
        Every entry must be well-formed; a malformed container raises
        :class:`AgentRunBundleFormatError` listing every problem."""
        if isinstance(value, (str, bytes)):
            try:
                # I-JSON forbids duplicate names, and parsers disagree on which value wins: refuse them (§7).
                value = json.loads(value, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
            except _DuplicateMember as ex:
                raise AgentRunBundleFormatError([f"bundle repeats a duplicate member name '{ex.name}'"]) from None
            except RecursionError:
                raise AgentRunBundleFormatError([f"bundle nests deeper than {MAX_DEPTH} levels"]) from None
            except ValueError as ex:
                raise AgentRunBundleFormatError([f"bundle is not valid JSON: {ex}"]) from None
            if _depth(value) > MAX_DEPTH:
                raise AgentRunBundleFormatError([f"bundle nests deeper than {MAX_DEPTH} levels"])
        if not isinstance(value, dict):
            raise AgentRunBundleFormatError(["bundle must be a JSON object"])
        errors: list[str] = []

        def shown(key: str) -> str:
            v = value.get(key)
            return v if isinstance(v, str) else json.dumps(v) if v is not None else "None"
        if value.get("format") != BUNDLE_FORMAT:
            errors.append(f"unsupported format '{shown('format')}' (expected {BUNDLE_FORMAT})")
        if value.get("bundleVersion") != BUNDLE_VERSION:
            errors.append(f"unsupported bundleVersion '{shown('bundleVersion')}' (expected {BUNDLE_VERSION})")

        def read(a: Any, label: str) -> Optional[AgentRunArtifact]:
            if not isinstance(a, dict):
                errors.append(f"{label}: not an object")
                return None
            if not isinstance(a.get("envelope"), dict) or not isinstance(a.get("signature"), dict):
                errors.append(f"{label}: lacks envelope or signature object")
                return None
            digests: dict[str, str] = {}
            ok = True
            if "objectDigests" in a:
                if not isinstance(a["objectDigests"], dict):
                    errors.append(f"{label}: objectDigests is not an object")
                    return None
                for uri, hex_ in a["objectDigests"].items():
                    if not isinstance(hex_, str) or not _HEX64.match(hex_):
                        errors.append(f"{label}: objectDigests['{uri}'] is not a 64-char hex digest")
                        ok = False
                    else:
                        digests[uri] = hex_
            return AgentRunArtifact(a["envelope"], a["signature"], digests) if ok else None

        control = read(value["controlArtifact"], "controlArtifact") if value.get("controlArtifact") is not None \
            else None

        artifacts: list[AgentRunArtifact] = []
        arr = value.get("artifacts")
        if not isinstance(arr, list):
            errors.append("artifacts[] missing or not an array")
        elif len(arr) > MAX_ARTIFACTS:
            errors.append(f"more than {MAX_ARTIFACTS} artifacts")
        else:
            if not arr and value.get("controlArtifact") is None:
                errors.append("bundle carries neither a Control Artifact nor any event")
            for i, a in enumerate(arr):
                r = read(a, f"artifacts[{i}]")
                if r is not None:
                    artifacts.append(r)

        evaluations: list[AgentRunArtifact] = []
        if value.get("evaluations") is not None:
            if not isinstance(value["evaluations"], list):
                errors.append("evaluations is not an array")
            elif len(value["evaluations"]) > MAX_EVALUATIONS:
                errors.append(f"more than {MAX_EVALUATIONS} evaluations")
            else:
                for i, a in enumerate(value["evaluations"]):
                    r = read(a, f"evaluations[{i}]")
                    if r is not None:
                        evaluations.append(r)

        payloads: dict[str, bytes] = {}
        if value.get("payloads") is not None:
            if not isinstance(value["payloads"], dict):
                errors.append("payloads is not an object")
            elif len(value["payloads"]) > MAX_PAYLOADS:
                errors.append(f"more than {MAX_PAYLOADS} payloads")
            else:
                for uri, b64 in value["payloads"].items():
                    if not isinstance(b64, str) or len(b64) % 4 != 0 or not _B64.match(b64):
                        errors.append(f"payloads['{uri}'] is not valid base64")
                        continue
                    try:
                        payloads[uri] = base64.b64decode(b64, validate=True)
                    except ValueError:
                        errors.append(f"payloads['{uri}'] is not valid base64")
        if errors:
            raise AgentRunBundleFormatError(errors)
        return cls(_str(value.get("correlationId")), control, artifacts, evaluations, payloads)
