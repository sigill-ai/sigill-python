# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""AgentExecutionProfileV1 — record and verify multi-step agent runs.

See ``spec/agent-execution-profile-v1.md``. A run is an ordered sequence of
ordinary AI evidence v2 artifacts, one per security-relevant step, each sealed
blind (digests and opaque URIs only) and chained to the previous step's
signature. The verifier reads the envelopes locally and checks each
signature over digests only.

Mirrors the .NET SDK one-to-one: same profile rules, same check names and
verdicts, same bundle format, same cross-language vectors.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, Sequence

from sigill_sdk._canonical import canonicalize, hash_bytes
from sigill_sdk._errors import SigillError
from sigill_sdk._schema import is_uuid, parse_date_time, validate_envelope_v2
from sigill_sdk._sign_objects import ENVELOPE_URI, SignedObjectDigest

PROFILE = "AgentExecutionProfileV1"
"""The bundle's ``profile`` value."""

BUNDLE_VERSION = "1"

EXTENSION_KEY = "ai.sigill.agent-execution"
"""Key of the signed profile block under ``extensions``."""

CONFIGURATION_KINDS = ("instruction-set", "tool-manifest", "model-config", "execution-policy")
"""The configuration object kinds bound by ``run_start`` and the identity record (§3.2)."""

OPTIONAL_CONFIGURATION_KINDS = ("model-config",)
"""Configuration kinds that may be absent — on both sides, or on neither (§3.2)."""

IDENTITY_KINDS = ("agent-manifest",) + CONFIGURATION_KINDS + ("registration-record",)
"""The object kinds an identity record carries, at most one each; all but the
optional configuration kinds are required (§3.6)."""

_AUTH_DECISIONS = ("allowed", "denied")

RESERVED_EXTENSION_KEYS = frozenset({
    "stepType", "agentVersion", "eventTime", "consequential", "timestamp", "objectKinds",
    "agentIdentityEvidenceId", "assuranceProfile", "timestampPolicy", "finalSeq", "finalPrevSignatureSha256",
    "runDisposition", "recordType", "agentId", "configSha256", "registeredBy", "delegation", "parentRun",
})
"""Profile-block names a producer extension must not use (§6)."""

_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")
_I_JSON_MAX_INT = 2 ** 53

MAX_ARTIFACTS = 2000
"""Upper bound on artifacts per bundle (§7)."""

SCOPE = (
    "Verifies the supplied record: integrity and capture order of what was sealed, under the signatures and "
    "timestamps shown. Does not establish that every event was captured, that producer-claimed event times "
    "are true, or that no other run took place."
)
"""What a verdict does and does not establish. Show it next to the verdict."""

_MAX_MISSING_LISTED = 64
_DISPOSITIONS = ("completed", "failed", "aborted")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


# ── Small helpers ───────────────────────────────────────────────────────────

def _str(v: Any) -> Optional[str]:
    return v if isinstance(v, str) else None


def _int(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    return None


def _obj(v: Any) -> Optional[dict]:
    return v if isinstance(v, dict) else None


def _b64u_decode(s: str) -> bytes:
    """Strict base64url (no padding, nothing outside the alphabet)."""
    if not isinstance(s, str) or not _B64URL.match(s) or len(s) % 4 == 1:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _is_i_json(v: Any) -> bool:
    """No integers beyond ±2^53 and no lone surrogates (§7)."""
    if v is None or isinstance(v, (bool, float)):
        return True
    if isinstance(v, int):
        return abs(v) <= _I_JSON_MAX_INT
    if isinstance(v, str):
        return not any(0xD800 <= ord(c) <= 0xDFFF for c in v)
    if isinstance(v, list):
        return all(_is_i_json(x) for x in v)
    if isinstance(v, dict):
        return all(isinstance(k, str) and _is_i_json(k) and _is_i_json(x) for k, x in v.items())
    return False


def _norm_id(v: Optional[str]) -> Optional[str]:
    """§8: ``urn:uuid:`` and bare forms of the same UUID compare equal."""
    if v is None:
        return None
    v = v[9:] if v.lower().startswith("urn:uuid:") else v
    return v.lower()


def _classical_entries(signature: Mapping[str, Any]) -> list[tuple[dict, Optional[dict]]]:
    """(entry, protected header or None if unreadable) for every non-ML-DSA entry."""
    if isinstance(signature.get("signatures"), list):
        entries = signature["signatures"]
    elif signature.get("signature") is not None:
        entries = [signature]
    else:
        entries = []
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        header = None
        try:
            parsed = json.loads(_b64u_decode(e.get("protected")))
            header = parsed if isinstance(parsed, dict) else None
        except Exception:  # unreadable protected header: counts as classical (§4)
            pass
        alg = header.get("alg") if header else None
        if isinstance(alg, str) and alg.upper().startswith("ML-DSA"):
            continue
        out.append((e, header))
    return out


def signer_of(signature: Mapping[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """The signer of an artifact (§4.1): ``(x5t#S256, None)``, or ``(None, problem)``.
    Requires exactly one classical signature entry whose protected header
    carries ``x5c`` and an ``x5t#S256`` equal to the SHA-256 of ``x5c[0]``."""
    classical = _classical_entries(signature)
    if len(classical) != 1:
        return None, f"carries {len(classical)} classical signatures; exactly one classical signature is required"
    _, header = classical[0]
    if header is None or not isinstance(header.get("alg"), str):
        return None, "its classical signature has no readable protected header"
    thumb, x5c = header.get("x5t#S256"), header.get("x5c")
    if not isinstance(thumb, str) or not isinstance(x5c, list) or not x5c or not isinstance(x5c[0], str):
        return None, "its protected header names no signing certificate (x5c, x5t#S256)"
    try:
        leaf = base64.b64decode(x5c[0], validate=True)
    except ValueError:
        return None, "its x5c[0] is not valid base64"
    if base64.urlsafe_b64encode(hashlib.sha256(leaf).digest()).rstrip(b"=").decode() != thumb:
        return None, "its x5t#S256 is not the SHA-256 of x5c[0]"
    return thumb, None


def _truncate(t: datetime) -> datetime:
    """The millisecond precision eventTime is signed with (§6.7)."""
    return t.replace(microsecond=(t.microsecond // 1000) * 1000)


def _format_time(t: datetime) -> str:
    t = t.astimezone(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _parse_time(s: str) -> Optional[datetime]:
    return parse_date_time(s)


def chain_digest(signature: Mapping[str, Any]) -> Optional[str]:
    """The chain digest of an artifact (§4): lowercase SHA-256 hex over the
    base64url-decoded JWS Signature Value of its classical signature — the
    first ``signatures[]`` entry whose protected ``alg`` is not ML-DSA, or the
    ``signature`` member of a flattened JWS. Unprotected headers are
    excluded, so augmenting an artifact later never breaks the chain.
    Returns None when the JWS carries no usable classical signature."""
    for e, _ in _classical_entries(signature):
        sig = _str(e.get("signature"))
        if sig is None:
            continue
        try:
            return hash_bytes(_b64u_decode(sig))
        except ValueError:
            return None
    return None


# ── Types ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AgentModelRef:
    """The model an agent runs on, bound into every step's envelope."""

    provider: str
    name: str
    deployment_id: Optional[str] = None


@dataclass(frozen=True)
class AgentConfiguration:
    """The agent's configuration (§3.2): the four objects every ``run_start``
    and identity record bind. The bytes stay local; only their digests are
    sealed. They are usually confidential — share them only with parties
    entitled to read them."""

    instruction_set: bytes
    """The stable instruction set (system prompt), without per-run context."""
    tool_manifest: bytes
    execution_policy: bytes
    """What the agent is allowed to do: scope, allowlists, approval rules, limits."""
    model_config: Optional[bytes] = None
    """Optional model configuration (sampling parameters, limits)."""

    def objects(self) -> list["AgentRunObject"]:
        """The configuration as detached objects, in a fixed order."""
        objs = [
            AgentRunObject("instruction-set", "input", self.instruction_set, "text/plain"),
            AgentRunObject("tool-manifest", "input", self.tool_manifest, "application/json"),
        ]
        if self.model_config is not None:
            objs.append(AgentRunObject("model-config", "input", self.model_config, "application/json"))
        objs.append(AgentRunObject("execution-policy", "input", self.execution_policy, "application/json"))
        return objs


@dataclass(frozen=True)
class AgentDefinition:
    """The agent whose runs are recorded."""

    agent_id: str
    """Stable, opaque identifier bound as ``actor.id``. No personal data."""
    agent_version: str
    model: AgentModelRef
    configuration: AgentConfiguration
    display_name: Optional[str] = None
    tenant_id: Optional[str] = None
    business_context: Optional[str] = None
    manifest: Optional[bytes] = None
    """Agent manifest bytes. When None the SDK derives a canonical manifest."""

    def manifest_bytes(self) -> bytes:
        if self.manifest is not None:
            return self.manifest
        model: dict = {"provider": self.model.provider, "name": self.model.name}
        if self.model.deployment_id is not None:
            model["deploymentId"] = self.model.deployment_id
        m: dict = {"agentId": self.agent_id, "agentVersion": self.agent_version, "model": model}
        if self.display_name is not None:
            m["displayName"] = self.display_name
        return canonicalize(m)


def configuration_digest(agent_manifest: bytes, configuration: AgentConfiguration) -> str:
    """The configuration digest (§3.6): SHA-256 over the JCS of the
    configuration objects' SHA-256 digests (``modelConfig`` only when bound)."""
    return _configuration_digest_from_hex(
        hash_bytes(agent_manifest), hash_bytes(configuration.instruction_set), hash_bytes(configuration.tool_manifest),
        hash_bytes(configuration.model_config) if configuration.model_config is not None else None,
        hash_bytes(configuration.execution_policy))


def _configuration_digest_from_hex(manifest: str, instruction_set: str, tool_manifest: str,
                                   model_config: Optional[str], execution_policy: str) -> str:
    d = {"agentManifest": manifest, "instructionSet": instruction_set, "toolManifest": tool_manifest,
         "executionPolicy": execution_policy}
    if model_config is not None:
        d["modelConfig"] = model_config
    return hash_bytes(canonicalize(d))


@dataclass(frozen=True)
class AgentAuthorization:
    """A policy decision taken before an action (§3.4)."""

    decision: str
    """``allowed`` or ``denied``."""
    policy_id: Optional[str] = None
    reason: Optional[str] = None

    def to_json(self) -> dict:
        if self.decision not in _AUTH_DECISIONS:
            raise ValueError("authorization decision must be 'allowed' or 'denied'.")
        out: dict = {"decision": self.decision}
        if self.policy_id is not None:
            out["policyId"] = self.policy_id
        if self.reason is not None:
            out["reason"] = self.reason
        return out


@dataclass(frozen=True)
class AgentRunObject:
    """One detached object of a step. The bytes are hashed locally and never
    transmitted."""

    kind: str
    """Profile kind (§3.5), e.g. ``tool-arguments``, ``assistant-reply``."""
    role: str
    """v2 role: prompt | input | context | output | artifact | log."""
    data: bytes
    content_type: str = "application/octet-stream"
    uri: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    """Opaque URI. No personal data."""

    @classmethod
    def text(cls, kind: str, role: str, text: str, content_type: str = "text/plain") -> "AgentRunObject":
        return cls(kind=kind, role=role, data=text.encode("utf-8"), content_type=content_type)

    @classmethod
    def json(cls, kind: str, role: str, value: Any) -> "AgentRunObject":
        """A JSON value, serialized in canonical (JCS) form so equal values hash equally."""
        return cls(kind=kind, role=role, data=canonicalize(value), content_type="application/json")


@dataclass(frozen=True)
class AgentTimestampPolicy:
    """The signed timestamp policy (§5)."""

    profile: str = "throughput"
    """"throughput" (default) or "per-event"."""
    every_events: int = 10
    """Require a timestamp on the N-th step since the last one. 0 = off."""
    every_seconds: int = 300
    """Require a timestamp on the first step this many seconds after the last one. 0 = off."""
    run_start: bool = False

    def to_json(self) -> dict:
        return {
            "profile": self.profile,
            "everyEvents": self.every_events,
            "everySeconds": self.every_seconds,
            "runStart": self.run_start,
            "runEnd": True,
            "consequential": True,
        }


PER_EVENT = AgentTimestampPolicy(profile="per-event")
"""Every step timestamped: for low-volume, high-consequence agents."""


@dataclass(frozen=True)
class AgentRunArtifact:
    """One sealed artifact of a run (or the identity record): the v2
    ``{envelope, signature}`` pair plus each object's SHA-256, keyed by URI."""

    envelope: dict
    signature: dict
    object_digests: dict[str, str]

    @property
    def seq(self) -> Optional[int]:
        return _int((_obj(self.envelope.get("chain")) or {}).get("seq"))

    @property
    def step_type(self) -> Optional[str]:
        ext = _obj((_obj(self.envelope.get("extensions")) or {}).get(EXTENSION_KEY)) or {}
        return _str(ext.get("stepType"))

    @property
    def evidence_id(self) -> Optional[str]:
        return _str(self.envelope.get("evidenceId"))

    @property
    def chain_digest(self) -> Optional[str]:
        return chain_digest(self.signature)

    def to_dict(self) -> dict:
        return {
            "envelope": json.loads(json.dumps(self.envelope)),
            "signature": json.loads(json.dumps(self.signature)),
            "objectDigests": dict(self.object_digests),
        }


class _DuplicateMember(ValueError):
    def __init__(self, name: str):
        super().__init__(name)
        self.name = name


def _reject_duplicates(pairs: list) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise _DuplicateMember(k)
        out[k] = v
    return out


class AgentRunBundleFormatError(SigillError):
    """A bundle failed strict parsing; ``errors`` lists every problem found."""

    def __init__(self, errors: list[str]):
        super().__init__("Malformed agent run bundle: " + "; ".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class AgentRunBundle:
    """The portable form of a run (§7). Without payloads it reveals no content."""

    correlation_id: Optional[str]
    agent_identity: Optional[AgentRunArtifact]
    artifacts: list[AgentRunArtifact]
    payloads: dict[str, bytes] = field(default_factory=dict)
    profile: str = PROFILE

    def __post_init__(self) -> None:
        if not all(isinstance(a, AgentRunArtifact) for a in self.artifacts):
            raise TypeError("artifacts must be AgentRunArtifact instances")
        if self.agent_identity is not None and not isinstance(self.agent_identity, AgentRunArtifact):
            raise TypeError("agent_identity must be an AgentRunArtifact")
        for uri, data in self.payloads.items():
            if not isinstance(uri, str) or not isinstance(data, (bytes, bytearray)):
                raise TypeError("payloads must map str URIs to bytes")

    def with_payloads(self, payloads: Optional[Mapping[str, bytes]]) -> "AgentRunBundle":
        """The same bundle with (other) payload bytes, e.g. to share content with an auditor."""
        return AgentRunBundle(self.correlation_id, self.agent_identity, list(self.artifacts),
                              dict(payloads or {}), self.profile)

    def to_dict(self) -> dict:
        out: dict = {
            "profile": self.profile,
            "bundleVersion": BUNDLE_VERSION,
            "correlationId": self.correlation_id,
            "agentIdentity": self.agent_identity.to_dict() if self.agent_identity else None,
            "artifacts": [a.to_dict() for a in self.artifacts],
        }
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
                value = json.loads(value, object_pairs_hook=_reject_duplicates)
            except _DuplicateMember as ex:
                raise AgentRunBundleFormatError([f"bundle repeats a duplicate member name '{ex.name}'"]) from None
            except ValueError as ex:
                raise AgentRunBundleFormatError([f"bundle is not valid JSON: {ex}"]) from None
        if not isinstance(value, dict):
            raise AgentRunBundleFormatError(["bundle must be a JSON object"])
        errors: list[str] = []
        profile = value.get("profile")
        if profile != PROFILE:
            errors.append(f"unsupported profile '{profile}' (expected {PROFILE})")
        if value.get("bundleVersion") != BUNDLE_VERSION:
            errors.append(f"unsupported bundleVersion '{value.get('bundleVersion')}' (expected {BUNDLE_VERSION})")

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

        artifacts: list[AgentRunArtifact] = []
        arr = value.get("artifacts")
        if not isinstance(arr, list) or not arr:
            errors.append("artifacts[] missing or empty")
        elif len(arr) > MAX_ARTIFACTS:
            errors.append(f"more than {MAX_ARTIFACTS} artifacts")
        else:
            for i, a in enumerate(arr):
                r = read(a, f"artifacts[{i}]")
                if r is not None:
                    artifacts.append(r)
        identity = read(value["agentIdentity"], "agentIdentity") if value.get("agentIdentity") is not None else None
        payloads: dict[str, bytes] = {}
        if value.get("payloads") is not None:
            if not isinstance(value["payloads"], dict):
                errors.append("payloads is not an object")
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
        return cls(_str(value.get("correlationId")), identity, artifacts, payloads)


# ── The §5 coverage rule ────────────────────────────────────────────────────

class _TimestampCoverage:
    """Walked in seq order. Used by the recorder to decide which steps it must
    timestamp and by the verifier to recompute the same decision from the
    signed policy — one implementation, so the two never drift apart."""

    def __init__(self, profile: str, every_events: int, every_seconds: int, run_start: bool):
        self._profile, self._every_events, self._every_seconds, self._run_start = (
            profile, every_events, every_seconds, run_start)
        self._since_stamp = 0
        self._last_stamp_time: Optional[datetime] = None

    def next(self, seq: int, step_type: str, consequential: bool, declared_required: bool,
             event_time: Optional[datetime]) -> bool:
        last = self._last_stamp_time
        required = (
            self._profile == "per-event"
            or step_type in ("run_end", "checkpoint")
            or consequential
            or (seq == 0 and self._run_start)
            or (self._every_events > 0 and self._since_stamp + 1 >= self._every_events)
            or (self._every_seconds > 0 and seq > 0 and last is not None and event_time is not None
                and (event_time - last).total_seconds() >= self._every_seconds)
            or declared_required
        )
        if required:
            self._since_stamp = 0
            self._last_stamp_time = event_time
        else:
            self._since_stamp += 1
        if seq == 0 and self._last_stamp_time is None:
            self._last_stamp_time = event_time
        return required


def _build_envelope(evidence_id: str, created_at: datetime, purpose_category: str, agent: AgentDefinition,
                    activity_name: str, correlation_id: Optional[str], parent_evidence_id: Optional[str],
                    objects: Sequence[AgentRunObject], chain_seq: Optional[int], prev_chain_digest: Optional[str],
                    block: dict) -> dict:
    activity: dict = {"name": activity_name}
    if correlation_id is not None:
        activity["correlationId"] = correlation_id
    if parent_evidence_id is not None:
        activity["parentEvidenceId"] = parent_evidence_id
    purpose: dict = {"category": purpose_category}
    if agent.business_context is not None:
        purpose["businessContext"] = agent.business_context
    actor: dict = {"type": "agent", "id": agent.agent_id}
    if agent.tenant_id is not None:
        actor["tenantId"] = agent.tenant_id
    model: dict = {"provider": agent.model.provider, "name": agent.model.name}
    if agent.model.deployment_id is not None:
        model["deploymentId"] = agent.model.deployment_id
    block["objectKinds"] = {o.uri: o.kind for o in objects}
    env: dict = {
        "schemaName": "AiEvidenceEnvelope",
        "schemaVersion": "2",
        "evidenceId": evidence_id,
        "createdAt": _format_time(created_at),
        "purpose": purpose,
        "actor": actor,
        "activity": activity,
        "model": model,
        "objects": [{"uri": o.uri, "role": o.role, "contentType": o.content_type, "sizeBytes": len(o.data)}
                    for o in objects],
    }
    if chain_seq is not None:
        chain: dict = {"seq": chain_seq}
        if prev_chain_digest is not None:
            chain["prevSignatureSha256"] = prev_chain_digest
        env["chain"] = chain
    env["extensions"] = {EXTENSION_KEY: block}
    return env


def _digests(objects: Sequence[AgentRunObject]) -> dict[str, str]:
    d: dict[str, str] = {}
    for o in objects:
        if o.uri in d:
            raise ValueError(f"Duplicate object URI '{o.uri}'.")
        d[o.uri] = hash_bytes(o.data)
    return d


def _seal(client: Any, envelope: dict, objects: Sequence[AgentRunObject], certificate_id: str, *,
          timestamp: bool, qualified: bool):
    # No operation label: a step type can be producer-defined, and only
    # digests, opaque URIs and content types reach the sealing service (§6).
    return client.sign_object_hashes(
        hash_bytes(canonicalize(envelope)),
        [SignedObjectDigest(uri=o.uri, hash_hex=hash_bytes(o.data), content_type=o.content_type) for o in objects],
        str(certificate_id),
        timestamp=timestamp,
        qualified=qualified and timestamp,
    )


def _prevalidate(envelope: dict) -> None:
    """§6: never seal an envelope the verifier would reject. Raises ValueError."""
    if not _is_i_json(envelope):
        raise ValueError("the envelope is not valid I-JSON")
    ext = envelope["extensions"][EXTENSION_KEY]
    is_identity = ext.get("recordType") == "agent-identity"
    errs = _conformance(envelope, ext, ext.get("stepType") or "", is_identity)
    if errs:
        raise ValueError("the step would not verify: " + "; ".join(errs))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _register_identity(client: Any, agent: AgentDefinition, certificate_id: str, registered_by: Optional[str],
                       qualified: bool, clock: Callable[[], datetime]) -> tuple[AgentRunArtifact, list[AgentRunObject]]:
    now = _truncate(clock())
    manifest = agent.manifest_bytes()
    config_sha = configuration_digest(manifest, agent.configuration)
    registration: dict = {
        "action": "agent-registration",
        "mode": "automatic-on-first-use",
        "agentId": agent.agent_id,
        "configSha256": config_sha,
        "registeredAt": _format_time(now),
    }
    if registered_by is not None:
        registration["registeredBy"] = registered_by
    objects = [AgentRunObject("agent-manifest", "input", manifest, "application/json")]
    objects += agent.configuration.objects()
    objects.append(AgentRunObject("registration-record", "input", canonicalize(registration), "application/json"))
    block: dict = {
        "recordType": "agent-identity",
        "stepType": "record:agent-identity",
        "agentId": agent.agent_id,
        "agentVersion": agent.agent_version,
        "configSha256": config_sha,
        "eventTime": _format_time(now),
    }
    if registered_by is not None:
        block["registeredBy"] = registered_by
    envelope = _build_envelope(str(uuid.uuid4()), now, "agent-identity", agent, "agent_identity",
                               None, None, objects, None, None, block)
    _prevalidate(envelope)
    result = _seal(client, envelope, objects, certificate_id, timestamp=True, qualified=qualified)
    if result.timestamped_by is None:
        raise SigillError("The identity record must be timestamped, but the seal carries no timestamp.")
    return AgentRunArtifact(envelope, result.signature, _digests(objects)), objects


def register_agent_identity(client: Any, agent: AgentDefinition, certificate_id: str, *,
                            registered_by: Optional[str] = None, qualified: bool = False) -> AgentRunArtifact:
    """Registers an identity record (§3.6) for the agent's current
    configuration. Store it and pass it as ``identity=`` to
    :meth:`AgentRun.start` while the configuration is unchanged."""
    return _register_identity(client, agent, certificate_id, registered_by, qualified, _utcnow)[0]


# ── The recorder ────────────────────────────────────────────────────────────

class AgentRun:
    """Records one agent run under AgentExecutionProfileV1.

    ::

        run = client.start_agent_run(agent, certificate_id=cert_id)
        run.record_tool_call("lookup_ticket", args_json)
        run.record_tool_result("lookup_ticket", result_json)
        run.record_model_output(answer)
        bundle = run.finish("completed")

    Steps are sealed one at a time, in call order; calls may come from any
    thread. A sealing failure raises and stops the chain (§6): later calls
    raise :class:`RuntimeError`, and the bundle so far verifies as open or
    invalid, never as finalized.
    """

    def __init__(self, *, _client: Any, _agent: AgentDefinition, _certificate_id: str,
                 _policy: AgentTimestampPolicy, _correlation_id: str, _retain: bool, _qualified: bool,
                 _on_sealed: Optional[Callable[[AgentRunArtifact], None]], _clock: Callable[[], datetime]):
        self._client = _client
        self._agent = _agent
        self._certificate_id = _certificate_id
        self._policy = _policy
        self._retain = _retain
        self._qualified = _qualified
        self._on_sealed = _on_sealed
        self._clock = _clock
        self._lock = threading.RLock()
        self._artifacts: list[AgentRunArtifact] = []
        self._payloads: dict[str, bytes] = {}
        self._coverage = _TimestampCoverage(_policy.profile, _policy.every_events, _policy.every_seconds,
                                            _policy.run_start)
        self._prev_chain_digest: Optional[str] = None
        self._prev_evidence_id: Optional[str] = None
        self._broken = False
        self._finished = False
        self.correlation_id = _correlation_id
        self.identity: AgentRunArtifact = None  # type: ignore[assignment]

    @classmethod
    def start(cls, client: Any, agent: AgentDefinition, *, certificate_id: str,
              identity: Optional[AgentRunArtifact] = None, registered_by: Optional[str] = None,
              timestamp_policy: Optional[AgentTimestampPolicy] = None, correlation_id: Optional[str] = None,
              start_objects: Optional[Sequence[AgentRunObject]] = None, retain_payloads: bool = False,
              qualified: bool = False, on_artifact_sealed: Optional[Callable[[AgentRunArtifact], None]] = None,
              _clock: Optional[Callable[[], datetime]] = None) -> "AgentRun":
        """Opens a run: registers the identity record unless ``identity`` is
        supplied, then seals ``run_start`` binding the agent's configuration.

        :param identity: a previously registered identity record for this exact
            configuration; reuse it across runs while the configuration is unchanged.
        :param registered_by: opaque identifier of who registers a new identity record.
        :param retain_payloads: keep payload bytes so :meth:`to_bundle` can include
            them. Off by default: a digests-only bundle reveals no content.
        :param on_artifact_sealed: called after each artifact is sealed, in chain
            order — persist it here so a crash loses nothing. An exception
            propagates; the run itself stays usable.
        :raises ValueError: the supplied identity record was registered for a different configuration.
        """
        policy = timestamp_policy or AgentTimestampPolicy()
        if policy.profile not in ("throughput", "per-event"):
            raise ValueError("timestamp_policy.profile must be 'throughput' or 'per-event'.")
        if policy.every_events < 0 or policy.every_seconds < 0:
            raise ValueError("timestamp_policy cadence values must be zero or positive.")
        clock = _clock or _utcnow

        config_sha = configuration_digest(agent.manifest_bytes(), agent.configuration)
        registered_objects: Optional[list[AgentRunObject]] = None
        if identity is not None:
            ext = _obj((_obj(identity.envelope.get("extensions")) or {}).get(EXTENSION_KEY)) or {}
            if (ext.get("configSha256") != config_sha or ext.get("agentId") != agent.agent_id
                    or ext.get("agentVersion") != agent.agent_version):
                raise ValueError("The supplied identity record was registered for a different agent, version or "
                                 "configuration; register a new one.")
        else:
            identity, registered_objects = _register_identity(client, agent, certificate_id, registered_by,
                                                              qualified, clock)

        run = cls(_client=client, _agent=agent, _certificate_id=str(certificate_id), _policy=policy,
                  _correlation_id=correlation_id or f"urn:uuid:{uuid.uuid4()}", _retain=retain_payloads,
                  _qualified=qualified, _on_sealed=on_artifact_sealed, _clock=clock)
        run.identity = identity
        run._prev_evidence_id = identity.evidence_id
        if retain_payloads:
            if registered_objects is not None:
                run._payloads.update({o.uri: o.data for o in registered_objects})
            else:
                run._payloads.update(_identity_payloads(agent, identity))

        objects = agent.configuration.objects()
        objects.extend(start_objects or [])
        start = run._seal_step("run_start", objects, {
            "agentIdentityEvidenceId": identity.evidence_id,
            "assuranceProfile": policy.profile,
            "timestampPolicy": policy.to_json(),
        }, consequential=False)
        # §4.1: one certificate per run, identity record included.
        if signer_of(start.signature)[0] != signer_of(identity.signature)[0]:
            run._broken = True
            raise SigillError("The identity record was sealed with a different certificate than this run "
                              "(certificate rotated?); register a new identity record.")
        run._notify(start)
        return run

    @property
    def artifacts(self) -> list[AgentRunArtifact]:
        with self._lock:
            return list(self._artifacts)

    @property
    def is_broken(self) -> bool:
        return self._broken

    @property
    def is_finished(self) -> bool:
        return self._finished

    # ── steps ──

    def record(self, step_type: str, objects: Optional[Sequence[AgentRunObject]] = None,
               extension: Optional[dict] = None, *, consequential: bool = False) -> AgentRunArtifact:
        """Seals one step. ``consequential`` marks an external side effect (a
        write-class tool call, a delivered message); such steps are always
        timestamped. ``extension`` adds producer fields to the signed profile
        block — keep them free of personal data."""
        if not step_type:
            raise ValueError("step_type is required.")
        if step_type in ("run_start", "run_end") or step_type.startswith("record:"):
            raise ValueError(f"'{step_type}' is not a step type a producer may record.")
        reserved = sorted(RESERVED_EXTENSION_KEYS.intersection(extension or {}))
        if reserved:
            raise ValueError(f"extension uses reserved profile name(s): {', '.join(reserved)}")
        with self._lock:
            self._ensure_open()
            artifact = self._seal_step(step_type, list(objects or []), json.loads(json.dumps(extension or {})),
                                       consequential=consequential)
        self._notify(artifact)
        return artifact

    def record_retrieval(self, context: bytes, content_type: str = "text/plain") -> AgentRunArtifact:
        """Retrieved context (RAG) the agent read."""
        return self.record("retrieval", [AgentRunObject("retrieval-result", "context", context, content_type)])

    def record_tool_call(self, tool: str, arguments: bytes, *, operation: Optional[str] = None,
                         authorization: Optional[AgentAuthorization] = None, consequential: bool = False,
                         use_id: Optional[str] = None, content_type: str = "application/json") -> AgentRunArtifact:
        """A tool call the agent decided to make (§3.4). ``operation`` classifies
        it (e.g. ``read``, ``write``); mark write-class calls ``consequential``.
        ``authorization`` records the policy decision taken before the call;
        ``use_id`` correlates the call with its result."""
        ext: dict = {"tool": _tool_block(tool, operation, use_id)}
        if authorization is not None:
            ext["authorization"] = authorization.to_json()
        return self.record("tool_call", [AgentRunObject("tool-arguments", "input", arguments, content_type)],
                           ext, consequential=consequential)

    def record_tool_result(self, tool: str, result: bytes, *, use_id: Optional[str] = None,
                           content_type: str = "application/json") -> AgentRunArtifact:
        """The result a tool returned — context for the model's next turn."""
        return self.record("tool_result", [AgentRunObject("tool-result", "context", result, content_type)],
                           {"tool": _tool_block(tool, None, use_id)})

    def record_authorization(self, authorization: AgentAuthorization, *, tool: Optional[str] = None,
                             operation: Optional[str] = None) -> AgentRunArtifact:
        """A standalone policy decision (§3.4), e.g. "this write needs approval"."""
        ext: dict = {"authorization": authorization.to_json()}
        if tool is not None:
            ext["tool"] = _tool_block(tool, operation, None)
        return self.record("authorization", extension=ext)

    def record_human_approval(self, decision: str, *, receipt: Optional[bytes] = None,
                              identity_assertion: Optional[bytes] = None, approver_ref: Optional[str] = None,
                              action_evidence_id: Optional[str] = None, decided_at: Optional[datetime] = None,
                              consequential: bool = True, receipt_content_type: str = "application/json",
                              identity_assertion_content_type: str = "application/jwt") -> AgentRunArtifact:
        """A human approval (§3.4). ``approver_ref`` is opaque — never a name or
        e-mail address. The receipt and an identity assertion (e.g. an IdP
        token) are bound as detached objects; their bytes stay local.
        Consequential by default: an approval authorizes a side effect."""
        if not decision:
            raise ValueError("decision is required.")
        approval: dict = {"decision": decision}
        if approver_ref is not None:
            approval["approverRef"] = approver_ref
        if action_evidence_id is not None:
            approval["actionEvidenceId"] = action_evidence_id
        if decided_at is not None:
            approval["decidedAt"] = _format_time(decided_at)
        objects = []
        if receipt is not None:
            objects.append(AgentRunObject("approval-receipt", "input", receipt, receipt_content_type))
        if identity_assertion is not None:
            objects.append(AgentRunObject("identity-assertion", "input", identity_assertion,
                                          identity_assertion_content_type))
        return self.record("human_approval", objects, {"approval": approval}, consequential=consequential)

    def record_model_output(self, output: bytes, content_type: str = "text/plain") -> AgentRunArtifact:
        """What the model produced."""
        return self.record("model_output", [AgentRunObject("assistant-reply", "output", output, content_type)])

    def checkpoint(self, reason: str = "idle") -> AgentRunArtifact:
        """Anchors the chain head with a timestamped ``checkpoint`` step (§5) —
        e.g. from a timer while the agent is idle."""
        return self.record("checkpoint", extension={"checkpoint": {"reason": reason}})

    def finish(self, disposition: str = "completed", usage: Optional[dict] = None) -> AgentRunBundle:
        """Seals ``run_end``, committing to the chain head (§3.3), and returns
        the bundle. ``disposition``: completed | failed | aborted."""
        if disposition not in _DISPOSITIONS:
            raise ValueError("disposition must be completed, failed or aborted.")
        with self._lock:
            self._ensure_open()
            head = self._artifacts[-1]
            block: dict = {
                "finalSeq": head.seq,
                "finalPrevSignatureSha256": self._prev_chain_digest,
                "runDisposition": disposition,
            }
            if usage is not None:
                block["usage"] = json.loads(json.dumps(usage))
            artifact = self._seal_step("run_end", [], block, consequential=True)
            bundle = self.to_bundle()
        self._notify(artifact)
        return bundle

    def to_bundle(self) -> AgentRunBundle:
        """The run as a bundle — available at any point, including after a failure."""
        with self._lock:
            return AgentRunBundle(self.correlation_id, self.identity, list(self._artifacts), dict(self._payloads))

    # ── sealing ──

    def _seal_step(self, step_type: str, objects: list[AgentRunObject], block: dict, *,
                   consequential: bool) -> AgentRunArtifact:
        """Builds, validates and seals one step. Call with the lock held; the
        callback is the caller's job, after releasing it."""
        now = _truncate(self._clock())  # the decision below must use the signed, truncated time
        seq = len(self._artifacts)
        coverage = copy.copy(self._coverage)  # committed only once the step is sealed
        stamp = coverage.next(seq, step_type, consequential, block.get("timestamp") == "required", now)
        block.update({
            "stepType": step_type,
            "agentVersion": self._agent.agent_version,
            "eventTime": _format_time(now),
            "consequential": consequential,
            "timestamp": "required" if stamp else "none",
        })
        envelope = _build_envelope(str(uuid.uuid4()), now, "agent-execution", self._agent, step_type,
                                   self.correlation_id, self._prev_evidence_id, objects, seq,
                                   self._prev_chain_digest, block)
        digests = _digests(objects)
        _prevalidate(envelope)  # a ValueError here leaves the run usable
        try:
            result = _seal(self._client, envelope, objects, self._certificate_id, timestamp=stamp,
                           qualified=self._qualified)
            if stamp and result.timestamped_by is None:
                raise SigillError(f"{step_type}: a timestamp is required by the run's policy, but the seal carries none.")
            artifact = AgentRunArtifact(envelope, result.signature, digests)
            link = artifact.chain_digest
            if link is None:
                raise SigillError("The seal returned no classical signature to chain to.")
            self._coverage = coverage
            self._prev_chain_digest = link
            self._prev_evidence_id = artifact.evidence_id
            self._artifacts.append(artifact)
            if step_type == "run_end":
                self._finished = True  # committed with the append, before any caller code runs
            if self._retain:
                self._payloads.update({o.uri: o.data for o in objects})
        except BaseException:
            self._broken = True
            raise
        return artifact

    def _notify(self, artifact: AgentRunArtifact) -> None:
        """Runs the callback outside the lock, so it may call back into the
        run. The artifact is already part of the chain; a failing callback is
        the caller's error and does not break the run."""
        if self._on_sealed is not None:
            self._on_sealed(artifact)

    def _ensure_open(self) -> None:
        if self._broken:
            raise RuntimeError("The run's chain is broken by an earlier sealing failure; no further steps can be sealed.")
        if self._finished:
            raise RuntimeError("The run is finished.")


def _tool_block(name: str, operation: Optional[str], use_id: Optional[str]) -> dict:
    if not name:
        raise ValueError("tool name is required.")
    block: dict = {"name": name}
    if use_id is not None:
        block["useId"] = use_id
    if operation is not None:
        block["operation"] = operation
    return block


def _identity_payloads(agent: AgentDefinition, identity: AgentRunArtifact) -> dict[str, bytes]:
    ext = _obj((_obj(identity.envelope.get("extensions")) or {}).get(EXTENSION_KEY)) or {}
    c = agent.configuration
    by_kind = {
        "agent-manifest": agent.manifest_bytes(),
        "instruction-set": c.instruction_set,
        "tool-manifest": c.tool_manifest,
        "model-config": c.model_config,
        "execution-policy": c.execution_policy,
    }  # the registration record's bytes are not reconstructible here
    return {uri: by_kind[k] for uri, k in (_obj(ext.get("objectKinds")) or {}).items()
            if k in by_kind and by_kind[k] is not None}


# ── Verification ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SignatureTimestampInfo:
    gen_time: Optional[str]
    tsa_name: Optional[str]
    signature_valid: bool


@dataclass(frozen=True)
class SignerCertificateInfo:
    subject: str
    issuer: str
    not_after: str
    trust: str
    """self_signed | issuer_distinct."""


@dataclass(frozen=True)
class BlindObjectsVerdict:
    """The cryptographic verdict over one multi-object signature."""

    signature_valid: bool
    complete: bool
    objects: list[tuple[str, bool]]
    """(uri, hash_match) per signed URI, including ``urn:sigill:envelope``."""
    missing: list[str] = field(default_factory=list)
    unreferenced: list[str] = field(default_factory=list)
    timestamp: Optional[SignatureTimestampInfo] = None
    certificate: Optional[SignerCertificateInfo] = None
    error: Optional[str] = None
    pqc: str = "absent"
    """The hybrid (ML-DSA) dimension: absent | verified | failed | not_checked."""

    @classmethod
    def from_verify_objects_response(cls, response: Mapping[str, Any]) -> "BlindObjectsVerdict":
        """Maps the ``objects`` member of a ``/seal/verify-objects`` response."""
        r = _obj(response.get("objects")) or {}
        underlying = _obj(r.get("underlying")) or {}
        ts = cert = None
        if isinstance(underlying.get("timestamp"), dict):
            t = underlying["timestamp"]
            ts = SignatureTimestampInfo(_str(t.get("genTime")), _str(t.get("tsaName")), t.get("signatureValid") is True)
        if isinstance(underlying.get("certificate"), dict):
            c = underlying["certificate"]
            cert = SignerCertificateInfo(_str(c.get("subject")) or "", _str(c.get("issuer")) or "",
                                         _str(c.get("notAfter")) or "",
                                         "self_signed" if c.get("isSelfSigned") is True else "issuer_distinct")
        return cls(
            signature_valid=r.get("signatureValid") is True,
            complete=r.get("complete") is True,
            objects=[(_str(o.get("par")) or "", o.get("hashMatch") is True)
                     for o in r.get("objects") or [] if isinstance(o, dict)],
            missing=[m for m in r.get("missing") or [] if isinstance(m, str)],
            unreferenced=[u for u in r.get("unreferenced") or [] if isinstance(u, str)],
            timestamp=ts,
            certificate=cert,
            error=_str(r.get("error")),
            pqc=_str(r.get("pqc")) or "absent",
        )


BlindObjectsVerifier = Callable[[dict, Mapping[str, str]], BlindObjectsVerdict]
"""Checks one artifact's signature over the supplied digests (v2 §7). Only
digests are passed; the default is the blind ``POST /seal/verify-objects``
endpoint (:func:`remote_verifier`)."""


def remote_verifier(client: Any) -> BlindObjectsVerifier:
    """The blind ``POST /seal/verify-objects`` endpoint as a :data:`BlindObjectsVerifier`."""
    def verify(signature: dict, digests: Mapping[str, str]) -> BlindObjectsVerdict:
        return BlindObjectsVerdict.from_verify_objects_response(client.verify_object_hashes(signature, digests).raw)
    return verify


@dataclass(frozen=True)
class AgentObjectVerdict:
    uri: str
    kind: str
    role: str
    content_type: Optional[str]
    size_bytes: Optional[int]
    hash_hex: str
    signed: bool
    retained: bool
    hash_match: bool


@dataclass(frozen=True)
class AgentStepVerdict:
    seq: int
    step_type: str
    evidence_id: str
    actor_id: str
    parent_evidence_id: Optional[str] = None
    prev_signature_sha256: Optional[str] = None
    agent_version: Optional[str] = None
    event_time: Optional[str] = None
    consequential: bool = False
    timestamp_declared: str = "unspecified"
    signature_valid: bool = False
    timestamp_required: bool = False
    timestamp_present: bool = False
    timestamp_valid: Optional[bool] = None
    timestamp_gen_time: Optional[str] = None
    tsa_name: Optional[str] = None
    objects_complete: bool = False
    chain_link_valid: bool = False
    error: Optional[str] = None
    certificate: Optional[SignerCertificateInfo] = None
    objects: list[AgentObjectVerdict] = field(default_factory=list)


@dataclass(frozen=True)
class AgentRunTimestampSummary:
    artifacts: int
    required: int
    present: int
    valid: int
    anchor_valid: bool
    profile: str
    every_events: int
    every_seconds: int
    policy_signed: bool


@dataclass(frozen=True)
class AgentIdentityVerdict:
    declared: bool = False
    present: bool = False
    signature_valid: bool = False
    objects_complete: bool = False
    timestamp_valid: bool = False
    well_formed: bool = False
    same_signer: bool = False
    linked: bool = False
    kinds_complete: bool = False
    config_matches: bool = False
    config_digest_valid: bool = False
    actor_matches: bool = False
    evidence_id: Optional[str] = None
    actor_id: Optional[str] = None
    agent_version: Optional[str] = None
    config_sha256: Optional[str] = None
    certificate: Optional[SignerCertificateInfo] = None
    objects: list[AgentObjectVerdict] = field(default_factory=list)


@dataclass(frozen=True)
class AgentRunVerificationResult:
    """The run-level result (§8)."""

    verdict: str
    """run_finalized | run_open | run_invalid."""
    checks: dict[str, str]
    """The nine checks: ok | warn | bad."""
    findings: list[str]
    warnings: list[str]
    disposition: Optional[str]
    agent_id: Optional[str]
    agent_version: Optional[str]
    correlation_id: Optional[str]
    missing_seqs: list[int]
    timestamps: AgentRunTimestampSummary
    certificates: list[SignerCertificateInfo]
    identity: AgentIdentityVerdict
    artifacts: list[AgentStepVerdict]
    fingerprint: Optional[str]
    """None when the evidence is not valid I-JSON (§8.1)."""
    signer: Optional[str] = None
    """The run's signer: ``x5t#S256`` of its signing certificate (§4.1)."""
    scope: str = SCOPE

    @property
    def is_finalized(self) -> bool:
        return self.verdict == "run_finalized"


@dataclass
class _Signed:
    env: dict
    jws: dict
    ext: dict
    evidence_id: str
    correlation_id: Optional[str]
    parent: Optional[str]
    seq: Optional[int]
    declared_prev: Optional[str]
    step_type: str
    actor_id: str
    agent_version: Optional[str]
    event_time: Optional[datetime]
    consequential: bool
    timestamp_declared: str
    objects: list[tuple[str, str, Optional[str], Optional[int], str]]  # uri, role, contentType, sizeBytes, kind
    timestamp_policy: Optional[dict]
    agent_identity_evidence_id: Optional[str]
    config_sha256: Optional[str]
    is_identity: bool
    conformance: list[str]
    """§2 / v2-schema problems. They fail ``envelope`` (or ``identity``), never ``signatures``."""


def _conformance(env: dict, ext: dict, step_type: str, is_identity: bool) -> list[str]:
    """The complete v2 schema (optional sections included when present) plus
    the §2 profile conventions."""
    errs = validate_envelope_v2(env)
    purpose = _obj(env.get("purpose")) or {}
    expected_category = "agent-identity" if is_identity else "agent-execution"
    if isinstance(purpose.get("category"), str) and purpose["category"] != expected_category:
        errs.append(f"purpose.category must be '{expected_category}'")
    actor = _obj(env.get("actor")) or {}
    if isinstance(actor.get("type"), str) and actor["type"] != "agent":
        errs.append("actor.type must be 'agent'")
    activity = _obj(env.get("activity")) or {}
    if isinstance(activity.get("name"), str) and activity["name"] != ("agent_identity" if is_identity else step_type):
        errs.append("activity.name must be 'agent_identity'" if is_identity else "activity.name must equal the step type")

    if "consequential" in ext and not isinstance(ext["consequential"], bool):
        errs.append("consequential is not a boolean")
    if "timestamp" in ext and ext["timestamp"] not in ("required", "none"):
        errs.append("timestamp must be 'required' or 'none'")
    if "agentVersion" in ext and not isinstance(ext["agentVersion"], str):
        errs.append("agentVersion is not a string")
    kinds = ext.get("objectKinds")
    if "objectKinds" in ext and not (isinstance(kinds, dict) and all(isinstance(x, str) for x in kinds.values())):
        errs.append("objectKinds is not an object of strings")

    errs.extend(_block_conformance(ext, step_type))

    if "usage" in ext and not isinstance(ext["usage"], dict):
        errs.append("usage is not an object")
    if "registeredBy" in ext and not isinstance(ext["registeredBy"], str):
        errs.append("registeredBy is not a string")

    if is_identity:
        if "correlationId" in activity:
            errs.append("the identity record must not carry activity.correlationId")
        if "chain" in env:
            errs.append("the identity record must not carry chain")
        if ext.get("agentId") != actor.get("id"):
            errs.append("agentId must equal actor.id")
    return errs


def _block_conformance(ext: dict, step_type: str) -> list[str]:
    """The §3.4 tool / authorization / approval block shapes."""
    errs: list[str] = []
    if "tool" in ext:
        tool = ext["tool"]
        if not (isinstance(tool, dict) and isinstance(tool.get("name"), str) and tool["name"]):
            errs.append("tool must be an object with a non-empty string name")
        else:
            for k in ("operation", "useId"):
                if k in tool and not isinstance(tool[k], str):
                    errs.append(f"tool.{k} is not a string")
    if "authorization" in ext:
        auth = ext["authorization"]
        if not isinstance(auth, dict):
            errs.append("authorization must be an object")
        else:
            if auth.get("decision") not in _AUTH_DECISIONS:
                errs.append("authorization.decision must be 'allowed' or 'denied'")
            for k in ("policyId", "reason"):
                if k in auth and not isinstance(auth[k], str):
                    errs.append(f"authorization.{k} is not a string")
    elif step_type == "authorization":
        errs.append("an authorization step must carry an authorization block")
    if "approval" in ext or step_type == "human_approval":
        appr = ext.get("approval")
        if not (isinstance(appr, dict) and isinstance(appr.get("decision"), str) and appr["decision"]):
            errs.append("approval must be an object with a non-empty string decision")
        else:
            if "approverRef" in appr and not isinstance(appr["approverRef"], str):
                errs.append("approval.approverRef is not a string")
            if "actionEvidenceId" in appr and not (isinstance(appr["actionEvidenceId"], str)
                                                   and is_uuid(appr["actionEvidenceId"])):
                errs.append("approval.actionEvidenceId is not a UUID")
            if "decidedAt" in appr and not (isinstance(appr["decidedAt"], str)
                                            and parse_date_time(appr["decidedAt"]) is not None):
                errs.append("approval.decidedAt is not a date-time")
    return errs


def _parse_signed(envelope: Any, signature: Any) -> tuple[Optional[_Signed], Optional[str]]:
    if not isinstance(envelope, dict) or not isinstance(signature, dict):
        return None, "envelope or signature is not a JSON object"
    if not _is_i_json(envelope) or not _is_i_json(signature):
        return None, "envelope or signature is not valid I-JSON"
    try:
        canonicalize(envelope)
        canonicalize(signature)
    except Exception:  # noqa: BLE001 — any canonicalization failure means the same thing
        return None, "envelope or signature is not valid I-JSON"
    if envelope.get("schemaName") != "AiEvidenceEnvelope" or envelope.get("schemaVersion") != "2":
        return None, "envelope is not an AiEvidenceEnvelope v2"
    evidence_id = _str(envelope.get("evidenceId"))
    actor_id = _str((_obj(envelope.get("actor")) or {}).get("id"))
    if not evidence_id or not actor_id:
        return None, "envelope lacks evidenceId or actor.id"
    ext = _obj((_obj(envelope.get("extensions")) or {}).get(EXTENSION_KEY))
    if ext is None:
        return None, f"envelope carries no {EXTENSION_KEY} extension"
    step_type = _str(ext.get("stepType"))
    if step_type is None and _str(ext.get("recordType")):
        step_type = "record:" + ext["recordType"]
    is_identity = ext.get("recordType") == "agent-identity"
    if not step_type:
        return None, "extension.stepType / recordType missing or not a string"
    seq = declared_prev = None
    if "chain" in envelope:
        chain = _obj(envelope["chain"])
        if chain is None:
            return None, "chain is not an object"
        seq = _int(chain.get("seq"))
        if seq is None or seq < 0:
            return None, "chain.seq missing, negative or not an integer"
        if "prevSignatureSha256" in chain:
            declared_prev = _str(chain["prevSignatureSha256"])
            if declared_prev is None:
                return None, "chain.prevSignatureSha256 is not a string"
    if not isinstance(envelope.get("objects"), list):
        return None, "objects is not an array"
    if not isinstance(envelope.get("extensions"), dict):
        return None, "extensions is not an object"
    kinds = _obj(ext.get("objectKinds")) or {}
    objects = []
    seen: set[str] = set()
    for o in envelope["objects"]:
        o = _obj(o) or {}
        uri, role = _str(o.get("uri")), _str(o.get("role"))
        if not uri or not role:
            return None, "an object lacks uri or role"
        if uri == ENVELOPE_URI:
            return None, "objects[] uses the reserved envelope URI"
        if uri in seen:
            return None, f"duplicate object URI '{uri}' in the signed envelope"
        seen.add(uri)
        objects.append((uri, role, _str(o.get("contentType")), _int(o.get("sizeBytes")), _str(kinds.get(uri)) or "?"))
    event_time = None
    if "eventTime" in ext:
        t = _str(ext["eventTime"])
        event_time = _parse_time(t) if t else None
        if event_time is None:
            return None, "extension.eventTime is not a date-time"
    activity = _obj(envelope.get("activity")) or {}
    return _Signed(
        env=envelope, jws=signature, ext=ext, evidence_id=evidence_id,
        correlation_id=_str(activity.get("correlationId")), parent=_str(activity.get("parentEvidenceId")),
        seq=seq, declared_prev=declared_prev, step_type=step_type, actor_id=actor_id,
        agent_version=_str(ext.get("agentVersion")), event_time=event_time,
        consequential=ext.get("consequential") is True, timestamp_declared=_str(ext.get("timestamp")) or "unspecified",
        objects=objects, timestamp_policy=_obj(ext.get("timestampPolicy")),
        agent_identity_evidence_id=_str(ext.get("agentIdentityEvidenceId")), config_sha256=_str(ext.get("configSha256")),
        is_identity=is_identity, conformance=_conformance(envelope, ext, step_type, is_identity),
    ), None


@dataclass
class _ArtifactCheck:
    signature_valid: bool = False
    objects_complete: bool = False
    timestamp_present: bool = False
    timestamp_valid: Optional[bool] = None
    gen_time: Optional[str] = None
    tsa_name: Optional[str] = None
    error: Optional[str] = None
    certificate: Optional[SignerCertificateInfo] = None
    objects: list[AgentObjectVerdict] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)


def _check_artifact(sa: _Signed, art: AgentRunArtifact, payloads: Mapping[str, bytes],
                    blind: BlindObjectsVerifier, label: str) -> _ArtifactCheck:
    c = _ArtifactCheck()
    digests: dict[str, str] = {}
    obj_ok = True
    signed_uris = {o[0] for o in sa.objects}
    for uri, role, ctype, size, kind in sa.objects:
        supplied = art.object_digests.get(uri)
        if uri in payloads:
            hex_ = hash_bytes(payloads[uri])
            if supplied is not None and supplied != hex_:
                c.findings.append(f"{label}: supplied payload for '{kind}' does not match its supplied digest.")
                obj_ok = False
            digests[uri] = hex_
            c.objects.append(AgentObjectVerdict(uri, kind, role, ctype, size, hex_, True, True, True))
        elif supplied is not None:
            digests[uri] = supplied
            c.objects.append(AgentObjectVerdict(uri, kind, role, ctype, size, supplied, True, False, True))
        else:
            c.objects.append(AgentObjectVerdict(uri, kind, role, ctype, size, "", True, False, False))
            c.findings.append(f"{label}: signed object '{kind}' was not supplied (no digest, no payload).")
            obj_ok = False
    for uri, hex_ in art.object_digests.items():
        if uri in signed_uris:
            continue
        c.objects.append(AgentObjectVerdict(uri, "?", "?", None, None, hex_, False, uri in payloads, False))
        c.findings.append(f"{label}: supplied object '{uri}' is not covered by the signature (unsigned data in the record).")
        obj_ok = False
    try:
        digests[ENVELOPE_URI] = hash_bytes(canonicalize(sa.env))
        r = blind(sa.jws, digests)
        if r is None:
            raise SigillError("blind verifier returned no result")
        c.signature_valid = r.signature_valid
        if r.pqc not in ("absent", "verified"):
            c.signature_valid = False
            c.findings.append(f"{label}: the hybrid seal's ML-DSA commitment is '{r.pqc}'.")
        c.error = r.error
        c.objects_complete = r.complete and not r.unreferenced and not r.missing and obj_ok
        for m in r.missing:
            c.findings.append(f"{label}: the signature covers '{m}' but the envelope does not list it.")
        for u in r.unreferenced:
            c.findings.append(f"{label}: the envelope lists '{u}' but the signature does not cover it.")
        matches = {}
        for uri, hm in r.objects:
            matches.setdefault(uri, hm)
        for i, o in enumerate(c.objects):
            if o.signed and matches.get(o.uri) is False:
                c.objects[i] = AgentObjectVerdict(o.uri, o.kind, o.role, o.content_type, o.size_bytes, o.hash_hex,
                                                  o.signed, o.retained, False)
                c.findings.append(f"{label}: object '{o.kind}' no longer matches its signed digest.")
        if matches.get(ENVELOPE_URI) is not True:
            c.objects_complete = False
            c.findings.append(f"{label}: the signature does not cover this envelope.")
        if r.timestamp is not None:
            c.timestamp_present = True
            c.timestamp_valid = r.timestamp.signature_valid
            c.gen_time = r.timestamp.gen_time
            c.tsa_name = r.timestamp.tsa_name
        c.certificate = r.certificate
        if not c.signature_valid:
            c.findings.append(f"{label}: signature invalid{' — ' + r.error if r.error else ''}.")
    except Exception as ex:  # noqa: BLE001 — a verifier failure is a finding, never a crash
        c.error = str(ex)
        c.findings.append(f"{label}: verification failed — {ex}")
    return c


def verify_agent_run(bundle: AgentRunBundle, verifier: BlindObjectsVerifier, *,
                     expected_signers: Optional[Sequence[str]] = None) -> AgentRunVerificationResult:
    """Verifies a run bundle (§8). Never raises for malformed evidence: that is
    an invalid verdict.

    :param expected_signers: ``x5t#S256`` thumbprints of the certificates the
        producer seals with (§4.1). When given, a run signed by anyone else fails.
    """
    findings: list[str] = []
    warnings: list[str] = []
    checks: dict[str, str] = {}

    parsed = []
    for i, a in enumerate(bundle.artifacts):
        sa, err = _parse_signed(a.envelope, a.signature)
        parsed.append((a, i, sa, err))
    arts = sorted(parsed, key=lambda p: ((p[2].seq if p[2] is not None and p[2].seq is not None else p[1]), p[1]))
    # The run identifier comes only from the signed envelopes, never from the bundle.
    correlation = next((p[2].correlation_id for p in arts if p[2] is not None and p[2].correlation_id), None)
    corr_ok = True
    for _, index, sa, _ in arts:
        if sa is not None and not sa.correlation_id:
            corr_ok = False
            findings.append(f"seq {sa.seq if sa.seq is not None else index}: no signed correlationId "
                            "(activity.correlationId).")
    if any(p[2] is not None and p[2].correlation_id and p[2].correlation_id != correlation for p in arts):
        corr_ok = False
        findings.append("An artifact's signed correlationId does not belong to this run (cross-run splice).")
    checks["correlation"] = "ok" if corr_ok else "bad"

    missing: list[int] = []
    seq_ok = True
    expected = 0
    for _, _, sa, _ in arts:
        if sa is None:
            seq_ok = False
            continue
        if sa.seq is None:
            seq_ok = False
            findings.append(f"{sa.step_type}: no chain.seq in the signed envelope.")
            continue
        sq = sa.seq
        if sq < expected:
            seq_ok = False
            findings.append(f"Duplicate signed seq {sq}.")
            continue
        while expected < sq and len(missing) < _MAX_MISSING_LISTED:
            missing.append(expected)
            expected += 1
        if expected < sq:
            seq_ok = False
            findings.append(f"Sequence gap too large to list (signed seq jumps to {sq}).")
        expected = sq + 1
    if missing:
        seq_ok = False
        findings.append(f"Sequence gap: no artifact for seq {', '.join(map(str, missing))} (deleted or withheld).")
    starts = [p[2] for p in arts if p[2] is not None and p[2].step_type == "run_start"]
    if not starts:
        seq_ok = False
        findings.append("The run has no run_start.")
    elif len(starts) > 1:
        seq_ok = False
        findings.append(f"More than one run_start (seq {', '.join(str(s.seq) for s in starts)}).")
    elif starts[0].seq != 0:
        seq_ok = False
        findings.append("run_start is not at seq 0.")
    checks["sequence"] = "ok" if seq_ok else "bad"

    start = next((p[2] for p in arts if p[2] is not None and p[2].step_type == "run_start"), None)
    policy: Optional[dict] = None
    policy_ok = True
    if start is not None:
        raw_policy = start.ext.get("timestampPolicy")
        problem = None
        if "timestampPolicy" not in start.ext:
            problem = "run_start carries no signed timestamp policy."
        elif not isinstance(raw_policy, dict):
            problem = "run_start: the signed timestamp policy is malformed (not an object)."
        elif raw_policy.get("profile") not in ("throughput", "per-event"):
            problem = f"run_start: the signed timestamp policy is malformed (unknown profile '{raw_policy.get('profile')}')."
        elif any(_int(raw_policy.get(k)) is None or _int(raw_policy.get(k)) < 0 for k in ("everyEvents", "everySeconds")):
            problem = "run_start: the signed timestamp policy is malformed (everyEvents/everySeconds must be non-negative integers)."
        elif not isinstance(raw_policy.get("runStart"), bool):
            problem = "run_start: the signed timestamp policy is malformed (runStart must be a boolean)."
        elif raw_policy.get("runEnd") is not True or raw_policy.get("consequential") is not True:
            problem = "run_start: the signed timestamp policy is malformed (runEnd and consequential must be true)."
        elif "assuranceProfile" in start.ext and start.ext["assuranceProfile"] != raw_policy["profile"]:
            problem = "run_start: assuranceProfile differs from the signed timestamp policy's profile."
        if problem is None:
            policy = raw_policy
        else:
            policy_ok = False
            findings.append(problem)
    profile = policy["profile"] if policy else "unknown"
    every_events = _int(policy["everyEvents"]) if policy else 0
    every_seconds = _int(policy["everySeconds"]) if policy else 0
    stamp_run_start = bool(policy and policy["runStart"])

    chain_ok = env_ok = sig_ok = ts_ok = obj_ok = actor_ok = True
    obj_warn = False
    ts_required = ts_present = ts_valid = 0
    anchor_valid = False
    certificates: list[SignerCertificateInfo] = []
    verdicts: list[AgentStepVerdict] = []
    prev_sig_hash: Optional[str] = None
    prev_evidence_id: Optional[str] = None
    prev_seq = -1
    coverage = _TimestampCoverage(profile, every_events, every_seconds, stamp_run_start)
    actor_id = start.actor_id if start else next((p[2].actor_id for p in arts if p[2] is not None), None)
    agent_version = start.agent_version if start else None

    # §4.1: one signer per run — run_start's, else the first artifact's that has one.
    candidates = ([start] if start is not None else []) + [p[2] for p in arts if p[2] is not None]
    run_signer = next((sg for sg in (signer_of(c.jws)[0] for c in candidates) if sg is not None), None)
    if run_signer is not None and expected_signers is not None and run_signer not in set(expected_signers):
        sig_ok = False
        findings.append(f"The run's signer (x5t#S256 {run_signer}) is not among the expected signers.")

    for art, index, sa, err in arts:
        if sa is None:
            env_ok = sig_ok = obj_ok = False
            findings.append(f"artifacts[{index}]: {err}")
            verdicts.append(AgentStepVerdict(seq=index, step_type="?", evidence_id="?", actor_id="?", error=err))
            prev_sig_hash = prev_evidence_id = None
            continue
        seq = sa.seq if sa.seq is not None else index
        if sa.conformance:
            env_ok = False
            findings.extend(f"seq {seq}: {e}." for e in sa.conformance)
        signer, signer_err = signer_of(sa.jws)
        if signer_err is not None:
            sig_ok = False
            findings.append(f"seq {seq}: {signer_err}.")
        elif signer != run_signer:
            sig_ok = False
            findings.append(f"seq {seq}: signed by a different certificate than the run (x5t#S256 {signer}).")
        if sa.actor_id != actor_id or (agent_version is not None and sa.agent_version != agent_version):
            actor_ok = False
            findings.append(f"seq {seq}: signed actor/version ({sa.actor_id}, {sa.agent_version}) differs from "
                            f"run_start ({actor_id}, {agent_version}).")
        if seq == 0:
            link_ok = sa.declared_prev is None
            if not link_ok:
                findings.append("seq 0 must not carry prevSignatureSha256.")
        elif prev_seq != seq - 1 or prev_sig_hash is None:
            link_ok = False
        else:
            link_ok = sa.declared_prev == prev_sig_hash
            if not link_ok:
                findings.append(f"seq {seq}: prevSignatureSha256 does not match the signature of seq {prev_seq}.")
        if not link_ok:
            chain_ok = False
        if seq > 0 and prev_evidence_id is not None and _norm_id(sa.parent) != _norm_id(prev_evidence_id):
            warnings.append(f"seq {seq}: parentEvidenceId is not the previous artifact (semantic link only; not an "
                            "integrity failure).")

        required = coverage.next(seq, sa.step_type, sa.consequential, sa.timestamp_declared == "required",
                                 sa.event_time)
        if required:
            ts_required += 1

        c = _check_artifact(sa, art, bundle.payloads, verifier, f"seq {seq}")
        findings.extend(c.findings)
        if any(o.signed and not o.retained for o in c.objects):
            obj_warn = True
        if not c.signature_valid:
            sig_ok = False
        if not c.objects_complete:
            obj_ok = False
        if c.timestamp_present:
            ts_present += 1
            if c.timestamp_valid is True:
                ts_valid += 1
        if required and c.timestamp_valid is not True:
            ts_ok = False
            findings.append(f"seq {seq} ({sa.step_type}): a timestamp is required here by the signed policy and it "
                            f"is {'invalid' if c.timestamp_present else 'missing'}.")
        elif c.timestamp_present and c.timestamp_valid is False:
            ts_ok = False
            findings.append(f"seq {seq}: timestamp invalid.")
        if sa.step_type == "run_end" and c.timestamp_valid is True and c.signature_valid:
            anchor_valid = True
        if c.certificate is not None and not any(
                x.subject == c.certificate.subject and x.issuer == c.certificate.issuer for x in certificates):
            certificates.append(c.certificate)

        verdicts.append(AgentStepVerdict(
            seq=seq, step_type=sa.step_type, evidence_id=sa.evidence_id, actor_id=sa.actor_id,
            parent_evidence_id=sa.parent, prev_signature_sha256=sa.declared_prev, agent_version=sa.agent_version,
            event_time=_format_time(sa.event_time) if sa.event_time else None, consequential=sa.consequential,
            timestamp_declared=sa.timestamp_declared, signature_valid=c.signature_valid, timestamp_required=required,
            timestamp_present=c.timestamp_present, timestamp_valid=c.timestamp_valid, timestamp_gen_time=c.gen_time,
            tsa_name=c.tsa_name, objects_complete=c.objects_complete, chain_link_valid=link_ok, error=c.error,
            certificate=c.certificate, objects=c.objects,
        ))
        prev_sig_hash = chain_digest(sa.jws)
        prev_seq = seq
        prev_evidence_id = sa.evidence_id
    if not actor_ok:
        env_ok = False

    id_sa = None
    if bundle.agent_identity is not None:
        id_sa, _ = _parse_signed(bundle.agent_identity.envelope, bundle.agent_identity.signature)
    signed_uris = {o[0] for p in arts if p[2] is not None for o in p[2].objects}
    signed_uris |= {o[0] for o in id_sa.objects} if id_sa is not None else set()
    for uri in sorted(bundle.payloads):
        if uri not in signed_uris:
            obj_ok = False
            findings.append(f"Supplied payload '{uri}' is not a signed object of any artifact (unsigned data in the record).")
    checks["chain"] = "ok" if chain_ok else "bad"
    checks["envelope"] = "ok" if env_ok else "bad"
    checks["signatures"] = "ok" if sig_ok else "bad"
    checks["objects"] = "bad" if not obj_ok else ("warn" if obj_warn else "ok")

    signed = [p[2] for p in arts if p[2] is not None]
    ends = [s for s in signed if s.step_type == "run_end"]
    end = ends[-1] if ends else None
    disposition = None
    if end is None:
        checks["finalization"] = "warn"
    else:
        fin_ok = True
        if len(ends) > 1:
            fin_ok = False
            findings.append(f"More than one run_end (seq {', '.join(str(e.seq) for e in ends)}).")
        disposition = _str(end.ext.get("runDisposition"))
        if disposition not in _DISPOSITIONS:
            fin_ok = False
            findings.append(f"run_end carries no valid runDisposition (got '{disposition or 'none'}').")
        if signed[-1] is not end:
            fin_ok = False
            findings.append("run_end is not the last artifact of the chain.")
        head = next((s for s in reversed(signed)
                     if s.seq is not None and end.seq is not None and s.seq < end.seq), None)
        if head is None:
            fin_ok = False
            findings.append("run_end has no preceding artifact.")
        else:
            final_seq = _int(end.ext.get("finalSeq"))
            if final_seq != head.seq:
                fin_ok = False
                findings.append(f"run_end commits to finalSeq {final_seq if final_seq is not None else 'none'}, "
                                f"observed {head.seq}.")
            final_prev = _str(end.ext.get("finalPrevSignatureSha256"))
            if not final_prev or final_prev != chain_digest(head.jws):
                fin_ok = False
                findings.append("run_end chain-head commitment does not match the observed head.")
        if not anchor_valid:
            fin_ok = False
        checks["finalization"] = "ok" if fin_ok else "bad"
    checks["timestamps"] = "bad" if (not ts_ok or not policy_ok) else ("ok" if anchor_valid else "warn")

    start_art = next((p[0] for p in arts if p[2] is not None and p[2] is start), None)
    identity, id_findings = _verify_identity(bundle, start, start_art, verifier, run_signer)
    if any(c.trust == "self_signed" for c in certificates):
        warnings.append("Signed with a self-signed certificate: the signatures are consistent, but they do not "
                        "establish who the signer is.")
    findings.extend(id_findings)
    if not identity.declared and not identity.present:
        checks["identity"] = "warn"
        warnings.append("run_start declares no agent identity record.")
    elif not identity.present:
        checks["identity"] = "bad"
    else:
        checks["identity"] = "ok" if (identity.well_formed and identity.same_signer and identity.linked
                                      and identity.kinds_complete
                                      and identity.config_matches and identity.config_digest_valid
                                      and identity.actor_matches and identity.signature_valid
                                      and identity.objects_complete and identity.timestamp_valid) else "bad"

    verdict = "run_invalid" if "bad" in checks.values() else ("run_finalized" if end is not None else "run_open")
    return AgentRunVerificationResult(
        verdict=verdict, checks=checks, findings=findings, warnings=warnings, disposition=disposition,
        agent_id=actor_id, agent_version=agent_version, correlation_id=correlation, missing_seqs=missing,
        timestamps=AgentRunTimestampSummary(len(arts), ts_required, ts_present, ts_valid, anchor_valid, profile,
                                            every_events, every_seconds, policy is not None),
        certificates=certificates, identity=identity, artifacts=verdicts, fingerprint=_safe_fingerprint(bundle),
        signer=run_signer,
    )


def _safe_fingerprint(bundle: AgentRunBundle) -> Optional[str]:
    try:
        return bundle_fingerprint(bundle)
    except Exception:  # noqa: BLE001 — not valid I-JSON: undefined (§8.1); the run is invalid anyway
        return None


def _verify_identity(bundle: AgentRunBundle, start: Optional[_Signed], start_art: Optional[AgentRunArtifact],
                     blind: BlindObjectsVerifier, run_signer: Optional[str]) -> tuple[AgentIdentityVerdict, list[str]]:
    findings: list[str] = []
    declared = start.agent_identity_evidence_id if start else None
    if bundle.agent_identity is None:
        if declared is not None:
            findings.append(f"run_start references identity record {declared}, but the bundle does not include it.")
        return AgentIdentityVerdict(declared=declared is not None, evidence_id=declared), findings
    sa, err = _parse_signed(bundle.agent_identity.envelope, bundle.agent_identity.signature)
    if sa is None:
        findings.append("Identity record: " + (err or ""))
        return AgentIdentityVerdict(declared=declared is not None, present=True), findings
    well_formed = sa.is_identity and not sa.conformance
    if not sa.is_identity:
        findings.append("Identity record: recordType is not 'agent-identity'.")
    findings.extend(f"Identity record: {e}." for e in sa.conformance)
    id_signer, id_signer_err = signer_of(sa.jws)
    same_signer = id_signer_err is None and id_signer == run_signer
    if id_signer_err is not None:
        findings.append(f"Identity record: {id_signer_err}.")
    elif not same_signer:
        findings.append("Identity record: signed by a different certificate than the run.")
    linked = (start is not None and _norm_id(start.parent) == _norm_id(sa.evidence_id)
              and _norm_id(declared) == _norm_id(sa.evidence_id))
    if not linked:
        findings.append("run_start does not reference the identity record (parentEvidenceId / agentIdentityEvidenceId).")
    actor_matches = start is not None and start.actor_id == sa.actor_id and start.agent_version == sa.agent_version
    if not actor_matches:
        findings.append("Identity record's signed agent/version differ from run_start's.")

    def digests_by_kind(s: _Signed, art: Optional[AgentRunArtifact], label: str,
                        exact: tuple) -> tuple[dict[str, str], bool]:
        """Effective digest per kind; False when a kind in ``exact`` appears more than once."""
        d: dict[str, str] = {}
        unique = True
        if art is None:
            return d, unique
        counts: dict[str, int] = {}
        for uri, _, _, _, kind in s.objects:
            counts[kind] = counts.get(kind, 0) + 1
            hex_ = hash_bytes(bundle.payloads[uri]) if uri in bundle.payloads else art.object_digests.get(uri)
            if hex_ is not None and kind not in d:
                d[kind] = hex_
        for kind in exact:
            if counts.get(kind, 0) > 1:
                unique = False
                findings.append(f"{label}: more than one signed object of kind '{kind}'.")
        return d, unique

    id_d, id_unique = digests_by_kind(sa, bundle.agent_identity, "Identity record", IDENTITY_KINDS)
    st_d, st_unique = (digests_by_kind(start, start_art, "run_start", CONFIGURATION_KINDS)
                       if start else ({}, True))
    missing_kinds = [k for k in IDENTITY_KINDS if k not in id_d and k not in OPTIONAL_CONFIGURATION_KINDS]
    for k in missing_kinds:
        findings.append(f"Identity record: no signed object of kind '{k}'.")
    kinds_complete = id_unique and st_unique and not missing_kinds
    # Required kinds must be present and equal; an optional kind is on both sides (and equal) or on neither.
    config_matches = all(
        (k in id_d and k in st_d and id_d[k] == st_d[k])
        or (k in OPTIONAL_CONFIGURATION_KINDS and k not in id_d and k not in st_d)
        for k in CONFIGURATION_KINDS)
    if not config_matches:
        findings.append("run_start's instruction set / tool manifest / model config / execution policy do not match "
                        "the identity record's.")
    config_digest_valid = False
    if all(k in id_d for k in ("agent-manifest", "instruction-set", "tool-manifest", "execution-policy")):
        recomputed = _configuration_digest_from_hex(
            id_d["agent-manifest"], id_d["instruction-set"], id_d["tool-manifest"], id_d.get("model-config"),
            id_d["execution-policy"])
        config_digest_valid = recomputed == sa.config_sha256
    if not config_digest_valid:
        findings.append("Identity record: configSha256 does not match the digest of its configuration objects.")
    c = _check_artifact(sa, bundle.agent_identity, bundle.payloads, blind, "identity record")
    findings.extend(c.findings)
    timestamp_valid = c.timestamp_present and c.timestamp_valid is True
    if not timestamp_valid:
        findings.append(f"Identity record: timestamp {'invalid' if c.timestamp_present else 'missing'}.")
    return AgentIdentityVerdict(
        declared=declared is not None, present=True, signature_valid=c.signature_valid,
        objects_complete=c.objects_complete, timestamp_valid=timestamp_valid, well_formed=well_formed,
        same_signer=same_signer,
        linked=linked, kinds_complete=kinds_complete, config_matches=config_matches,
        config_digest_valid=config_digest_valid, actor_matches=actor_matches, evidence_id=sa.evidence_id,
        actor_id=sa.actor_id, agent_version=sa.agent_version, config_sha256=sa.config_sha256,
        certificate=c.certificate, objects=c.objects,
    ), findings


def bundle_fingerprint(bundle: AgentRunBundle) -> str:
    """The deterministic bundle fingerprint (§8.1)."""
    every = list(bundle.artifacts) + ([bundle.agent_identity] if bundle.agent_identity else [])
    if not all(_is_i_json(a.envelope) and _is_i_json(a.signature) for a in every):
        raise ValueError("the fingerprint is undefined for evidence that is not valid I-JSON (§8.1)")

    def one(a: AgentRunArtifact) -> dict:
        return {"e": hash_bytes(canonicalize(a.envelope)), "s": hash_bytes(canonicalize(a.signature)),
                "d": dict(sorted(a.object_digests.items()))}
    arts = []
    for a in bundle.artifacts:
        chain = a.envelope.get("chain") if isinstance(a.envelope, dict) else None
        raw = chain.get("seq") if isinstance(chain, dict) else None
        seq = raw if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0 else -1
        arts.append({"seq": seq, **one(a)})
    arts.sort(key=lambda x: (x["seq"], x["e"]))
    payloads = [{"uri": u, "sha256": hash_bytes(bundle.payloads[u])} for u in sorted(bundle.payloads)]
    return hash_bytes(canonicalize({
        "profile": bundle.profile,
        "artifacts": arts,
        "identity": one(bundle.agent_identity) if bundle.agent_identity else None,
        "payloads": payloads,
    }))
