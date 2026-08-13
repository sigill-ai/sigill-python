# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""AI evidence v2 — the blind multi-object JAdES contract.

Producer/verifier types for ``spec/ai-evidence-envelope-v2.md``: the envelope
is canonicalized (RFC 8785) and hashed locally, every payload is hashed
locally, and only digests + opaque URIs travel to Sigill. The
``{envelope, signature}`` artifact is always assembled client-side — no
artifact ever exists server-side.
"""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from sigill_sdk._canonical import canonicalize, hash_bytes
from sigill_sdk._errors import SigillError

ENVELOPE_URI = "urn:sigill:envelope"
"""The reserved sigD URI of the envelope (signed object 0)."""

MEDIA_TYPE = "application/vnd.sigill.ai-evidence+json"
"""The artifact media type / default envelope content type."""

V2_ROLES = frozenset({"prompt", "input", "context", "output", "artifact", "log"})


@dataclass(frozen=True)
class EvidenceV2Payload:
    """One content payload of an AI evidence v2 record.

    The bytes NEVER leave the machine — the SDK hashes them locally and
    transmits digests only. URIs are opaque identifiers; when omitted the SDK
    generates a ``urn:uuid:`` (the normative choice for remote paths, spec
    §3.1). Human-meaningful names belong in :attr:`metadata`, which stays
    inside the envelope.
    """

    role: str
    data: bytes
    uri: str | None = None
    content_type: str | None = None
    encoding: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class EvidenceV2Artifact:
    """The self-contained artifact ``{envelope, signature}`` (spec §6)."""

    envelope: dict[str, Any]
    signature: dict[str, Any]
    envelope_hash_hex: str
    """SHA-256 hex of the RFC 8785 canonical envelope — the signed hashV[0]."""

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialize the artifact file (``*.ai-evidence.json``)."""
        return json.dumps(
            {"envelope": self.envelope, "signature": self.signature},
            indent=indent,
            ensure_ascii=False,
        )

    @classmethod
    def parse(cls, text: str) -> "EvidenceV2Artifact":
        """Load a previously produced artifact; recomputes the envelope digest."""
        root = json.loads(text)
        if not isinstance(root, dict) or "envelope" not in root or "signature" not in root:
            raise SigillError("Artifact must carry 'envelope' and 'signature' members.")
        return cls(
            envelope=root["envelope"],
            signature=root["signature"],
            envelope_hash_hex=hash_bytes(canonicalize(root["envelope"])),
        )


@dataclass(frozen=True)
class EvidenceV2ObjectVerdict:
    """Per-object verdict from blind object-level verification."""

    uri: str
    content_type: str | None
    supplied: bool
    hash_match: bool


@dataclass(frozen=True)
class EvidenceV2VerificationResult:
    """Compound result: the platform's cryptographic verdicts plus the
    envelope-layer checks that are the SDK's job (spec §7.1)."""

    signature_valid: bool
    complete: bool
    pqc: str
    """absent | verified | failed | not_checked — the hybrid dimension."""
    object_count: int
    supplied_count: int
    matched_count: int
    objects: list[EvidenceV2ObjectVerdict]
    missing: list[str]
    unreferenced: list[str]
    alignment_ok: bool
    missing_roles: list[str]
    issues: list[str]
    raw: dict[str, Any] = field(repr=False)

    @property
    def ok(self) -> bool:
        """The single answer: complete ∧ aligned ∧ required roles covered ∧
        the hybrid dimension settled (pqc absent-or-verified). The last clause
        is enforced client-side as well as server-side, so a hybrid artifact
        is never Ok from the classical verdict alone."""
        return (
            self.complete
            and self.alignment_ok
            and not self.missing_roles
            and self.pqc in ("absent", "verified")
        )


def build_envelope_and_request_objects(
    envelope: dict[str, Any],
    payloads: list[EvidenceV2Payload],
    *,
    pqc: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fill identity defaults and derive both object lists from the payloads.

    The SDK OWNS ``objects[]``: deriving envelope entries and request entries
    from the same list, in order, makes the envelope and the signed sigD
    aligned by construction (spec §5.2).
    """
    env = json.loads(json.dumps(envelope))  # deep copy; caller input never mutated
    env.setdefault("schemaName", "AiEvidenceEnvelope")
    env.setdefault("schemaVersion", "2")
    env.setdefault("evidenceId", str(uuid.uuid4()))
    env.setdefault("createdAt", _utc_now_iso())

    seen: set[str] = set()
    envelope_objects: list[dict[str, Any]] = []
    request_objects: list[dict[str, Any]] = []
    for p in payloads:
        if p.role not in V2_ROLES:
            raise SigillError(
                f"Invalid payload role '{p.role}' — expected one of: {', '.join(sorted(V2_ROLES))}."
            )
        uri = (p.uri or "").strip() or f"urn:uuid:{uuid.uuid4()}"
        if uri == ENVELOPE_URI:
            raise SigillError(f"'{ENVELOPE_URI}' is reserved for the envelope itself.")
        if uri in seen:
            raise SigillError(
                f"Duplicate payload URI '{uri}' — URIs are compared byte-exactly and must be unique."
            )
        seen.add(uri)

        env_obj: dict[str, Any] = {"uri": uri, "role": p.role}
        if p.content_type is not None:
            env_obj["contentType"] = p.content_type
        if p.encoding is not None:
            env_obj["encoding"] = p.encoding
        env_obj["sizeBytes"] = len(p.data)
        if p.metadata is not None:
            env_obj["metadata"] = p.metadata
        envelope_objects.append(env_obj)

        req_obj: dict[str, Any] = {"uri": uri, "hashHex": hash_bytes(p.data)}
        if pqc:
            req_obj["hashHex512"] = hash_bytes(p.data, alg="SHA-512")
        if p.content_type is not None:
            req_obj["contentType"] = p.content_type
        request_objects.append(req_obj)

    env["objects"] = envelope_objects
    return env, request_objects


def has_ml_dsa_signer(signature: dict[str, Any]) -> bool:
    """Does the General JWS carry an ML-DSA (hybrid) signature entry?"""
    for entry in signature.get("signatures") or []:
        prot = entry.get("protected") if isinstance(entry, dict) else None
        if not isinstance(prot, str):
            continue
        try:
            padded = prot.replace("-", "+").replace("_", "/")
            padded += "=" * (-len(padded) % 4)
            header = json.loads(base64.b64decode(padded))
            if str(header.get("alg", "")).startswith("ML-DSA"):
                return True
        except (ValueError, json.JSONDecodeError):
            continue  # unparseable entry — not evidence of a hybrid signer
    return False


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
