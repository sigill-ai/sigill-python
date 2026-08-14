# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""The profile-agnostic multi-object signing tier (spec §2, §12).

Sibling profiles of the AI-evidence envelope sign through the same blind
mechanism — digests and opaque URIs in, a JAdES JWS out — but carry their own
envelope content type, the profile discriminator (spec §5.2). This module
holds the digests-in types beneath :mod:`sigill_sdk._evidence_v2`: the caller
computes every digest itself and assembles its own artifact from the returned
signature. Content never travels.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sigill_sdk._errors import SigillError

ENVELOPE_URI = "urn:sigill:envelope"
"""The reserved sigD URI of the envelope (signed object 0)."""

MAX_SIGN_HASHES_OBJECTS = 128
"""Mirror of the platform's per-seal object cap."""

_HEX = set("0123456789abcdefABCDEF")


def _is_hex(s: str | None, length: int) -> bool:
    return isinstance(s, str) and len(s) == length and all(c in _HEX for c in s)


@dataclass(frozen=True)
class SignedObjectDigest:
    """One detached object of a blind multi-object seal: an opaque
    URI-reference and the digest(s) of the object bytes, computed by the
    caller. URIs must carry no personal data (opaque URNs);
    ``urn:sigill:envelope`` is reserved for the envelope itself."""

    uri: str
    hash_hex: str
    """SHA-256 of the object bytes, hex."""
    hash_hex512: str | None = None
    """SHA-512 of the same bytes — required for every object when ``pqc``."""
    content_type: str | None = None
    """MIME type persisted as the object's signed ``ctys`` entry."""


@dataclass(frozen=True)
class SignHashesResult:
    """Result of a blind multi-object signing call: the JAdES signature
    (General JWS JSON Serialization) plus the operation identity. The caller
    assembles its own artifact — no artifact ever exists server-side."""

    signature: dict[str, Any]
    operation_id: str | None
    format: str | None
    timestamped_by: str | None
    qualified: bool
    pqc: bool
    raw: dict[str, Any] = field(repr=False, default_factory=dict)


@dataclass(frozen=True)
class SignedObjectVerdict:
    """Per-object verdict from blind object-level verification."""

    uri: str
    content_type: str | None
    supplied: bool
    hash_match: bool


@dataclass(frozen=True)
class ObjectsVerificationResult:
    """The platform's cryptographic verdicts over a multi-object seal,
    profile-agnostic. Envelope-layer checks (schema, alignment, role
    coverage) are the calling profile's job on its own copy of the
    envelope."""

    signature_valid: bool
    complete: bool
    pqc: str
    """absent | verified | failed | not_checked — the hybrid dimension."""
    object_count: int
    supplied_count: int
    matched_count: int
    objects: list[SignedObjectVerdict]
    missing: list[str]
    unreferenced: list[str]
    issues: list[str]
    raw: dict[str, Any] = field(repr=False, default_factory=dict)

    @property
    def ok(self) -> bool:
        """The cryptographic answer: complete ∧ the hybrid dimension settled
        (pqc absent-or-verified). Enforced client-side as well as
        server-side, so a hybrid seal is never ok from the classical verdict
        alone. Profile-layer checks come on top of this."""
        return self.complete and self.pqc in ("absent", "verified")


def build_sign_hashes_body(
    envelope_hash_hex: str,
    objects: list[SignedObjectDigest],
    certificate_id: str,
    *,
    envelope_content_type: str | None,
    envelope_hash_hex512: str | None,
    qualified: bool,
    pqc: bool,
    label: str | None,
    tags: list[str] | None,
    reminders: str | None,
    reminder_days: int | None,
) -> dict[str, Any]:
    """Validate the digest inputs and build the wire body — every failure
    here happens before any network call."""
    if not _is_hex(envelope_hash_hex, 64):
        raise SigillError(
            "envelope_hash_hex must be 64 hex characters (SHA-256 of the canonical envelope)."
        )
    if pqc and not _is_hex(envelope_hash_hex512, 128):
        raise SigillError(
            "pqc requires envelope_hash_hex512 — 128 hex characters (SHA-512 of the same canonical envelope)."
        )
    if len(objects) > MAX_SIGN_HASHES_OBJECTS:
        raise SigillError(
            f"objects[] is capped at {MAX_SIGN_HASHES_OBJECTS} entries per seal."
        )

    seen: set[str] = set()
    request_objects: list[dict[str, Any]] = []
    for o in objects:
        uri = (o.uri or "").strip()
        if not uri:
            raise SigillError("Every object needs a non-empty opaque URI.")
        if uri == ENVELOPE_URI:
            raise SigillError(f"'{ENVELOPE_URI}' is reserved for the envelope itself.")
        if uri in seen:
            raise SigillError(
                f"Duplicate object URI '{uri}' — URIs are compared byte-exactly and must be unique."
            )
        seen.add(uri)
        if not _is_hex(o.hash_hex, 64):
            raise SigillError(f"Object '{uri}': hash_hex must be 64 hex characters (SHA-256).")
        if pqc and not _is_hex(o.hash_hex512, 128):
            raise SigillError(
                f"Object '{uri}': pqc requires hash_hex512 — 128 hex characters (SHA-512)."
            )

        req_obj: dict[str, Any] = {"uri": uri, "hashHex": o.hash_hex}
        if pqc:
            req_obj["hashHex512"] = o.hash_hex512
        if o.content_type is not None:
            req_obj["contentType"] = o.content_type
        request_objects.append(req_obj)

    body: dict[str, Any] = {
        "envelopeHashHex": envelope_hash_hex,
        "certificateId": str(certificate_id),
        "objects": request_objects,
        "qualified": qualified,
    }
    if envelope_content_type is not None:
        body["envelopeContentType"] = envelope_content_type
    if pqc:
        body["pqc"] = True
        body["envelopeHashHex512"] = envelope_hash_hex512
    if label is not None:
        body["label"] = label
    if tags:
        body["tags"] = list(tags)
    if reminders is not None:
        body["reminders"] = reminders
    if reminder_days is not None:
        body["reminderDays"] = reminder_days
    return body


def parse_objects_verdict(
    raw: dict[str, Any], *, hybrid: bool, had_digests512: bool
) -> ObjectsVerificationResult:
    """Map the /seal/verify-objects response, enforcing the hybrid
    both-required rule client-side: the SDK detected the ML-DSA signer
    itself, so a response with no pqc verdict (older or third-party verifier
    build) must NEVER let the classical verdict stand in for the hybrid
    one. Missing pqc on a hybrid JWS ⇒ not_checked."""
    r = raw.get("objects") or {}

    verdicts = [
        SignedObjectVerdict(
            uri=o.get("par") or "",
            content_type=o.get("contentType"),
            supplied=bool(o.get("supplied")),
            hash_match=bool(o.get("hashMatch")),
        )
        for o in r.get("objects") or []
    ]

    issues: list[str] = []
    pqc_verdict = r.get("pqc")
    if pqc_verdict is None:
        pqc_verdict = "not_checked" if hybrid else "absent"
        if hybrid:
            issues.append(
                "Hybrid seal: the verifier returned no pqc verdict — treat the ML-DSA commitment as not checked."
            )
    elif pqc_verdict in ("not_checked", "failed"):
        issues.append(f"Hybrid seal: the ML-DSA commitment is '{pqc_verdict}'.")
    if hybrid and not had_digests512:
        issues.append(
            "Hybrid seal: no SHA-512 digests were supplied — the ML-DSA commitment cannot verify without them."
        )
    for w in r.get("warnings") or []:
        if isinstance(w, str):
            issues.append(w)

    return ObjectsVerificationResult(
        signature_valid=bool(r.get("signatureValid")),
        complete=bool(r.get("complete")),
        pqc=pqc_verdict,
        object_count=int(r.get("objectCount") or 0),
        supplied_count=int(r.get("suppliedCount") or 0),
        matched_count=int(r.get("matchedCount") or 0),
        objects=verdicts,
        missing=[m for m in r.get("missing") or [] if isinstance(m, str)],
        unreferenced=[u for u in r.get("unreferenced") or [] if isinstance(u, str)],
        issues=issues,
        raw=raw,
    )
