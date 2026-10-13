# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""The ``sigD.pars`` reference rules of AiEvidenceEnvelopeV2 v2.1 (§3.1, §5.2, §5.4).

One place for every reader and producer in this SDK: the envelope reference is
classified from the signature being verified, never from configuration, and the
two accepted values are exact strings, never aliases.
"""

from __future__ import annotations

import enum
import json
import uuid
from typing import Any, Mapping, Optional

from sigill_sdk._errors import SigillError

LOCATOR_REFERENCE = "sigill-envelope.json"
"""The envelope reference new seals carry (v2.1)."""

LEGACY_REFERENCE = "urn:sigill:envelope"
"""The envelope reference of seals made before v2.1."""

LEGACY_DIAGNOSTIC = "legacy URN envelope reference; retained for compatibility, not locator form"
"""The explanatory diagnostic for a legacy envelope reference (§5.4). Never a warning."""

_SEGMENT_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-")


class EnvelopeReferenceForm(str, enum.Enum):
    """The form of a seal's envelope reference, ``sigD.pars[0]`` (v2 §5.2 rule 2)."""

    INVALID = "invalid"
    LOCATOR = "locator"
    """``sigill-envelope.json`` — the v2.1 locator reference."""
    LEGACY_URN = "legacy_urn"
    """``urn:sigill:envelope`` — retained for compatibility, not locator form."""


def classify(pars0: Optional[str]) -> EnvelopeReferenceForm:
    """Classify a ``sigD.pars[0]`` value by exact string match."""
    if pars0 == LOCATOR_REFERENCE:
        return EnvelopeReferenceForm.LOCATOR
    if pars0 == LEGACY_REFERENCE:
        return EnvelopeReferenceForm.LEGACY_URN
    return EnvelopeReferenceForm.INVALID


def is_reserved(uri: Optional[str]) -> bool:
    """Both envelope references are reserved: neither may name an object (§3.1)."""
    return uri in (LOCATOR_REFERENCE, LEGACY_REFERENCE)


def new_object_uri() -> str:
    """A new opaque object URI in the production profile: ``objects/<uuid>``."""
    return f"objects/{uuid.uuid4()}"


def is_production_reference(uri: Optional[str]) -> bool:
    """Whether ``uri`` matches the §3.1 production reference profile — Sigill's deliberately narrower subset of
    relative references: non-empty segments of ``A–Z a–z 0–9 . _ ~ -`` separated by single ``/``, no ``.`` or
    ``..`` segment. Governs what a producer emits; never applied to historical evidence."""
    if not isinstance(uri, str) or not uri:
        return False
    for segment in uri.split("/"):
        if not segment or segment in (".", "..") or any(c not in _SEGMENT_CHARS for c in segment):
            return False
    return True


def require_emittable(uri: str) -> None:
    """Raise unless ``uri`` may be emitted as a NEW object URI."""
    if is_reserved(uri):
        raise SigillError(f"'{uri}' is reserved for the envelope itself.")
    if not is_production_reference(uri):
        raise SigillError(
            f"Object URI '{uri}' is not a production-profile reference (AiEvidenceEnvelopeV2 §3.1): use relative "
            "segments of A–Z a–z 0–9 . _ ~ - separated by '/', e.g. objects/<uuid>. Omit the URI to have one generated."
        )


def _pars_of(header: Optional[Mapping[str, Any]]) -> Optional[list[str]]:
    sig_d = header.get("sigD") if isinstance(header, Mapping) else None
    pars = sig_d.get("pars") if isinstance(sig_d, Mapping) else None
    if not isinstance(pars, list) or not all(isinstance(p, str) for p in pars):
        return None
    return list(pars)


def strict_signed_pars(signature: Mapping[str, Any]) -> Optional[list[str]]:
    """``sigD.pars`` of the signature's ONLY classical entry, in signed order — the strict view every success
    decision uses. None unless there is exactly one classical entry, its protected header passes the strict
    reading (§1: strict UTF-8, no repeated member names, I-JSON) and ``pars`` is a list of strings."""
    from sigill_sdk._agent_profiles import _classical_entries

    classical = _classical_entries(signature)
    return _pars_of(classical[0][1]) if len(classical) == 1 else None


def strict_envelope_reference(signature: Mapping[str, Any]) -> Optional[str]:
    """The envelope reference of a structurally valid signature, when it is one of the two; otherwise None.
    Only this establishes a valid envelope form."""
    pars = strict_signed_pars(signature)
    r = pars[0] if pars else None
    return r if classify(r) is not EnvelopeReferenceForm.INVALID else None


def digest_key_for(signature: Mapping[str, Any], *, lenient: bool) -> str:
    """The key under which a verifier supplies the envelope digest. From the strict view when it yields one of the
    two references; otherwise the locator reference — a fallback key never establishes a valid form.
    ``lenient`` (agent-run verification only): when the strict view fails, read ``pars[0]`` of the FIRST classical
    entry the way a lenient signature service does (repeated member: the last value wins), so the cryptographic
    dimension is still reported; that run's signer and verdict fail on their own (common rules §1–§3)."""
    strict = strict_envelope_reference(signature)
    if strict is not None:
        return strict
    if lenient:
        r = _lenient_first_envelope_reference(signature)
        if classify(r) is not EnvelopeReferenceForm.INVALID:
            return r  # type: ignore[return-value]
    return LOCATOR_REFERENCE


def pqc_pars_mismatch(signature: Mapping[str, Any]) -> bool:
    """True when an ML-DSA entry carries a ``sigD`` whose ``pars`` differ from the classical entry's (v2 §5.2
    rule 5: byte-identical, including the envelope reference form). An ML-DSA entry without a readable ``sigD`` is
    left to the cryptographic tier."""
    classical = strict_signed_pars(signature)
    entries = signature.get("signatures")
    if classical is None or not isinstance(entries, list):
        return False
    for e in entries:
        header = _read_header(e)
        alg = header.get("alg") if header else None
        if not (isinstance(alg, str) and alg.upper().startswith("ML-DSA")) or "sigD" not in header:  # type: ignore[operator]
            continue
        if _pars_of(header) != classical:
            return True
    return False


def _read_header(entry: Any) -> Optional[dict]:
    from sigill_sdk._agent_profiles import _b64u_decode

    if not isinstance(entry, dict) or not isinstance(entry.get("protected"), str):
        return None
    try:
        parsed = json.loads(_b64u_decode(entry["protected"]))
    except Exception:  # noqa: BLE001 — unreadable: nothing to compare
        return None
    return parsed if isinstance(parsed, dict) else None


def _lenient_first_envelope_reference(signature: Mapping[str, Any]) -> Optional[str]:
    from sigill_sdk._agent_profiles import _b64u_decode, _classical_entries

    classical = _classical_entries(signature)
    if not classical:
        return None
    try:
        # json.loads keeps the LAST value of a repeated member — the lenient reading.
        header = json.loads(_b64u_decode(classical[0][0].get("protected")))
    except Exception:  # noqa: BLE001
        return None
    pars = header.get("sigD", {}).get("pars") if isinstance(header, dict) and isinstance(header.get("sigD"), dict) else None
    return pars[0] if isinstance(pars, list) and pars and isinstance(pars[0], str) else None
