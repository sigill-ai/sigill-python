# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Agent Evidence Profiles v1 — constants and the normative digests.

See ``spec/agent-profiles-common-v1.md``: the binding digest (§2) and the
signer (§3). Recording and verification build on these; they are public so
other producers and verifiers can reproduce them. Mirrors the .NET SDK's
``AgentProfiles`` one-to-one.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from sigill_sdk._canonical import canonicalize, hash_bytes
from sigill_sdk._schema import validate_profile
from sigill_sdk._sign_objects import ENVELOPE_URI

BUNDLE_FORMAT = "AgentRunBundle"
"""The bundle's ``format`` value (§7)."""

BUNDLE_VERSION = "1"

CONTROL_ARTIFACT_SCHEMA = "AgentControlArtifact"
EXECUTION_EVIDENCE_SCHEMA = "AgentExecutionEvidence"
CONTROL_EVALUATION_SCHEMA = "ControlEvaluation"

CONTROL_ARTIFACT_CONTENT_TYPE = "application/vnd.sigill.agent-control+json"
"""The Control Artifact's content type, signed as ``sigD.ctys[0]``."""
EXECUTION_EVIDENCE_CONTENT_TYPE = "application/vnd.sigill.agent-execution+json"
CONTROL_EVALUATION_CONTENT_TYPE = "application/vnd.sigill.control-evaluation+json"

MAX_ARTIFACTS = 2000
"""Upper bound on events per bundle (§7)."""
MAX_EVALUATIONS = 64
"""Upper bound on Control Evaluations per bundle; each costs one signature check."""
MAX_PAYLOADS = 20000
"""Upper bound on supplied payloads per bundle."""
MAX_DEPTH = 64
"""Upper bound on JSON nesting depth."""

_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")
_I_JSON_MAX_INT = 2 ** 53


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


def _b64u_decode(s: Any) -> bytes:
    """Strict base64url: no padding, nothing outside the alphabet (§2)."""
    if not isinstance(s, str) or not _B64URL.match(s) or len(s) % 4 == 1:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _truncate(t: datetime) -> datetime:
    """The millisecond precision ``eventTime`` is signed with (§4)."""
    return t.replace(microsecond=(t.microsecond // 1000) * 1000)


def _format_time(t: datetime) -> str:
    t = t.astimezone(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _is_i_json(v: Any) -> bool:
    """No integers beyond ±2^53, no lone surrogates, no NaN or Infinity (§1)."""
    if v is None or isinstance(v, bool):
        return True
    if isinstance(v, float):
        return math.isfinite(v)
    if isinstance(v, int):
        return abs(v) <= _I_JSON_MAX_INT
    if isinstance(v, str):
        return not any(0xD800 <= ord(c) <= 0xDFFF for c in v)
    if isinstance(v, list):
        return all(_is_i_json(x) for x in v)
    if isinstance(v, dict):
        return all(isinstance(k, str) and _is_i_json(k) and _is_i_json(x) for k, x in v.items())
    return False


def _is_i_json_strict(v: Any) -> bool:
    """I-JSON that also canonicalizes."""
    if not _is_i_json(v):
        return False
    try:
        canonicalize(v)
        return True
    except Exception:  # noqa: BLE001 — anything JCS refuses is not usable evidence
        return False


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


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


# ── The binding digest (§2) and the signer (§3) ─────────────────────────────

def _classical_entries(signature: Mapping[str, Any]) -> list[tuple[dict, Optional[dict]]]:
    """(entry, protected header or None when unreadable — it still counts, §2) for every non-ML-DSA entry."""
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
            # A repeated member name makes the header unreadable (§1): parsers disagree on which value wins.
            # §1 applies to the header too: strict UTF-8, no repeated names, I-JSON throughout.
            text = _b64u_decode(e.get("protected")).decode("utf-8", errors="strict")
            parsed = json.loads(text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
            header = parsed if isinstance(parsed, dict) and _is_i_json(parsed) else None
        except Exception:  # noqa: BLE001 — unreadable protected header: counts as classical (§2)
            pass
        alg = header.get("alg") if header else None
        if isinstance(alg, str) and alg.upper().startswith("ML-DSA"):
            continue
        out.append((e, header))
    return out


def signature_sha256(signature: Mapping[str, Any]) -> Optional[str]:
    """The binding digest of an artifact (§2): lowercase SHA-256 hex over the
    base64url-decoded JWS Signature Value of its classical signature — the
    first ``signatures[]`` entry whose protected ``alg`` is not ML-DSA, or the
    ``signature`` member of a flattened JWS. Unprotected headers are
    excluded. None when the JWS carries no usable classical signature."""
    for e, _ in _classical_entries(signature):
        sig = _str(e.get("signature"))
        if sig is None:
            continue
        try:
            return hash_bytes(_b64u_decode(sig))
        except ValueError:
            return None
    return None


def signer_of(signature: Mapping[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """The signer of an artifact (§3): ``(x5t#S256, None)``, or ``(None, problem)``.

    Requires exactly one classical entry whose protected header carries
    ``x5c`` and an ``x5t#S256`` equal to the SHA-256 of ``x5c[0]``. This names
    the signer; it proves it together with a signature check against that same
    ``x5c[0]``."""
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
    if _b64u_encode(hashlib.sha256(leaf).digest()) != thumb:
        return None, "its x5t#S256 is not the SHA-256 of x5c[0]"
    return thumb, None


def _content_type_problem(jws: Mapping[str, Any], expected: str) -> Optional[str]:
    """The signed content type (``sigD.ctys[0]``) differs from the profile's; None when it matches or the header
    is unreadable (the signer check reports that)."""
    classical = _classical_entries(jws)
    if len(classical) != 1 or classical[0][1] is None:
        return None
    ctys = (_obj(classical[0][1].get("sigD")) or {}).get("ctys")
    actual = _str(ctys[0]) if isinstance(ctys, list) and ctys else None
    return None if actual == expected else \
        f"its signed content type (sigD.ctys[0]) is '{actual if actual is not None else 'absent'}', not '{expected}'"


def _layout_problem(envelope: Mapping[str, Any], jws: Mapping[str, Any]) -> Optional[str]:
    """§1 / v2 §5.2: the signed ``sigD`` must list the envelope's objects in order — ``pars[0]`` the
    envelope, ``pars[i+1]`` = ``objects[i].uri``, one ``hashV`` and one ``ctys`` entry each, and
    ``ctys[i+1]`` = ``objects[i].contentType`` ("" when absent). A blind verifier matches digests by URI
    and never sees the envelope, so only the profile layer can check this. None when it holds or the header
    is unreadable (the signer check reports that)."""
    classical = _classical_entries(jws)
    if len(classical) != 1 or classical[0][1] is None:
        return None
    sig_d = classical[0][1].get("sigD")
    if not isinstance(sig_d, dict):
        return "the signature carries no sigD object"
    raw = envelope.get("objects")
    objects = [o if isinstance(o, dict) else None for o in raw] if isinstance(raw, list) else []
    expected = [ENVELOPE_URI] + [_str(o.get("uri")) if o is not None else None for o in objects]
    pars = sig_d.get("pars")
    if not isinstance(pars, list) or [_str(p) for p in pars] != expected:
        return "sigD.pars is not the envelope followed by objects[] in order"
    hash_v = sig_d.get("hashV")
    if not isinstance(hash_v, list) or len(hash_v) != len(pars):
        return "sigD.hashV does not have one entry per signed object"
    ctys = sig_d.get("ctys")
    if not isinstance(ctys, list) or len(ctys) != len(pars):
        return "sigD.ctys does not have one entry per signed object"
    for i, o in enumerate(objects):
        signed_type = _str(ctys[i + 1])
        envelope_type = (_str(o.get("contentType")) if o is not None else None) or ""
        if signed_type != envelope_type:
            shown = signed_type if signed_type is not None else ""
            return f"sigD.ctys[{i + 1}] is '{shown}', but objects[{i}].contentType is '{envelope_type}'"
    return None


def _prevalidate(envelope: dict, schema_name: str) -> None:
    """§6.4: never seal an envelope the verifier would reject. Raises ValueError."""
    if not _is_i_json_strict(envelope):
        raise ValueError("the envelope is not valid I-JSON")
    errs = validate_profile(envelope, schema_name)
    if errs:
        raise ValueError("the artifact would not verify: " + "; ".join(errs))


# ── The §4 coverage rule ────────────────────────────────────────────────────

class _TimestampCoverage:
    """Walked in seq order. Used by the recorder to decide which events it must
    timestamp and by the verifier to recompute the same decision from the
    signed policy — one implementation, so the two can never drift apart.

    ``policy`` is the signed policy, or None when unknown (no Control
    Artifact): then only ``run_end`` and declared events are required."""

    def __init__(self, policy: Any):
        self._policy = policy
        self._since_stamp = 0
        self._last_stamp_time: Optional[datetime] = None

    def next(self, seq: int, step_type: str, consequential: bool, declared_required: bool,
             event_time: Optional[datetime]) -> bool:
        p = self._policy
        last = self._last_stamp_time
        required = (
            step_type == "run_end"
            or declared_required
            or (p is not None and (
                p.profile == "per-event"
                or (p.consequential and consequential)
                or (p.every_events > 0 and self._since_stamp + 1 >= p.every_events)
                or (p.every_seconds > 0 and seq > 0 and last is not None and event_time is not None
                    and (event_time - last).total_seconds() >= p.every_seconds)))
        )
        if required:
            self._since_stamp = 0
            self._last_stamp_time = event_time
        else:
            self._since_stamp += 1
        if seq == 0 and self._last_stamp_time is None:
            self._last_stamp_time = event_time
        return required
