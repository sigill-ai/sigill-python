"""RFC 8785 canonicalization and envelope-hash computation.

This module implements the deterministic operations every consumer of the spec must
agree on, byte for byte:

  1. canonicalize(obj) -> bytes
       Produce the RFC 8785 (JCS) canonical form. Delegates to the `jcs` reference
       implementation.

  2. compute_envelope_hash(envelope) -> (hex_digest, canonical_bytes)
       Strip integrity.envelopeHash and proofs, canonicalize, SHA-256 the result. Per
       spec §4.

The two-step is exposed publicly so the SDK can hand callers the canonical bytes for
inspection or external use (e.g. feeding directly to /tsa/stamp without going through
seal()).
"""
from __future__ import annotations

import copy
import hashlib
from typing import Any

import jcs

from sigill_sdk._errors import CanonicalizationFailed


_HASH_ALGS = {
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
}


def canonicalize(obj: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of *obj*.

    Wraps the `jcs` reference library and lifts its errors into CanonicalizationFailed
    so callers get a stable error surface.
    """
    try:
        return jcs.canonicalize(obj)
    except (TypeError, ValueError) as e:
        raise CanonicalizationFailed(f"JCS canonicalization failed: {e}") from e


def compute_envelope_hash(
    envelope: dict, alg: str = "SHA-256"
) -> tuple[str, bytes]:
    """Compute the envelope hash per spec §4.

    Returns `(hex_digest, canonical_bytes)`. The canonical bytes are returned so callers
    can audit, log, or feed them into a TSA without recomputing.

    The input envelope is NOT mutated. A deep copy is taken; integrity.envelopeHash and
    proofs are stripped from the copy before canonicalization.
    """
    if alg not in _HASH_ALGS:
        raise CanonicalizationFailed(
            f"Unsupported hash algorithm: {alg!r}. Supported: {sorted(_HASH_ALGS)}"
        )

    stripped = copy.deepcopy(envelope)
    integrity = stripped.get("integrity")
    if isinstance(integrity, dict) and "envelopeHash" in integrity:
        del integrity["envelopeHash"]
    if "proofs" in stripped:
        del stripped["proofs"]

    canonical = canonicalize(stripped)
    digest = _HASH_ALGS[alg](canonical).hexdigest()
    return digest, canonical


def hash_bytes(data: bytes, alg: str = "SHA-256") -> str:
    """Hash arbitrary bytes with the named algorithm. Lowercase hex."""
    if alg not in _HASH_ALGS:
        raise CanonicalizationFailed(
            f"Unsupported hash algorithm: {alg!r}. Supported: {sorted(_HASH_ALGS)}"
        )
    return _HASH_ALGS[alg](data).hexdigest()
