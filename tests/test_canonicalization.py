"""Cross-language interop tests: the SDK MUST produce the same canonical bytes and
envelope hash as the reference test vectors. If this file ever fails, either the spec
has shifted or one of the SDKs has drifted — both warrant a release-blocking fix.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sigill_sdk import (
    EnvelopeBuilder,
    canonicalize,
    compute_envelope_hash,
)
from sigill_sdk._errors import CanonicalizationFailed


# --------------------------------------------------------------------------- vectors


@pytest.mark.parametrize("vector_name", ["01-complete-ai-call", "02-pii-redacted"])
def test_vector_canonical_bytes_match(vectors_dir: Path, vector_name: str) -> None:
    """The SDK's canonical output MUST be byte-identical to the committed canonical.json."""
    vec = vectors_dir / vector_name
    expected = (vec / "expected.json").read_bytes()
    expected_obj = json.loads(expected)

    # Strip integrity.envelopeHash and proofs (per spec §4) and canonicalize.
    to_hash = json.loads(json.dumps(expected_obj))
    to_hash.get("integrity", {}).pop("envelopeHash", None)
    to_hash.pop("proofs", None)
    actual_canonical = canonicalize(to_hash)

    expected_canonical = (vec / "canonical.json").read_bytes()
    assert actual_canonical == expected_canonical, (
        f"canonical bytes drift in vector {vector_name}\n"
        f"expected len={len(expected_canonical)}, actual len={len(actual_canonical)}"
    )


@pytest.mark.parametrize("vector_name", ["01-complete-ai-call", "02-pii-redacted"])
def test_vector_envelope_hash_matches(vectors_dir: Path, vector_name: str) -> None:
    """The SDK's envelope-hash MUST equal the committed envelope-hash.txt."""
    vec = vectors_dir / vector_name
    expected_obj = json.loads((vec / "expected.json").read_text())
    expected_hex = (vec / "envelope-hash.txt").read_text().strip()

    actual_hex, _ = compute_envelope_hash(expected_obj)
    assert actual_hex == expected_hex


def test_envelope_hash_is_independent_of_proofs(vectors_dir: Path) -> None:
    """Adding proofs[] after sealing MUST NOT change envelopeHash. The whole point of
    stripping proofs before hashing (spec §4) is that proofs can be appended (e.g.
    archival re-stamps) without invalidating earlier proofs."""
    expected_obj = json.loads((vectors_dir / "01-complete-ai-call" / "expected.json").read_text())
    h1, _ = compute_envelope_hash(expected_obj)

    expected_obj["proofs"] = [
        {"type": "rfc3161", "tsrBase64": "AAAA", "tsaName": "DigiCert"},
        {"type": "rfc3161", "tsrBase64": "BBBB", "tsaName": "Sectigo"},
    ]
    h2, _ = compute_envelope_hash(expected_obj)
    assert h1 == h2


# --------------------------------------------------------------------------- determinism


def test_builder_is_deterministic_with_pinned_id_and_time() -> None:
    """The EnvelopeBuilder produces the same canonical hash on repeated calls when
    evidence_id and created_at are pinned. Without pinning they vary by design."""

    def make() -> dict:
        env = (
            EnvelopeBuilder()
            .with_evidence_id("01957f3e-2c4d-7c3b-a1d2-3a8b9e1f4c2d")
            .with_created_at("2026-05-08T12:00:00Z")
            .with_purpose(category="test")
            .with_actor(type="service", id="svc")
            .with_activity(name="x")
            .with_model(provider="anthropic", name="claude-opus-4-7")
            .with_prompt_inline("hi")
            .with_output_inline("hello")
            .build()
        )
        env["integrity"] = {"canonicalization": "RFC8785"}
        return env

    h1, _ = compute_envelope_hash(make())
    h2, _ = compute_envelope_hash(make())
    h3, _ = compute_envelope_hash(make())
    assert h1 == h2 == h3


def test_key_order_in_input_does_not_affect_hash() -> None:
    """JCS sorts keys lexicographically by UTF-16 code-unit order. Two structurally
    identical envelopes produced with different insertion orders MUST hash the same."""
    envA = {
        "schemaName": "AiEvidenceEnvelope",
        "schemaVersion": "1",
        "evidenceId": "01957f3e-2c4d-7c3b-a1d2-3a8b9e1f4c2d",
        "createdAt": "2026-05-08T12:00:00Z",
        "purpose": {"category": "x"},
        "actor": {"type": "service", "id": "s"},
        "activity": {"name": "y"},
        "model": {"provider": "p", "name": "n"},
        "integrity": {"canonicalization": "RFC8785"},
    }
    envB = {
        "model": {"name": "n", "provider": "p"},
        "integrity": {"canonicalization": "RFC8785"},
        "actor": {"id": "s", "type": "service"},
        "activity": {"name": "y"},
        "purpose": {"category": "x"},
        "createdAt": "2026-05-08T12:00:00Z",
        "evidenceId": "01957f3e-2c4d-7c3b-a1d2-3a8b9e1f4c2d",
        "schemaVersion": "1",
        "schemaName": "AiEvidenceEnvelope",
    }
    h1, c1 = compute_envelope_hash(envA)
    h2, c2 = compute_envelope_hash(envB)
    assert h1 == h2
    assert c1 == c2


def test_unicode_content_is_handled_canonically() -> None:
    """Non-ASCII content must round-trip through JCS deterministically. Two envelopes
    containing equivalent Norwegian text MUST hash identically."""
    base = {
        "schemaName": "AiEvidenceEnvelope",
        "schemaVersion": "1",
        "evidenceId": "01957f3e-2c4d-7c3b-a1d2-3a8b9e1f4c2d",
        "createdAt": "2026-05-08T12:00:00Z",
        "purpose": {"category": "test", "businessContext": "Tjørstad-saken"},
        "actor": {"type": "service", "id": "s"},
        "activity": {"name": "y"},
        "model": {"provider": "p", "name": "n"},
        "integrity": {"canonicalization": "RFC8785"},
    }
    h1, _ = compute_envelope_hash(base)
    h2, _ = compute_envelope_hash(json.loads(json.dumps(base, ensure_ascii=False)))
    h3, _ = compute_envelope_hash(json.loads(json.dumps(base, ensure_ascii=True)))
    assert h1 == h2 == h3


# --------------------------------------------------------------------------- error paths


def test_canonicalization_rejects_nan() -> None:
    """JCS forbids NaN/Infinity (I-JSON constraint). The SDK must surface that as
    CanonicalizationFailed, not a bare TypeError."""
    bad = {"x": float("nan")}
    with pytest.raises(CanonicalizationFailed):
        canonicalize(bad)


def test_canonicalization_rejects_unsupported_alg() -> None:
    with pytest.raises(CanonicalizationFailed):
        compute_envelope_hash({"x": 1}, alg="MD5")


# --------------------------------------------------------------------------- generator parity


@pytest.mark.parametrize("vector_name", ["01-complete-ai-call", "02-pii-redacted"])
def test_generator_output_matches_committed_files(vectors_dir: Path, vector_name: str) -> None:
    """Sanity: the committed canonical.json matches SHA-256(canonical.json) == envelope-hash.txt.
    Catches drift if someone hand-edits one but not the other."""
    vec = vectors_dir / vector_name
    canonical = (vec / "canonical.json").read_bytes()
    expected_hex = (vec / "envelope-hash.txt").read_text().strip()
    assert hashlib.sha256(canonical).hexdigest() == expected_hex
