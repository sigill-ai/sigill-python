"""Verification tests.

Cover every documented failure mode from spec §7:

  - canonicalization_failed   (envelope can't be canonicalized at all)
  - hash_mismatch             (envelope content modified, OR external payload missing/wrong)
  - invalid_proof             (TSR doesn't parse, OR its imprint doesn't match the canonical bytes)
  - timestamp_unavailable     (envelope was sealed with no proofs)

Verification is contract-level: result.is_valid is the boolean answer; result.issues
is the structured report with one entry per problem found. Tests assert both shape
and content.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest

from sigill_sdk import (
    SigillClient,
    AiEvidenceVerificationResult,
    VerificationIssueKind,
    compute_envelope_hash,
)
from _tsr_factory import make_tsr


@pytest.fixture
def client() -> SigillClient:
    """A SigillClient that won't make any network calls because we never call seal()."""
    return SigillClient(api_key="not-used-in-these-tests")


def _seal_offline(envelope: dict) -> dict:
    """Mimic SigillClient.seal() *without* the HTTP round-trip. Stamps the canonical
    envelope bytes locally with the test TSA factory and attaches the proof. Used to
    produce well-formed sealed envelopes the verifier can chew on."""
    env = copy.deepcopy(envelope)
    env.setdefault("integrity", {})
    env["integrity"]["canonicalization"] = "RFC8785"
    env["integrity"].pop("envelopeHash", None)
    env.pop("proofs", None)
    digest_hex, canonical = compute_envelope_hash(env)
    env["integrity"]["envelopeHash"] = {"alg": "SHA-256", "hex": digest_hex}

    imprint = hashlib.sha256(canonical).digest()
    tsr_bytes = make_tsr(imprint, hash_alg="SHA-256")
    env["proofs"] = [
        {
            "type": "rfc3161",
            "tsrBase64": base64.b64encode(tsr_bytes).decode("ascii"),
            "tsaName": "Sigill SDK Test TSA",
        }
    ]
    return env


# --------------------------------------------------------------------------- happy path


def test_verify_happy_path_inline(vectors_dir: Path, client: SigillClient) -> None:
    """Vector 01 has only inline payloads — no external map needed for verification."""
    expected = json.loads((vectors_dir / "01-complete-ai-call" / "expected.json").read_text())
    sealed = _seal_offline(expected)

    result = client.verify(sealed)
    assert result.is_valid, [str(i) for i in result.issues]
    assert result.envelope_hash_hex == sealed["integrity"]["envelopeHash"]["hex"]
    assert len(result.timestamps) == 1
    assert result.timestamps[0]["tsa_name"] == "Sigill SDK Test TSA"


def test_verify_happy_path_with_external_payloads(vectors_dir: Path, client: SigillClient) -> None:
    """Vector 02 references PII payloads externally — verifier needs the bytes."""
    vec = vectors_dir / "02-pii-redacted"
    expected = json.loads((vec / "expected.json").read_text())
    sealed = _seal_offline(expected)

    payloads = {
        "prompt": (vec / "external-payloads" / "prompt.txt").read_bytes(),
        "ctx-1": (vec / "external-payloads" / "ctx-1.txt").read_bytes(),
        "output": (vec / "external-payloads" / "output.json").read_bytes(),
    }
    result = client.verify(sealed, external_payloads=payloads)
    assert result.is_valid, [str(i) for i in result.issues]


def test_verify_returns_a_result_for_truthiness(vectors_dir: Path, client: SigillClient) -> None:
    """Idiomatic Python — `if client.verify(env): ...` should Just Work."""
    expected = json.loads((vectors_dir / "01-complete-ai-call" / "expected.json").read_text())
    sealed = _seal_offline(expected)
    assert bool(client.verify(sealed)) is True


# --------------------------------------------------------------------------- hash_mismatch: envelope tampering


def test_envelope_tampering_is_detected(vectors_dir: Path, client: SigillClient) -> None:
    expected = json.loads((vectors_dir / "01-complete-ai-call" / "expected.json").read_text())
    sealed = _seal_offline(expected)

    # Mutate any field; the recomputed hash will differ from the registered one.
    sealed["model"]["name"] = "claude-haiku-4-5-20251001"

    result = client.verify(sealed)
    assert not result.is_valid
    issues = [i for i in result.issues if i.kind == VerificationIssueKind.HASH_MISMATCH and i.target == "envelope"]
    assert len(issues) == 1
    assert "envelope_hash_does_not_match" in issues[0].message
    assert issues[0].expected != issues[0].actual


def test_missing_envelope_hash_is_reported(vectors_dir: Path, client: SigillClient) -> None:
    expected = json.loads((vectors_dir / "01-complete-ai-call" / "expected.json").read_text())
    sealed = _seal_offline(expected)
    del sealed["integrity"]["envelopeHash"]

    result = client.verify(sealed)
    assert not result.is_valid
    assert any(
        i.kind == VerificationIssueKind.HASH_MISMATCH and i.target == "envelope"
        for i in result.issues
    )


# --------------------------------------------------------------------------- hash_mismatch: external payloads (vector 03 scenarios)


def test_missing_external_payload_is_reported(vectors_dir: Path, client: SigillClient) -> None:
    """Vector 03 scenario 1: prompt bytes not supplied. The verifier must report which
    ref was missing and surface the registered hash for diagnostics."""
    vec = vectors_dir / "02-pii-redacted"
    expected = json.loads((vec / "expected.json").read_text())
    sealed = _seal_offline(expected)

    # Supply ctx-1 and output but NOT prompt
    payloads = {
        "ctx-1": (vec / "external-payloads" / "ctx-1.txt").read_bytes(),
        "output": (vec / "external-payloads" / "output.json").read_bytes(),
    }
    result = client.verify(sealed, external_payloads=payloads)
    assert not result.is_valid
    missing = [i for i in result.issues if i.target == "prompt"]
    assert len(missing) == 1
    assert missing[0].kind == VerificationIssueKind.HASH_MISMATCH
    assert "payload_not_supplied" in missing[0].message
    assert missing[0].expected  # registered hash is surfaced for diagnostics


def test_wrong_external_payload_is_reported(vectors_dir: Path, client: SigillClient) -> None:
    """Vector 03 scenario 2: prompt mapped to different bytes. Must report both
    expected and actual hex."""
    vec = vectors_dir / "02-pii-redacted"
    expected = json.loads((vec / "expected.json").read_text())
    sealed = _seal_offline(expected)

    payloads = {
        "prompt": b"these are the wrong bytes entirely",
        "ctx-1": (vec / "external-payloads" / "ctx-1.txt").read_bytes(),
        "output": (vec / "external-payloads" / "output.json").read_bytes(),
    }
    result = client.verify(sealed, external_payloads=payloads)
    assert not result.is_valid
    bad = [i for i in result.issues if i.target == "prompt"]
    assert len(bad) == 1
    assert bad[0].kind == VerificationIssueKind.HASH_MISMATCH
    assert "digest_does_not_match" in bad[0].message
    assert bad[0].expected and bad[0].actual
    assert bad[0].expected != bad[0].actual


def test_correct_external_payload_passes(vectors_dir: Path, client: SigillClient) -> None:
    """Sanity inverse of the wrong-payload test."""
    vec = vectors_dir / "02-pii-redacted"
    expected = json.loads((vec / "expected.json").read_text())
    sealed = _seal_offline(expected)

    payloads = {
        "prompt": (vec / "external-payloads" / "prompt.txt").read_bytes(),
        "ctx-1": (vec / "external-payloads" / "ctx-1.txt").read_bytes(),
        "output": (vec / "external-payloads" / "output.json").read_bytes(),
    }
    result = client.verify(sealed, external_payloads=payloads)
    assert result.is_valid


# --------------------------------------------------------------------------- invalid_proof


def test_malformed_tsr_is_reported(vectors_dir: Path, client: SigillClient) -> None:
    expected = json.loads((vectors_dir / "01-complete-ai-call" / "expected.json").read_text())
    sealed = _seal_offline(expected)
    sealed["proofs"][0]["tsrBase64"] = base64.b64encode(b"garbage that is not a TSR").decode()

    result = client.verify(sealed)
    assert not result.is_valid
    assert any(i.kind == VerificationIssueKind.INVALID_PROOF for i in result.issues)


def test_tsr_imprint_mismatch_is_reported(vectors_dir: Path, client: SigillClient) -> None:
    """The TSR is well-formed and signed, but its imprint is over different bytes than
    the envelope's canonical form. This is the proof-substitution attack the SDK
    must catch."""
    expected = json.loads((vectors_dir / "01-complete-ai-call" / "expected.json").read_text())
    sealed = _seal_offline(expected)

    # Replace the proof with a TSR over UNRELATED bytes
    fake_imprint = hashlib.sha256(b"this is not the canonical envelope").digest()
    bogus_tsr = make_tsr(fake_imprint)
    sealed["proofs"][0]["tsrBase64"] = base64.b64encode(bogus_tsr).decode()

    result = client.verify(sealed)
    assert not result.is_valid
    bad = [i for i in result.issues if i.kind == VerificationIssueKind.INVALID_PROOF]
    assert len(bad) >= 1
    assert any("message-imprint" in i.message for i in bad)


def test_unsupported_proof_type_is_reported(vectors_dir: Path, client: SigillClient) -> None:
    expected = json.loads((vectors_dir / "01-complete-ai-call" / "expected.json").read_text())
    sealed = _seal_offline(expected)
    sealed["proofs"] = [{"type": "jws", "value": "not-supported-in-v1"}]

    result = client.verify(sealed)
    assert not result.is_valid
    assert any(
        i.kind == VerificationIssueKind.INVALID_PROOF and "unsupported proof type" in i.message
        for i in result.issues
    )


# --------------------------------------------------------------------------- timestamp_unavailable


def test_envelope_with_no_proofs_reports_timestamp_unavailable(
    vectors_dir: Path, client: SigillClient
) -> None:
    """A producer can return an envelope with no proofs[] when every TSA failed at
    seal time. The verifier surfaces this as a distinct issue, not a generic failure."""
    expected = json.loads((vectors_dir / "01-complete-ai-call" / "expected.json").read_text())
    sealed = _seal_offline(expected)
    del sealed["proofs"]

    result = client.verify(sealed)
    assert not result.is_valid
    assert any(
        i.kind == VerificationIssueKind.TIMESTAMP_UNAVAILABLE for i in result.issues
    )


def test_empty_proofs_array_also_reports_timestamp_unavailable(
    vectors_dir: Path, client: SigillClient
) -> None:
    expected = json.loads((vectors_dir / "01-complete-ai-call" / "expected.json").read_text())
    sealed = _seal_offline(expected)
    sealed["proofs"] = []

    result = client.verify(sealed)
    assert not result.is_valid
    assert any(
        i.kind == VerificationIssueKind.TIMESTAMP_UNAVAILABLE for i in result.issues
    )


# --------------------------------------------------------------------------- multi-issue reporting


def test_verify_collects_all_issues_not_just_first(vectors_dir: Path, client: SigillClient) -> None:
    """Verifier MUST NOT short-circuit on the first error. An audit UI needs the full
    report (per spec §7)."""
    vec = vectors_dir / "02-pii-redacted"
    expected = json.loads((vec / "expected.json").read_text())
    sealed = _seal_offline(expected)

    # Tamper with the envelope AND supply wrong bytes for prompt — both should be
    # reported.
    sealed["model"]["name"] = "tampered"

    result = client.verify(
        sealed,
        external_payloads={
            "prompt": b"wrong bytes",
            "ctx-1": (vec / "external-payloads" / "ctx-1.txt").read_bytes(),
            "output": (vec / "external-payloads" / "output.json").read_bytes(),
        },
    )
    assert not result.is_valid
    targets = {i.target for i in result.issues}
    assert "envelope" in targets
    assert "prompt" in targets
