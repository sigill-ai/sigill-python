"""Builder ergonomics: missing required fields fail early; payloadRef shapes are
correct; the result conforms to the schema."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sigill_sdk import EnvelopeBuilder


def test_minimal_envelope_builds() -> None:
    env = (
        EnvelopeBuilder()
        .with_purpose(category="x")
        .with_actor(type="service", id="s")
        .with_activity(name="a")
        .with_model(provider="p", name="n")
        .build()
    )
    # Required fields all present
    for field in ("schemaName", "schemaVersion", "evidenceId", "createdAt",
                  "purpose", "actor", "activity", "model"):
        assert field in env
    assert env["schemaName"] == "AiEvidenceEnvelope"
    assert env["schemaVersion"] == "1"


def test_missing_required_fields_raise_value_error() -> None:
    b = EnvelopeBuilder().with_purpose(category="x")  # missing actor/activity/model
    with pytest.raises(ValueError) as exc:
        b.build()
    msg = str(exc.value)
    assert "actor" in msg and "activity" in msg and "model" in msg


def test_inline_prompt_shape() -> None:
    env = (
        EnvelopeBuilder()
        .with_purpose(category="x")
        .with_actor(type="user", id="u")
        .with_activity(name="a")
        .with_model(provider="p", name="n")
        .with_prompt_inline("hi", content_type="text/plain")
        .build()
    )
    assert env["prompt"] == {
        "contentType": "text/plain",
        "encoding": "utf-8",
        "inline": "hi",
    }


def test_ref_prompt_shape() -> None:
    env = (
        EnvelopeBuilder()
        .with_purpose(category="x")
        .with_actor(type="user", id="u")
        .with_activity(name="a")
        .with_model(provider="p", name="n")
        .with_prompt_ref("prompt-001")
        .build()
    )
    assert env["prompt"] == {
        "ref": "prompt-001",
        "contentType": "text/plain",
        "encoding": "utf-8",
    }


def test_build_returns_independent_copy() -> None:
    """Subsequent mutations of the builder must not leak into a previously-built envelope.
    This protects against subtle bugs where a caller calls build(), then keeps tweaking."""
    b = (
        EnvelopeBuilder()
        .with_purpose(category="x")
        .with_actor(type="user", id="u")
        .with_activity(name="a")
        .with_model(provider="p", name="n")
    )
    env1 = b.build()
    b.with_model(provider="p2", name="n2")
    env2 = b.build()
    assert env1["model"]["provider"] == "p"
    assert env2["model"]["provider"] == "p2"


def test_evidence_id_pinning(vectors_dir: Path) -> None:
    """Pinning evidence_id and created_at allows deterministic-output tests."""
    env = (
        EnvelopeBuilder()
        .with_evidence_id("01957f3e-2c4d-7c3b-a1d2-3a8b9e1f4c2d")
        .with_created_at("2026-05-08T12:00:00Z")
        .with_purpose(category="x")
        .with_actor(type="user", id="u")
        .with_activity(name="a")
        .with_model(provider="p", name="n")
        .build()
    )
    assert env["evidenceId"] == "01957f3e-2c4d-7c3b-a1d2-3a8b9e1f4c2d"
    assert env["createdAt"] == "2026-05-08T12:00:00Z"


def test_builder_reproduces_test_vector_01(vectors_dir: Path) -> None:
    """The builder, fed the same logical content as vector 01, must produce the same
    envelope (modulo created_at / evidence_id which we pin from the vector). This is
    the SDK's promise: 'use the builder and you get the spec-conforming result.'"""
    expected = json.loads((vectors_dir / "01-complete-ai-call" / "expected.json").read_text())

    env = (
        EnvelopeBuilder()
        .with_evidence_id(expected["evidenceId"])
        .with_created_at(expected["createdAt"])
        .with_purpose(
            category=expected["purpose"]["category"],
            business_context=expected["purpose"].get("businessContext"),
        )
        .with_actor(
            type=expected["actor"]["type"],
            id=expected["actor"]["id"],
            tenant_id=expected["actor"].get("tenantId"),
        )
        .with_activity(
            name=expected["activity"]["name"],
            correlation_id=expected["activity"].get("correlationId"),
        )
        .with_model(
            provider=expected["model"]["provider"],
            name=expected["model"]["name"],
            parameters=expected["model"].get("parameters"),
        )
        .with_prompt_inline(
            expected["prompt"]["inline"],
            content_type=expected["prompt"]["contentType"],
        )
        .with_output_inline(
            expected["output"]["inline"],
            content_type=expected["output"]["contentType"],
        )
        .with_processing_metadata(**expected["processingMetadata"])
        .with_policy_metadata(**expected["policyMetadata"])
        .build()
    )
    # The builder produces the input shape (no integrity.envelopeHash yet).
    expected_minus_hash = {k: v for k, v in expected.items() if k != "integrity"}
    env_minus_integrity = {k: v for k, v in env.items() if k != "integrity"}
    assert env_minus_integrity == expected_minus_hash
