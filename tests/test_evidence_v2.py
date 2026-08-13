# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""The blind v2 contract from the SDK side: seal sends digests + opaque URIs
only (never envelope, never content), the artifact is assembled client-side,
and verification compounds the platform's cryptographic verdicts with the
envelope-layer checks that are the SDK's job. HTTP is faked; hashes are real.

Mirrors the .NET suite one-to-one.
"""

from __future__ import annotations

import base64
import hashlib
import json

import httpx
import pytest

from sigill_sdk import (
    EvidenceV2Artifact,
    EvidenceV2Payload,
    SigillClient,
    SigillError,
    canonicalize,
)


def _client(handler) -> tuple[SigillClient, list]:
    requests: list = []

    def wrapper(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        requests.append((request.url.path, body))
        return handler(request, body)

    http = httpx.Client(
        base_url="https://api.sigill.ai",
        headers={"Authorization": "Bearer fake"},
        transport=httpx.MockTransport(wrapper),
        timeout=5,
    )
    return SigillClient(api_key="fake", http_client=http), requests


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def _core_envelope() -> dict:
    return {
        "purpose": {"category": "summarization"},
        "actor": {"type": "user", "id": "opaque-actor"},
        "activity": {"name": "chat.completion"},
        "model": {"provider": "anthropic", "name": "claude-fable-5"},
    }


FAKE_SIGNATURE = {"signatures": [{"protected": "e30", "signature": "c2ln"}]}

CERT = "11111111-2222-3333-4444-555555555555"


def test_seal_sends_digests_only_and_assembles_artifact_client_side() -> None:
    prompt = b"the prompt"
    output = b"the output"

    def handler(request, body):
        return httpx.Response(200, json={
            "signature": FAKE_SIGNATURE,
            "operationId": "0be049c7-0000-0000-0000-000000000000",
            "format": "jades-b-t",
        })

    client, requests = _client(handler)
    artifact = client.seal_evidence_v2(
        _core_envelope(),
        [
            EvidenceV2Payload(role="prompt", data=prompt, content_type="text/plain", encoding="utf-8"),
            EvidenceV2Payload(role="output", data=output, uri="urn:test:out", content_type="text/markdown"),
        ],
        CERT,
    )

    path, body = requests[0]
    assert path == "/seal/sign-hashes"

    # Blind: the request carries digests + URIs + ctys — and nothing else.
    assert "envelope" not in body, "the envelope must never be transmitted"
    raw = json.dumps(body)
    assert "the prompt" not in raw and "the output" not in raw
    assert "summarization" not in raw, "envelope metadata must never be transmitted"

    objects = body["objects"]
    assert len(objects) == 2
    assert objects[0]["hashHex"] == _sha256(prompt)
    assert objects[0]["uri"].startswith("urn:uuid:"), "generated URIs are opaque by default"
    assert objects[1]["uri"] == "urn:test:out"

    # The envelope hash binds the SDK's own canonicalization.
    expected = _sha256(canonicalize(artifact.envelope))
    assert body["envelopeHashHex"] == expected
    assert artifact.envelope_hash_hex == expected

    # Client-side artifact: envelope (with SDK-owned objects[]) + returned JWS.
    assert artifact.envelope["schemaName"] == "AiEvidenceEnvelope"
    assert artifact.envelope["schemaVersion"] == "2"
    assert [o["role"] for o in artifact.envelope["objects"]] == ["prompt", "output"]
    assert artifact.signature == FAKE_SIGNATURE

    # Round-trips through the artifact file format.
    reparsed = EvidenceV2Artifact.parse(artifact.to_json())
    assert reparsed.envelope_hash_hex == expected


def test_seal_pqc_sends_sha512_digests_throughout() -> None:
    prompt = b"pqc prompt"

    def handler(request, body):
        return httpx.Response(200, json={"signature": {"signatures": []}})

    client, requests = _client(handler)
    artifact = client.seal_evidence_v2(
        _core_envelope(),
        [EvidenceV2Payload(role="prompt", data=prompt)],
        CERT,
        pqc=True,
    )

    body = requests[0][1]
    assert body["pqc"] is True
    assert body["envelopeHashHex512"] == _sha512(canonicalize(artifact.envelope))
    assert body["objects"][0]["hashHex512"] == _sha512(prompt)


def test_seal_rejects_reserved_and_duplicate_uris_and_bad_roles() -> None:
    def handler(request, body):  # pragma: no cover — must never be reached
        raise AssertionError("validation failures must not reach the network")

    client, requests = _client(handler)
    data = b"x"

    with pytest.raises(SigillError, match="reserved"):
        client.seal_evidence_v2(
            _core_envelope(),
            [EvidenceV2Payload(role="prompt", data=data, uri="urn:sigill:envelope")],
            CERT,
        )
    with pytest.raises(SigillError, match="Duplicate"):
        client.seal_evidence_v2(
            _core_envelope(),
            [
                EvidenceV2Payload(role="prompt", data=data, uri="urn:t:a"),
                EvidenceV2Payload(role="output", data=data, uri="urn:t:a"),
            ],
            CERT,
        )
    with pytest.raises(SigillError, match="role"):
        client.seal_evidence_v2(
            _core_envelope(),
            [EvidenceV2Payload(role="thought", data=data)],
            CERT,
        )
    assert requests == []


def _artifact_with(*objects: tuple[str, str]) -> EvidenceV2Artifact:
    envelope = _core_envelope()
    envelope["schemaName"] = "AiEvidenceEnvelope"
    envelope["schemaVersion"] = "2"
    envelope["objects"] = [{"uri": u, "role": r} for u, r in objects]
    signature = {"signatures": [{"protected": "e30", "signature": "c2ln"}]}
    return EvidenceV2Artifact(envelope=envelope, signature=signature, envelope_hash_hex="ignored")


def _verdict(**overrides) -> dict:
    base = {
        "signatureValid": True,
        "complete": True,
        "pqc": "absent",
        "objectCount": 2,
        "suppliedCount": 2,
        "matchedCount": 2,
        "objects": [
            {"par": "urn:sigill:envelope", "supplied": True, "hashMatch": True},
            {"par": "urn:t:prompt", "supplied": True, "hashMatch": True},
        ],
        "missing": [],
        "unreferenced": [],
    }
    base.update(overrides)
    return {"objects": base}


def test_verify_compounds_platform_verdicts_with_envelope_layer_checks() -> None:
    prompt = b"verify me"
    artifact = _artifact_with(("urn:t:prompt", "prompt"))
    envelope_hex = _sha256(canonicalize(artifact.envelope))

    client, requests = _client(lambda req, body: httpx.Response(200, json=_verdict()))
    result = client.verify_evidence_v2(
        artifact, {"urn:t:prompt": prompt}, required_roles=["prompt"]
    )

    path, body = requests[0]
    assert path == "/seal/verify-objects"
    assert body["digests"]["urn:sigill:envelope"] == envelope_hex, (
        "the envelope digest is computed locally with JCS — the envelope itself never travels"
    )
    assert body["digests"]["urn:t:prompt"] == _sha256(prompt)
    assert "digests512" not in body, "no ML-DSA signer in this JWS"
    assert "summarization" not in json.dumps(body)

    assert result.signature_valid and result.complete
    assert result.alignment_ok and not result.missing_roles
    assert result.ok


def _add_ml_dsa_entry(artifact: EvidenceV2Artifact) -> None:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "ML-DSA-87"}).encode()).decode().rstrip("=")
    artifact.signature["signatures"].append({"protected": header, "signature": "cA"})


def test_verify_hybrid_seal_sends_digests512_automatically() -> None:
    artifact = _artifact_with(("urn:t:prompt", "prompt"))
    _add_ml_dsa_entry(artifact)
    prompt = b"hybrid payload"

    client, requests = _client(
        lambda req, body: httpx.Response(200, json=_verdict(pqc="verified"))
    )
    result = client.verify_evidence_v2(artifact, {"urn:t:prompt": prompt})

    body = requests[0][1]
    assert body["digests512"]["urn:t:prompt"] == _sha512(prompt)
    assert body["digests512"]["urn:sigill:envelope"] == _sha512(canonicalize(artifact.envelope))
    assert result.pqc == "verified"
    assert result.ok


def test_verify_hybrid_against_verifier_without_pqc_verdict_never_reports_ok() -> None:
    # A verifier build that predates the hybrid contract returns complete=true
    # from the classical dimension and NO pqc field. The SDK detected the
    # ML-DSA signer itself, so it must refuse to let that stand in for the
    # hybrid verdict.
    artifact = _artifact_with(("urn:t:prompt", "prompt"))
    _add_ml_dsa_entry(artifact)

    legacy = _verdict()
    del legacy["objects"]["pqc"]
    client, _ = _client(lambda req, body: httpx.Response(200, json=legacy))
    result = client.verify_evidence_v2(artifact, {"urn:t:prompt": b"p"})

    assert result.complete, "the classical verdict is what the old verifier reported"
    assert result.pqc == "not_checked", "a hybrid JWS with no pqc verdict is unchecked, not absent"
    assert not result.ok, "the classical verdict must never stand in for the hybrid one"
    assert any("no pqc verdict" in i for i in result.issues)


def test_verify_surfaces_misalignment_and_uncovered_roles() -> None:
    # Envelope claims urn:t:prompt, but the signature signed urn:t:evil.
    artifact = _artifact_with(("urn:t:prompt", "prompt"))
    verdict = _verdict(
        complete=False,
        suppliedCount=1,
        matchedCount=1,
        objects=[
            {"par": "urn:sigill:envelope", "supplied": True, "hashMatch": True},
            {"par": "urn:t:evil", "supplied": False, "hashMatch": False},
        ],
        missing=["urn:t:evil"],
    )
    client, _ = _client(lambda req, body: httpx.Response(200, json=verdict))
    result = client.verify_evidence_v2(artifact, required_roles=["prompt"])

    assert not result.alignment_ok, "the signed object list does not mirror the envelope's"
    assert result.missing_roles == ["prompt"]
    assert not result.ok
    assert any("align" in i for i in result.issues)
