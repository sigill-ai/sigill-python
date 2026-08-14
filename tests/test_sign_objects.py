# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""The profile-agnostic tier (spec §2/§12): sibling profiles sign and verify
multi-object seals by digests, with their own envelope content type — the
profile discriminator. The AI-evidence methods stay pinned to their own cty
on top of this same tier. HTTP is faked; hashes are real.

Mirrors the .NET suite one-to-one.
"""

from __future__ import annotations

import base64
import hashlib
import json

import httpx
import pytest

from sigill_sdk import (
    EvidenceV2Payload,
    SigillClient,
    SigillError,
    SignedObjectDigest,
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


SIBLING_CTY = "application/vnd.example.records+json"

ENVELOPE_HEX = hashlib.sha256(b"a sibling-profile envelope").hexdigest()
ENVELOPE_512 = hashlib.sha512(b"a sibling-profile envelope").hexdigest()
OBJECT_HEX = hashlib.sha256(b"object one").hexdigest()
OBJECT_512 = hashlib.sha512(b"object one").hexdigest()

CERT = "11111111-2222-3333-4444-555555555555"


def test_sign_object_hashes_carries_caller_content_types_including_object_zero() -> None:
    def handler(request, body):
        return httpx.Response(200, json={
            "signature": {"signatures": []},
            "operationId": "0be049c7-0000-0000-0000-000000000000",
            "format": "jades-b-t",
            "timestampedBy": "Sigill TSA",
            "qualified": False,
            "pqc": False,
        })

    client, requests = _client(handler)
    result = client.sign_object_hashes(
        ENVELOPE_HEX,
        [
            SignedObjectDigest(uri="urn:example:1", hash_hex=OBJECT_HEX, content_type="text/plain"),
            SignedObjectDigest(uri="urn:example:2", hash_hex=hashlib.sha256(b"object two").hexdigest()),
        ],
        CERT,
        envelope_content_type=SIBLING_CTY,
        label="sibling-seal",
    )

    path, body = requests[0]
    assert path == "/seal/sign-hashes"

    # Object 0's content type — the profile discriminator — travels.
    assert body["envelopeContentType"] == SIBLING_CTY
    assert body["envelopeHashHex"] == ENVELOPE_HEX

    objects = body["objects"]
    assert len(objects) == 2
    assert objects[0] == {"uri": "urn:example:1", "hashHex": OBJECT_HEX, "contentType": "text/plain"}
    assert "contentType" not in objects[1], "absent ctys stay absent"

    # Digests-in: nothing but digests, URIs, and ctys ever travels.
    assert "envelope" not in body
    assert body["label"] == "sibling-seal"

    assert result.operation_id == "0be049c7-0000-0000-0000-000000000000"
    assert result.format == "jades-b-t"
    assert result.timestamped_by == "Sigill TSA"
    assert result.signature == {"signatures": []}


def test_sign_object_hashes_pqc_requires_and_sends_sha512_throughout() -> None:
    client, requests = _client(
        lambda req, body: httpx.Response(200, json={"signature": {"signatures": []}, "pqc": True})
    )

    # Missing the SHA-512 envelope digest → rejected before any network call.
    with pytest.raises(SigillError, match="envelope_hash_hex512"):
        client.sign_object_hashes(
            ENVELOPE_HEX,
            [SignedObjectDigest(uri="urn:example:1", hash_hex=OBJECT_HEX, hash_hex512=OBJECT_512)],
            CERT,
            pqc=True,
        )

    # Missing a per-object SHA-512 digest → rejected before any network call.
    with pytest.raises(SigillError, match="hash_hex512"):
        client.sign_object_hashes(
            ENVELOPE_HEX,
            [SignedObjectDigest(uri="urn:example:1", hash_hex=OBJECT_HEX)],
            CERT,
            pqc=True,
            envelope_hash_hex512=ENVELOPE_512,
        )
    assert requests == [], "validation failures must not reach the network"

    result = client.sign_object_hashes(
        ENVELOPE_HEX,
        [SignedObjectDigest(uri="urn:example:1", hash_hex=OBJECT_HEX, hash_hex512=OBJECT_512)],
        CERT,
        pqc=True,
        envelope_hash_hex512=ENVELOPE_512,
    )

    body = requests[0][1]
    assert body["pqc"] is True
    assert body["envelopeHashHex512"] == ENVELOPE_512
    assert body["objects"][0]["hashHex512"] == OBJECT_512
    assert result.pqc is True


def test_sign_object_hashes_validates_uris_and_digests_before_network() -> None:
    def handler(request, body):  # pragma: no cover — must never be reached
        raise AssertionError("validation failures must not reach the network")

    client, requests = _client(handler)
    one = SignedObjectDigest(uri="urn:example:1", hash_hex=OBJECT_HEX)

    with pytest.raises(SigillError, match="reserved"):
        client.sign_object_hashes(
            ENVELOPE_HEX, [SignedObjectDigest(uri="urn:sigill:envelope", hash_hex=OBJECT_HEX)], CERT
        )
    with pytest.raises(SigillError, match="Duplicate"):
        client.sign_object_hashes(ENVELOPE_HEX, [one, one], CERT)
    # Byte-exact identity: a padded URI is rejected, never silently trimmed —
    # the caller's envelope already references it verbatim, and a normalized
    # signature would no longer align with that envelope.
    with pytest.raises(SigillError, match="whitespace"):
        client.sign_object_hashes(
            ENVELOPE_HEX, [SignedObjectDigest(uri="urn:example:1 ", hash_hex=OBJECT_HEX)], CERT
        )
    with pytest.raises(SigillError, match="envelope_hash_hex"):
        client.sign_object_hashes("not-hex", [one], CERT)
    with pytest.raises(SigillError, match="64 hex"):
        client.sign_object_hashes(
            ENVELOPE_HEX, [SignedObjectDigest(uri="urn:example:1", hash_hex="abc")], CERT
        )
    with pytest.raises(SigillError, match="capped"):
        client.sign_object_hashes(
            ENVELOPE_HEX,
            [SignedObjectDigest(uri=f"urn:example:{i}", hash_hex=OBJECT_HEX) for i in range(129)],
            CERT,
        )
    assert requests == []


def _verdict(**overrides) -> dict:
    base = {
        "signatureValid": True,
        "complete": True,
        "pqc": "absent",
        "objectCount": 2,
        "suppliedCount": 2,
        "matchedCount": 2,
        "objects": [
            {"par": "urn:sigill:envelope", "contentType": SIBLING_CTY, "supplied": True, "hashMatch": True},
            {"par": "urn:example:1", "supplied": True, "hashMatch": True},
        ],
        "missing": [],
        "unreferenced": [],
    }
    base.update(overrides)
    return {"objects": base}


def _classical_jws() -> dict:
    return {"signatures": [{"protected": "e30", "signature": "c2ln"}]}


def _add_ml_dsa_entry(jws: dict) -> None:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "ML-DSA-87"}).encode()).decode().rstrip("=")
    jws["signatures"].append({"protected": header, "signature": "cA"})


def test_verify_object_hashes_sends_digest_maps_verbatim_and_maps_verdicts() -> None:
    client, requests = _client(lambda req, body: httpx.Response(200, json=_verdict()))

    result = client.verify_object_hashes(
        _classical_jws(),
        {"urn:sigill:envelope": ENVELOPE_HEX, "urn:example:1": OBJECT_HEX},
    )

    path, body = requests[0]
    assert path == "/seal/verify-objects"
    assert body["digests"] == {"urn:sigill:envelope": ENVELOPE_HEX, "urn:example:1": OBJECT_HEX}
    assert "digests512" not in body
    assert "tsrBase64" not in body

    assert result.signature_valid and result.complete
    assert result.pqc == "absent"
    assert len(result.objects) == 2
    assert result.objects[0].uri == "urn:sigill:envelope"
    assert result.objects[0].content_type == SIBLING_CTY, (
        "the signed cty comes back — the profile discriminator is verifiable"
    )
    assert result.ok


def test_verify_object_hashes_hybrid_without_pqc_verdict_never_ok() -> None:
    # A verifier build that predates the hybrid contract returns complete=true
    # from the classical dimension and NO pqc field. The SDK detected the
    # ML-DSA signer itself, so the classical verdict must never stand in for
    # the hybrid one.
    legacy = _verdict()
    del legacy["objects"]["pqc"]
    client, _ = _client(lambda req, body: httpx.Response(200, json=legacy))

    jws = _classical_jws()
    _add_ml_dsa_entry(jws)
    result = client.verify_object_hashes(
        jws,
        {"urn:sigill:envelope": ENVELOPE_HEX},
        {"urn:sigill:envelope": ENVELOPE_512},
    )

    assert result.complete, "the classical verdict is what the old verifier reported"
    assert result.pqc == "not_checked"
    assert not result.ok, "the classical verdict must never stand in for the hybrid one"
    assert any("no pqc verdict" in i for i in result.issues)


def test_verify_object_hashes_hybrid_without_sha512_digests_flags_the_gap() -> None:
    client, _ = _client(
        lambda req, body: httpx.Response(200, json=_verdict(pqc="not_checked", complete=False))
    )

    jws = _classical_jws()
    _add_ml_dsa_entry(jws)
    result = client.verify_object_hashes(jws, {"urn:sigill:envelope": ENVELOPE_HEX})

    assert not result.ok
    assert any("no SHA-512 digests" in i for i in result.issues)


def test_v2_seal_stays_pinned_to_its_own_profile() -> None:
    # The AI-evidence methods ride the same tier but never expose the envelope
    # content type: object 0 keeps the platform's AI-evidence default, so a
    # sibling profile cannot be minted as AI evidence.
    client, requests = _client(
        lambda req, body: httpx.Response(200, json={"signature": {"signatures": []}})
    )
    client.seal_evidence_v2(
        {"purpose": {"category": "summarization"}},
        [EvidenceV2Payload(role="prompt", data=b"p")],
        CERT,
    )
    assert "envelopeContentType" not in requests[0][1], (
        "the AI-evidence profile is pinned to the platform default cty"
    )
