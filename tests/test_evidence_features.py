"""Evidence-store features: create-time tags, the two-phase PAdES flow
(prepare → seal-prepared / complete-from-escrow), and the evidence helpers
(get_seal_cms, get_evidence_record, lookup, export_audit_package).

All against httpx.MockTransport; mirrors the .NET SDK's EvidenceFeatureTests.
"""
from __future__ import annotations

import base64
import hashlib
import json

import httpx
import pytest

from sigill_sdk import EnvelopeBuilder, SigillClient
from sigill_sdk import _pdf


def _client_with_handler(handler) -> SigillClient:
    transport = httpx.MockTransport(handler)
    http = httpx.Client(
        base_url="https://api.sigill.ai",
        headers={"Authorization": "Bearer fake"},
        transport=transport,
        timeout=5,
    )
    return SigillClient(api_key="fake", http_client=http)


MINIMAL_PDF = (
    "%PDF-1.4\n"
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
    "xref\n0 4\n0000000000 65535 f \n"
    "trailer\n<< /Size 4 /Root 1 0 R >>\n"
    "startxref\n9\n%%EOF\n"
).encode("ascii")

FAKE_CMS = bytes(i % 251 for i in range(900))
CERT_ID = "0b7f7c6e-1111-2222-3333-444455556666"
OPERATION_ID = "6a1e12e8-6bb9-4d0e-9f6e-1c2d3e4f5a6b"
TX_ID = "9c7cbb17-aaaa-bbbb-cccc-ddddeeeeffff"


def _sign_pades_ok() -> httpx.Response:
    return httpx.Response(200, json={
        "cmsBase64": base64.b64encode(FAKE_CMS).decode(),
        "certChainDers": [],
        "ocspDers": [],
        "operationId": OPERATION_ID,
        "certificateId": CERT_ID,
        "timestampedBy": "Test TSA",
        "qualified": False,
        "format": "pades-b-t",
    })


# ------------------------------------------------------------------------ tags


def test_tags_forwarded_on_all_seal_methods() -> None:
    bodies: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        bodies[request.url.path] = body
        if request.url.path == "/seal/sign-pades-hash":
            return _sign_pades_ok()
        if request.url.path == "/tsa/stamp-hash":
            return httpx.Response(200, json={
                "tsrBase64": base64.b64encode(b"\x30\x03\x02\x01\x00").decode(),
                "tsaName": "Test TSA",
            })
        return httpx.Response(200, content=b"sig-bytes")

    client = _client_with_handler(handler)
    tags = ["release-4.2", "backend"]

    client.seal_cades(b"data", CERT_ID, tags=tags, reminders="on", reminder_days=60)
    assert bodies["/seal/sign-hash"]["tags"] == tags
    assert bodies["/seal/sign-hash"]["reminders"] == "on"
    assert bodies["/seal/sign-hash"]["reminderDays"] == 60

    client.seal_jades(b'{"a":1}', CERT_ID, tags=tags, reminders="off")
    assert bodies["/seal/sign-hash"]["tags"] == tags
    assert bodies["/seal/sign-hash"]["reminders"] == "off"

    client.seal_pades(MINIMAL_PDF, CERT_ID, ltv=False, tags=tags)
    assert bodies["/seal/sign-pades-hash"]["tags"] == tags

    env = (
        EnvelopeBuilder()
        .with_purpose(category="test")
        .with_actor(type="service", id="t")
        .with_activity(name="t.run")
        .with_model(provider="test", name="test-model")
        .build()
    )
    client.seal(env, tags=tags)
    assert bodies["/tsa/stamp-hash"]["tags"] == tags


def test_upload_fallback_forwards_tags_and_reminders() -> None:
    """The fallback must carry the caller's full intent — QA: reminders were
    silently dropped on this path."""
    unsupported = b"%PDF-1.4\nnot really a pdf"
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/seal/sign"
        seen["body"] = request.content
        return httpx.Response(200, content=b"sealed", headers={
            "X-Seal-Operation-Id": OPERATION_ID,
            "X-Seal-Format": "pades-b-lta",
            "X-Seal-Timestamped-By": "Test TSA",
            "X-Seal-Qualified": "false",
        })

    client = _client_with_handler(handler)
    client.seal_pades(unsupported, CERT_ID, allow_upload_fallback=True,
                      tags=["a", "b"], reminders="on", reminder_days=60)

    body = seen["body"]
    # Repeated form fields for tags; scalar fields for the reminder override.
    assert body.count(b'name="tags"') == 2
    assert b'name="reminders"' in body and b"\r\non\r\n" in body
    assert b'name="reminderDays"' in body and b"\r\n60\r\n" in body


def test_tags_omitted_when_not_supplied() -> None:
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, content=b"sig-bytes")

    client = _client_with_handler(handler)
    client.seal_cades(b"data", CERT_ID)
    assert "tags" not in bodies[0]
    assert "reminders" not in bodies[0]


# ------------------------------------------------------------ two-phase PAdES


def test_prepare_recover_roundtrip_is_exact() -> None:
    client = _client_with_handler(lambda r: httpx.Response(500))
    checkpoint = client.prepare_pades(MINIMAL_PDF)

    direct = _pdf.prepare.__wrapped__ if hasattr(_pdf.prepare, "__wrapped__") else None
    recovered = _pdf.recover(checkpoint.prepared_pdf)

    # The recovered offsets and digest must match what prepare computed —
    # the checkpoint alone carries everything needed to resume.
    assert recovered.document_hash.hex() == checkpoint.hash_hex
    assert recovered.bytes == checkpoint.prepared_pdf
    # Embedding through the recovered prep yields a structurally sealed PDF.
    sealed = _pdf.embed(recovered, FAKE_CMS)
    assert sealed[:len(MINIMAL_PDF)] == MINIMAL_PDF
    assert FAKE_CMS.hex().encode("ascii") in sealed


def test_seal_prepared_pades_signs_the_checkpoint_digest() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return _sign_pades_ok()

    client = _client_with_handler(handler)
    checkpoint = client.prepare_pades(MINIMAL_PDF)

    result = client.seal_prepared_pades(checkpoint.prepared_pdf, CERT_ID, ltv=False)

    assert seen["hashHex"] == checkpoint.hash_hex
    assert result.operation_id == OPERATION_ID
    assert result.format == "pades-b-t"
    assert FAKE_CMS.hex().encode("ascii") in result.sealed_pdf


def test_complete_pades_finishes_from_escrowed_cms() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == f"/seal/operations/{OPERATION_ID}/p7s":
            return httpx.Response(200, content=FAKE_CMS,
                                  headers={"Content-Type": "application/pkcs7-signature"})
        return _sign_pades_ok()

    client = _client_with_handler(handler)

    # The crash story: phase 1 checkpointed, phase 2's response was lost.
    checkpoint = client.prepare_pades(MINIMAL_PDF)
    client.seal_prepared_pades(checkpoint.prepared_pdf, CERT_ID, ltv=False)

    # Later process: re-fetch the escrowed CMS and finish offline.
    cms = client.get_seal_cms(OPERATION_ID)
    assert cms == FAKE_CMS
    sealed = SigillClient.complete_pades(checkpoint.prepared_pdf, cms)

    # Byte-identical to what the uninterrupted flow would have produced.
    recovered = _pdf.recover(checkpoint.prepared_pdf)
    assert sealed == _pdf.embed(recovered, FAKE_CMS)


def test_recover_rejects_unprepared_bytes() -> None:
    with pytest.raises(ValueError):
        _pdf.recover(MINIMAL_PDF)  # no placeholder revision


def test_get_seal_cms_returns_none_when_not_stored() -> None:
    client = _client_with_handler(lambda r: httpx.Response(404, json={"message": "not stored"}))
    assert client.get_seal_cms(OPERATION_ID) is None


# ------------------------------------------------------------------- evidence


def test_get_evidence_record_maps_fields_and_hashes_locally() -> None:
    data = b"artifact-bytes"
    expected_hash = hashlib.sha256(data).hexdigest()
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return httpx.Response(200, json={
            "id": TX_ID,
            "hash": expected_hash,
            "alg": "SHA-256",
            "genTime": "2026-07-31T10:00:00Z",
            "createdAt": "2026-07-31T10:00:01Z",
            "tsaName": "DigiCert",
            "label": "artifact.bin",
            "certNotBefore": "2026-01-01T00:00:00Z",
            "certNotAfter": "2028-01-01T00:00:00Z",
            "isRestamp": False,
            "hasTsr": True,
        })

    client = _client_with_handler(handler)
    rec = client.get_evidence_record(data)

    assert seen["path"] == f"/api/transactions/by-hash/{expected_hash}"
    assert rec is not None
    assert rec.transaction_id == TX_ID
    assert rec.cert_not_after == "2028-01-01T00:00:00Z"
    assert rec.tsa_name == "DigiCert"
    assert rec.has_tsr is True


def test_get_evidence_record_returns_none_on_404() -> None:
    client = _client_with_handler(lambda r: httpx.Response(404))
    assert client.get_evidence_record(hash_hex="a" * 64) is None


def test_get_evidence_record_requires_exactly_one_input() -> None:
    client = _client_with_handler(lambda r: httpx.Response(500))
    with pytest.raises(ValueError):
        client.get_evidence_record()
    with pytest.raises(ValueError):
        client.get_evidence_record(b"x", hash_hex="a" * 64)


def test_lookup_maps_result_and_none_on_404() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("f" * 64):
            return httpx.Response(404, json={"found": False})
        return httpx.Response(200, json={
            "found": True,
            "count": 2,
            "records": [{"id": TX_ID, "hash": "a" * 64}, {"id": OPERATION_ID, "hash": "a" * 64}],
            "latest": {"id": TX_ID, "hash": "a" * 64},
        })

    client = _client_with_handler(handler)
    result = client.lookup(hash_hex="A" * 64)  # uppercase input is normalized
    assert result is not None
    assert result.count == 2
    assert result.latest["id"] == TX_ID
    assert len(result.records) == 2

    assert client.lookup(hash_hex="f" * 64) is None


def test_export_audit_package_returns_zip_bytes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/api/transactions/{TX_ID}/audit-package.zip"
        return httpx.Response(200, content=b"PK\x03\x04fakezip",
                              headers={"Content-Type": "application/zip"})

    client = _client_with_handler(handler)
    assert client.export_audit_package(TX_ID).startswith(b"PK")
