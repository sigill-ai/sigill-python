"""seal_pades() tests with a mocked Sigill HTTP layer.

Delegated PAdES sealing: the SDK assembles the PDF signature revision locally
and only ByteRange digests cross the wire. These tests exercise the full
orchestration against httpx.MockTransport and assert the privacy property
directly (no request ever carries the PDF bytes). Mirrors the .NET SDK's
PadesSealTests.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

import httpx
import pytest

from sigill_sdk import PdfUnsupported, SigillClient


def _client_with_handler(handler) -> SigillClient:
    transport = httpx.MockTransport(handler)
    http = httpx.Client(
        base_url="https://api.sigill.ai",
        headers={"Authorization": "Bearer fake"},
        transport=transport,
        timeout=5,
    )
    return SigillClient(api_key="fake", http_client=http)


# Minimal but structurally complete xref-table PDF.
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
FAKE_CERT = bytes(i % 13 for i in range(300))
FAKE_OCSP = bytes(i % 17 for i in range(200))
FAKE_TOKEN = bytes(i % 23 for i in range(400))

CERT_ID = "0b7f7c6e-1111-2222-3333-444455556666"
OPERATION_ID = "6a1e12e8-6bb9-4d0e-9f6e-1c2d3e4f5a6b"


def _sign_pades_ok(with_ltv: bool) -> httpx.Response:
    return httpx.Response(200, json={
        "cmsBase64": base64.b64encode(FAKE_CMS).decode(),
        "certChainDers": [base64.b64encode(FAKE_CERT).decode()] if with_ltv else [],
        "ocspDers": [base64.b64encode(FAKE_OCSP).decode()] if with_ltv else [],
        "operationId": OPERATION_ID,
        "certificateId": CERT_ID,
        "timestampedBy": "Test TSA",
        "qualified": False,
        "format": "pades-b-t",
    })


def _stamp_ok() -> httpx.Response:
    return httpx.Response(200, json={
        "tsrBase64": base64.b64encode(b"\x30\x03\x02\x01\x00").decode(),
        "tokenBase64": base64.b64encode(FAKE_TOKEN).decode(),
        "tsaName": "Test TSA",
        "qualified": False,
    })


# --------------------------------------------------------------------------- happy path


def test_seal_pades_transmits_only_hashes_never_pdf_bytes() -> None:
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path, request.content.decode("latin-1")))
        assert request.url.path == "/seal/sign-pades-hash"
        return _sign_pades_ok(with_ltv=False)

    client = _client_with_handler(handler)
    result = client.seal_pades(MINIMAL_PDF, CERT_ID)

    # The privacy claim, asserted literally: no request body may contain the
    # PDF (raw, base64, or hex).
    pdf_b64 = base64.b64encode(MINIMAL_PDF).decode()
    for _, body in calls:
        assert "%PDF" not in body
        assert pdf_b64 not in body

    # Exactly one round-trip, JSON only, with the two identity fields.
    assert len(calls) == 1
    sent = json.loads(calls[0][1])
    assert len(sent["hashHex"]) == 64
    assert sent["certificateId"] == CERT_ID

    assert result.format == "pades-b-t"
    assert result.timestamped_by == "Test TSA"
    assert result.operation_id == OPERATION_ID

    # Output: original bytes are an untouched prefix (incremental update model)
    # and the CMS hex landed in the /Contents slot.
    assert result.sealed_pdf[:len(MINIMAL_PDF)] == MINIMAL_PDF
    text = result.sealed_pdf.decode("latin-1")
    assert "/SubFilter /ETSI.CAdES.detached" in text
    assert FAKE_CMS.hex() in text


def test_seal_pades_hash_covers_the_declared_byte_ranges_of_the_output() -> None:
    sent_hash_hex: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_hash_hex.append(json.loads(request.content)["hashHex"])
        return _sign_pades_ok(with_ltv=False)

    client = _client_with_handler(handler)
    result = client.seal_pades(MINIMAL_PDF, CERT_ID)

    # Recompute the digest from the sealed artifact exactly the way a PAdES
    # validator does: parse /ByteRange, hash the two ranges. Embedding the
    # CMS must not have disturbed the signed ranges.
    text = result.sealed_pdf.decode("latin-1")
    br = re.search(r"/ByteRange \[(\d+) (\d+) (\d+) (\d+)\]\s", text)
    assert br is not None
    r1, r1_len, r2, r2_len = (int(br.group(i)) for i in range(1, 5))

    sha = hashlib.sha256()
    sha.update(result.sealed_pdf[r1:r1 + r1_len])
    sha.update(result.sealed_pdf[r2:r2 + r2_len])
    assert sha.hexdigest() == sent_hash_hex[0]

    # The gap between the ranges is exactly '<' + hex + '>'.
    assert r2 - (r1 + r1_len) == 16_384 * 2 + 2
    assert r2 + r2_len == len(result.sealed_pdf)


# --------------------------------------------------------------------------- ltv


def test_seal_pades_with_ltv_material_builds_dss_and_doc_timestamp() -> None:
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path, request.content.decode("latin-1")))
        if request.url.path == "/seal/sign-pades-hash":
            return _sign_pades_ok(with_ltv=True)
        return _stamp_ok()

    client = _client_with_handler(handler)
    result = client.seal_pades(MINIMAL_PDF, CERT_ID)

    assert [path for path, _ in calls] == ["/seal/sign-pades-hash", "/tsa/stamp-hash"]
    assert result.format == "pades-b-lta"

    # The DocTimeStamp stamp call must carry the seal-operation link so the
    # platform can attach the archival token to the operation's evidence.
    stamp_sent = json.loads(calls[1][1])
    assert stamp_sent["sealOperationId"] == OPERATION_ID

    text = result.sealed_pdf.decode("latin-1")
    assert "/Type /DSS" in text
    assert "/VRI" in text
    assert "/Type /DocTimeStamp" in text
    assert "/SubFilter /ETSI.RFC3161" in text
    assert FAKE_TOKEN.hex() in text


def test_seal_pades_doc_timestamp_failure_degrades_to_b_lt() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/seal/sign-pades-hash":
            return _sign_pades_ok(with_ltv=True)
        return httpx.Response(502)

    client = _client_with_handler(handler)
    result = client.seal_pades(MINIMAL_PDF, CERT_ID)

    assert result.format == "pades-b-lt"
    text = result.sealed_pdf.decode("latin-1")
    assert "/Type /DSS" in text
    assert "/Type /DocTimeStamp" not in text


def test_seal_pades_ltv_false_stays_b_t() -> None:
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return _sign_pades_ok(with_ltv=True)

    client = _client_with_handler(handler)
    result = client.seal_pades(MINIMAL_PDF, CERT_ID, ltv=False)

    assert calls == ["/seal/sign-pades-hash"]
    assert result.format == "pades-b-t"
    assert "/Type /DSS" not in result.sealed_pdf.decode("latin-1")


# --------------------------------------------------------------------------- unsupported


def test_seal_pades_unsupported_pdf_raises_with_upload_fallback_hint() -> None:
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return _sign_pades_ok(with_ltv=False)

    client = _client_with_handler(handler)

    with pytest.raises(PdfUnsupported) as exc:
        client.seal_pades(b"%PDF-1.4\nnot really a pdf", CERT_ID)

    assert "/seal/sign" in str(exc.value)
    # Nothing should be transmitted when local preparation fails.
    assert calls == []


def test_seal_pades_reason_and_location_land_in_signature_dictionary() -> None:
    client = _client_with_handler(lambda request: _sign_pades_ok(with_ltv=False))

    result = client.seal_pades(
        MINIMAL_PDF, CERT_ID, reason="Approval", location="Oslo (NO)")

    text = result.sealed_pdf.decode("latin-1")
    assert "/Reason (Approval)" in text
    assert "/Location (Oslo \\(NO\\))" in text


def test_seal_pades_upload_fallback_is_off_by_default_and_opt_in_uploads() -> None:
    unsupported = b"%PDF-1.4\nnot really a pdf"
    sealed_by_server = bytes(i % 29 for i in range(500))
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        assert request.url.path == "/seal/sign"
        assert request.headers["content-type"].startswith("multipart/form-data")
        return httpx.Response(
            200,
            content=sealed_by_server,
            headers={
                "X-Seal-Operation-Id": "9c65b917-6a10-4c7a-8f3e-2b1a0d4e5f60",
                "X-Seal-Format": "pades-b-lta",
                "X-Seal-Timestamped-By": "Test TSA",
                "X-Seal-Qualified": "false",
            },
        )

    client = _client_with_handler(handler)

    # Default: hard privacy guarantee — raises, transmits nothing.
    with pytest.raises(PdfUnsupported):
        client.seal_pades(unsupported, CERT_ID)
    assert calls == []

    # Opt-in: the SDK uploads via /seal/sign and maps the header metadata.
    result = client.seal_pades(unsupported, CERT_ID, allow_upload_fallback=True)

    assert calls == ["/seal/sign"]
    assert result.sealed_pdf == sealed_by_server
    assert result.format == "pades-b-lta"
    assert result.timestamped_by == "Test TSA"
    assert result.operation_id == "9c65b917-6a10-4c7a-8f3e-2b1a0d4e5f60"
