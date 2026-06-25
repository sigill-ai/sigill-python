"""seal() integration tests with a mocked Sigill HTTP layer.

We use httpx's MockTransport to drive the SigillClient without any real network call.
Goals:

  - seal() canonicalizes correctly, computes the right hash, sends only hashHex to /tsa/stamp-hash
  - the returned envelope has a populated proofs[]
  - 502 ("All TSAs failed") raises TimestampUnavailable with structured failures
  - external payload bytes are hashed and inserted into the corresponding payloadRef
  - tsa_slug and qualified are forwarded
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from sigill_sdk import (
    EnvelopeBuilder,
    SigillClient,
    TimestampUnavailable,
    HashMismatch,
    CadesVerifyResult,
)
from _tsr_factory import make_tsr


def _make_mock_transport(handler):
    return httpx.MockTransport(handler)


def _client_with_handler(handler) -> SigillClient:
    transport = _make_mock_transport(handler)
    http = httpx.Client(
        base_url="https://api.sigill.ai",
        headers={"Authorization": "Bearer fake"},
        transport=transport,
        timeout=5,
    )
    return SigillClient(api_key="fake", http_client=http)


# --------------------------------------------------------------------------- seal: happy path


def test_seal_calls_tsa_stamp_and_attaches_proof(vectors_dir: Path) -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/tsa/stamp-hash"
        body = json.loads(request.content)
        captured.update(body)
        imprint = bytes.fromhex(body["hashHex"])
        tsr = make_tsr(imprint)
        return httpx.Response(
            200,
            json={
                "serial": "1234567",
                "genTime": "2026-05-08T12:00:00Z",
                "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1",
                "hashHex": body["hashHex"],
                "tsrBase64": base64.b64encode(tsr).decode(),
                "tsaName": "Sigill SDK Test TSA",
                "qualified": False,
                "policyOid": None,
            },
        )

    client = _client_with_handler(handler)
    expected = json.loads((vectors_dir / "01-complete-ai-call" / "expected.json").read_text())
    # Strip the integrity field so seal() builds it fresh (mimics caller flow)
    input_env = {k: v for k, v in expected.items() if k not in ("integrity", "proofs")}

    sealed = client.seal(input_env)

    # Assert it's been canonicalized and stamped
    assert sealed["integrity"]["canonicalization"] == "RFC8785"
    assert "envelopeHash" in sealed["integrity"]
    assert sealed["integrity"]["envelopeHash"]["alg"] == "SHA-256"
    assert sealed["proofs"][0]["type"] == "rfc3161"
    assert sealed["proofs"][0]["tsaName"] == "Sigill SDK Test TSA"

    # The body sent to Sigill should have used the default tsaSlug ("auto") and the
    # envelope hash hex (64 chars = SHA-256)
    assert captured["tsaSlug"] == "auto"
    assert captured["qualified"] is False
    assert len(captured["hashHex"]) == 64  # SHA-256 hex digest
    assert captured["hashHex"] == sealed["integrity"]["envelopeHash"]["hex"]


def test_seal_forwards_tsa_slug_and_qualified(vectors_dir: Path) -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured.update(body)
        imprint = bytes.fromhex(body["hashHex"])
        return httpx.Response(
            200,
            json={
                "serial": "x", "genTime": "2026-05-08T12:00:00Z",
                "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1", "hashHex": body["hashHex"],
                "tsrBase64": base64.b64encode(make_tsr(imprint)).decode(),
                "tsaName": "DigiCert", "qualified": True,
                "policyOid": "1.3.6.1.4.1.4146.2.2",
            },
        )

    client = _client_with_handler(handler)
    env = (
        EnvelopeBuilder()
        .with_purpose(category="x").with_actor(type="user", id="u")
        .with_activity(name="a").with_model(provider="p", name="n")
        .build()
    )
    sealed = client.seal(env, tsa_slug="digicert", qualified=True)

    assert captured["tsaSlug"] == "digicert"
    assert captured["qualified"] is True
    assert sealed["proofs"][0]["qualified"] is True
    assert sealed["proofs"][0]["policyOid"] == "1.3.6.1.4.1.4146.2.2"


# --------------------------------------------------------------------------- seal: label


def test_seal_defaults_label_to_activity_name() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured.update(body)
        imprint = bytes.fromhex(body["hashHex"])
        return httpx.Response(200, json={
            "serial": "x", "genTime": "2026-05-08T12:00:00Z",
            "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1", "hashHex": body["hashHex"],
            "tsrBase64": base64.b64encode(make_tsr(imprint)).decode(),
            "tsaName": "DigiCert", "qualified": False, "policyOid": None,
        })

    client = _client_with_handler(handler)
    env = (
        EnvelopeBuilder()
        .with_purpose(category="x").with_actor(type="user", id="u")
        .with_activity(name="ticket.summarize").with_model(provider="p", name="n")
        .build()
    )
    client.seal(env)
    assert captured["label"] == "ticket.summarize"


def test_seal_label_can_be_overridden() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured.update(body)
        imprint = bytes.fromhex(body["hashHex"])
        return httpx.Response(200, json={
            "serial": "x", "genTime": "2026-05-08T12:00:00Z",
            "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1", "hashHex": body["hashHex"],
            "tsrBase64": base64.b64encode(make_tsr(imprint)).decode(),
            "tsaName": "DigiCert", "qualified": False, "policyOid": None,
        })

    client = _client_with_handler(handler)
    env = (
        EnvelopeBuilder()
        .with_purpose(category="x").with_actor(type="user", id="u")
        .with_activity(name="ticket.summarize").with_model(provider="p", name="n")
        .build()
    )
    client.seal(env, label="my custom label")
    assert captured["label"] == "my custom label"


# --------------------------------------------------------------------------- seal: external payloads


def test_seal_hashes_supplied_external_payloads(vectors_dir: Path) -> None:
    """If the caller supplies bytes for a payloadRef, the SDK MUST hash them and
    populate payloadRef.hash before sealing — that hash must end up bound by the
    canonical envelope and therefore by the proof."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        imprint = bytes.fromhex(body["hashHex"])
        return httpx.Response(
            200,
            json={
                "serial": "x", "genTime": "2026-05-08T12:00:00Z",
                "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1", "hashHex": body["hashHex"],
                "tsrBase64": base64.b64encode(make_tsr(imprint)).decode(),
                "tsaName": "DigiCert", "qualified": False, "policyOid": None,
            },
        )

    client = _client_with_handler(handler)
    env = (
        EnvelopeBuilder()
        .with_purpose(category="x").with_actor(type="user", id="u")
        .with_activity(name="a").with_model(provider="p", name="n")
        .with_prompt_ref("prompt").with_output_ref("output")
        .build()
    )
    payloads = {"prompt": b"the prompt", "output": b"the response"}
    sealed = client.seal(env, external_payloads=payloads)

    expected_prompt_hex = hashlib.sha256(b"the prompt").hexdigest()
    expected_output_hex = hashlib.sha256(b"the response").hexdigest()
    assert sealed["prompt"]["hash"]["hex"] == expected_prompt_hex
    assert sealed["prompt"]["hash"]["sizeBytes"] == len(b"the prompt")
    assert sealed["output"]["hash"]["hex"] == expected_output_hex


def test_seal_rejects_predeclared_hash_that_doesnt_match_bytes() -> None:
    """If a caller pre-declares hash AND supplies bytes that hash differently, that's
    a bug at the caller — fail loudly at seal time, don't paper it over."""
    client = _client_with_handler(lambda req: httpx.Response(500))  # never reached
    env = (
        EnvelopeBuilder()
        .with_purpose(category="x").with_actor(type="user", id="u")
        .with_activity(name="a").with_model(provider="p", name="n")
        .build()
    )
    env["prompt"] = {
        "ref": "prompt",
        "contentType": "text/plain",
        "encoding": "utf-8",
        "hash": {"alg": "SHA-256", "hex": "00" * 32},  # wrong on purpose
    }
    with pytest.raises(HashMismatch):
        client.seal(env, external_payloads={"prompt": b"hello"})


# --------------------------------------------------------------------------- seal: TSA outage


def test_seal_502_raises_timestamp_unavailable() -> None:
    """When Sigill returns 502 because every TSA failed, raise the structured error.
    The caller decides whether to retry, fall back, or store unsealed."""
    failures = [
        {"tsa": "DigiCert", "errorClass": "timeout", "statusCode": None,
         "message": "Request timed out", "latencyMs": 10042},
        {"tsa": "Sectigo", "errorClass": "http_status", "statusCode": 503,
         "message": "service unavailable", "latencyMs": 412},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            502,
            json={
                "message": "All enabled TSAs failed.",
                "attemptsTried": 2,
                "failures": failures,
            },
        )

    client = _client_with_handler(handler)
    env = (
        EnvelopeBuilder()
        .with_purpose(category="x").with_actor(type="user", id="u")
        .with_activity(name="a").with_model(provider="p", name="n")
        .build()
    )
    with pytest.raises(TimestampUnavailable) as exc:
        client.seal(env)
    assert exc.value.attempts == 2
    assert len(exc.value.failures) == 2
    assert exc.value.failures[0]["tsa"] == "DigiCert"


# --------------------------------------------------------------------------- seal_cades


def test_seal_cades_sends_hash_and_returns_p7s() -> None:
    """seal_cades() sends only the SHA-256 hash to /seal/sign-hash and returns .p7s bytes."""
    fake_p7s = b"\x30\x82\x01\x00" + b"\x00" * 252
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/seal/sign-hash"
        body = json.loads(request.content)
        captured.update(body)
        return httpx.Response(200, content=fake_p7s,
                              headers={"Content-Type": "application/pkcs7-signature"})

    client = _client_with_handler(handler)
    data = b"this is a JSON envelope or any document"
    cert_id = "aaaaaaaa-bbbb-cccc-dddd-ffffffffffff"
    p7s = client.seal_cades(data, certificate_id=cert_id)

    assert p7s == fake_p7s
    assert captured["hashHex"] == hashlib.sha256(data).hexdigest()
    assert captured["certificateId"] == cert_id
    assert captured["qualified"] is False
    assert "label" not in captured


def test_verify_cades_parses_response() -> None:
    """verify_cades() posts JSON to /seal/verify-hash and maps the JSON response."""
    fake_response = {
        "format": "cades",
        "cades": {
            "signaturePresent": True,
            "hashMatch": True,
            "signatureValid": True,
            "certificate": {
                "subject": "CN=Sigill Platform Seal,O=SIGILL AS",
                "trust": "trusted_chain",
            },
            "timestamp": {
                "genTime": "2026-06-25T16:16:31Z",
                "tsaName": "SSL.com",
                "qualificationSource": "none",
            },
            "tsrSource": "embedded",
            "error": None,
            "warnings": None,
        },
    }
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/seal/verify-hash"
        body = json.loads(request.content)
        captured.update(body)
        return httpx.Response(200, json=fake_response)

    client = _client_with_handler(handler)
    data = b"original doc"
    p7s = b"\x30\x00"
    result = client.verify_cades(data, p7s)

    assert isinstance(result, CadesVerifyResult)
    assert result.is_valid is True
    assert result.hash_match is True
    assert result.signature_valid is True
    assert result.signer == "CN=Sigill Platform Seal,O=SIGILL AS"
    assert result.trust == "trusted_chain"
    assert result.tsa_name == "SSL.com"
    assert result.gen_time == "2026-06-25T16:16:31Z"
    assert result.qualified is False
    assert result.error is None
    assert result.warnings == []
    assert captured["hashHex"] == hashlib.sha256(data).hexdigest()
    assert captured["p7sBase64"] == base64.b64encode(p7s).decode()
    assert "tsrBase64" not in captured


def test_verify_cades_includes_tsr_when_supplied() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(200, json={
            "format": "cades",
            "cades": {"hashMatch": False, "signatureValid": False, "error": "TSR does not cover this .p7s"},
        })

    client = _client_with_handler(handler)
    tsr = b"\x30\x01\x00"
    result = client.verify_cades(b"doc", b"\x30\x00", tsr=tsr)

    assert "tsrBase64" in captured
    assert captured["tsrBase64"] == base64.b64encode(tsr).decode()
    assert result.is_valid is False
    assert result.error == "TSR does not cover this .p7s"


def test_seal_cades_forwards_label_and_qualified() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured.update(body)
        return httpx.Response(200, content=b"\x30\x00",
                              headers={"Content-Type": "application/pkcs7-signature"})

    client = _client_with_handler(handler)
    client.seal_cades(b"doc", certificate_id="cert-id", label="my-doc.json", qualified=True)

    assert captured["label"] == "my-doc.json"
    assert captured["qualified"] is True


# --------------------------------------------------------------------------- end-to-end


def test_seal_then_verify_roundtrip(vectors_dir: Path) -> None:
    """The acid test: seal an envelope through the SDK, then verify it through the
    SDK. Result must be valid with no issues."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        imprint = bytes.fromhex(body["hashHex"])
        return httpx.Response(
            200,
            json={
                "serial": "x", "genTime": "2026-05-08T12:00:00Z",
                "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1", "hashHex": body["hashHex"],
                "tsrBase64": base64.b64encode(make_tsr(imprint)).decode(),
                "tsaName": "Test TSA", "qualified": False, "policyOid": None,
            },
        )

    client = _client_with_handler(handler)

    env = (
        EnvelopeBuilder()
        .with_purpose(category="summarization")
        .with_actor(type="service", id="svc-x")
        .with_activity(name="ticket.summarize")
        .with_model(provider="anthropic", name="claude-opus-4-7")
        .with_prompt_ref("p")
        .with_output_ref("o")
        .build()
    )
    payloads = {"p": b"prompt bytes", "o": b"output bytes"}

    sealed = client.seal(env, external_payloads=payloads)
    result = client.verify(sealed, external_payloads=payloads)

    assert result.is_valid, [str(i) for i in result.issues]
    assert len(result.timestamps) == 1
