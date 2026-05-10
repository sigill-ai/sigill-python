"""seal() integration tests with a mocked Sigill HTTP layer.

We use httpx's MockTransport to drive the SigillClient without any real network call.
Goals:

  - seal() canonicalizes correctly, computes the right hash, sends it base64'd to /tsa/stamp
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
        assert request.url.path == "/tsa/stamp"
        body = json.loads(request.content)
        captured.update(body)
        file_bytes = base64.b64decode(body["fileBase64"])
        imprint = hashlib.sha256(file_bytes).digest()
        tsr = make_tsr(imprint)
        return httpx.Response(
            200,
            json={
                "serial": "1234567",
                "genTime": "2026-05-08T12:00:00Z",
                "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1",
                "hashHex": imprint.hex(),
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
    # canonical envelope bytes
    assert captured["tsaSlug"] == "auto"
    assert captured["qualified"] is False
    file_bytes = base64.b64decode(captured["fileBase64"])
    # The bytes the SDK sent must canonicalize to themselves — i.e. they ARE canonical
    import jcs
    assert jcs.canonicalize(json.loads(file_bytes)) == file_bytes


def test_seal_forwards_tsa_slug_and_qualified(vectors_dir: Path) -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured.update(body)
        file_bytes = base64.b64decode(body["fileBase64"])
        imprint = hashlib.sha256(file_bytes).digest()
        return httpx.Response(
            200,
            json={
                "serial": "x", "genTime": "2026-05-08T12:00:00Z",
                "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1", "hashHex": imprint.hex(),
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
        file_bytes = base64.b64decode(body["fileBase64"])
        imprint = hashlib.sha256(file_bytes).digest()
        return httpx.Response(200, json={
            "serial": "x", "genTime": "2026-05-08T12:00:00Z",
            "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1", "hashHex": imprint.hex(),
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
        file_bytes = base64.b64decode(body["fileBase64"])
        imprint = hashlib.sha256(file_bytes).digest()
        return httpx.Response(200, json={
            "serial": "x", "genTime": "2026-05-08T12:00:00Z",
            "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1", "hashHex": imprint.hex(),
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
        file_bytes = base64.b64decode(body["fileBase64"])
        imprint = hashlib.sha256(file_bytes).digest()
        return httpx.Response(
            200,
            json={
                "serial": "x", "genTime": "2026-05-08T12:00:00Z",
                "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1", "hashHex": imprint.hex(),
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


# --------------------------------------------------------------------------- end-to-end


def test_seal_then_verify_roundtrip(vectors_dir: Path) -> None:
    """The acid test: seal an envelope through the SDK, then verify it through the
    SDK. Result must be valid with no issues."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        file_bytes = base64.b64decode(body["fileBase64"])
        imprint = hashlib.sha256(file_bytes).digest()
        return httpx.Response(
            200,
            json={
                "serial": "x", "genTime": "2026-05-08T12:00:00Z",
                "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1", "hashHex": imprint.hex(),
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
