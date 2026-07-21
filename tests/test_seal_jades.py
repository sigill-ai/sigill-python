"""seal_jades() / verify_jades() tests with a mocked Sigill HTTP layer.

JAdES detached sealing (ETSI TS 119 182-1) — same hash-only model as CAdES,
routed through /seal/sign-hash with ``format: "jades"``. Verification goes via
/seal/verify-hash, which sniffs the artifact bytes (JSON → JAdES). Mirrors the
.NET SDK's JadesSealTests.
"""
from __future__ import annotations

import base64
import hashlib
import json

import httpx

from sigill_sdk import SigillClient

CERT_ID = "aaaaaaaa-bbbb-cccc-dddd-ffffffffffff"

# The artifact is JSON text (a detached JWS with sigD), not DER.
FAKE_JADES = json.dumps(
    {"payload": "", "signatures": [{"protected": "e30", "signature": "c2ln"}]}
).encode()


def _client_with_handler(handler) -> SigillClient:
    transport = httpx.MockTransport(handler)
    http = httpx.Client(
        base_url="https://api.sigill.ai",
        headers={"Authorization": "Bearer fake"},
        transport=transport,
        timeout=5,
    )
    return SigillClient(api_key="fake", http_client=http)


def test_seal_jades_sends_format_jades_and_returns_artifact_bytes() -> None:
    sent: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/seal/sign-hash"
        sent.update(json.loads(request.content))
        return httpx.Response(
            200, content=FAKE_JADES,
            headers={"Content-Type": "application/jose+json"})

    client = _client_with_handler(handler)

    data = b'{"decision":"approved","amount":42000}'
    artifact = client.seal_jades(
        data, CERT_ID, label="decision.json", content_type="application/json")

    assert artifact == FAKE_JADES
    assert sent["format"] == "jades"
    assert sent["contentType"] == "application/json"
    assert sent["hashHex"] == hashlib.sha256(data).hexdigest()
    assert "pqc" not in sent


def test_seal_jades_pqc_sends_sha512_and_flag() -> None:
    sent: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent.update(json.loads(request.content))
        return httpx.Response(200, content=FAKE_JADES)

    client = _client_with_handler(handler)

    data = b"content"
    client.seal_jades(data, CERT_ID, pqc=True)

    assert sent["pqc"] is True
    assert sent["hashHex512"] == hashlib.sha512(data).hexdigest()


def test_verify_jades_parses_jades_branch_into_result() -> None:
    sent: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/seal/verify-hash"
        sent.update(json.loads(request.content))
        return httpx.Response(200, json={
            "format": "jades",
            "jades": {
                "signaturePresent": True,
                "hashMatch": True,
                "signatureValid": True,
                "certificate": {
                    "subject": "CN=Sigill Platform Seal,O=SIGILL AS",
                    "trust": "trusted_chain",
                },
                "timestamp": {
                    "genTime": "2026-07-19T10:00:00Z",
                    "tsaName": "SSL.com",
                    "qualificationSource": "none",
                },
                "tsrSource": "embedded",
                "error": None,
                "warnings": None,
                "postQuantum": {
                    "present": True, "valid": True, "signatureValid": True,
                    "contentBound": "yes", "trusted": "not_evaluated",
                    "algorithm": "ml-dsa-87",
                },
            },
        })

    client = _client_with_handler(handler)

    data = b'{"decision":"approved"}'
    result = client.verify_jades(data, FAKE_JADES)

    assert result.is_valid
    assert result.signer == "CN=Sigill Platform Seal,O=SIGILL AS"
    assert result.trust == "trusted_chain"
    assert result.tsa_name == "SSL.com"
    assert result.qualified is False
    assert result.post_quantum is not None
    assert result.post_quantum.algorithm == "ml-dsa-87"
    assert result.post_quantum.content_bound == "yes"

    # Both digests always go along so a hybrid seal's SHA-512 binding is checked.
    assert sent["hashHex"] == hashlib.sha256(data).hexdigest()
    assert sent["hashHex512"] == hashlib.sha512(data).hexdigest()
    assert sent["p7sBase64"] == base64.b64encode(FAKE_JADES).decode()
