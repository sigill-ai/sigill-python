# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""AiEvidenceEnvelopeV2 v2.1 reference form (spec §3.1, §5.2, §5.4): the production profile, both envelope
references read from each signature, reserved names, strict headers and the legacy note — mirroring the .NET SDK."""

from __future__ import annotations

import json
import re

import httpx
import pytest

from sigill_sdk import (
    LEGACY_ENVELOPE_REFERENCE,
    LEGACY_ENVELOPE_REFERENCE_DIAGNOSTIC,
    LOCATOR_ENVELOPE_REFERENCE,
    AgentRunBundle,
    EnvelopeReferenceForm,
    EvidenceV2Payload,
    SignedObjectDigest,
    SigillError,
    canonicalize,
    classify_envelope_reference,
    is_production_reference,
    new_object_uri,
    verify_agent_run,
)
from test_agent_run import VECTORS, stub_verify
from test_evidence_v2 import (
    CERT,
    _artifact_signed,
    _b64url,
    _client,
    _core_envelope,
    _header,
    _sha256,
    _sha512,
)

BOTH = [LOCATOR_ENVELOPE_REFERENCE, LEGACY_ENVELOPE_REFERENCE]


def _verdict_for(*pars: str) -> dict:
    return {"objects": {
        "signatureValid": True, "complete": True, "pqc": "absent",
        "objectCount": len(pars), "suppliedCount": len(pars), "matchedCount": len(pars),
        "objects": [{"par": p, "supplied": True, "hashMatch": True} for p in pars],
        "missing": [], "unreferenced": [],
    }}


def _comparing(pars: list[str], expected: dict[str, str], expected512: dict[str, str] | None = None):
    """Compares the supplied digests with what was signed, like the platform; hybrid when expected512 is given."""
    def handler(_req, body):
        supplied = body["digests"]
        match = {p: supplied.get(p) == expected[p] for p in pars}
        pqc = "absent"
        if expected512 is not None:
            d512 = body.get("digests512")
            pqc = "not_checked" if d512 is None else (
                "verified" if all(d512.get(p) == expected512[p] for p in pars) else "failed")
        return httpx.Response(200, json={"objects": {
            "signatureValid": True, "complete": all(match.values()) and pqc in ("absent", "verified"), "pqc": pqc,
            "objectCount": len(pars), "suppliedCount": sum(p in supplied for p in pars),
            "matchedCount": sum(match.values()),
            "objects": [{"par": p, "supplied": p in supplied, "hashMatch": match[p]} for p in pars],
            "missing": [p for p in pars if p not in supplied], "unreferenced": [],
        }})
    return handler


# ── the production profile ──────────────────────────────────────────────────

@pytest.mark.parametrize("uri,expected", [
    ("", False), (".", False), ("..", False), ("a/", False), ("/a", False), ("a//b", False), ("a\\b", False),
    ("a b", False), ("a%20b", False), ("a?b", False), ("a#b", False), ("urn:x", False), ("https://x", False),
    ("objects/../x", False), ("a\tb", False), ("ø", False),
    ("a", True), ("objects/6f1c2a4e-0b7d-4c1e-9a52-3d8f0e1b7c90", True), ("x/y.z/A_b~c-d", True), ("...", True),
])
def test_production_profile_boundaries(uri: str, expected: bool) -> None:
    assert is_production_reference(uri) is expected, uri


def test_new_object_uri_is_in_the_production_profile() -> None:
    uri = new_object_uri()
    assert is_production_reference(uri)
    assert re.fullmatch(r"objects/[0-9a-f-]{36}", uri)
    assert classify_envelope_reference(uri) is EnvelopeReferenceForm.INVALID


@pytest.mark.parametrize("uri", ["urn:uuid:6f1c2a4e-0b7d-4c1e-9a52-3d8f0e1b7c90", "contract olsen.pdf",
                                 "https://example.com/x"])
def test_seal_rejects_caller_uris_outside_the_profile(uri: str) -> None:
    client, requests = _client(lambda req, body: httpx.Response(200, json={}))
    with pytest.raises(SigillError, match="production-profile"):
        client.seal_evidence_v2(_core_envelope(), [EvidenceV2Payload(role="prompt", data=b"x", uri=uri)], CERT)
    assert requests == []


@pytest.mark.parametrize("reserved", BOTH)
def test_seal_rejects_both_reserved_names(reserved: str) -> None:
    client, requests = _client(lambda req, body: httpx.Response(200, json={}))
    with pytest.raises(SigillError, match="reserved"):
        client.seal_evidence_v2(_core_envelope(), [EvidenceV2Payload(role="prompt", data=b"x", uri=reserved)], CERT)
    assert requests == []


def test_sign_object_hashes_enforces_the_profile_except_for_reused_uris() -> None:
    client, requests = _client(lambda req, body: httpx.Response(200, json={"signature": {"signatures": []}}))
    hex_ = "a" * 64
    with pytest.raises(SigillError, match="production-profile"):
        client.sign_object_hashes(hex_, [SignedObjectDigest(uri="urn:uuid:6f1c2a4e-0b7d-4c1e-9a52-3d8f0e1b7c90",
                                                            hash_hex=hex_)], CERT)
    for reserved in BOTH:
        with pytest.raises(SigillError, match="reserved"):
            client.sign_object_hashes(hex_, [SignedObjectDigest(uri=reserved, hash_hex=hex_)], CERT,
                                      _reused_uris=frozenset({reserved}))
    assert requests == []

    # An evaluation of a run that straddles the upgrade re-references a control set sealed under a legacy URI: the
    # transition allowance (spec §10.1). Its own new objects still conform.
    legacy = "urn:uuid:00000000-0000-4000-8000-000000000001"
    client.sign_object_hashes(hex_, [SignedObjectDigest(uri="objects/observed", hash_hex=hex_),
                                     SignedObjectDigest(uri=legacy, hash_hex=hex_)], CERT,
                              _reused_uris=frozenset({legacy}))
    assert [o["uri"] for o in requests[0][1]["objects"]] == ["objects/observed", legacy]


# ── verification ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ref", BOTH)
def test_verify_keys_the_envelope_digest_by_the_signatures_own_reference(ref: str) -> None:
    artifact = _artifact_signed(ref, ["objects/p"], ("objects/p", "prompt"))
    client, requests = _client(lambda req, body: httpx.Response(200, json=_verdict_for(ref, "objects/p")))

    result = client.verify_evidence_v2(artifact, {"objects/p": b"p"})

    digests = requests[0][1]["digests"]
    assert set(digests) == {ref, "objects/p"}, "never under both references"
    assert digests[ref] == _sha256(canonicalize(artifact.envelope))
    assert result.alignment_ok and result.ok
    assert result.notes == ([LEGACY_ENVELOPE_REFERENCE_DIAGNOSTIC] if ref == LEGACY_ENVELOPE_REFERENCE else [])


def test_verify_rejects_an_unknown_envelope_reference() -> None:
    artifact = _artifact_signed("envelope.json", ["objects/p"], ("objects/p", "prompt"))
    client, requests = _client(lambda req, body: httpx.Response(200, json=_verdict_for("envelope.json", "objects/p")))

    result = client.verify_evidence_v2(artifact, {"objects/p": b"p"})

    assert "envelope.json" not in requests[0][1]["digests"], "an unknown name is never trusted as the envelope"
    assert not result.alignment_ok and not result.ok
    assert any("not an envelope reference" in i for i in result.issues)


@pytest.mark.parametrize("reserved", BOTH)
def test_verify_fails_when_an_object_uses_a_reserved_name(reserved: str) -> None:
    artifact = _artifact_signed(LOCATOR_ENVELOPE_REFERENCE, [reserved], (reserved, "prompt"))
    client, _ = _client(lambda req, body: httpx.Response(200, json=_verdict_for(LOCATOR_ENVELOPE_REFERENCE, reserved)))
    result = client.verify_evidence_v2(artifact)
    assert not result.ok
    assert any("reserved" in i for i in result.issues)


@pytest.mark.parametrize("reserved", BOTH)
def test_verify_refuses_a_payload_under_either_envelope_reference(reserved: str) -> None:
    # Supplying the ORIGINAL envelope bytes under the envelope key used to replace the SDK's own digest, so an
    # edited envelope verified (found in the .NET review).
    artifact = _artifact_signed(LOCATOR_ENVELOPE_REFERENCE, ["objects/p"], ("objects/p", "prompt"))
    original = canonicalize(artifact.envelope)
    artifact.envelope["purpose"] = {"category": "edited after sealing"}
    client, requests = _client(lambda req, body: httpx.Response(200, json=_verdict_for(LOCATOR_ENVELOPE_REFERENCE,
                                                                                       "objects/p")))
    with pytest.raises(SigillError, match="reserved"):
        client.verify_evidence_v2(artifact, {reserved: original, "objects/p": b"p"})
    assert requests == []


@pytest.mark.parametrize("ref", BOTH)
@pytest.mark.parametrize("hybrid", [False, True])
def test_verify_an_edited_envelope_fails_in_both_forms(ref: str, hybrid: bool) -> None:
    prompt = b"p"
    artifact = _artifact_signed(ref, ["objects/p"], ("objects/p", "prompt"))
    canonical = canonicalize(artifact.envelope)
    pars = [ref, "objects/p"]
    expected = {ref: _sha256(canonical), "objects/p": _sha256(prompt)}
    expected512 = None
    if hybrid:
        artifact.signature["signatures"].append({"protected": _header("ML-DSA-87", *pars), "signature": "cA"})
        expected512 = {ref: _sha512(canonical), "objects/p": _sha512(prompt)}

    client, _ = _client(_comparing(pars, expected, expected512))
    assert client.verify_evidence_v2(artifact, {"objects/p": prompt}).ok, "the untouched artifact verifies"

    artifact.envelope["purpose"] = {"category": "edited after sealing"}
    client, _ = _client(_comparing(pars, expected, expected512))
    result = client.verify_evidence_v2(artifact, {"objects/p": prompt})
    assert not result.ok
    assert next(o for o in result.objects if o.uri == ref).hash_match is False


def test_verify_hybrid_locator_seal_keys_sha512_by_the_locator_reference() -> None:
    prompt = b"p"
    pars = [LOCATOR_ENVELOPE_REFERENCE, "objects/p"]
    artifact = _artifact_signed(pars[0], ["objects/p"], ("objects/p", "prompt"))
    artifact.signature["signatures"].append({"protected": _header("ML-DSA-87", *pars), "signature": "cA"})
    canonical = canonicalize(artifact.envelope)
    client, requests = _client(_comparing(pars, {pars[0]: _sha256(canonical), "objects/p": _sha256(prompt)},
                                          {pars[0]: _sha512(canonical), "objects/p": _sha512(prompt)}))

    result = client.verify_evidence_v2(artifact, {"objects/p": prompt})

    d512 = requests[0][1]["digests512"]
    assert set(d512) == set(pars) and d512[pars[0]] == _sha512(canonical)
    assert result.pqc == "verified" and result.ok


def test_verify_pqc_entry_with_another_reference_form_fails_alignment() -> None:
    artifact = _artifact_signed(LOCATOR_ENVELOPE_REFERENCE, ["objects/p"], ("objects/p", "prompt"))
    artifact.signature["signatures"].append(
        {"protected": _header("ML-DSA-87", LEGACY_ENVELOPE_REFERENCE, "objects/p"), "signature": "cA"})
    client, _ = _client(lambda req, body: httpx.Response(200, json=_verdict_for(LOCATOR_ENVELOPE_REFERENCE,
                                                                                "objects/p")))
    result = client.verify_evidence_v2(artifact, {"objects/p": b"p"})
    assert not result.alignment_ok and not result.ok
    assert any("ML-DSA" in i for i in result.issues)


def _invalid_headers():
    for form in BOTH:
        yield "duplicate-member", form, _b64url(f'{{"alg":"RS256","alg":"RS256","sigD":{{"pars":["{form}","objects/p"]}}}}')
        yield "duplicate-pars", form, _b64url(f'{{"alg":"RS256","sigD":{{"pars":["evil"],"pars":["{form}","objects/p"]}}}}')
        yield "missing-pars", form, _b64url('{"alg":"RS256","sigD":{}}')
        yield "non-string-pars", form, _b64url(f'{{"alg":"RS256","sigD":{{"pars":["{form}",7]}}}}')
        yield "two-classical", form, _header("RS256", form, "objects/p")


@pytest.mark.parametrize("name,form,protected", list(_invalid_headers()))
def test_verify_refuses_a_structurally_invalid_header_even_with_a_lenient_crypto_tier(name, form, protected) -> None:
    artifact = _artifact_signed(form, ["objects/p"], ("objects/p", "prompt"))
    entries = artifact.signature["signatures"]
    if name == "two-classical":
        entries.append({"protected": protected, "signature": "c2ln"})
    else:
        entries[0]["protected"] = protected
    client, _ = _client(lambda req, body: httpx.Response(200, json=_verdict_for(form, "objects/p")))

    result = client.verify_evidence_v2(artifact, {"objects/p": b"p"})

    assert not result.alignment_ok and not result.ok, name
    assert result.notes == [], "a form is only reported from a structurally valid header"


# ── agent runs ──────────────────────────────────────────────────────────────

def _run(name: str):
    v = json.loads((VECTORS / "runs" / name).read_text(encoding="utf-8"))
    return v, verify_agent_run(AgentRunBundle.parse(v["bundle"]), stub_verify)


@pytest.mark.parametrize("name,note", [
    ("01-finalized-digests-only.json", "7 of 7 artifact(s)"),
    ("72-locator-finalized-with-payloads.json", None),
    ("73-mixed-form-run.json", "3 of 7 artifact(s)"),
    ("75-legacy-objects-locator-envelope.json", None),
])
def test_legacy_envelope_reference_is_a_note_never_a_warning(name: str, note: str | None) -> None:
    v, result = _run(name)
    if note is None:
        assert result.notes == []
    else:
        assert len(result.notes) == 1 and result.notes[0].startswith(note)
        assert LEGACY_ENVELOPE_REFERENCE_DIAGNOSTIC in result.notes[0]
    assert len(result.warnings) == v["expected"]["warningCount"], "a note never adds a warning"


@pytest.mark.parametrize("name", ["25-duplicate-header-member.json", "60-header-integer-beyond-i-json.json"])
def test_lenient_digest_key_never_rescues_a_refused_header(name: str) -> None:
    _, result = _run(name)
    assert result.verdict == "run_invalid"
    assert result.checks["signatures"] == "bad"
