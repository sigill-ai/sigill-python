# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Agent Model Calls v1: model calls with the provider's own identifiers, sealed as schemaVersion 3, and the
httpx transports that record them from the provider's response. Mirrors the .NET suite."""

from __future__ import annotations

import asyncio
import gzip
import json
from typing import Callable

import httpx
import pytest
from test_agent_run import StubSealer, _client, _start, stub_verify

from sigill_sdk import (
    AgentRun,
    AgentRunBundle,
    AsyncModelCallTransport,
    ModelCall,
    ModelCallTransport,
    ModelInfo,
    ModelUsage,
    VendorRef,
    verify_agent_run,
)

PROMPT = b'{"messages":[{"role":"user","content":"Customer Jane Doe asks for a payout"}]}'
REPLY = b'{"content":[{"type":"text","text":"Approve 1200 for Jane Doe"}]}'


def _anthropic_call(msg: str = "msg_01XyZ8kq3VcR2mWd9TfLpA7e") -> ModelCall:
    return ModelCall(
        model=ModelInfo("anthropic", "claude-sonnet-5-20261015", requested="claude-sonnet-5"),
        vendor_refs=[VendorRef("anthropic", "message", msg), VendorRef("anthropic", "request", "req_011CabcQx7Nn4Tz2Pf8Rk1Ws")],
        usage=ModelUsage(input_tokens=2960, output_tokens=488, stop_reason="tool_use"),
    )


def _model_step(run: AgentRun) -> dict | None:
    return next((a.envelope["step"] for a in run.artifacts if a.envelope["step"]["type"] == "model_output"), None)


# ── AgentRun.record_model_call ──────────────────────────────────────────────

def test_model_calls_seal_as_version3_with_the_providers_ids_and_only_digests_travel() -> None:
    sealer = StubSealer()
    run = _start(_client(sealer), records_model_calls=True)
    run.record_model_call(_anthropic_call(), PROMPT, REPLY)
    run.record_tool_call("claims.approve_payout", b'{"amount":1200}', operation="update", consequential=True)
    run.record_model_call(ModelCall(vendor_refs=[VendorRef("openai", "response", "resp_68a1f0c2")]))
    bundle = run.finish()

    assert {a.envelope["schemaVersion"] for a in run.artifacts} == {"3"}
    step = _model_step(run)
    assert step["model"]["served"] == "claude-sonnet-5-20261015"
    assert step["vendorRefs"][1]["id"] == "req_011CabcQx7Nn4Tz2Pf8Rk1Ws"
    assert step["usage"] == {"inputTokens": 2960, "outputTokens": 488, "stopReason": "tool_use"}
    assert [o["role"] for o in run.artifacts[1].envelope["objects"]] == ["model-input", "model-output"]
    assert all("Jane Doe" not in json.dumps(r) for r in sealer.requests)  # digests only

    r = verify_agent_run(bundle, stub_verify)
    assert r.verdict == "run_finalized", r.findings
    assert (r.model_calls, r.model_calls_with_vendor_refs) == (2, 2)


def test_model_calls_need_the_option_and_invalid_identifiers_are_refused_before_sealing() -> None:
    sealer = StubSealer()
    client = _client(sealer)
    v1 = _start(client)
    with pytest.raises(RuntimeError, match="records_model_calls"):
        v1.record_model_call(_anthropic_call())
    # The members are reserved: they cannot be smuggled into another step or a v1 run through record().
    with pytest.raises(ValueError, match="reserved"):
        v1.record("model_output", fields={"vendorRefs": []})

    v3 = _start(client, records_model_calls=True)
    before = len(sealer.requests)
    for bad in (_anthropic_call("msg with space"), _anthropic_call("x" * 256),
                ModelCall(vendor_refs=[VendorRef("anthropic", "invoice", "x")]),
                ModelCall(model=ModelInfo("Anthropic", "m"))):  # provider must be lowercase
        with pytest.raises(ValueError):
            v3.record_model_call(bad)
    assert len(sealer.requests) == before  # nothing was sealed
    v3.record_model_call(_anthropic_call())  # and the run stays usable


def test_a_run_mixing_version3_with_version2_is_invalid() -> None:
    v3 = _start(_client(StubSealer()), records_model_calls=True)
    v3.record_model_call(_anthropic_call())
    bundle = json.loads(v3.finish().to_json())
    # Rewriting the version breaks the signature too; the version rule is reported on its own as well.
    bundle["artifacts"][0]["envelope"]["schemaVersion"] = "2"
    r = verify_agent_run(AgentRunBundle.parse(json.dumps(bundle)), stub_verify)
    assert r.verdict == "run_invalid"
    assert any("mix schemaVersion" in f for f in r.findings)


def test_a_version3_run_may_delegate() -> None:
    run = _start(_client(StubSealer()), records_model_calls=True)
    delegation = run.delegate("urn:example:agent:researcher", b"look it up")
    assert delegation.artifact.envelope["schemaVersion"] == "3"


# ── ModelCallTransport ──────────────────────────────────────────────────────

def _provider(body: bytes | str, content_type: str = "application/json", headers: dict | None = None,
              seen: list | None = None) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request.read())
        return httpx.Response(200, content=body.encode() if isinstance(body, str) else body,
                              headers={"content-type": content_type, **(headers or {})})
    return httpx.MockTransport(handle)


def _through(url: str, request_json: str, provider: httpx.MockTransport,
             on_error: Callable[[Exception], None] | None = None) -> tuple[AgentRun, StubSealer, str]:
    sealer = StubSealer()
    run = _start(_client(sealer), records_model_calls=True)
    with httpx.Client(transport=ModelCallTransport(run, provider, on_error)) as http:
        reply = http.post(url, content=request_json, headers={"content-type": "application/json"}).text
    return run, sealer, reply


def test_transport_records_an_anthropic_call_from_the_response_and_the_prompt_stays_local() -> None:
    body = ('{"id":"msg_01XyZ8kq3VcR2mWd9TfLpA7e","type":"message","model":"claude-sonnet-5-20261015",'
            '"stop_reason":"tool_use","usage":{"input_tokens":2960,"output_tokens":488,"cache_read_input_tokens":1200},'
            '"content":[{"type":"text","text":"Approve for Jane Doe"}]}')
    seen: list = []
    request = '{"model":"claude-sonnet-5","messages":[{"role":"user","content":"Jane Doe"}]}'
    run, sealer, reply = _through("https://api.anthropic.com/v1/messages", request,
                                  _provider(body, headers={"request-id": "req_011CabcQx7Nn4Tz2Pf8Rk1Ws"}, seen=seen))
    assert reply == body  # the caller gets the response unchanged
    assert seen == [request.encode()]  # and the provider the request
    step = _model_step(run)
    assert step["model"] == {"provider": "anthropic", "served": "claude-sonnet-5-20261015",
                             "requested": "claude-sonnet-5"}
    assert [(r["kind"], r["id"]) for r in step["vendorRefs"]] == \
        [("message", "msg_01XyZ8kq3VcR2mWd9TfLpA7e"), ("request", "req_011CabcQx7Nn4Tz2Pf8Rk1Ws")]
    assert step["usage"]["cacheReadTokens"] == 1200
    assert all("Jane Doe" not in json.dumps(r) for r in sealer.requests)


def test_transport_records_openai_azure_and_bedrock_calls() -> None:
    openai, _, _ = _through("https://api.openai.com/v1/chat/completions", '{"model":"gpt-6"}', _provider(
        '{"id":"chatcmpl-9x","model":"gpt-6-2026-09-01","choices":[{"finish_reason":"stop"}],'
        '"usage":{"prompt_tokens":10,"completion_tokens":5}}', headers={"x-request-id": "req_abc123"}))
    o = _model_step(openai)
    assert o["vendorRefs"][0]["kind"] == "completion"
    assert o["usage"] == {"inputTokens": 10, "outputTokens": 5, "stopReason": "stop"}

    azure, _, _ = _through("https://contoso.openai.azure.com/openai/deployments/prod-gpt/responses?api-version=1", "{}",
                           _provider('{"id":"resp_1","model":"gpt-6","status":"completed"}',
                                     headers={"apim-request-id": "a1b2"}))
    a = _model_step(azure)
    assert a["model"] == {"provider": "azure-openai", "served": "gpt-6", "deployment": "prod-gpt"}
    assert [(r["kind"], r["id"]) for r in a["vendorRefs"]] == [("response", "resp_1"), ("request", "a1b2")]

    bedrock, _, _ = _through(
        "https://bedrock-runtime.eu-north-1.amazonaws.com/model/eu.anthropic.claude-sonnet-5-v1%3A0/converse", "{}",
        _provider('{"stopReason":"end_turn","usage":{"inputTokens":7,"outputTokens":3}}',
                  headers={"x-amzn-requestid": "4b0a8d3e-1f2c-4d5e-9a7b-0c1d2e3f4a5b"}))
    b = _model_step(bedrock)
    assert (b["model"]["served"], b["model"]["region"]) == ("eu.anthropic.claude-sonnet-5-v1:0", "eu-north-1")
    assert b["vendorRefs"][0]["id"] == "4b0a8d3e-1f2c-4d5e-9a7b-0c1d2e3f4a5b"


@pytest.mark.parametrize("url", [
    "https://acme.openai.azure.com/openai/deployments/gpt-6-prod/chat/completions?api-version=2026-06-01",
    "https://acme.cognitiveservices.azure.com/openai/deployments/gpt-6-prod/chat/completions?api-version=2026-06-01",
    "https://acme.services.ai.azure.com/openai/deployments/gpt-6-prod/chat/completions?api-version=2026-06-01",
])
def test_transport_records_azure_openai_on_every_azure_ai_domain(url: str) -> None:
    run, _, _ = _through(url, "{}", _provider(
        '{"id":"chatcmpl-AZ1","model":"gpt-6-2026-09-01","choices":[{"finish_reason":"stop"}]}',
        headers={"apim-request-id": "6f1e2d3c-aaaa-bbbb-cccc-0123456789ab"}))
    step = _model_step(run)
    assert (step["model"]["provider"], step["model"]["deployment"]) == ("azure-openai", "gpt-6-prod")
    assert [r["kind"] for r in step["vendorRefs"]] == ["completion", "request"]


def test_transport_records_google_generate_content_on_the_gemini_api_and_vertex() -> None:
    body = ('{"responseId":"mT4xaKXyJ8-tz7IPq9GJ","modelVersion":"gemini-3.0-pro-001",'
            '"candidates":[{"finishReason":"STOP"}],'
            '"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":4,"cachedContentTokenCount":8}}')
    gemini, _, _ = _through("https://generativelanguage.googleapis.com/v1beta/models/gemini-3.0-pro:generateContent",
                            "{}", _provider(body))
    g = _model_step(gemini)
    assert g["model"] == {"provider": "google", "served": "gemini-3.0-pro-001", "requested": "gemini-3.0-pro"}
    assert [(r["kind"], r["id"]) for r in g["vendorRefs"]] == [("response", "mT4xaKXyJ8-tz7IPq9GJ")]
    assert g["usage"] == {"inputTokens": 12, "outputTokens": 4, "cacheReadTokens": 8, "stopReason": "STOP"}

    vertex, _, _ = _through(
        "https://europe-west4-aiplatform.googleapis.com/v1/projects/acme/locations/europe-west4/publishers/google/"
        "models/gemini-3.0-pro:generateContent", "{}", _provider(body))
    v = _model_step(vertex)
    assert (v["model"]["provider"], v["model"]["region"]) == ("google-vertex", "europe-west4")


def test_transport_passes_other_requests_through_records_streams_by_header_and_never_fails_the_call() -> None:
    other, _, _ = _through("https://example.com/api", "{}", _provider('{"id":"x"}'))
    assert _model_step(other) is None

    stream, _, _ = _through("https://api.anthropic.com/v1/messages", '{"model":"claude-sonnet-5","stream":true}',
                            _provider("event: message_start\ndata: {}\n\n", "text/event-stream",
                                      {"request-id": "req_stream1"}))
    s = _model_step(stream)
    assert [r["id"] for r in s["vendorRefs"]] == ["req_stream1"]
    assert [o["role"] for o in stream.artifacts[1].envelope["objects"]] == ["model-input"]

    seen: list = []
    bad, _, reply = _through("https://api.anthropic.com/v1/messages", "{}", _provider("[not an object"), seen.append)
    assert reply == "[not an object"  # the model call itself is untouched
    assert _model_step(bad) is None  # nothing the provider said: nothing recorded
    assert seen == []

    # A value that does not fit is left out, never shortened; a recording failure goes to on_error only.
    long_model, _, _ = _through("https://api.anthropic.com/v1/messages", "{}",
                                _provider(json.dumps({"id": "msg_1", "model": "m" * 129})))
    assert "model" not in _model_step(long_model)
    v1 = _start(_client(StubSealer()))
    errors: list = []
    with httpx.Client(transport=ModelCallTransport(v1, _provider('{"id":"msg_1","model":"m"}'), errors.append)) as http:
        assert http.post("https://api.anthropic.com/v1/messages", content="{}").json()["id"] == "msg_1"
    assert len(errors) == 1 and isinstance(errors[0], RuntimeError)


def test_transport_hands_back_a_compressed_response_still_readable() -> None:
    body = b'{"id":"msg_gz","model":"claude-sonnet-5-20261015"}'
    run, _, reply = _through("https://api.anthropic.com/v1/messages", "{}",
                             _provider(gzip.compress(body), headers={"content-encoding": "gzip"}))
    assert reply == body.decode()
    assert _model_step(run)["vendorRefs"][0]["id"] == "msg_gz"


def test_async_transport_records_off_the_event_loop() -> None:
    async def provider(request: httpx.Request) -> httpx.Response:
        await request.aread()
        return httpx.Response(200, json={"id": "resp_9", "model": "gpt-6", "status": "completed"},
                              headers={"x-request-id": "req_9"})

    run = _start(_client(StubSealer()), records_model_calls=True)

    async def call() -> dict:
        async with httpx.AsyncClient(transport=AsyncModelCallTransport(run, httpx.MockTransport(provider))) as http:
            return (await http.post("https://api.openai.com/v1/responses", content='{"model":"gpt-6"}')).json()

    assert asyncio.run(call())["id"] == "resp_9"
    step = _model_step(run)
    assert step["model"] == {"provider": "openai", "served": "gpt-6", "requested": "gpt-6"}
    assert [(r["kind"], r["id"]) for r in step["vendorRefs"]] == [("response", "resp_9"), ("request", "req_9")]
