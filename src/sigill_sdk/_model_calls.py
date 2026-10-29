# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Agent Model Calls v1 — record model calls made through an httpx client.

Put :class:`ModelCallTransport` under any provider SDK that accepts an httpx client::

    http = httpx.Client(transport=ModelCallTransport(run))
    anthropic = Anthropic(http_client=http)          # or OpenAI(http_client=http)

Recognised: the Anthropic Messages API, OpenAI Responses and Chat Completions (also via Azure OpenAI) and the
Amazon Bedrock Runtime Converse / InvokeModel APIs. Other requests pass through unrecorded. The request and
response bodies are sealed as digests only; their content never leaves the process. A streamed response
(server-sent events) is recorded with the identifiers in its headers only. The run must be started with
``records_model_calls=True``. A failure to record never fails the model call: it is reported to ``on_error``.

Mirrors the .NET SDK's ``ModelCallHandler`` / ``ModelCallParser``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Callable, Optional
from urllib.parse import unquote

import httpx

from sigill_sdk._agent_types import ModelCall, ModelInfo, ModelUsage, VendorRef

_ANTHROPIC, _OPENAI, _AZURE_OPENAI, _BEDROCK = "anthropic", "openai", "azure-openai", "bedrock"


def _path(request: httpx.Request) -> str:
    """The request path as sent (still percent-encoded), without the query."""
    return request.url.raw_path.split(b"?", 1)[0].decode("ascii")


def _classify(request: httpx.Request) -> Optional[str]:
    if request.method != "POST":
        return None
    host = request.url.host.lower()
    path = _path(request)
    if host == "api.anthropic.com" and path.endswith("/messages"):
        return _ANTHROPIC
    if host == "api.openai.com" and (path.endswith("/responses") or path.endswith("/chat/completions")):
        return _OPENAI
    if host.endswith(".openai.azure.com") and "/openai/" in path:
        return _AZURE_OPENAI
    if host.startswith("bedrock-runtime.") and host.endswith(".amazonaws.com") and path.startswith("/model/"):
        return _BEDROCK
    return None


def _is_stream(response: httpx.Response) -> bool:
    return response.headers.get("content-type", "").split(";")[0].strip().lower() == "text/event-stream"


def _try_json(body: Optional[bytes]) -> Optional[dict]:
    # Only a JSON object is read; anything else (an array, a scalar, not JSON) gives no values.
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _fit(s: Optional[str], max_len: int) -> Optional[str]:
    return s if isinstance(s, str) and 0 < len(s) <= max_len else None


def _parse(api: str, request: httpx.Request, request_body: Optional[bytes], response: httpx.Response,
           response_body: Optional[bytes]) -> Optional[ModelCall]:
    """Reads a provider's response into a :class:`ModelCall` (Agent Model Calls v1 §7). Values only from the
    response; the request supplies ``requested``."""
    req = _try_json(request_body) or {}
    res = _try_json(response_body) or {}

    def s(v: Any) -> Optional[str]:
        return v if isinstance(v, str) and v else None

    def n(v: Any) -> Optional[int]:
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    def first(d: dict, *keys: str) -> Any:
        return next((d[k] for k in keys if d.get(k) is not None), None)

    refs: list[VendorRef] = []

    def ref(provider: str, kind: str, id_: Optional[str]) -> None:
        if id_ is not None and len(id_) <= 255 and all("!" <= c <= "~" for c in id_) and len(refs) < 8:
            refs.append(VendorRef(provider, kind, id_))

    u = res.get("usage") if isinstance(res.get("usage"), dict) else {}
    if api == _ANTHROPIC:
        ref("anthropic", "message", s(res.get("id")))
        ref("anthropic", "request", response.headers.get("request-id"))
        served = s(res.get("model"))
        return _build(None if served is None else ModelInfo("anthropic", served, s(req.get("model"))), refs,
                      ModelUsage(n(u.get("input_tokens")), n(u.get("output_tokens")),
                                 n(u.get("cache_read_input_tokens")), n(u.get("cache_creation_input_tokens")),
                                 s(res.get("stop_reason"))))
    if api in (_OPENAI, _AZURE_OPENAI):
        provider = "openai" if api == _OPENAI else "azure-openai"
        id_ = s(res.get("id"))
        ref(provider, "completion" if id_ is not None and id_.startswith("chatcmpl") else "response", id_)
        ref(provider, "request", response.headers.get("x-request-id" if api == _OPENAI else "apim-request-id"))
        served = s(res.get("model"))
        choices = res.get("choices")
        stop = (s(choices[0].get("finish_reason")) if isinstance(choices, list) and choices
                and isinstance(choices[0], dict) else None) or s(res.get("status"))
        deployment = _deployment_of(_path(request)) if api == _AZURE_OPENAI else None
        return _build(None if served is None else ModelInfo(provider, served, s(req.get("model")), deployment), refs,
                      ModelUsage(n(first(u, "prompt_tokens", "input_tokens")),
                                 n(first(u, "completion_tokens", "output_tokens")), stop_reason=stop))
    # Bedrock
    ref("aws-bedrock", "request",
        response.headers.get("x-amzn-requestid") or response.headers.get("x-amzn-request-id"))
    ref("aws-bedrock", "message", s(res.get("id")))
    segments = [p for p in _path(request).split("/") if p]
    model_id = unquote(segments[1]) if len(segments) > 1 else None
    host = request.url.host.split(".")
    region = host[1] if len(host) > 2 else None
    # The model the provider names in its response when it does (InvokeModel with an Anthropic body), else the
    # model id the request addressed — Bedrock routes to exactly that id or inference profile.
    served = s(res.get("model")) or (model_id[model_id.rfind("/") + 1:]
                                     if model_id is not None and model_id.startswith("arn:") else model_id)
    return _build(None if served is None else ModelInfo("aws-bedrock", served, None, _fit(model_id, 255), region),
                  refs, ModelUsage(n(first(u, "inputTokens", "input_tokens")),
                                   n(first(u, "outputTokens", "output_tokens")),
                                   stop_reason=s(res.get("stopReason")) or s(res.get("stop_reason"))))


def _build(model: Optional[ModelInfo], refs: list[VendorRef], usage: ModelUsage) -> Optional[ModelCall]:
    # Values are recorded exactly as the provider returned them or not at all: one that does not fit the schema
    # is left out, never shortened (a shortened model name would be a different statement).
    if model is not None:
        if _fit(model.served, 128) is None or (model.region is not None and _fit(model.region, 32) is None):
            model = None
        else:
            model = ModelInfo(model.provider, model.served, _fit(model.requested, 128), _fit(model.deployment, 255),
                              model.region)
    usage = ModelUsage(usage.input_tokens, usage.output_tokens, usage.cache_read_tokens, usage.cache_write_tokens,
                       _fit(usage.stop_reason, 64))
    if model is None and not refs:
        return None  # nothing the provider said about this call
    has_usage = any(v is not None for v in (usage.input_tokens, usage.output_tokens, usage.cache_read_tokens,
                                            usage.cache_write_tokens, usage.stop_reason))
    return ModelCall(model, tuple(refs), usage if has_usage else None)


def _deployment_of(path: str) -> Optional[str]:
    parts = [p for p in path.split("/") if p]
    i = parts.index("deployments") if "deployments" in parts else -1
    return _fit(parts[i + 1], 255) if 0 <= i < len(parts) - 1 else None


def _replay(response: httpx.Response, raw: bytes, request: httpx.Request) -> httpx.Response:
    """A fresh response over the raw (still content-encoded) bytes: the caller reads it exactly as it would
    have read the original."""
    return httpx.Response(response.status_code, headers=response.headers, stream=httpx.ByteStream(raw),
                          extensions=response.extensions, request=request)


def _decoded(response: httpx.Response, raw: bytes) -> bytes:
    """The body as the caller sees it (content-encoding removed)."""
    return httpx.Response(response.status_code, headers=response.headers, stream=httpx.ByteStream(raw)).read()


class ModelCallTransport(httpx.BaseTransport):
    """An httpx transport that records every recognised model call on ``run`` as an Agent Model Calls v1 step
    (see the module docs). ``inner`` defaults to :class:`httpx.HTTPTransport`."""

    def __init__(self, run: Any, inner: Optional[httpx.BaseTransport] = None,
                 on_error: Optional[Callable[[Exception], None]] = None) -> None:
        if run is None:
            raise ValueError("run is required.")
        self._run = run
        self._inner = inner if inner is not None else httpx.HTTPTransport()
        self._on_error = on_error

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        api = _classify(request)
        if api is None:
            return self._inner.handle_request(request)
        request_body = request.read() or None  # read() also makes the body replayable for the inner transport
        response = self._inner.handle_request(request)
        response_body = None
        if not _is_stream(response):
            # Read outside the try below: a failure here is the call's own error, not a recording failure.
            try:
                raw = b"".join(response.stream)  # the raw stream: content-encoding kept for the caller
            finally:
                response.close()
            response, response_body = _replay(response, raw, request), _decoded(response, raw)
        try:
            call = _parse(api, request, request_body, response, response_body)
            if call is not None:
                self._run.record_model_call(call, request_body, response_body)
        except Exception as ex:  # noqa: BLE001 — recording never fails the model call
            if self._on_error is not None:
                self._on_error(ex)
        return response

    def close(self) -> None:
        self._inner.close()


class AsyncModelCallTransport(httpx.AsyncBaseTransport):
    """The async counterpart of :class:`ModelCallTransport`, for ``httpx.AsyncClient`` (e.g.
    ``AsyncAnthropic(http_client=...)``). :class:`~sigill_sdk.AgentRun` seals synchronously, so the event is
    sealed on a worker thread (:func:`asyncio.to_thread`) and the event loop is never blocked. ``inner``
    defaults to :class:`httpx.AsyncHTTPTransport`."""

    def __init__(self, run: Any, inner: Optional[httpx.AsyncBaseTransport] = None,
                 on_error: Optional[Callable[[Exception], None]] = None) -> None:
        if run is None:
            raise ValueError("run is required.")
        self._run = run
        self._inner = inner if inner is not None else httpx.AsyncHTTPTransport()
        self._on_error = on_error

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        api = _classify(request)
        if api is None:
            return await self._inner.handle_async_request(request)
        request_body = (await request.aread()) or None
        response = await self._inner.handle_async_request(request)
        response_body = None
        if not _is_stream(response):
            try:
                raw = b"".join([chunk async for chunk in response.stream])  # type: ignore[union-attr]
            finally:
                await response.aclose()
            response, response_body = _replay(response, raw, request), _decoded(response, raw)
        try:
            call = _parse(api, request, request_body, response, response_body)
            if call is not None:
                await asyncio.to_thread(self._run.record_model_call, call, request_body, response_body)
        except Exception as ex:  # noqa: BLE001 — recording never fails the model call
            if self._on_error is not None:
                self._on_error(ex)
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()
