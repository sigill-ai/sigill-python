# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""The policy engine: the official Cedar core (``cedar-policy`` 4.14.0) as one WebAssembly module, run in-process
with Wasmtime. Calls and answers are the JSON objects of ``@cedar-policy/cedar-wasm``'s ``isAuthorized`` and
``validate``. ``wasmtime`` is optional (the ``policy`` extra): importing this module never imports it."""

from __future__ import annotations

import hashlib
import json
import threading
from importlib import resources
from typing import Any, Optional, Protocol

from sigill_sdk._canonical import canonicalize
from sigill_sdk._errors import CanonicalizationFailed, SigillError

CEDAR_VERSION = "4.14.0"
"""The Cedar core the bundled module carries."""
MODULE_SHA256 = "a0cd395067e77a157116f6b25bcdb612d34c61d1a4446918d75da1a07c80d1f3"
"""SHA-256 of the bundled ``sigill_cedar.wasm``: any other file is refused."""
_MEMORY_LIMIT = 256 * 1024 * 1024  # the module's linear memory: a hostile policy cannot exhaust the host


class PolicyEngineError(SigillError):
    """The policy engine could not load, or a call to it failed (a trap, the memory cap, an unreadable answer), or
    it refused a request of an evaluation. The engine stays usable: the next call starts a fresh instance."""

    def __init__(self, message: str, refused: bool = False) -> None:
        super().__init__(message)
        self.refused = refused
        """True only when :meth:`AgentPolicy.evaluate` raises it for a ``type: failure`` answer: the policy or the
        request cannot be evaluated at all."""


class PolicyEngine(Protocol):
    """A Cedar policy engine. Calls and answers are the JSON objects of ``@cedar-policy/cedar-wasm``
    ``isAuthorized`` and ``validate``. Implementations must be safe to share between threads."""

    @property
    def version(self) -> str:
        """The Cedar core's version, e.g. ``4.14.0``; evidence names the engine ``cedar-policy@<version>``."""
        ...

    def authorize(self, call: dict) -> dict:
        """An ``isAuthorized`` call; the answer's ``diagnostics.reason`` and ``errors`` sorted by rule id."""
        ...

    def validate(self, call: dict) -> dict:
        """A ``validate`` call."""
        ...


def _module_bytes() -> bytes:
    return resources.files("sigill_sdk").joinpath("_policy/sigill_cedar.wasm").read_bytes()


class CedarEngine:
    """The bundled Cedar core in Wasmtime. Needs ``pip install 'sigill-sdk[policy]'``.

    Loaded on first use; the module's SHA-256 and Cedar version are checked then. The module gets no filesystem,
    network, clock, arguments, environment or stdio, and at most 256 MiB of memory. One instance serves every
    thread, one call at a time. Calls and answers are never logged."""

    def __init__(self) -> None:
        try:
            import wasmtime
        except ImportError:
            raise ImportError("CedarEngine needs the wasmtime package: install the 'policy' extra "
                              "(pip install 'sigill-sdk[policy]').") from None
        self._wasmtime: Any = wasmtime
        self._lock = threading.Lock()
        self._engine: Any = None
        self._module: Any = None
        self._instance: Optional[tuple] = None  # (store, exports, memory); dropped after any failure
        self._version: Optional[str] = None

    @property
    def version(self) -> str:
        with self._lock:
            self._load()
            return self._version  # type: ignore[return-value]

    def authorize(self, call: dict) -> dict:
        return self._call("cedar_authorize", call)

    def validate(self, call: dict) -> dict:
        return self._call("cedar_validate", call)

    def _load(self) -> None:
        if self._instance is not None:
            return
        wt = self._wasmtime
        try:
            if self._module is None:
                data = _module_bytes()
                if hashlib.sha256(data).hexdigest() != MODULE_SHA256:
                    raise PolicyEngineError("The policy engine module is not the bundled sigill_cedar.wasm (its "
                                            "SHA-256 differs); it is not run.")
                self._engine = wt.Engine()
                self._module = wt.Module(self._engine, data)
            linker = wt.Linker(self._engine)
            linker.define_wasi()
            store = wt.Store(self._engine)
            store.set_wasi(wt.WasiConfig())  # no arguments, environment, preopened directories or inherited stdio
            store.set_limits(memory_size=_MEMORY_LIMIT)
            exports = linker.instantiate(store, self._module).exports(store)
            if "_initialize" in exports:
                exports["_initialize"](store)
            instance = (store, exports, exports["memory"])
            slot = exports["cedar_alloc"](store, 4)
            version = self._take(instance, exports["cedar_version"](store, slot), slot).decode("utf-8")
            exports["cedar_free"](store, slot, 4)
        except PolicyEngineError:
            raise
        except Exception as e:
            raise PolicyEngineError(f"The policy engine could not be loaded: {e}") from e
        if version != CEDAR_VERSION:
            raise PolicyEngineError(f"The policy engine module carries Cedar {version}, not {CEDAR_VERSION}.")
        self._instance, self._version = instance, version

    @staticmethod
    def _take(instance: tuple, ptr: int, len_ptr: int) -> bytes:
        store, exports, memory = instance
        n = int.from_bytes(memory.read(store, len_ptr, len_ptr + 4), "little")
        out = bytes(memory.read(store, ptr, ptr + n))
        exports["cedar_free"](store, ptr, n)
        return out

    def _call(self, fn: str, call: dict) -> dict:
        # JCS, as the reference evaluator sees the call: integral numbers as integers (20.0, 2e1 and -0 alike).
        try:
            data = canonicalize(call)
        except (CanonicalizationFailed, RecursionError) as e:
            raise PolicyEngineError(f"The policy engine failed ({fn}): the call is not I-JSON ({e})") from e
        with self._lock:
            self._load()
            store, exports, memory = instance = self._instance  # type: ignore[misc]
            try:
                p = exports["cedar_alloc"](store, len(data) + 4)  # the input, then the 4-byte answer length
                memory.write(store, data, p)
                raw = self._take(instance, exports[fn](store, p, len(data), p + len(data)), p + len(data))
                exports["cedar_free"](store, p, len(data) + 4)
            except Exception as e:
                self._instance = None  # a trapped instance is never reused
                raise PolicyEngineError(f"The policy engine failed ({fn}): {e}") from e
        try:
            answer = json.loads(raw)
        except ValueError:
            answer = None
        if not isinstance(answer, dict):
            raise PolicyEngineError(f"The policy engine's answer ({fn}) is not a JSON object.")
        return answer
