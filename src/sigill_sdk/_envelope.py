"""Envelope shape and builder.

The envelope itself is just a dict — that matches the JSON Schema directly and avoids
forcing a particular ORM/dataclass library onto consumers. The Builder wraps the dict
in fluent methods so the common case (build → seal) reads naturally.

PayloadRef and ContentHash are exposed as TypedDicts for static-type users; runtime they
are plain dicts.
"""
from __future__ import annotations

import datetime as _dt
import uuid
from typing import Any, Literal, TypedDict

# ---------------------------------------------------------------------------
# Type aliases — these mirror the JSON Schema $defs.
# ---------------------------------------------------------------------------


class ContentHash(TypedDict, total=False):
    alg: Literal["SHA-256", "SHA-384", "SHA-512"]
    hex: str
    sizeBytes: int


class PayloadRef(TypedDict, total=False):
    ref: str
    contentType: str
    encoding: Literal["utf-8", "base64", "binary"]
    inline: Any
    hash: ContentHash
    metadata: dict


# Type alias for an unsealed envelope; the dict shape is enforced at validation time.
AiEvidenceEnvelopeInput = dict
SealedAiEvidenceEnvelope = dict


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    """RFC 3339 UTC with seconds precision, Z suffix. Stable representation across runs."""
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


class EnvelopeBuilder:
    """Fluent builder for an AiEvidenceEnvelopeV1 input.

    Producing the same logical envelope from this builder produces the same canonical
    bytes (modulo the auto-generated evidenceId / createdAt, which the caller can pin
    explicitly via :meth:`with_evidence_id` and :meth:`with_created_at` for deterministic
    tests).

    The builder enforces the spec's required fields via :meth:`build` — missing required
    fields raise ValueError immediately rather than during seal().
    """

    def __init__(self) -> None:
        self._env: dict[str, Any] = {
            "schemaName": "AiEvidenceEnvelope",
            "schemaVersion": "1",
            "evidenceId": str(uuid.uuid4()),
            "createdAt": _utc_now_iso(),
        }

    # -- identity -----------------------------------------------------------
    def with_evidence_id(self, evidence_id: str) -> "EnvelopeBuilder":
        self._env["evidenceId"] = evidence_id
        return self

    def with_created_at(self, ts: str) -> "EnvelopeBuilder":
        self._env["createdAt"] = ts
        return self

    # -- context ------------------------------------------------------------
    def with_purpose(
        self,
        category: str,
        business_context: str | None = None,
        regulatory_basis: list[str] | None = None,
    ) -> "EnvelopeBuilder":
        purpose: dict[str, Any] = {"category": category}
        if business_context is not None:
            purpose["businessContext"] = business_context
        if regulatory_basis is not None:
            purpose["regulatoryBasis"] = list(regulatory_basis)
        self._env["purpose"] = purpose
        return self

    def with_actor(
        self,
        type: Literal["user", "service", "system"],
        id: str,
        tenant_id: str | None = None,
        display_hint: str | None = None,
    ) -> "EnvelopeBuilder":
        actor: dict[str, Any] = {"type": type, "id": id}
        if tenant_id is not None:
            actor["tenantId"] = tenant_id
        if display_hint is not None:
            actor["displayHint"] = display_hint
        self._env["actor"] = actor
        return self

    def with_activity(
        self,
        name: str,
        correlation_id: str | None = None,
        parent_evidence_id: str | None = None,
    ) -> "EnvelopeBuilder":
        activity: dict[str, Any] = {"name": name}
        if correlation_id is not None:
            activity["correlationId"] = correlation_id
        if parent_evidence_id is not None:
            activity["parentEvidenceId"] = parent_evidence_id
        self._env["activity"] = activity
        return self

    # -- AI call ------------------------------------------------------------
    def with_model(
        self,
        provider: str,
        name: str,
        version: str | None = None,
        deployment_id: str | None = None,
        parameters: dict | None = None,
    ) -> "EnvelopeBuilder":
        model: dict[str, Any] = {"provider": provider, "name": name}
        if version is not None:
            model["version"] = version
        if deployment_id is not None:
            model["deploymentId"] = deployment_id
        if parameters is not None:
            model["parameters"] = dict(parameters)
        self._env["model"] = model
        return self

    def with_prompt_inline(self, text: str, content_type: str = "text/plain") -> "EnvelopeBuilder":
        self._env["prompt"] = {
            "contentType": content_type,
            "encoding": "utf-8",
            "inline": text,
        }
        return self

    def with_prompt_ref(
        self, ref: str, content_type: str = "text/plain", encoding: str = "utf-8"
    ) -> "EnvelopeBuilder":
        """Declare the prompt as a hash reference. The bytes are supplied at seal() time."""
        self._env["prompt"] = {"ref": ref, "contentType": content_type, "encoding": encoding}
        return self

    def with_output_inline(self, text: str, content_type: str = "text/plain") -> "EnvelopeBuilder":
        self._env["output"] = {
            "contentType": content_type,
            "encoding": "utf-8",
            "inline": text,
        }
        return self

    def with_output_ref(
        self, ref: str, content_type: str = "text/plain", encoding: str = "utf-8"
    ) -> "EnvelopeBuilder":
        self._env["output"] = {"ref": ref, "contentType": content_type, "encoding": encoding}
        return self

    def with_retrieved_context(self, items: list[dict]) -> "EnvelopeBuilder":
        self._env["retrievedContext"] = list(items)
        return self

    def with_source_trace(self, items: list[dict]) -> "EnvelopeBuilder":
        self._env["sourceTrace"] = list(items)
        return self

    def with_inputs(self, items: list[dict]) -> "EnvelopeBuilder":
        self._env["inputs"] = list(items)
        return self

    def with_output_artifacts(self, items: list[dict]) -> "EnvelopeBuilder":
        self._env["outputArtifacts"] = list(items)
        return self

    # -- operational --------------------------------------------------------
    def with_processing_metadata(self, **fields: Any) -> "EnvelopeBuilder":
        self._env["processingMetadata"] = {k: v for k, v in fields.items() if v is not None}
        return self

    def with_policy_metadata(self, **fields: Any) -> "EnvelopeBuilder":
        self._env["policyMetadata"] = {k: v for k, v in fields.items() if v is not None}
        return self

    # -- escape hatch -------------------------------------------------------
    def merge(self, **fields: Any) -> "EnvelopeBuilder":
        """Merge arbitrary top-level fields into the envelope.

        Use sparingly — preferred path is to add a typed builder method. Provided so
        callers aren't blocked when the schema gains a field before the builder does.
        """
        for k, v in fields.items():
            self._env[k] = v
        return self

    # -- finalize -----------------------------------------------------------
    REQUIRED = ("schemaName", "schemaVersion", "evidenceId", "createdAt", "purpose", "actor", "activity", "model")

    def build(self) -> AiEvidenceEnvelopeInput:
        missing = [f for f in self.REQUIRED if f not in self._env]
        if missing:
            raise ValueError(
                f"Cannot build envelope: missing required field(s) {missing}. "
                f"Use with_purpose / with_actor / with_activity / with_model."
            )
        # Return a copy so subsequent builder mutations don't leak back into the result.
        import copy

        return copy.deepcopy(self._env)
