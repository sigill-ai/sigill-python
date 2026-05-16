"""Sigill SDK — AI Evidence Envelopes.

A Python SDK for sealing and verifying AiEvidenceEnvelopeV1 records, backed by
RFC 3161 timestamps from the Sigill timestamping service.

Quick start:

    from sigill_sdk import SigillClient, EnvelopeBuilder

    client = SigillClient(api_key="...")

    envelope = (
        EnvelopeBuilder()
        .with_purpose(category="summarization")
        .with_actor(type="service", id="my-service")
        .with_activity(name="ticket.summarize")
        .with_model(provider="anthropic", name="claude-opus-4-7")
        .with_prompt_ref("prompt")    # hash-ref keeps content out of Sigill
        .with_output_ref("output")
        .build()
    )

    payloads = {"prompt": b"Summarise this ticket.", "output": b"Login fails after password reset."}
    sealed = client.seal(envelope, external_payloads=payloads)
    result = client.verify(sealed, external_payloads=payloads)
    assert result.is_valid

The full spec lives at https://github.com/sigill-ai/sigill-python/blob/main/spec/README.md
"""

from sigill_sdk._envelope import (
    AiEvidenceEnvelopeInput,
    SealedAiEvidenceEnvelope,
    EnvelopeBuilder,
    PayloadRef,
    ContentHash,
)
from sigill_sdk._client import SigillClient, ISigillAiEvidenceClient
from sigill_sdk._verify import (
    AiEvidenceVerificationResult,
    VerificationIssue,
    VerificationIssueKind,
)
from sigill_sdk._errors import (
    SigillError,
    CanonicalizationFailed,
    HashMismatch,
    InvalidProof,
    TimestampUnavailable,
    InlineContentWarning,
)
from sigill_sdk._canonical import canonicalize, compute_envelope_hash
from importlib.metadata import version as _meta_version, PackageNotFoundError as _PNF

try:
    __version__ = _meta_version("sigill-sdk")
except _PNF:
    __version__ = "0.0.0.dev"
__all__ = [
    "SigillClient",
    "ISigillAiEvidenceClient",
    "EnvelopeBuilder",
    "AiEvidenceEnvelopeInput",
    "SealedAiEvidenceEnvelope",
    "PayloadRef",
    "ContentHash",
    "AiEvidenceVerificationResult",
    "VerificationIssue",
    "VerificationIssueKind",
    "SigillError",
    "CanonicalizationFailed",
    "HashMismatch",
    "InvalidProof",
    "TimestampUnavailable",
    "InlineContentWarning",
    "canonicalize",
    "compute_envelope_hash",
]
