"""Explicit error types for the Sigill SDK.

The four documented verification failure modes from spec §7:

  - canonicalization_failed
  - hash_mismatch
  - invalid_proof
  - timestamp_unavailable

These are surfaced as exceptions when raised during seal() (a producer-time error), and
as VerificationIssue entries inside an AiEvidenceVerificationResult when encountered during
verify() (so callers can collect a complete report rather than failing fast).
"""
from __future__ import annotations


class SigillError(Exception):
    """Base class for all Sigill SDK errors."""


class InlineContentWarning(UserWarning):
    """Issued when content is embedded inline in an envelope.

    Inline content is transmitted to Sigill as part of the envelope. For fields that
    may carry sensitive data (prompt, output) use the hash-reference form instead:
    call with_prompt_ref() / with_output_ref() and supply the raw bytes via
    external_payloads at seal() time. Sigill will never see the bytes — only their hash.

    To suppress this warning when inline content is genuinely non-sensitive::

        import warnings, sigill_sdk
        warnings.filterwarnings("ignore", category=sigill_sdk.InlineContentWarning)
    """


class CanonicalizationFailed(SigillError):
    """The envelope cannot be canonicalized.

    Typical causes: input contains values JCS rejects (NaN, Infinity), non-UTF-8 strings,
    cyclic references, or non-string object keys.
    """


class HashMismatch(SigillError):
    """A computed hash does not match the registered hash.

    Raised at producer time only when an external payload is supplied to seal() but the
    SDK's recomputed digest doesn't match what the input declared. During verification,
    hash mismatches are reported as VerificationIssue entries instead.
    """


class InvalidProof(SigillError):
    """A proof (e.g. RFC 3161 TSR) cannot be parsed or its signature is invalid."""


class PdfUnsupported(SigillError):
    """The local PDF parser cannot handle this PDF's structure.

    Raised by seal_pades() when the incremental signer cannot parse the input
    (e.g. an object stream with an exotic filter or /Predictor, or a
    pathological page tree) — before anything is transmitted. The document is
    fine — it just needs the server-side path: upload it to ``POST /seal/sign``
    instead, which uses the full parser with the same PAdES output. Note that
    path transmits the PDF to Sigill.
    """

    def __init__(self, message: str):
        super().__init__(
            message
            + " — this PDF's structure is not supported by local (hash-only) sealing. "
            "Fall back to uploading it to POST /seal/sign for server-side PAdES sealing."
        )


class TimestampUnavailable(SigillError):
    """Sigill returned 502 — every TSA in the auto-rotation failed.

    The structured failure list from Sigill is attached as `failures`. The envelope was
    NOT sealed; the caller decides whether to retry, fall back, or surface to a human.
    """

    def __init__(self, message: str, failures: list[dict] | None = None, attempts: int = 0):
        super().__init__(message)
        self.failures = failures or []
        self.attempts = attempts
