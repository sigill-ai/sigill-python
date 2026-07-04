"""Structured verification result.

verify() does NOT raise on the first issue — it walks the envelope and collects every
problem it finds, so an audit UI can render a complete report. Exceptions are reserved
for *unexpected* failures (the caller passed something that isn't an envelope, the SDK
itself misbehaved).

The four documented issue kinds correspond 1:1 to spec §7's error model.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class VerificationIssueKind(str, Enum):
    CANONICALIZATION_FAILED = "canonicalization_failed"
    HASH_MISMATCH = "hash_mismatch"
    INVALID_PROOF = "invalid_proof"
    TIMESTAMP_UNAVAILABLE = "timestamp_unavailable"


@dataclass(frozen=True)
class VerificationIssue:
    """A single problem encountered while verifying an envelope."""

    kind: VerificationIssueKind
    target: str
    """Where the problem is. For envelope hash issues, 'envelope'. For payload issues,
    the payloadRef.ref value. For proof issues, 'proofs[i]' (zero-indexed)."""

    message: str
    """Human-readable description suitable for inclusion in an audit log."""

    expected: str | None = None
    """If applicable, the expected value (e.g. registered hash hex)."""

    actual: str | None = None
    """If applicable, the actual / computed value."""


@dataclass
class AiEvidenceVerificationResult:
    """The structured result of verify()."""

    is_valid: bool
    """True iff there are no issues. A short-circuit for the common case."""

    envelope_hash_hex: str | None = None
    """The hex digest computed by the verifier. None if canonicalization failed."""

    issues: list[VerificationIssue] = field(default_factory=list)
    """Every issue found, in order encountered."""

    timestamps: list[dict] = field(default_factory=list)
    """One entry per successfully-parsed proof. Shape:
    {tsa_name, gen_time, serial, qualified, hash_alg, hashed_message_hex}."""

    def __bool__(self) -> bool:  # convenience: `if result: ...`
        return self.is_valid

    def add_issue(self, issue: VerificationIssue) -> None:
        self.issues.append(issue)
        self.is_valid = False


@dataclass(frozen=True)
class PqcVerifyInfo:
    """Post-quantum dimension of a CAdES verification (the ML-DSA-87 SignerInfo)."""

    present: bool
    """An ML-DSA signer is present in the CMS."""

    valid: bool
    """Convenience roll-up: signature verified AND content bound."""

    signature_valid: bool
    """The ML-DSA signature over its signedAttrs verified against the signer cert."""

    content_bound: str
    """'yes' | 'no' | 'not_checked' (the last when no SHA-512 digest was supplied)."""

    trusted: str
    """'yes' | 'no' | 'not_evaluated' (self-signed platform certs are 'not_evaluated')."""

    algorithm: str
    """Signature algorithm, e.g. 'ml-dsa-87'."""


@dataclass(frozen=True)
class CadesVerifyResult:
    """Result of verify_cades() — server-side CAdES signature verification.

    ``is_valid`` reflects the classical signer only — the legal instrument. Any
    post-quantum signer is reported separately via ``post_quantum`` and is
    additive (quantum-resistant protection, not a qualified/legal upgrade).
    """

    is_valid: bool
    """True iff hash_match, signature_valid, and no error from the server."""

    hash_match: bool
    """The .p7s messageDigest attribute matches SHA-256(original document)."""

    signature_valid: bool
    """The RSA/ECDSA signature over signedAttrs verified against the signer cert."""

    signer: str | None
    """Certificate subject DN of the signing certificate."""

    trust: str | None
    """Chain trust status: 'trusted_chain', 'self_signed', 'dev_ca', etc."""

    tsa_name: str | None
    """Name of the timestamping authority that sealed the signature, if present."""

    gen_time: str | None
    """ISO-8601 timestamp from the embedded RFC 3161 token, if present."""

    qualified: bool
    """True if the qualification source is not 'none' (LOTL or QC statement)."""

    error: str | None
    """Server-reported error message, or None on success."""

    warnings: list[str]
    """Non-fatal warnings from the server verifier."""

    post_quantum: PqcVerifyInfo | None = None
    """Non-null when the seal carries an ML-DSA-87 signer; otherwise None."""
