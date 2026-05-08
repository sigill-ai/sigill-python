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
