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
from sigill_sdk._client import (
    SigillClient,
    ISigillAiEvidenceClient,
    PadesSealResult,
    PreparedPadesPdf,
    EvidenceRecord,
    PublicLookupResult,
)
from sigill_sdk._verify import (
    AiEvidenceVerificationResult,
    CadesVerifyResult,
    JadesVerifyResult,
    PqcVerifyInfo,
    VerificationIssue,
    VerificationIssueKind,
)
from sigill_sdk._errors import (
    SigillError,
    CanonicalizationFailed,
    HashMismatch,
    InvalidProof,
    PdfUnsupported,
    TimestampUnavailable,
    InlineContentWarning,
)
from sigill_sdk._canonical import canonicalize, compute_envelope_hash
from sigill_sdk._evidence_v2 import (
    EvidenceV2Artifact,
    EvidenceV2ObjectVerdict,
    EvidenceV2Payload,
    EvidenceV2VerificationResult,
)
from sigill_sdk._references import (
    LEGACY_DIAGNOSTIC as LEGACY_ENVELOPE_REFERENCE_DIAGNOSTIC,
    LEGACY_REFERENCE as LEGACY_ENVELOPE_REFERENCE,
    LOCATOR_REFERENCE as LOCATOR_ENVELOPE_REFERENCE,
    EnvelopeReferenceForm,
    classify as classify_envelope_reference,
    is_production_reference,
    new_object_uri,
)
from sigill_sdk._sign_objects import (
    ObjectsVerificationResult,
    SignedObjectDigest,
    SignedObjectVerdict,
    SignHashesResult,
)
from sigill_sdk._agent_profiles import (
    signature_sha256,
    signer_of,
)
from sigill_sdk._agent_types import (
    AgentAuthorization,
    AgentConfiguration,
    AgentControlSet,
    AgentDefinition,
    AgentDelegation,
    AgentIndexResult,
    AgentRunActor,
    AgentRunArtifact,
    AgentRunBundle,
    AgentRunBundleFormatError,
    AgentRunObject,
    AgentTimestampPolicy,
    AttestedEvaluationRequest,
    ControlEvaluationRequest,
    ControlResult,
    EvaluationReference,
    ModelCall,
    ModelInfo,
    ModelUsage,
    PER_EVENT,
    PolicyEvaluationRequest,
    PolicyRuleResult,
    PreparedEvaluation,
    QualifiedArtifacts,
    VendorRef,
)
from sigill_sdk._model_calls import AsyncModelCallTransport, ModelCallTransport
from sigill_sdk._agent_policy import (
    POLICY_CONTROL_SET_CONTENT_TYPE,
    AgentPolicy,
    PolicyDigests,
    PolicyFacts,
)
from sigill_sdk._agent_run import (
    AgentRun,
    AgentRunCallbackError,
    ControlEvaluation,
    seal_control_evaluation,
)
from sigill_sdk._agent_verify import (
    AgentControlVerdict,
    AgentEvaluationVerdict,
    AgentObjectVerdict,
    AgentRunTimestampSummary,
    AgentRunVerificationResult,
    AgentStepVerdict,
    BlindObjectsVerdict,
    SignatureTimestampInfo,
    SignerCertificateInfo,
    bundle_fingerprint,
    remote_verifier,
    verify_agent_run,
)
from sigill_sdk._agent_tree import (
    TREE_SCOPE,
    AgentRunTreeBundle,
    AgentRunTreeEdge,
    AgentRunTreeFinding,
    AgentRunTreeOptions,
    AgentRunTreeRun,
    AgentRunTreeVerificationResult,
    verify_agent_run_tree,
)
from importlib.metadata import version as _meta_version, PackageNotFoundError as _PNF

try:
    __version__ = _meta_version("sigill-sdk")
except _PNF:
    __version__ = "0.0.0.dev"
__all__ = [
    "EnvelopeReferenceForm",
    "LEGACY_ENVELOPE_REFERENCE",
    "LEGACY_ENVELOPE_REFERENCE_DIAGNOSTIC",
    "LOCATOR_ENVELOPE_REFERENCE",
    "classify_envelope_reference",
    "is_production_reference",
    "new_object_uri",
    "SigillClient",
    "ISigillAiEvidenceClient",
    "EnvelopeBuilder",
    "AiEvidenceEnvelopeInput",
    "SealedAiEvidenceEnvelope",
    "PayloadRef",
    "ContentHash",
    "AiEvidenceVerificationResult",
    "CadesVerifyResult",
    "JadesVerifyResult",
    "PadesSealResult",
    "PreparedPadesPdf",
    "EvidenceRecord",
    "PublicLookupResult",
    "PqcVerifyInfo",
    "VerificationIssue",
    "VerificationIssueKind",
    "SigillError",
    "CanonicalizationFailed",
    "HashMismatch",
    "InvalidProof",
    "PdfUnsupported",
    "TimestampUnavailable",
    "InlineContentWarning",
    "EvidenceV2Artifact",
    "EvidenceV2ObjectVerdict",
    "EvidenceV2Payload",
    "EvidenceV2VerificationResult",
    "ObjectsVerificationResult",
    "SignedObjectDigest",
    "SignedObjectVerdict",
    "SignHashesResult",
    "canonicalize",
    "compute_envelope_hash",
    "AgentAuthorization",
    "AgentConfiguration",
    "AgentControlSet",
    "AgentControlVerdict",
    "AgentDefinition",
    "AgentDelegation",
    "AgentEvaluationVerdict",
    "AgentIndexResult",
    "AgentObjectVerdict",
    "AgentPolicy",
    "AgentRun",
    "AgentRunActor",
    "AgentRunArtifact",
    "AgentRunBundle",
    "AgentRunBundleFormatError",
    "AgentRunCallbackError",
    "AgentRunObject",
    "AgentRunTimestampSummary",
    "AgentRunTreeBundle",
    "AgentRunTreeEdge",
    "AgentRunTreeFinding",
    "AgentRunTreeOptions",
    "AgentRunTreeRun",
    "AgentRunTreeVerificationResult",
    "AgentRunVerificationResult",
    "AgentStepVerdict",
    "AsyncModelCallTransport",
    "ModelCall",
    "ModelCallTransport",
    "ModelInfo",
    "ModelUsage",
    "VendorRef",
    "AgentTimestampPolicy",
    "AttestedEvaluationRequest",
    "BlindObjectsVerdict",
    "ControlEvaluation",
    "ControlEvaluationRequest",
    "ControlResult",
    "EvaluationReference",
    "PER_EVENT",
    "POLICY_CONTROL_SET_CONTENT_TYPE",
    "PolicyDigests",
    "PolicyEvaluationRequest",
    "PolicyFacts",
    "PolicyRuleResult",
    "PreparedEvaluation",
    "QualifiedArtifacts",
    "SignatureTimestampInfo",
    "SignerCertificateInfo",
    "TREE_SCOPE",
    "bundle_fingerprint",
    "remote_verifier",
    "seal_control_evaluation",
    "signature_sha256",
    "signer_of",
    "verify_agent_run",
    "verify_agent_run_tree",
]
