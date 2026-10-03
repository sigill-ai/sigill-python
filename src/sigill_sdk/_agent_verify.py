# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Agent Evidence Profiles v1 — verify a controlled agent run (common rules §8).

The envelopes are read locally; each artifact's signature is checked over
digests only, by the supplied :data:`BlindObjectsVerifier`. Mirrors the .NET
SDK one-to-one: same checks, same findings, same verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Callable, Mapping, Optional, Sequence

from sigill_sdk._agent_profiles import (
    BUNDLE_FORMAT,
    CONTROL_ARTIFACT_CONTENT_TYPE,
    CONTROL_ARTIFACT_SCHEMA,
    CONTROL_EVALUATION_CONTENT_TYPE,
    CONTROL_EVALUATION_SCHEMA,
    EXECUTION_EVIDENCE_CONTENT_TYPE,
    EXECUTION_EVIDENCE_SCHEMA,
    _content_type_problem,
    _format_time,
    _int,
    _is_i_json,
    _is_i_json_strict,
    _obj,
    _str,
    _TimestampCoverage,
    signature_sha256,
    signer_of,
)
from sigill_sdk._agent_types import (
    AgentRunArtifact,
    AgentRunBundle,
    AgentTimestampPolicy,
    ControlResult,
)
from sigill_sdk._canonical import canonicalize, hash_bytes
from sigill_sdk._errors import SigillError
from sigill_sdk._schema import _json_equal, parse_date_time, validate_profile
from sigill_sdk._sign_objects import ENVELOPE_URI

SCOPE = (
    "run_finalized means: the control basis was sealed before the first event, all recorded events are unchanged "
    "since run_end was timestamped and are in the recorded order, and the run was closed under one signer; a Control "
    "Evaluation's result is the named verifier's claim against the pre-sealed control set. It does not establish "
    "that every event was captured, that producer-claimed event times are true, that no other run took place, that "
    "the verifier measured correctly, or — unless expected signers were given — who produced the run. Events without "
    "a timestamp could have been rewritten by anyone able to seal with the run's certificate until run_end was "
    "timestamped."
)
"""What a verdict does and does not establish. Show it next to the verdict."""

_MAX_MISSING_LISTED = 64
_SEAL_TIME_ALLOWANCE = timedelta(seconds=6)  # 5 s skew + up to 1 s TSA accuracy
_TRUSTED_CHAINS = ("trusted_chain", "platform")
_DISPOSITIONS = ("completed", "failed", "aborted")


# ── The blind signature verdict ─────────────────────────────────────────────

@dataclass(frozen=True)
class SignatureTimestampInfo:
    """The signature timestamp of one artifact."""

    gen_time: Optional[str]
    tsa_name: Optional[str]
    signature_valid: bool


@dataclass(frozen=True)
class SignerCertificateInfo:
    """The signer certificate of one artifact. ``trust`` is the signature
    service's chain verdict: trusted_chain | platform | valid_untrusted_chain | self_signed | …"""

    subject: str
    issuer: str
    not_after: str
    trust: str


@dataclass(frozen=True)
class BlindObjectsVerdict:
    """The cryptographic verdict over one multi-object signature."""

    signature_valid: bool
    complete: bool
    objects: list[tuple[str, bool]]
    """(uri, hash_match) per signed URI, including ``urn:sigill:envelope``."""
    missing: list[str] = field(default_factory=list)
    unreferenced: list[str] = field(default_factory=list)
    timestamp: Optional[SignatureTimestampInfo] = None
    certificate: Optional[SignerCertificateInfo] = None
    error: Optional[str] = None
    pqc: str = "absent"
    """The hybrid (ML-DSA) dimension: absent | verified | failed | not_checked."""

    @classmethod
    def from_verify_objects_response(cls, response: Mapping[str, Any]) -> "BlindObjectsVerdict":
        """Maps the ``objects`` member of a ``/seal/verify-objects`` response."""
        r = _obj(response.get("objects")) or {}
        underlying = _obj(r.get("underlying")) or {}
        ts = cert = None
        if isinstance(underlying.get("timestamp"), dict):
            t = underlying["timestamp"]
            ts = SignatureTimestampInfo(_str(t.get("genTime")), _str(t.get("tsaName")), t.get("signatureValid") is True)
        if isinstance(underlying.get("certificate"), dict):
            c = underlying["certificate"]
            cert = SignerCertificateInfo(_str(c.get("subject")) or "", _str(c.get("issuer")) or "",
                                         _str(c.get("notAfter")) or "",
                                         # the service's chain verdict; older services only report isSelfSigned
                                         _str(c.get("trust"))
                                         or ("self_signed" if c.get("isSelfSigned") is True else "issuer_distinct"))
        return cls(
            signature_valid=r.get("signatureValid") is True,
            complete=r.get("complete") is True,
            objects=[(_str(o.get("par")) or "", o.get("hashMatch") is True)
                     for o in r.get("objects") or [] if isinstance(o, dict)],
            missing=[m for m in r.get("missing") or [] if isinstance(m, str)],
            unreferenced=[u for u in r.get("unreferenced") or [] if isinstance(u, str)],
            timestamp=ts,
            certificate=cert,
            error=_str(r.get("error")),
            pqc=_str(r.get("pqc")) or "absent",
        )


BlindObjectsVerifier = Callable[[dict, Mapping[str, str]], BlindObjectsVerdict]
"""Checks one artifact's signature over the supplied digests (v2 §7). Only
digests are passed; the default is the blind ``POST /seal/verify-objects``
endpoint (:func:`remote_verifier`)."""


def remote_verifier(client: Any) -> BlindObjectsVerifier:
    """The blind ``POST /seal/verify-objects`` endpoint as a :data:`BlindObjectsVerifier`.

    It verifies each signature against ``x5c[0]`` of the protected header that
    names the signer, which §3 requires of any verifier plugged in here. Only
    SHA-256 digests are sent, so a hybrid (ML-DSA) seal reports ``pqc:
    not_checked`` and fails ``signatures``; the recorder never requests one."""
    def verify(signature: dict, digests: Mapping[str, str]) -> BlindObjectsVerdict:
        return BlindObjectsVerdict.from_verify_objects_response(client.verify_object_hashes(signature, digests).raw)
    return verify


# ── Results ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AgentObjectVerdict:
    """Per-object outcome within one artifact."""

    uri: str
    role: str
    content_type: Optional[str]
    size_bytes: Optional[int]
    hash_hex: str
    signed: bool
    retained: bool
    hash_match: bool


@dataclass(frozen=True)
class AgentStepVerdict:
    """Per-event outcome."""

    seq: int
    step_type: str
    evidence_id: Optional[str] = None
    prev_signature_sha256: Optional[str] = None
    signature_sha256: Optional[str] = None
    actor_id: Optional[str] = None
    actor_version: Optional[str] = None
    event_time: Optional[str] = None
    consequential: bool = False
    timestamp_declared: Optional[str] = None
    signature_valid: bool = False
    signer: Optional[str] = None
    timestamp_required: bool = False
    timestamp_present: bool = False
    timestamp_valid: Optional[bool] = None
    timestamp_gen_time: Optional[str] = None
    tsa_name: Optional[str] = None
    objects_complete: bool = False
    chain_link_valid: bool = False
    error: Optional[str] = None
    certificate: Optional[SignerCertificateInfo] = None
    objects: list[AgentObjectVerdict] = field(default_factory=list)


@dataclass(frozen=True)
class AgentRunTimestampSummary:
    """Timestamp coverage of the run (common rules §4)."""

    artifacts: int
    required: int
    present: int
    valid: int
    anchor_valid: bool
    policy: Optional[AgentTimestampPolicy]
    policy_signed: bool


@dataclass(frozen=True)
class AgentControlVerdict:
    """Outcome of the Control Artifact check."""

    present: bool = False
    evidence_id: Optional[str] = None
    signature_sha256: Optional[str] = None
    signature_valid: bool = False
    objects_complete: bool = False
    timestamp_valid: bool = False
    timestamp_gen_time: Optional[str] = None
    signer: Optional[str] = None
    well_formed: bool = False
    bound: bool = False
    """The first event's ``binds.controlArtifactSignatureSha256`` is this artifact's ``signatureSha256``."""
    control_set_id: Optional[str] = None
    control_set_version: Optional[str] = None
    agent_id: Optional[str] = None
    agent_version: Optional[str] = None
    certificate: Optional[SignerCertificateInfo] = None
    objects: list[AgentObjectVerdict] = field(default_factory=list)


@dataclass(frozen=True)
class AgentEvaluationVerdict:
    """One Control Evaluation, reported on its own and never merged into the
    run verdict (common rules §8). ``overall`` and ``controls`` are the
    verifier's claims, unchanged: the SDK never evaluates controls."""

    evidence_id: Optional[str] = None
    verifier_id: Optional[str] = None
    verifier_version: Optional[str] = None
    subject_bound: bool = False
    """Its ``subject`` names this run's ``run_end`` and Control Artifact."""
    control_set_digest_matches: bool = False
    """Same control set (id, version, URI and digest) as the Control Artifact."""
    baseline_digest_matches: Optional[bool] = None
    """Same baseline (URI and digest) as the Control Artifact; None unless the evaluation carries one."""
    signature_valid: bool = False
    """Valid signature with an established signer (and an expected one, when given)."""
    timestamp_valid: bool = False
    timestamp_gen_time: Optional[str] = None
    objects_complete: bool = False
    well_formed: bool = False
    signer: Optional[str] = None
    certificate: Optional[SignerCertificateInfo] = None
    overall: Optional[str] = None
    controls: list[ControlResult] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AgentRunVerificationResult:
    """The run-level result (common rules §8)."""

    verdict: str
    """run_finalized | run_open | run_invalid."""
    checks: dict[str, str]
    """The nine checks (correlation, sequence, chain, envelope, signatures, timestamps, objects, finalization,
    control): ok | warn | bad."""
    binding: str
    """bound | run_only | control_only | unbound."""
    findings: list[str]
    warnings: list[str]
    disposition: Optional[str]
    agent_id: Optional[str]
    agent_version: Optional[str]
    correlation_id: Optional[str]
    missing_seqs: list[int]
    timestamps: AgentRunTimestampSummary
    certificates: list[SignerCertificateInfo]
    control: AgentControlVerdict
    artifacts: list[AgentStepVerdict]
    evaluations: list[AgentEvaluationVerdict]
    fingerprint: Optional[str]
    """Deterministic fingerprint of everything the verdict depends on (§8.2); None when not valid I-JSON."""
    signer: Optional[str] = None
    """The run's signer: ``x5t#S256`` of its signing certificate (§3)."""
    control_sealed_before_run: Optional[bool] = None
    """Seal time, defence in depth (§8): the Control Artifact's timestamp is not later than run_start's."""
    event_times_plausible: Optional[bool] = None
    """No timestamped event claims an eventTime later than its own seal time (with allowance)."""

    @property
    def scope(self) -> str:
        return SCOPE

    @property
    def is_finalized(self) -> bool:
        return self.verdict == "run_finalized"


# ── Typed signed artifact ───────────────────────────────────────────────────

@dataclass
class _SignedObject:
    uri: str
    role: str
    content_type: Optional[str]
    size_bytes: Optional[int]


@dataclass
class _Signed:
    env: dict
    jws: dict
    conformance: list[str]
    """Schema and §1 problems. They fail ``envelope``, never ``signatures``."""
    evidence_id: Optional[str] = None
    correlation_id: Optional[str] = None
    actor_id: Optional[str] = None
    actor_version: Optional[str] = None
    declared_prev: Optional[str] = None
    binds: Optional[str] = None
    timestamp_declared: Optional[str] = None
    seq: Optional[int] = None
    step_type: str = "?"
    event_time: Optional[datetime] = None
    consequential: bool = False
    objects: list[_SignedObject] = field(default_factory=list)


def _parse_signed(envelope: dict, signature: dict, schema_name: str) -> tuple[Optional[_Signed], Optional[str]]:
    if not _is_i_json_strict(envelope) or not _is_i_json_strict(signature):
        return None, "envelope or signature is not valid I-JSON"
    sa = _Signed(envelope, signature, validate_profile(envelope, schema_name))
    sa.evidence_id = _str(envelope.get("evidenceId"))
    sa.correlation_id = _str((_obj(envelope.get("activity")) or {}).get("correlationId"))
    actor = _obj(envelope.get("actor")) or {}
    sa.actor_id = _str(actor.get("id"))
    sa.actor_version = _str(actor.get("version"))
    chain = _obj(envelope.get("chain"))
    if chain is not None:
        seq = _int(chain.get("seq"))
        if seq is not None and seq >= 0:
            sa.seq = seq
        sa.declared_prev = _str(chain.get("prevSignatureSha256"))
    step = _obj(envelope.get("step"))
    if step is not None:
        sa.step_type = _str(step.get("type")) or "?"
        sa.event_time = parse_date_time(step.get("eventTime"))
        sa.consequential = step.get("consequential") is True
        sa.timestamp_declared = _str(step.get("timestamp"))
    sa.binds = _str((_obj(envelope.get("binds")) or {}).get("controlArtifactSignatureSha256"))
    seen: set[str] = set()
    objs = envelope.get("objects")
    for o in objs if isinstance(objs, list) else []:
        if not isinstance(o, dict) or not isinstance(o.get("uri"), str):
            continue
        uri = o["uri"]
        if uri == ENVELOPE_URI:
            sa.conformance.append("objects[] uses the reserved envelope URI")
            continue
        if uri in seen:
            sa.conformance.append(f"objects[] lists '{uri}' more than once")
            continue
        seen.add(uri)
        sa.objects.append(_SignedObject(uri, _str(o.get("role")) or "?", _str(o.get("contentType")),
                                        _int(o.get("sizeBytes"))))
    return sa, None


# ── One artifact ────────────────────────────────────────────────────────────

@dataclass
class _ArtifactCheck:
    signature_valid: bool = False
    objects_complete: bool = False
    timestamp_present: bool = False
    timestamp_valid: Optional[bool] = None
    gen_time: Optional[str] = None
    tsa_name: Optional[str] = None
    error: Optional[str] = None
    certificate: Optional[SignerCertificateInfo] = None
    objects: list[AgentObjectVerdict] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    @property
    def all_retained(self) -> bool:
        return all(o.retained for o in self.objects if o.signed)

    @property
    def timestamp_ok(self) -> bool:
        return self.timestamp_present and self.timestamp_valid is True


def _check_artifact(sa: _Signed, art: AgentRunArtifact, payloads: Mapping[str, bytes],
                    blind: BlindObjectsVerifier, label: str) -> _ArtifactCheck:
    c = _ArtifactCheck()
    digests: dict[str, str] = {}
    obj_ok = True
    signed_uris = {o.uri for o in sa.objects}
    for so in sa.objects:
        supplied = art.object_digests.get(so.uri)
        if so.uri in payloads:
            hex_ = hash_bytes(payloads[so.uri])
            if supplied is not None and supplied != hex_:
                c.findings.append(f"{label}: supplied payload for '{so.uri}' does not match its supplied digest.")
                obj_ok = False
            digests[so.uri] = hex_
            c.objects.append(AgentObjectVerdict(so.uri, so.role, so.content_type, so.size_bytes, hex_, True, True, True))
        elif supplied is not None:
            digests[so.uri] = supplied
            c.objects.append(AgentObjectVerdict(so.uri, so.role, so.content_type, so.size_bytes, supplied, True, False,
                                                True))
        else:
            c.objects.append(AgentObjectVerdict(so.uri, so.role, so.content_type, so.size_bytes, "", True, False, False))
            c.findings.append(f"{label}: signed object '{so.uri}' ({so.role}) was not supplied (no digest, no payload).")
            obj_ok = False
    for uri, hex_ in art.object_digests.items():
        if uri in signed_uris:
            continue
        c.objects.append(AgentObjectVerdict(uri, "?", None, None, hex_, False, uri in payloads, False))
        c.findings.append(f"{label}: supplied object '{uri}' is not covered by the signature (unsigned data in the record).")
        obj_ok = False
    try:
        digests[ENVELOPE_URI] = hash_bytes(canonicalize(sa.env))
        r = blind(sa.jws, digests)
        if r is None:
            raise SigillError("blind verifier returned no result")
        c.signature_valid = r.signature_valid
        if r.pqc not in ("absent", "verified"):
            c.signature_valid = False
            c.findings.append(f"{label}: the hybrid seal's ML-DSA commitment is '{r.pqc}'.")
        c.error = r.error
        c.objects_complete = r.complete and not r.unreferenced and not r.missing and obj_ok
        for m in r.missing:
            c.findings.append(f"{label}: the signature covers '{m}' but the envelope does not list it.")
        for u in r.unreferenced:
            c.findings.append(f"{label}: the envelope lists '{u}' but the signature does not cover it.")
        matches: dict[str, bool] = {}
        for uri, hm in r.objects:
            matches.setdefault(uri, hm)
        for i, o in enumerate(c.objects):
            if o.signed and matches.get(o.uri) is False:
                c.objects[i] = replace(o, hash_match=False)
                c.findings.append(f"{label}: object '{o.uri}' ({o.role}) no longer matches its signed digest.")
        if matches.get(ENVELOPE_URI) is not True:
            c.objects_complete = False
            c.findings.append(f"{label}: the signature does not cover this envelope.")
        if r.timestamp is not None:
            c.timestamp_present = True
            c.timestamp_valid = r.timestamp.signature_valid
            c.gen_time = r.timestamp.gen_time
            c.tsa_name = r.timestamp.tsa_name
        c.certificate = r.certificate
        if not c.signature_valid:
            c.findings.append(f"{label}: signature invalid{' — ' + r.error if r.error else ''}.")
    except Exception as ex:  # noqa: BLE001 — a verifier failure is a finding, never a crash
        c.error = str(ex)
        c.findings.append(f"{label}: verification failed — {ex}")
    return c


def _time(s: Optional[str]) -> Optional[datetime]:
    return parse_date_time(s) if isinstance(s, str) else None


# ── The run ─────────────────────────────────────────────────────────────────

def verify_agent_run(bundle: AgentRunBundle, verifier: BlindObjectsVerifier, *,
                     expected_signers: Optional[Sequence[str]] = None,
                     expected_evaluation_signers: Optional[Sequence[str]] = None) -> AgentRunVerificationResult:
    """Verifies a run bundle (common rules §8). Never raises for malformed
    evidence: that is an invalid verdict.

    :param expected_signers: ``x5t#S256`` thumbprints of the certificates the
        producer seals with (§3); when given, a run signed by anyone else fails.
    :param expected_evaluation_signers: the same for Control Evaluations.
    """
    if bundle is None:
        raise ValueError("bundle is required")
    if verifier is None:
        raise ValueError("verifier is required")

    findings: list[str] = []
    warnings: list[str] = []
    checks: dict[str, str] = {}

    ctl: Optional[_Signed] = None
    ctl_error: Optional[str] = None
    if bundle.control_artifact is not None:
        ctl, ctl_error = _parse_signed(bundle.control_artifact.envelope, bundle.control_artifact.signature,
                                       CONTROL_ARTIFACT_SCHEMA)

    parsed = []
    for i, a in enumerate(bundle.artifacts):
        sa, error = _parse_signed(a.envelope, a.signature, EXECUTION_EVIDENCE_SCHEMA)
        parsed.append((a, i, sa, error))
    big = 2 ** 31 - 1
    arts = sorted(parsed, key=lambda p: (p[2].seq if p[2] is not None and p[2].seq is not None else big, p[1]))
    good = [p[2] for p in arts if p[2] is not None]
    starts = [s for s in good if s.step_type == "run_start"]
    # The reference event: run_start, else the first event. Binding, signer and actor are judged against it.
    reference = starts[0] if len(starts) == 1 else (good[0] if good else None)

    def label_of(s: _Signed) -> str:
        return f"seq {s.seq}" if s.seq is not None else "an event without seq"
    reference_label = "" if reference is None else "run_start" if reference.step_type == "run_start" \
        else label_of(reference)

    # ── correlation: the run identifier comes only from the signed envelopes, never from the bundle.
    correlation = reference.correlation_id if reference is not None and reference.correlation_id else \
        next((s.correlation_id for s in good if s.correlation_id), None)
    corr_ok = True
    for s in good:
        if not s.correlation_id:
            corr_ok = False
            findings.append(f"{label_of(s)}: no signed correlationId (activity.correlationId).")
    if any(s.correlation_id and s.correlation_id != correlation for s in good):
        corr_ok = False
        findings.append("An event's signed correlationId does not belong to this run (cross-run splice).")
    checks["correlation"] = "ok" if corr_ok else "bad"

    # ── sequence
    missing: list[int] = []
    seq_ok = True
    expected = 0
    for _, _, sa, _ in arts:
        if sa is None:
            seq_ok = False
            continue
        if sa.seq is None:
            seq_ok = False
            findings.append(f"{sa.step_type}: no valid chain.seq in the signed envelope.")
            continue
        sq = sa.seq
        if sq < expected:
            seq_ok = False
            findings.append(f"Duplicate signed seq {sq}.")
            continue
        while expected < sq and len(missing) < _MAX_MISSING_LISTED:
            missing.append(expected)
            expected += 1
        if expected < sq:
            seq_ok = False
            findings.append(f"Sequence gap too large to list (signed seq jumps to {sq}).")
        expected = sq + 1
    if missing:
        seq_ok = False
        findings.append(f"Sequence gap: no artifact for seq {', '.join(str(m) for m in missing)} (deleted or withheld).")
    if arts:
        if not starts:
            seq_ok = False
            findings.append("The run has no run_start.")
        elif len(starts) > 1:
            seq_ok = False
            findings.append(f"More than one run_start (seq {', '.join(_n(s.seq) for s in starts)}).")
        elif starts[0].seq != 0:
            seq_ok = False
            findings.append("run_start is not at seq 0.")
    checks["sequence"] = "ok" if seq_ok else "bad"

    # ── the signed timestamp policy, from the Control Artifact (§4)
    policy: Optional[AgentTimestampPolicy] = None
    policy_ok = True
    policy_signed = False
    if ctl is not None:
        if "timestampPolicy" not in ctl.env:
            policy = AgentTimestampPolicy()
            warnings.append("The Control Artifact signs no timestampPolicy: the run is judged under the default policy.")
        else:
            signed = AgentTimestampPolicy._from_json(ctl.env["timestampPolicy"])
            if signed is not None:
                policy = signed
                policy_signed = True
            else:
                policy_ok = False
                policy = AgentTimestampPolicy()
                findings.append("control artifact: the signed timestampPolicy is malformed.")

    # ── one signer per run (§3): the reference event's, else the first that has one, else the Control Artifact's
    run_signer = next((t for t in (signer_of(s.jws)[0] for s in ([reference] if reference else []) + good)
                       if t is not None), None)
    if run_signer is None and ctl is not None:
        run_signer = signer_of(ctl.jws)[0]
    chain_ok = env_ok = sig_ok = ts_ok = obj_ok = True
    obj_warn = False
    later_binds_ok = True
    if run_signer is not None and expected_signers is not None and run_signer not in expected_signers:
        sig_ok = False
        findings.append(f"The run's signer (x5t#S256 {run_signer}) is not among the expected signers.")

    ts_required = ts_present = ts_valid = 0
    anchor_valid = False
    plausible: Optional[bool] = None
    certificates: list[SignerCertificateInfo] = []

    def add_certificate(cert: Optional[SignerCertificateInfo]) -> None:
        if cert is not None and not any(x.subject == cert.subject and x.issuer == cert.issuer for x in certificates):
            certificates.append(cert)
    verdicts: list[AgentStepVerdict] = []
    prev_sig_hash: Optional[str] = None
    prev_seq = -1
    coverage = _TimestampCoverage(policy)
    start_gen_time: Optional[str] = None

    for art, index, sa, error in arts:
        if sa is None:
            env_ok = sig_ok = obj_ok = chain_ok = False
            findings.append(f"artifacts[{index}]: {error}")
            verdicts.append(AgentStepVerdict(seq=-1, step_type="?", error=error))
            prev_sig_hash = None
            continue
        seq = sa.seq if sa.seq is not None else -1
        label = label_of(sa)
        if sa.conformance:
            env_ok = False
            findings.extend(f"{label}: {e}." for e in sa.conformance)
        if reference is not None and (sa.actor_id != reference.actor_id or sa.actor_version != reference.actor_version):
            env_ok = False
            findings.append(f"{label}: signed actor/version ({_n(sa.actor_id)}, {_n(sa.actor_version)}) differs from "
                            f"{reference_label} ({_n(reference.actor_id)}, {_n(reference.actor_version)}).")
        signer, signer_problem = signer_of(sa.jws)
        if signer_problem is not None:
            sig_ok = False
            findings.append(f"{label}: {signer_problem}.")
        elif signer != run_signer:
            sig_ok = False
            findings.append(f"{label}: signed by a different certificate than the run (x5t#S256 {signer}).")
        cty_problem = _content_type_problem(sa.jws, EXECUTION_EVIDENCE_CONTENT_TYPE)
        if cty_problem is not None:
            sig_ok = False
            findings.append(f"{label}: {cty_problem}.")
        if sa is not reference and sa.binds is not None and sa.binds != (reference.binds if reference else None):
            later_binds_ok = False
            findings.append(f"{label} binds another control artifact than {reference_label}.")

        if seq == 0:
            link_ok = sa.declared_prev is None
            if not link_ok:
                findings.append("seq 0 must not carry prevSignatureSha256.")
        elif seq < 0 or prev_seq != seq - 1 or prev_sig_hash is None:
            link_ok = False
        else:
            link_ok = sa.declared_prev == prev_sig_hash
            if not link_ok:
                findings.append(f"{label}: prevSignatureSha256 does not match the signature of seq {prev_seq}.")
        if not link_ok:
            chain_ok = False

        required = coverage.next(seq, sa.step_type, sa.consequential, sa.timestamp_declared == "required",
                                 sa.event_time)
        if required:
            ts_required += 1

        c = _check_artifact(sa, art, bundle.payloads, verifier, label)
        findings.extend(c.findings)
        if not c.all_retained:
            obj_warn = True
        if not c.signature_valid:
            sig_ok = False
        if not c.objects_complete:
            obj_ok = False
        if c.timestamp_present:
            ts_present += 1
            if c.timestamp_valid is True:
                ts_valid += 1
        if required and not c.timestamp_ok:
            ts_ok = False
            findings.append(f"{label} ({sa.step_type}): a timestamp is required here by the signed policy and it is "
                            f"{'invalid' if c.timestamp_present else 'missing'}.")
        elif c.timestamp_present and c.timestamp_valid is False:
            ts_ok = False
            findings.append(f"{label}: timestamp invalid.")
        if sa.step_type == "run_end" and c.timestamp_ok and c.signature_valid:
            anchor_valid = True
        sealed_at = _time(c.gen_time) if c.timestamp_ok else None
        if sealed_at is not None and sa.event_time is not None:
            ok = sa.event_time <= sealed_at + _SEAL_TIME_ALLOWANCE
            plausible = (True if plausible is None else plausible) and ok
            if not ok:
                warnings.append(f"{label}: eventTime {_format_time(sa.event_time)} is later than its own seal time "
                                f"{c.gen_time}.")
        if sa is reference and sa.step_type == "run_start" and c.timestamp_ok:
            start_gen_time = c.gen_time
        add_certificate(c.certificate)

        verdicts.append(AgentStepVerdict(
            seq=seq, step_type=sa.step_type, evidence_id=sa.evidence_id, prev_signature_sha256=sa.declared_prev,
            signature_sha256=signature_sha256(sa.jws), actor_id=sa.actor_id, actor_version=sa.actor_version,
            event_time=_format_time(sa.event_time) if sa.event_time else None, consequential=sa.consequential,
            timestamp_declared=sa.timestamp_declared, signature_valid=c.signature_valid, signer=signer,
            timestamp_required=required, timestamp_present=c.timestamp_present, timestamp_valid=c.timestamp_valid,
            timestamp_gen_time=c.gen_time, tsa_name=c.tsa_name, objects_complete=c.objects_complete,
            chain_link_valid=link_ok, error=c.error, certificate=c.certificate, objects=c.objects))
        prev_sig_hash = signature_sha256(sa.jws)
        prev_seq = seq

    # ── the Control Artifact
    control_ok = later_binds_ok
    ctl_check: Optional[_ArtifactCheck] = None
    ctl_sig = signature_sha256(bundle.control_artifact.signature) if bundle.control_artifact is not None else None
    if bundle.control_artifact is None:
        # run_start must bind a Control Artifact, so a bundle without one is incomplete. Leaving it out must
        # not turn an invalid run into a finalized one (it may hide a stricter policy or a broken basis).
        binding = "run_only" if good else "unbound"
        control_ok = False
        if reference is not None and reference.binds is not None:
            findings.append(f"{reference_label} binds Control Artifact {reference.binds}, which was not supplied.")
        else:
            findings.append("No Control Artifact supplied, and "
                            f"{'no event' if reference is None else reference_label} binds none.")
        control = AgentControlVerdict()
    elif ctl is None:
        control_ok = env_ok = False
        findings.append(f"control artifact: {ctl_error}")
        binding = "unbound"
        control = AgentControlVerdict(present=True)
    else:
        label = "control artifact"
        for e in ctl.conformance:
            env_ok = False
            findings.append(f"{label}: {e}.")
        signer, signer_problem = signer_of(ctl.jws)
        if signer_problem is not None:
            sig_ok = False
            findings.append(f"{label}: {signer_problem}.")
        elif signer != run_signer:
            sig_ok = False
            findings.append(f"{label}: signed by a different certificate than the run (x5t#S256 {signer}).")
        cty_problem = _content_type_problem(ctl.jws, CONTROL_ARTIFACT_CONTENT_TYPE)
        if cty_problem is not None:
            sig_ok = False
            findings.append(f"{label}: {cty_problem}.")
        ctl_check = _check_artifact(ctl, bundle.control_artifact, bundle.payloads, verifier, label)
        findings.extend(ctl_check.findings)
        if not ctl_check.all_retained:
            obj_warn = True
        if not ctl_check.objects_complete:
            obj_ok = control_ok = False
        if not ctl_check.signature_valid:
            sig_ok = control_ok = False
        if not ctl_check.timestamp_ok:
            control_ok = False
            findings.append(f"{label}: a timestamp is required and it is "
                            f"{'invalid' if ctl_check.timestamp_present else 'missing'}.")
        add_certificate(ctl_check.certificate)
        if correlation is not None and ctl.correlation_id != correlation:
            control_ok = False
            findings.append(f"{label}: its signed correlationId is not the run's.")
        agent = _obj(ctl.env.get("agent")) or {}
        agent_id, agent_version = _str(agent.get("id")), _str(agent.get("version"))
        if reference is not None and (agent_id != reference.actor_id or (
                reference.actor_version is not None and agent_version != reference.actor_version)):
            control_ok = False
            findings.append(f"{label}: its agent ({_n(agent_id)}, {_n(agent_version)}) is not the run's actor "
                            f"({_n(reference.actor_id)}, {_n(reference.actor_version)}).")
        bound = False
        if reference is None:
            binding = "control_only"
        elif reference.binds is None or reference.binds != ctl_sig:
            control_ok = False
            binding = "unbound"
            findings.append(f"{reference_label}: binds.controlArtifactSignatureSha256 is not the signatureSha256 of "
                            f"the supplied Control Artifact.")
        else:
            binding = "bound"
            bound = True
        control_set = _obj(ctl.env.get("controlSet")) or {}
        control = AgentControlVerdict(
            present=True, evidence_id=ctl.evidence_id, signature_sha256=ctl_sig,
            signature_valid=ctl_check.signature_valid, objects_complete=ctl_check.objects_complete,
            timestamp_valid=ctl_check.timestamp_ok, timestamp_gen_time=ctl_check.gen_time, signer=signer,
            well_formed=not ctl.conformance, bound=bound, control_set_id=_str(control_set.get("id")),
            control_set_version=_str(control_set.get("version")), agent_id=agent_id, agent_version=agent_version,
            certificate=ctl_check.certificate, objects=ctl_check.objects)
    checks["control"] = "ok" if control_ok else "bad"

    sealed_before_run: Optional[bool] = None
    ctl_at = _time(ctl_check.gen_time) if ctl_check is not None and ctl_check.timestamp_ok else None
    start_at = _time(start_gen_time)
    if ctl_at is not None and start_at is not None:
        sealed_before_run = ctl_at <= start_at + timedelta(seconds=1)  # TSAs state up to 1 s accuracy
        if not sealed_before_run:
            warnings.append("The Control Artifact's timestamp is later than run_start's: the control basis may not "
                            "have been sealed before the run.")

    # ── every payload must be a signed object of some artifact (§7)
    eval_parsed = [_parse_signed(e.envelope, e.signature, CONTROL_EVALUATION_SCHEMA) for e in bundle.evaluations]
    signed_uris = {o.uri for s in good for o in s.objects}
    signed_uris.update(o.uri for o in (ctl.objects if ctl else []))
    signed_uris.update(o.uri for s, _ in eval_parsed if s is not None for o in s.objects)
    for uri in sorted(bundle.payloads):
        if uri in signed_uris:
            continue
        obj_ok = False
        findings.append(f"Supplied payload '{uri}' is not a signed object of any artifact (unsigned data in the "
                        f"record).")
    checks["chain"] = "ok" if chain_ok else "bad"
    checks["envelope"] = "ok" if env_ok else "bad"
    checks["signatures"] = "ok" if sig_ok else "bad"
    checks["objects"] = "bad" if not obj_ok else "warn" if obj_warn else "ok"

    # ── finalization
    ends = [s for s in good if s.step_type == "run_end"]
    end = ends[-1] if ends else None
    disposition: Optional[str] = None
    if end is None:
        checks["finalization"] = "warn"
    else:
        fin_ok = True
        if len(ends) > 1:
            fin_ok = False
            findings.append(f"More than one run_end (seq {', '.join(_n(e.seq) for e in ends)}).")
        end_step = _obj(end.env.get("step")) or {}
        disposition = _str(end_step.get("runDisposition"))
        if disposition is None or disposition not in _DISPOSITIONS:
            fin_ok = False
            findings.append(f"run_end carries no valid runDisposition (got '{disposition or 'none'}').")
        if good[-1] is not end:
            fin_ok = False
            findings.append("run_end is not the last artifact of the chain.")
        final_seq = _int(end_step.get("finalSeq"))
        if final_seq is None or final_seq != end.seq:
            fin_ok = False
            findings.append(f"run_end's finalSeq is {final_seq if final_seq is not None else 'absent'}, not its own "
                            f"seq {_n(end.seq)}.")
        final_prev = _str(end_step.get("finalPrevSignatureSha256"))
        if final_prev is None or final_prev != end.declared_prev:
            fin_ok = False
            findings.append("run_end's finalPrevSignatureSha256 is not its own chain.prevSignatureSha256.")
        if not anchor_valid:
            fin_ok = False
        checks["finalization"] = "ok" if fin_ok else "bad"
    checks["timestamps"] = "bad" if not ts_ok or not policy_ok else "warn" if not anchor_valid or ctl is None else "ok"

    # ── evaluations: reported on their own, never merged into the run verdict
    evaluations: list[AgentEvaluationVerdict] = []
    run_end_sig = signature_sha256(end.jws) if end is not None else None

    def effective(uri: str, a: AgentRunArtifact) -> Optional[str]:
        if uri in bundle.payloads:
            return hash_bytes(bundle.payloads[uri])
        return a.object_digests.get(uri)

    def with_role(s: _Signed, role: str) -> list[_SignedObject]:
        return [o for o in s.objects if o.role == role]

    for i, (art, (sa, error)) in enumerate(zip(bundle.evaluations, eval_parsed)):
        label = f"evaluation {i}"
        if sa is None:
            evaluations.append(AgentEvaluationVerdict(findings=[f"{label}: {error}"]))
            continue
        ef = [f"{label}: {e}." for e in sa.conformance]
        c = _check_artifact(sa, art, bundle.payloads, verifier, label)
        ef.extend(c.findings)
        signature_valid = c.signature_valid
        signer, signer_problem = signer_of(sa.jws)
        if signer_problem is not None:
            signature_valid = False
            ef.append(f"{label}: {signer_problem}.")
        elif expected_evaluation_signers is not None and signer not in expected_evaluation_signers:
            signature_valid = False
            ef.append(f"{label}: its signer (x5t#S256 {signer}) is not among the expected evaluation signers.")
        cty_problem = _content_type_problem(sa.jws, CONTROL_EVALUATION_CONTENT_TYPE)
        if cty_problem is not None:
            signature_valid = False
            ef.append(f"{label}: {cty_problem}.")
        if signer is not None and signer == run_signer:
            warnings.append(f"{label} is signed by the run's own certificate; an independent verifier should seal "
                            f"with its own.")
        if expected_evaluation_signers is None and c.certificate is not None \
                and c.certificate.trust not in _TRUSTED_CHAINS:
            warnings.append(f"{label}: its signing certificate does not chain to a trusted root (trust: "
                            f"{c.certificate.trust}) and no expected evaluation signers were given.")
        if not c.timestamp_ok:
            ef.append(f"{label}: a timestamp is required and it is {'invalid' if c.timestamp_present else 'missing'}.")

        subject = _obj(sa.env.get("subject")) or {}
        subject_bound = (run_end_sig is not None and ctl_sig is not None
                         and subject.get("runEndSignatureSha256") == run_end_sig
                         and subject.get("controlArtifactSignatureSha256") == ctl_sig
                         and (correlation is None or sa.correlation_id == correlation))
        if not subject_bound:
            ef.append(f"{label}: its subject does not name this run's run_end and Control Artifact.")

        control_set_matches = False
        baseline_matches: Optional[bool] = None
        if ctl is not None and bundle.control_artifact is not None:
            ctl_art = bundle.control_artifact
            e_set, c_set = with_role(sa, "control-set"), with_role(ctl, "control-set")
            eh = effective(e_set[0].uri, art) if len(e_set) == 1 else None
            control_set_matches = (len(e_set) == 1 and len(c_set) == 1 and e_set[0].uri == c_set[0].uri
                                   and eh is not None and eh == effective(c_set[0].uri, ctl_art)
                                   and _json_equal(sa.env.get("controlSet"), ctl.env.get("controlSet")))
            e_base, c_base = with_role(sa, "baseline-state"), with_role(ctl, "baseline-state")
            if e_base:
                bh = effective(e_base[0].uri, art) if len(e_base) == 1 else None
                baseline_matches = (len(e_base) == 1 and len(c_base) == 1 and e_base[0].uri == c_base[0].uri
                                    and bh is not None and bh == effective(c_base[0].uri, ctl_art))
        if not control_set_matches:
            ef.append(f"{label}: its control set is not the one sealed in the Control Artifact.")
        if baseline_matches is False:
            ef.append(f"{label}: its baseline is not the one sealed in the Control Artifact.")

        controls = [ControlResult(_str(x.get("id")) or "", _str(x.get("result")) or "", _str(x.get("detail")))
                    for x in (sa.env.get("controls") if isinstance(sa.env.get("controls"), list) else [])
                    if isinstance(x, dict)]
        evaluations.append(AgentEvaluationVerdict(
            evidence_id=sa.evidence_id, verifier_id=sa.actor_id, verifier_version=sa.actor_version,
            subject_bound=subject_bound, control_set_digest_matches=control_set_matches,
            baseline_digest_matches=baseline_matches, signature_valid=signature_valid,
            timestamp_valid=c.timestamp_ok, timestamp_gen_time=c.gen_time, objects_complete=c.objects_complete,
            well_formed=not sa.conformance, signer=signer, certificate=c.certificate,
            overall=_str(sa.env.get("overall")), controls=controls, findings=ef))

    # §3: consistency is not identity. Without pinned signers, say so unless the chain is trusted.
    if expected_signers is None:
        seen_trust: list[str] = []
        for cert in certificates:
            if cert.trust not in _TRUSTED_CHAINS and cert.trust not in seen_trust:
                seen_trust.append(cert.trust)
                warnings.append(f"The signing certificate does not chain to a trusted root (trust: {cert.trust}) and no "
                                f"expected signers were given: the run is consistent, but the verdict does not "
                                f"establish who produced it.")

    verdict = "run_invalid" if "bad" in checks.values() else "run_finalized" if end is not None else "run_open"
    return AgentRunVerificationResult(
        verdict=verdict, checks=checks, binding=binding, findings=findings, warnings=warnings,
        disposition=disposition, agent_id=reference.actor_id if reference else None,
        agent_version=reference.actor_version if reference else None, correlation_id=correlation,
        missing_seqs=missing,
        timestamps=AgentRunTimestampSummary(len(arts), ts_required, ts_present, ts_valid, anchor_valid, policy,
                                            policy_signed),
        certificates=certificates, control=control, artifacts=verdicts, evaluations=evaluations,
        fingerprint=_safe_fingerprint(bundle), signer=run_signer, control_sealed_before_run=sealed_before_run,
        event_times_plausible=plausible)


def _n(v: Any) -> str:
    """How .NET interpolates null: as empty."""
    return "" if v is None else str(v)


def _safe_fingerprint(bundle: AgentRunBundle) -> Optional[str]:
    try:
        return bundle_fingerprint(bundle)
    except Exception:  # noqa: BLE001 — not valid I-JSON: undefined (§8.2); the run is invalid anyway
        return None


def bundle_fingerprint(bundle: AgentRunBundle) -> str:
    """The deterministic bundle fingerprint (common rules §8.2).

    :raises ValueError: the evidence is not valid I-JSON: the fingerprint is undefined."""
    every = list(bundle.artifacts) + list(bundle.evaluations) + \
        ([bundle.control_artifact] if bundle.control_artifact else [])
    if not all(_is_i_json(a.envelope) and _is_i_json(a.signature) for a in every):
        raise ValueError("The fingerprint is undefined for evidence that is not valid I-JSON (§8.2).")

    def one(a: AgentRunArtifact) -> dict:
        return {"e": hash_bytes(canonicalize(a.envelope)), "s": hash_bytes(canonicalize(a.signature)),
                "d": dict(sorted(a.object_digests.items()))}
    arts = []
    for a in bundle.artifacts:
        chain = a.envelope.get("chain")
        raw = chain.get("seq") if isinstance(chain, dict) else None
        seq = _int(raw)
        arts.append({"seq": seq if seq is not None and seq >= 0 else -1, **one(a)})
    arts.sort(key=lambda x: (x["seq"], x["e"]))
    evals = sorted((one(e) for e in bundle.evaluations), key=lambda x: x["e"])
    payloads = [{"uri": u, "sha256": hash_bytes(bundle.payloads[u])} for u in sorted(bundle.payloads)]
    return hash_bytes(canonicalize({
        "format": BUNDLE_FORMAT,
        "artifacts": arts,
        "control": one(bundle.control_artifact) if bundle.control_artifact else None,
        "evaluations": evals,
        "payloads": payloads,
    }))
