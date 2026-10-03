# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Agent Evidence Profiles v1 — record a controlled agent run.

See ``spec/agent-profiles-common-v1.md``. Starting a run seals the Control
Artifact (configuration, control set, timestamp policy), then ``run_start``,
which binds it. Every later event is sealed blind (digests and opaque URIs
only) and chained to the previous event's signature, so a verifier detects
removed, reordered, inserted or spliced events.

Mirrors the .NET SDK one-to-one: same profile rules, same bundle format, same
cross-language vectors.
"""

from __future__ import annotations

import copy
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Sequence

from sigill_sdk._agent_profiles import (
    CONTROL_ARTIFACT_CONTENT_TYPE,
    CONTROL_ARTIFACT_SCHEMA,
    CONTROL_EVALUATION_CONTENT_TYPE,
    CONTROL_EVALUATION_SCHEMA,
    EXECUTION_EVIDENCE_CONTENT_TYPE,
    EXECUTION_EVIDENCE_SCHEMA,
    _format_time,
    _prevalidate,
    _str,
    _TimestampCoverage,
    _truncate,
    signer_of,
)
from sigill_sdk._agent_types import (
    AgentAuthorization,
    AgentControlSet,
    AgentDefinition,
    AgentRunActor,
    AgentRunArtifact,
    AgentRunBundle,
    AgentRunObject,
    AgentTimestampPolicy,
    ControlEvaluationRequest,
)
from sigill_sdk._canonical import canonicalize, hash_bytes
from sigill_sdk._errors import SigillError
from sigill_sdk._sign_objects import SignedObjectDigest

_RESERVED_STEP_FIELDS = frozenset({
    "type", "eventTime", "consequential", "timestamp", "finalSeq", "finalPrevSignatureSha256", "runDisposition",
})
_DISPOSITIONS = ("completed", "failed", "aborted")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _objects_block(objects: Sequence[AgentRunObject]) -> list[dict]:
    return [{"uri": o.uri, "role": o.role, "contentType": o.content_type, "sizeBytes": len(o.data)} for o in objects]


def _digests(objects: Sequence[AgentRunObject]) -> dict[str, str]:
    d: dict[str, str] = {}
    for o in objects:
        if o.data is None:
            raise ValueError(f"Object '{o.uri}' has no bytes.")
        if o.uri in d:
            raise ValueError(f"Duplicate object URI '{o.uri}'.")
        d[o.uri] = hash_bytes(o.data)
    return d


def _signed_digests(objects: Sequence[AgentRunObject]) -> list[SignedObjectDigest]:
    return [SignedObjectDigest(uri=o.uri, hash_hex=hash_bytes(o.data), content_type=o.content_type) for o in objects]


def _seal(client: Any, envelope: dict, digests: Sequence[SignedObjectDigest], profile_content_type: str,
          certificate_id: str, *, timestamp: bool, qualified: bool) -> Any:
    # No operation label: only digests, opaque URIs and content types reach the sealing service (§6).
    return client.sign_object_hashes(
        hash_bytes(canonicalize(envelope)),
        list(digests),
        str(certificate_id),
        envelope_content_type=profile_content_type,
        timestamp=timestamp,
        qualified=qualified and timestamp,
    )


def _validate_policy(p: AgentTimestampPolicy) -> None:
    if p.profile not in ("throughput", "per-event"):
        raise ValueError("timestamp_policy.profile must be 'throughput' or 'per-event'.")
    if p.every_events < 0 or p.every_seconds < 0:
        raise ValueError("timestamp_policy cadence values must be zero or positive.")


def _tool_block(name: str, operation: Optional[str], use_id: Optional[str]) -> dict:
    if not name:
        raise ValueError("tool name is required.")
    block: dict = {"name": name}
    if operation is not None:
        block["operation"] = operation
    if use_id is not None:
        block["useId"] = use_id
    return block


def _detail(fields: dict, detail: Optional[str]) -> dict:
    if detail is not None:
        fields["detail"] = detail
    return fields


class AgentRun:
    """Records one controlled agent run.

    ::

        run = client.start_agent_run(agent, certificate_id=cert_id, activity="support-ticket-close",
                                     control_set=controls)
        run.record_tool_call("lookup_ticket", args_json, operation="read")
        run.record_tool_result("lookup_ticket", result_json)
        run.record_model_output(answer)
        bundle = run.finish("completed")

    Under the default policy only the Control Artifact and ``run_end`` are
    timestamped; every other event is sealed B-B (common rules §4). Events are
    sealed one at a time, in call order; calls may come from any thread. A
    sealing failure raises and stops the chain (§6): later calls raise
    :class:`RuntimeError`, and the bundle so far verifies as open or invalid,
    never as finalized.
    """

    def __init__(self, *, _client: Any, _agent: AgentDefinition, _certificate_id: str, _activity: str,
                 _policy: AgentTimestampPolicy, _correlation_id: str, _retain: bool, _qualified: bool,
                 _on_sealed: Optional[Callable[[AgentRunArtifact], None]], _clock: Callable[[], datetime]):
        self._client = _client
        self._agent = _agent
        self._certificate_id = _certificate_id
        self._activity = _activity
        self._retain = _retain
        self._qualified = _qualified
        self._on_sealed = _on_sealed
        self._clock = _clock
        self._lock = threading.RLock()
        self._notify_cond = threading.Condition()
        self._next_notify = -1
        self._in_callback = threading.local()
        self._artifacts: list[AgentRunArtifact] = []
        self._payloads: dict[str, bytes] = {}
        self._coverage = _TimestampCoverage(_policy)
        self._prev_signature_sha256: Optional[str] = None
        self._signer: Optional[str] = None
        self._broken = False
        self._finished = False
        self.correlation_id = _correlation_id
        """The run identifier (``activity.correlationId``)."""
        self.control_artifact: AgentRunArtifact = None  # type: ignore[assignment]
        """The run's Control Artifact, sealed before ``run_start``."""

    @classmethod
    def start(cls, client: Any, agent: AgentDefinition, *, certificate_id: str, activity: str,
              control_set: AgentControlSet, baseline_state: Optional[bytes] = None,
              baseline_state_content_type: str = "application/json", authority: Optional[bytes] = None,
              authority_content_type: str = "application/jwt", control_actor: Optional[AgentRunActor] = None,
              timestamp_policy: Optional[AgentTimestampPolicy] = None, correlation_id: Optional[str] = None,
              start_objects: Optional[Sequence[AgentRunObject]] = None, retain_payloads: bool = False,
              qualified: bool = False, on_artifact_sealed: Optional[Callable[[AgentRunArtifact], None]] = None,
              _clock: Optional[Callable[[], datetime]] = None) -> "AgentRun":
        """Opens a run: seals the Control Artifact (always timestamped), then
        ``run_start`` binding it.

        :param certificate_id: the seal certificate that signs the Control Artifact and every
            event (one signer per run).
        :param activity: what the run does (``activity.name``), e.g. ``customer-address-change``.
        :param control_set: the control set the run will be evaluated against.
        :param baseline_state: the target's state as read before the run (role ``baseline-state``) —
            what every "unchanged" control rests on.
        :param authority: the authority the agent acts under, e.g. a delegation token (role ``authority``).
        :param control_actor: who seals the Control Artifact. Default: the agent itself (``type: agent``).
        :param start_objects: objects bound into ``run_start``, e.g. the request (role ``model-input``).
        :param retain_payloads: keep payload bytes so :meth:`to_bundle` can include
            them. Off by default: a digests-only bundle reveals no content.
        :param on_artifact_sealed: called after each artifact is sealed — the Control Artifact
            first, then every event strictly in chain order. Persist it here so a crash leaves a
            shorter prefix, never a hole. An exception propagates; the run itself stays usable.
        """
        if control_set is None:
            raise ValueError("control_set is required.")
        policy = timestamp_policy or AgentTimestampPolicy()
        _validate_policy(policy)
        clock = _clock or _utcnow
        run = cls(_client=client, _agent=agent, _certificate_id=str(certificate_id), _activity=activity,
                  _policy=policy, _correlation_id=correlation_id or f"urn:uuid:{uuid.uuid4()}",
                  _retain=retain_payloads, _qualified=qualified, _on_sealed=on_artifact_sealed, _clock=clock)

        now = _truncate(clock())
        config = agent.configuration
        objects: list[AgentRunObject] = []
        for role, data, ctype in (
                ("instruction-set", config.instruction_set, "text/plain"),
                ("tool-manifest", config.tool_manifest, "application/json"),
                ("execution-policy", config.execution_policy, "application/json"),
                ("model-config", config.model_config, "application/json"),
                ("control-set", control_set.content, control_set.content_type),
                ("authority", authority, authority_content_type),
                ("baseline-state", baseline_state, baseline_state_content_type)):
            if data is not None:
                objects.append(AgentRunObject(role, data, ctype))

        actor = control_actor or AgentRunActor("agent", agent.agent_id, agent.agent_version)
        actor_json: dict = {"type": actor.type, "id": actor.id}
        if actor.version is not None:
            actor_json["version"] = actor.version
        agent_json: dict = {"id": agent.agent_id, "version": agent.agent_version}
        if agent.identity_ref is not None:
            agent_json["identityRef"] = agent.identity_ref
        envelope = {
            "schemaName": CONTROL_ARTIFACT_SCHEMA,
            "schemaVersion": "1",
            "evidenceId": str(uuid.uuid4()),
            "createdAt": _format_time(now),
            "actor": actor_json,
            "activity": {"name": activity, "correlationId": run.correlation_id},
            "agent": agent_json,
            "controlSet": {"id": control_set.id, "version": control_set.version},
            "timestampPolicy": policy.to_json(),
            "objects": _objects_block(objects),
        }
        _prevalidate(envelope, CONTROL_ARTIFACT_SCHEMA)
        digests = _digests(objects)

        result = _seal(client, envelope, _signed_digests(objects), CONTROL_ARTIFACT_CONTENT_TYPE,
                       str(certificate_id), timestamp=True, qualified=qualified)
        if result.timestamped_by is None:
            raise SigillError("The Control Artifact must be timestamped, but the seal carries no timestamp.")
        signer, problem = signer_of(result.signature)
        if problem is not None:
            raise SigillError(f"The sealing service returned a signature whose signer cannot be established: {problem}.")
        run._signer = signer
        run.control_artifact = AgentRunArtifact(envelope, result.signature, digests)
        if retain_payloads:
            run._payloads.update({o.uri: o.data for o in objects})
        run._notify(run.control_artifact, -1)

        start = run._seal_event("run_start", list(start_objects or []), {}, consequential=False)
        run._notify(start, 0)
        return run

    @property
    def artifacts(self) -> list[AgentRunArtifact]:
        """The sealed events so far, in chain order."""
        with self._lock:
            return list(self._artifacts)

    @property
    def is_broken(self) -> bool:
        """A sealing failure stopped the chain."""
        return self._broken

    @property
    def is_finished(self) -> bool:
        """``run_end`` has been sealed."""
        return self._finished

    # ── events ──

    def record(self, step_type: str, objects: Optional[Sequence[AgentRunObject]] = None,
               fields: Optional[dict] = None, *, consequential: bool = False,
               require_timestamp: bool = False) -> AgentRunArtifact:
        """Seals one event. ``fields`` adds the type-specific step fields
        (``tool``, ``decision``, ``policyId``, ``approver``, ``detail``) — keep
        them free of personal data. ``consequential`` marks an external side
        effect (a write-class tool call, a delivered message); it is
        timestamped when the signed policy says ``consequential: true``.
        ``require_timestamp`` timestamps this event even when the policy would
        not (a producer may require more, never less).

        :raises ValueError: the event would not verify; nothing was sealed and the run stays usable.
        """
        if not step_type:
            raise ValueError("step_type is required.")
        if step_type in ("run_start", "run_end"):
            raise ValueError(f"'{step_type}' is sealed by start() / finish().")
        reserved = sorted(_RESERVED_STEP_FIELDS.intersection(fields or {}))
        if reserved:
            raise ValueError(f"fields uses reserved step member(s): {', '.join(reserved)}")
        with self._lock:
            self._ensure_open()
            step = json.loads(json.dumps(fields or {}))
            if require_timestamp:
                step["timestamp"] = "required"
            artifact = self._seal_event(step_type, list(objects or []), step, consequential=consequential)
        self._notify(artifact, artifact.seq)
        return artifact

    def record_retrieval(self, context: bytes, content_type: str = "text/plain", *,
                         detail: Optional[str] = None) -> AgentRunArtifact:
        """Retrieved context (RAG) the agent read."""
        return self.record("retrieval", [AgentRunObject("retrieved-context", context, content_type)],
                           _detail({}, detail))

    def record_tool_call(self, tool: str, arguments: bytes, *, operation: Optional[str] = None,
                         consequential: bool = False, content_type: str = "application/json",
                         use_id: Optional[str] = None) -> AgentRunArtifact:
        """A tool call the agent decided to make. ``operation`` classifies it
        (e.g. ``read``, ``update``); mark write-class calls ``consequential``.
        ``use_id`` correlates the call with its result."""
        return self.record("tool_call", [AgentRunObject("tool-arguments", arguments, content_type)],
                           {"tool": _tool_block(tool, operation, use_id)}, consequential=consequential)

    def record_tool_result(self, tool: str, result: bytes, *, content_type: str = "application/json",
                           use_id: Optional[str] = None) -> AgentRunArtifact:
        """The result a tool returned — context for the model's next turn."""
        return self.record("tool_result", [AgentRunObject("tool-result", result, content_type)],
                           {"tool": _tool_block(tool, None, use_id)})

    def record_authorization(self, authorization: AgentAuthorization) -> AgentRunArtifact:
        """A policy decision taken before an action, e.g. "this write needs approval"."""
        if authorization is None:
            raise ValueError("authorization is required.")
        fields: dict = {"decision": authorization.decision}
        if authorization.policy_id is not None:
            fields["policyId"] = authorization.policy_id
        return self.record("authorization", fields=_detail(fields, authorization.detail))

    def record_human_approval(self, decision: str, *, receipt: Optional[bytes] = None,
                              identity_assertion: Optional[bytes] = None, approver: Optional[str] = None,
                              detail: Optional[str] = None, receipt_content_type: str = "application/json",
                              identity_assertion_content_type: str = "application/jwt") -> AgentRunArtifact:
        """A human approval: ``decision`` is ``approved`` or ``rejected``.
        ``approver`` is an opaque identifier — never a name or e-mail address.
        What the approval covers (the receipt) and an identity assertion (e.g.
        an IdP token) are bound as detached objects; their bytes stay local."""
        fields: dict = {"decision": decision}
        if approver is not None:
            fields["approver"] = approver
        objects = []
        if receipt is not None:
            objects.append(AgentRunObject("approval-receipt", receipt, receipt_content_type))
        if identity_assertion is not None:
            objects.append(AgentRunObject("identity-assertion", identity_assertion, identity_assertion_content_type))
        return self.record("human_approval", objects, _detail(fields, detail))

    def record_model_output(self, output: bytes, content_type: str = "text/plain", *,
                            consequential: bool = False) -> AgentRunArtifact:
        """What the model produced."""
        return self.record("model_output", [AgentRunObject("model-output", output, content_type)],
                           consequential=consequential)

    def checkpoint(self, detail: Optional[str] = None) -> AgentRunArtifact:
        """Anchors the chain head with a timestamped ``checkpoint`` — e.g. from
        a timer while a long run is idle, so the head does not wait for
        ``run_end`` to be anchored."""
        return self.record("checkpoint", fields=_detail({}, detail), require_timestamp=True)

    def finish(self, disposition: str = "completed", detail: Optional[str] = None) -> AgentRunBundle:
        """Seals ``run_end`` (always timestamped), closing the run, and returns
        the bundle. ``disposition``: completed | failed | aborted."""
        if disposition not in _DISPOSITIONS:
            raise ValueError("disposition must be completed, failed or aborted.")
        with self._lock:
            self._ensure_open()
            # finalSeq is run_end's own seq, finalPrev its own chain link (§11): closure is checkable on its own.
            step = {
                "finalSeq": len(self._artifacts),
                "finalPrevSignatureSha256": self._prev_signature_sha256,
                "runDisposition": disposition,
            }
            artifact = self._seal_event("run_end", [], _detail(step, detail), consequential=False)
            bundle = self.to_bundle()
        self._notify(artifact, artifact.seq)
        return bundle

    def to_bundle(self) -> AgentRunBundle:
        """The run as a bundle — available at any point, including after a failure."""
        with self._lock:
            return AgentRunBundle(self.correlation_id, self.control_artifact, list(self._artifacts), [],
                                  dict(self._payloads))

    # ── sealing ──

    def _seal_event(self, step_type: str, objects: list[AgentRunObject], fields: dict, *,
                    consequential: bool) -> AgentRunArtifact:
        """Builds, validates and seals one event. Call with the lock held (or
        before the run is published); the callback is the caller's job."""
        now = _truncate(self._clock())  # the decision below must use the signed, truncated time
        seq = len(self._artifacts)
        coverage = copy.copy(self._coverage)  # committed only once the event is sealed
        stamp = coverage.next(seq, step_type, consequential, fields.get("timestamp") == "required", now)
        step: dict = {
            "type": step_type,
            "eventTime": _format_time(now),
            "consequential": consequential,
            "timestamp": "required" if stamp else "none",
        }
        step.update({k: v for k, v in fields.items() if k != "timestamp"})
        actor: dict = {"type": "agent", "id": self._agent.agent_id, "version": self._agent.agent_version}
        if self._agent.tenant_id is not None:
            actor["tenantId"] = self._agent.tenant_id
        chain: dict = {"seq": seq}
        if seq > 0:
            chain["prevSignatureSha256"] = self._prev_signature_sha256
        envelope: dict = {
            "schemaName": EXECUTION_EVIDENCE_SCHEMA,
            "schemaVersion": "1",
            "evidenceId": str(uuid.uuid4()),
            "createdAt": _format_time(now),
            "actor": actor,
            "activity": {"name": self._activity, "correlationId": self.correlation_id},
            "chain": chain,
            "step": step,
        }
        if seq == 0:
            envelope["binds"] = {"controlArtifactSignatureSha256": self.control_artifact.signature_sha256}
        envelope["objects"] = _objects_block(objects)
        digests = _digests(objects)
        _prevalidate(envelope, EXECUTION_EVIDENCE_SCHEMA)  # raises before anything is sealed
        try:
            result = _seal(self._client, envelope, _signed_digests(objects), EXECUTION_EVIDENCE_CONTENT_TYPE,
                           self._certificate_id, timestamp=stamp, qualified=self._qualified)
            if stamp and result.timestamped_by is None:
                raise SigillError(f"{step_type}: a timestamp is required by the run's policy, but the seal carries none.")
            signer, problem = signer_of(result.signature)
            if problem is not None:
                raise SigillError(f"The sealing service returned a signature whose signer cannot be established: "
                                  f"{problem}.")
            if signer != self._signer:
                raise SigillError("The event was sealed with a different certificate than the run's Control Artifact "
                                  "(certificate rotated?); a run has one signer.")
            artifact = AgentRunArtifact(envelope, result.signature, digests)
            link = artifact.signature_sha256
            if link is None:
                raise SigillError("The seal returned no classical signature to chain to.")
            self._prev_signature_sha256 = link
            self._coverage = coverage
            self._artifacts.append(artifact)
            if step_type == "run_end":
                self._finished = True  # committed with the append, before any caller code runs
            if self._retain:
                self._payloads.update({o.uri: o.data for o in objects})
        except BaseException:
            self._broken = True
            raise
        return artifact

    def _notify(self, artifact: AgentRunArtifact, seq: int) -> None:
        """Runs the callback outside the lock, so it may call back into the
        run, and in order (the Control Artifact as -1, then each seq):
        concurrent events wait their turn, so a crash can leave the persisted
        prefix short, never with a hole. An event recorded from inside a
        callback is delivered immediately (it is next in order, and waiting
        would deadlock on the callback that recorded it). A failing callback
        is the caller's error and does not break the run."""
        nested = getattr(self._in_callback, "active", False)
        with self._notify_cond:
            if not nested:
                self._notify_cond.wait_for(lambda: self._next_notify >= seq)
        try:
            if self._on_sealed is not None:
                self._in_callback.active = True
                try:
                    self._on_sealed(artifact)
                finally:
                    self._in_callback.active = nested
        finally:
            with self._notify_cond:
                self._next_notify = max(self._next_notify, seq + 1)
                self._notify_cond.notify_all()

    def _ensure_open(self) -> None:
        if self._broken:
            raise RuntimeError("The run's chain is broken by an earlier sealing failure; no further events can be "
                               "sealed.")
        if self._finished:
            raise RuntimeError("The run is finished.")


class ControlEvaluation:
    """Seals a Control Evaluation (``spec/control-evaluation-v1.md``): what an
    independent verifier observed after a run and how each control came out.
    Always timestamped. Seal it with the verifier's own certificate."""

    @staticmethod
    def seal(client: Any, request: ControlEvaluationRequest, *,
             _clock: Optional[Callable[[], datetime]] = None) -> AgentRunArtifact:
        """:raises ValueError: the evaluation would not verify; nothing was sealed."""
        if request is None:
            raise ValueError("request is required.")
        control = request.control_artifact
        if control is None:
            raise ValueError("control_artifact is required.")
        if request.run_end is None or request.run_end.step_type != "run_end":
            raise ValueError("run_end must be the run's run_end artifact.")
        control_sig = control.signature_sha256
        if control_sig is None:
            raise ValueError("The Control Artifact carries no classical signature.")
        run_end_sig = request.run_end.signature_sha256
        if run_end_sig is None:
            raise ValueError("run_end carries no classical signature.")

        def control_object(role: str) -> Optional[dict]:
            for o in control.envelope.get("objects") or []:
                if isinstance(o, dict) and o.get("role") == role:
                    return o
            return None

        objects: list[dict] = []
        digests: dict[str, str] = {}
        seal: list[SignedObjectDigest] = []

        def reuse(o: dict) -> None:
            # The control set and baseline are referred to by the Control Artifact's own URI and digest; no bytes.
            uri = o["uri"]
            hex_ = control.object_digests.get(uri)
            if hex_ is None:
                raise ValueError(f"The Control Artifact carries no digest for its '{_str(o.get('role'))}' object.")
            objects.append(json.loads(json.dumps(o)))
            digests[uri] = hex_
            seal.append(SignedObjectDigest(uri=uri, hash_hex=hex_, content_type=_str(o.get("contentType"))))

        for o in request.observed_state or []:
            if o.role != "observed-state":
                raise ValueError("observed_state objects must have role 'observed-state'.")
            objects.extend(_objects_block([o]))
            if o.uri in digests:
                raise ValueError(f"Duplicate object URI '{o.uri}'.")
            digests[o.uri] = hash_bytes(o.data)
            seal.append(SignedObjectDigest(uri=o.uri, hash_hex=digests[o.uri], content_type=o.content_type))
        control_set = control_object("control-set")
        if control_set is None:
            raise ValueError("The Control Artifact carries no control-set object.")
        reuse(control_set)
        baseline = control_object("baseline-state")
        if request.include_baseline and baseline is not None:
            reuse(baseline)

        now = _truncate((_clock or _utcnow)())
        controls = []
        for c in request.controls or []:
            j: dict = {"id": c.id, "result": c.result}
            if c.detail is not None:
                j["detail"] = c.detail
            controls.append(j)
        envelope = {
            "schemaName": CONTROL_EVALUATION_SCHEMA,
            "schemaVersion": "1",
            "evidenceId": str(uuid.uuid4()),
            "createdAt": _format_time(now),
            "actor": {"type": "verifier", "id": request.verifier_id, "version": request.verifier_version},
            "activity": json.loads(json.dumps(control.envelope.get("activity"))),
            "subject": {"runEndSignatureSha256": run_end_sig, "controlArtifactSignatureSha256": control_sig},
            "controlSet": json.loads(json.dumps(control.envelope.get("controlSet"))),
            "controls": controls,
            "overall": request.overall,
            "evaluatedAt": _format_time(_truncate(request.evaluated_at or now)),
            "objects": objects,
        }
        _prevalidate(envelope, CONTROL_EVALUATION_SCHEMA)
        result = _seal(client, envelope, seal, CONTROL_EVALUATION_CONTENT_TYPE, str(request.certificate_id),
                       timestamp=True, qualified=request.qualified)
        if result.timestamped_by is None:
            raise SigillError("A Control Evaluation must be timestamped, but the seal carries no timestamp.")
        return AgentRunArtifact(envelope, result.signature, digests)


def seal_control_evaluation(client: Any, request: ControlEvaluationRequest) -> AgentRunArtifact:
    """Seals a Control Evaluation of a finished run. See :class:`ControlEvaluation`."""
    return ControlEvaluation.seal(client, request)
