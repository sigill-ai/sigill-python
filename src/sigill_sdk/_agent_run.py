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

import asyncio
import copy
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, Sequence

from sigill_sdk._agent_profiles import (
    CONTROL_ARTIFACT_CONTENT_TYPE,
    CONTROL_ARTIFACT_SCHEMA,
    CONTROL_EVALUATION_CONTENT_TYPE,
    CONTROL_EVALUATION_SCHEMA,
    CONTROL_EVALUATION_SCHEMA_V2,
    EXECUTION_EVIDENCE_CONTENT_TYPE,
    EXECUTION_EVIDENCE_SCHEMA,
    MAX_ARTIFACTS,
    _execution_schema_for,
    _format_time,
    _int,
    _obj,
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
    AgentDelegation,
    AgentIndexResult,
    AgentRunActor,
    AgentRunArtifact,
    AgentRunBundle,
    AgentRunObject,
    AgentTimestampPolicy,
    AttestedEvaluationRequest,
    ControlEvaluationRequest,
    EvaluationReference,
    PolicyEvaluationRequest,
    PreparedEvaluation,
    QualifiedArtifacts,
)
from sigill_sdk._agent_policy import FACTS_VERSION, POLICY_CONTROL_SET_CONTENT_TYPE, AgentPolicy, _build_facts
from sigill_sdk._canonical import canonicalize, hash_bytes
from sigill_sdk._errors import SigillError
from sigill_sdk._references import new_object_uri
from sigill_sdk._sign_objects import SignedObjectDigest

_RESERVED_STEP_FIELDS = frozenset({
    "type", "eventTime", "consequential", "timestamp", "finalSeq", "finalPrevSignatureSha256", "runDisposition",
    "delegation",
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
          certificate_id: str, *, timestamp: bool, qualified: bool, reused_uris: frozenset[str] | None = None) -> Any:
    # No operation label: only digests, opaque URIs and content types reach the sealing service (§6).
    extra = {"_reused_uris": reused_uris} if reused_uris else {}
    return client.sign_object_hashes(
        hash_bytes(canonicalize(envelope)),
        list(digests),
        str(certificate_id),
        envelope_content_type=profile_content_type,
        timestamp=timestamp,
        qualified=qualified and timestamp,
        **extra,
    )


def _validate_policy(p: AgentTimestampPolicy) -> None:
    if p.profile not in ("throughput", "per-event"):
        raise ValueError("timestamp_policy.profile must be 'throughput' or 'per-event'.")
    if p.every_events < 0 or p.every_seconds < 0:
        raise ValueError("timestamp_policy cadence values must be zero or positive.")


def _validate_control_set(control_set: AgentControlSet, disclose_policy: bool) -> None:
    """A policy control set is checked before anything is sealed: a malformed policy must never
    become the run's control basis."""
    if control_set.content_type != POLICY_CONTROL_SET_CONTENT_TYPE:
        if disclose_policy:
            raise ValueError(f"disclose_policy requires a control set of type {POLICY_CONTROL_SET_CONTENT_TYPE} "
                             "(AgentPolicy.control_set_from_document).")
        return
    errors = AgentPolicy.validate(control_set.content)
    if errors:
        raise ValueError("Invalid policy control set: " + "; ".join(errors))
    doc = json.loads(control_set.content)
    if doc["id"] != control_set.id or doc["version"] != control_set.version:
        raise ValueError("control_set id and version must equal the document's id and version.")


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
                 _on_sealed: Optional[Callable[[AgentRunArtifact], None]], _clock: Callable[[], datetime],
                 _schema_version: str = "1", _parent: Optional[AgentDelegation] = None,
                 _qualified_for: QualifiedArtifacts = QualifiedArtifacts.NONE):
        self._client = _client
        self._agent = _agent
        self._certificate_id = _certificate_id
        self._activity = _activity
        self._retain = _retain
        self._qualified = _qualified
        self._qualified_for = _qualified_for
        self._on_sealed = _on_sealed
        self._clock = _clock
        self._lock = threading.RLock()
        self._notify_cond = threading.Condition()
        self._next_notify = -1
        self._in_callback = threading.local()
        self._artifacts: list[AgentRunArtifact] = []
        self._payloads: dict[str, bytes] = {}
        self._sealed_digests: dict[str, str] = {}
        self._coverage = _TimestampCoverage(_policy)
        self._prev_signature_sha256: Optional[str] = None
        self._signer: Optional[str] = None
        self._broken = False
        self._finished = False
        self._schema_version = _schema_version
        self._parent = _parent
        # delegation §4: open delegations (child correlationId → delegation seq) and those already resolved.
        self._outstanding: dict[str, int] = {}
        self._resolved: set[str] = set()
        self.correlation_id = _correlation_id
        """The run identifier (``activity.correlationId``)."""
        self.control_artifact: AgentRunArtifact = None  # type: ignore[assignment]
        """The run's Control Artifact, sealed before ``run_start``."""
        self.policy_disclosure: Optional[AgentIndexResult] = None
        """Outcome of ``disclose_policy=True``; None when the policy was not shared."""

    @classmethod
    def start(cls, client: Any, agent: AgentDefinition, *, certificate_id: str, activity: str,
              control_set: AgentControlSet, baseline_state: Optional[bytes] = None,
              baseline_state_content_type: str = "application/json", authority: Optional[bytes] = None,
              authority_content_type: str = "application/jwt", control_actor: Optional[AgentRunActor] = None,
              timestamp_policy: Optional[AgentTimestampPolicy] = None, correlation_id: Optional[str] = None,
              start_objects: Optional[Sequence[AgentRunObject]] = None, retain_payloads: bool = False,
              qualified: bool = False, on_artifact_sealed: Optional[Callable[[AgentRunArtifact], None]] = None,
              delegating: bool = False, qualified_for: QualifiedArtifacts = QualifiedArtifacts.NONE,
              disclose_policy: bool = False, _clock: Optional[Callable[[], datetime]] = None,
              _parent: Optional[AgentDelegation] = None) -> "AgentRun":
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
            shorter prefix, never a hole. It may call back into the run; an event recorded from
            inside the callback is delivered at once (waiting would deadlock), so it can arrive
            ahead of an event another thread sealed meanwhile. An exception propagates; the run
            itself stays usable.
        :param delegating: the run may start sub-agent runs (``spec/agent-delegation-v1.md``). Its events
            are sealed as ``AgentExecutionEvidence`` ``schemaVersion "2"``, which a run must use throughout
            once it delegates. Child runs (:meth:`start_child`) always use version 2.
        :param qualified_for: request qualified timestamps for these artifacts only, in addition to
            ``qualified``: the Control Artifact and ``run_end`` are the ones a declared policy rests on.
        :param disclose_policy: **preview** — share the declared policy with your Sigill organisation's evidence index:
            after the Control Artifact is sealed, upload its signed envelope (metadata and digests, no
            content) together with the control-set document, so the organisation can review, approve and
            track the policy. Requires an :class:`AgentPolicy` control set. Off by default. The upload never
            fails the run; its outcome is :attr:`policy_disclosure`. Execution events are not uploaded.
        """
        if control_set is None:
            raise ValueError("control_set is required.")
        policy = timestamp_policy or AgentTimestampPolicy()
        _validate_policy(policy)
        _validate_control_set(control_set, disclose_policy)
        if _parent is not None:
            if not _parent.child_correlation_id or not _parent.parent_correlation_id \
                    or not _parent.delegation_signature_sha256:
                raise ValueError("The delegation is incomplete.")
            if correlation_id is not None and correlation_id != _parent.child_correlation_id:
                raise ValueError("A child run's correlationId is the one its parent declared.")
            if _parent.child_agent_id != agent.agent_id:
                raise ValueError(f"The parent delegated to '{_parent.child_agent_id}', not '{agent.agent_id}'.")
        clock = _clock or _utcnow
        if _parent is not None:
            correlation = _parent.child_correlation_id
        else:
            correlation = correlation_id or f"urn:uuid:{uuid.uuid4()}"
        run = cls(_client=client, _agent=agent, _certificate_id=str(certificate_id), _activity=activity,
                  _policy=policy, _correlation_id=correlation,
                  _retain=retain_payloads, _qualified=qualified, _on_sealed=on_artifact_sealed, _clock=clock,
                  _schema_version="2" if delegating or _parent is not None else "1", _parent=_parent,
                  _qualified_for=QualifiedArtifacts(qualified_for))

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
                       str(certificate_id), timestamp=True,
                       qualified=qualified or bool(qualified_for & QualifiedArtifacts.CONTROL_ARTIFACT))
        if result.timestamped_by is None:
            raise SigillError("The Control Artifact must be timestamped, but the seal carries no timestamp.")
        signer, problem = signer_of(result.signature)
        if problem is not None:
            raise SigillError(f"The sealing service returned a signature whose signer cannot be established: {problem}.")
        run._signer = signer
        run.control_artifact = AgentRunArtifact(envelope, result.signature, digests)
        run._sealed_digests.update(digests)
        if retain_payloads:
            run._payloads.update({o.uri: o.data for o in objects})

        # Seal run_start before any callback runs, so a failing callback cannot strand a sealed control basis.
        start = run._seal_event("run_start", list(start_objects or []), {}, consequential=False)
        if disclose_policy:
            # Sharing is a side channel: it never fails the run (the evidence is in the producer's bundle either way).
            try:
                upload = getattr(client, "_index_agent_artifact", None)
                run.policy_disclosure = upload(run.control_artifact, control_set.content) if upload else \
                    AgentIndexResult("failed", error="Only SigillClient can share a policy with the evidence index.")
            except Exception as ex:  # noqa: BLE001
                run.policy_disclosure = AgentIndexResult("failed", error=str(ex))
        # Both are delivered even when the first callback fails: later events wait for their turn in order.
        failure: Optional[BaseException] = None
        for artifact, seq in ((run.control_artifact, -1), (start, 0)):
            try:
                run._notify(artifact, seq)
            except (Exception, asyncio.CancelledError) as ex:  # noqa: BLE001 — every failure, a cancellation
                if failure is None:                                 # included, surfaces with the started run
                    failure = ex
        if failure is not None:
            raise AgentRunCallbackError(run, failure) from failure
        return run

    @classmethod
    def start_child(cls, client: Any, agent: AgentDefinition, delegation: AgentDelegation, *,
                    certificate_id: str, activity: str, control_set: AgentControlSet, **options: Any) -> "AgentRun":
        """Opens a child run for a delegation the parent sealed (``spec/agent-delegation-v1.md`` §4 rule 2):
        the child's Control Artifact, then its ``run_start`` binding both the Control Artifact and the
        parent's ``delegation``. The child's correlationId is the one the parent declared, and
        ``agent.agent_id`` must be the declared ``child_agent_id``. Call it before the child acts: the child
        must do nothing before its ``run_start`` is sealed. Other options are those of :meth:`start`.

        :raises ValueError: the delegation is incomplete, or does not name this agent or correlationId.
        """
        if delegation is None:
            raise ValueError("delegation is required.")
        return cls.start(client, agent, certificate_id=certificate_id, activity=activity, control_set=control_set,
                         _parent=delegation, **options)

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

    @property
    def outstanding_delegations(self) -> list[str]:
        """Delegations sealed but not yet resolved by a ``delegation_result``."""
        with self._lock:
            return list(self._outstanding)

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
        if step_type in ("delegation", "delegation_result"):
            raise ValueError(f"'{step_type}' is sealed by delegate() / complete_delegation().")
        reserved = sorted(_RESERVED_STEP_FIELDS.intersection(fields or {}))
        if reserved:
            raise ValueError(f"fields uses reserved step member(s): {', '.join(reserved)}")
        with self._lock:
            self._ensure_open()
            # Keep the last slot for run_end, and one per open delegation for its result (delegation §4 rule 6),
            # so a bundle always fits MAX_ARTIFACTS and can finish.
            open_ = len(self._outstanding)
            if len(self._artifacts) >= MAX_ARTIFACTS - 1 - open_:
                raise RuntimeError(
                    f"The run has {len(self._artifacts)} events; only run_end fits within the bundle limit of "
                    f"{MAX_ARTIFACTS}. Finish the run." if open_ == 0 else
                    f"The run has {len(self._artifacts)} events; the rest of the bundle limit of {MAX_ARTIFACTS} is "
                    f"reserved for run_end and {open_} delegation result(s).")
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
            if disposition == "completed" and self._outstanding:
                raise RuntimeError(f"{len(self._outstanding)} delegation(s) have no result: record them first, or close "
                                   f"the run as aborted or failed (delegation §4 rule 5).")
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

    # ── delegation (spec/agent-delegation-v1.md) ──

    def delegate(self, child_agent_id: str, instruction: Optional[bytes] = None,
                 instruction_content_type: str = "text/plain", *, use_id: Optional[str] = None,
                 consequential: bool = False, child_correlation_id: Optional[str] = None) -> AgentDelegation:
        """Seals a ``delegation`` event declaring a child run (§3.2, §4 rule 1): call it before the child
        starts, then open the child with :meth:`start_child` and the returned :class:`AgentDelegation`.
        ``instruction`` is what the child is asked to do; only its digest is sealed (role
        ``delegation-input``). Mark ``consequential`` when the child is granted write authority. Requires
        ``delegating=True`` (or a child run).

        :raises RuntimeError: the run does not delegate, or the event budget is reserved (§4 rule 6).
        :raises ValueError: the child is this run, or is already delegated by it.
        """
        if not child_agent_id:
            raise ValueError("child_agent_id is required.")
        if self._schema_version != "2":
            raise RuntimeError("This run was not started with delegating=True; a run that delegates uses "
                               "schemaVersion 2 throughout.")
        child = child_correlation_id if child_correlation_id is not None else f"urn:uuid:{uuid.uuid4()}"
        if not child or child == self.correlation_id:
            raise ValueError("A run cannot delegate to itself.")
        with self._lock:
            self._ensure_open()
            if child in self._outstanding or child in self._resolved:
                raise ValueError(f"'{child}' is already delegated by this run (§4 rule 10).")
            # This event, a result for every open delegation including this one, and run_end must fit.
            if len(self._artifacts) + 1 + len(self._outstanding) + 1 + 1 > MAX_ARTIFACTS:
                raise RuntimeError(f"No room for another delegation: the bundle limit of {MAX_ARTIFACTS} is reserved "
                                   f"for run_end and the results of {len(self._outstanding)} open delegation(s).")
            block: dict = {"childCorrelationId": child, "childAgentId": child_agent_id}
            if use_id is not None:
                block["useId"] = use_id
            objects = [] if instruction is None else \
                [AgentRunObject("delegation-input", instruction, instruction_content_type)]
            artifact = self._seal_event("delegation", objects, {"delegation": block}, consequential=consequential)
            self._outstanding[child] = artifact.seq
        self._notify(artifact, artifact.seq)
        return AgentDelegation(self.correlation_id, artifact.signature_sha256, child, child_agent_id,
                               artifact=artifact)

    def complete_delegation(self, child: "AgentRun | str", child_run_end_signature_sha256: Optional[str] = None,
                            child_disposition: Optional[str] = None) -> AgentRunArtifact:
        """Seals the ``delegation_result`` for a finished child (§4 rule 3). Pass the child :class:`AgentRun`
        when it ran in this process, or — for a child that ran elsewhere — its correlationId, the
        ``signatureSha256`` of its sealed ``run_end`` and that ``run_end``'s disposition (§3.2). One result per
        delegation, whatever the child's disposition.

        :raises RuntimeError: the child is not finished, never delegated by this run, or already resolved.
        :raises ValueError: the disposition is not completed, failed or aborted.
        """
        if isinstance(child, AgentRun):
            if child_run_end_signature_sha256 is not None or child_disposition is not None:
                raise ValueError("Pass either a child run or its values, not both.")
            if not child.is_finished:
                raise RuntimeError("The child run is not finished: seal its run_end first (§4 rule 3).")
            end = child.artifacts[-1]
            disposition = _str((end.envelope.get("step") or {}).get("runDisposition"))
            return self.complete_delegation(child.correlation_id, end.signature_sha256, disposition)
        if child is None:
            raise ValueError("child is required.")
        if child_disposition not in _DISPOSITIONS:
            raise ValueError("child_disposition must be completed, failed or aborted.")
        with self._lock:
            self._ensure_open()
            if child not in self._outstanding:
                raise RuntimeError(f"'{child}' already has its result (§4 rule 4)." if child in self._resolved
                                   else f"This run never delegated to '{child}'.")
            block = {
                "childCorrelationId": child,
                "childRunEndSignatureSha256": child_run_end_signature_sha256,
                "childDisposition": child_disposition,
            }
            artifact = self._seal_event("delegation_result", [], {"delegation": block}, consequential=False)
            del self._outstanding[child]
            self._resolved.add(child)
        self._notify(artifact, artifact.seq)
        return artifact

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
            "schemaVersion": self._schema_version,
            "evidenceId": str(uuid.uuid4()),
            "createdAt": _format_time(now),
            "actor": actor,
            "activity": {"name": self._activity, "correlationId": self.correlation_id},
            "chain": chain,
            "step": step,
        }
        if seq == 0:
            binds = {"controlArtifactSignatureSha256": self.control_artifact.signature_sha256}
            if self._parent is not None:
                binds["parentDelegationSignatureSha256"] = self._parent.delegation_signature_sha256
                binds["parentCorrelationId"] = self._parent.parent_correlation_id
            envelope["binds"] = binds
        envelope["objects"] = _objects_block(objects)
        digests = _digests(objects)
        self._check_uri_reuse(digests)
        _prevalidate(envelope, _execution_schema_for(envelope))  # raises before anything is sealed
        try:
            result = _seal(self._client, envelope, _signed_digests(objects), EXECUTION_EVIDENCE_CONTENT_TYPE,
                           self._certificate_id, timestamp=stamp,
                           qualified=self._qualified or (step_type == "run_end"
                                                         and bool(self._qualified_for & QualifiedArtifacts.RUN_END)))
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
            self._sealed_digests.update(digests)
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

    def _check_uri_reuse(self, digests: Mapping[str, str]) -> None:
        """§5: a URI used again in this run must name the same content (the verifier fails it otherwise)."""
        for uri, hex_ in digests.items():
            earlier = self._sealed_digests.get(uri)
            if earlier is not None and earlier != hex_:
                raise ValueError(f"Object URI '{uri}' was already sealed in this run with different content.")

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


class AgentRunCallbackError(SigillError):
    """An ``on_artifact_sealed`` callback failed while the run was starting.

    The run itself started: the Control Artifact and ``run_start`` are sealed,
    and :attr:`run` carries on from there. The callback's exception is the
    ``__cause__``.
    """

    def __init__(self, run: "AgentRun", cause: BaseException) -> None:
        super().__init__(f"The run started, but an on_artifact_sealed callback failed: {cause}")
        self.run = run


_RANK = {"PASS": 0, "INDETERMINATE": 1, "FAIL": 2}
_STATUSES = ("approved_before_run", "approved_after_start", "unapproved")
_POLICY_APPROVAL_CONTENT_TYPE = "application/vnd.sigill.policy-approval+json"


def _worst(results: Sequence[str]) -> str:
    """§2: overall is derived from the results, never asserted."""
    worst = "PASS"
    for r in results:
        if _RANK[r] > _RANK[worst]:
            worst = r
    return worst


class ControlEvaluation:
    """Seals a Control Evaluation: what an independent verifier observed after a
    run and how each control came out (``spec/control-evaluation-v1.md``), or a
    v2 policy or attested evaluation (``spec/control-evaluation-v2.md``), built
    with :meth:`prepare_policy` or :meth:`prepare_attested`. Always timestamped.
    Seal it with the verifier's own certificate."""

    @staticmethod
    def seal(client: Any, request: "ControlEvaluationRequest | PreparedEvaluation",
             certificate_id: Optional[str] = None, *, qualified: bool = False,
             _clock: Optional[Callable[[], datetime]] = None) -> AgentRunArtifact:
        """Seals a v1 :class:`ControlEvaluationRequest`, or signs a :class:`PreparedEvaluation` through the
        blind sealing endpoint with ``certificate_id`` (and ``qualified``).

        :raises ValueError: the evaluation would not verify; nothing was sealed."""
        if request is None:
            raise ValueError("request is required.")
        if isinstance(request, PreparedEvaluation):
            if certificate_id is None:
                raise ValueError("certificate_id is required to seal a prepared evaluation.")
            result = _seal(client, request.envelope, request.objects, CONTROL_EVALUATION_CONTENT_TYPE,
                           str(certificate_id), timestamp=True, qualified=qualified,
                           reused_uris=frozenset(request.reused_uris))
            if result.timestamped_by is None:
                raise SigillError("A Control Evaluation must be timestamped, but the seal carries no timestamp.")
            return ControlEvaluation.complete(request, result.signature)
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
        reused: set[str] = set()

        def reuse(o: dict) -> None:
            # The control set and baseline are referred to by the Control Artifact's own URI and digest; no bytes.
            uri = o["uri"]
            reused.add(uri)
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
                       timestamp=True, qualified=request.qualified, reused_uris=frozenset(reused))
        if result.timestamped_by is None:
            raise SigillError("A Control Evaluation must be timestamped, but the seal carries no timestamp.")
        return AgentRunArtifact(envelope, result.signature, digests)

    @staticmethod
    def prepare_policy(request: PolicyEvaluationRequest, *,
                       _clock: Optional[Callable[[], datetime]] = None) -> PreparedEvaluation:
        """Builds a policy evaluation (``spec/control-evaluation-v2.md`` §4) ready to sign. Nothing is sent.

        :raises ValueError: the evaluation would not verify."""
        if request is None:
            raise ValueError("request is required.")
        control = request.control_artifact
        if control is None:
            raise ValueError("control_artifact is required.")
        doc = request.control_set_document
        if doc is None:
            raise ValueError("control_set_document is required.")
        problems = AgentPolicy.validate(doc)
        if problems:
            raise ValueError("Invalid policy control set: " + "; ".join(problems))
        policy_doc = json.loads(doc)
        cedar = policy_doc.get("cedar")
        if not isinstance(cedar, dict):
            raise ValueError("The control set carries no Cedar rules.")
        cs_uri, cs_node = _control_set_object(control, doc)
        if _str(cs_node.get("contentType")) != POLICY_CONTROL_SET_CONTENT_TYPE:
            raise ValueError("The Control Artifact's control set is not a policy control set.")
        if request.policy_status not in _STATUSES:
            raise ValueError(f"Unknown policy status '{request.policy_status or ''}'.")
        if (request.policy_status == "unapproved") != (request.approval_record is None):
            raise ValueError("approval_record is required exactly when the policy status is not unapproved.")
        declares_private = isinstance(policy_doc.get("privateControls"), list) and len(policy_doc["privateControls"]) > 0
        if declares_private != (request.private_controls_reported is not None):
            raise ValueError("private_controls_reported is required exactly when the control set declares private "
                             "controls.")

        agent_id = _str((_obj(control.envelope.get("agent")) or {}).get("id"))
        if agent_id is None:
            raise ValueError("The Control Artifact names no agent.")
        correlation_id = _str((_obj(control.envelope.get("activity")) or {}).get("correlationId"))
        if correlation_id is None:
            raise ValueError("The Control Artifact has no correlationId.")
        events = sorted(request.events or [], key=lambda e: (e.seq is not None, e.seq or 0))
        if not events:
            raise ValueError("events must hold the evaluated prefix, starting at seq 0.")
        facts = _build_facts(agent_id, correlation_id, [e.envelope for e in events], list(request.missing_seqs or []))
        if facts.missing_seqs and facts.missing_seqs[0] != facts.through_seq + 1:
            raise ValueError("missing_seqs must start right after the evaluated prefix.")
        last = events[-1]
        run_end = next((e for e in events if e.step_type == "run_end"), None)
        finalized = run_end is not None and not facts.missing_seqs

        rules = list(request.rules or [])
        rule_ids = list(cedar["policies"]["staticPolicies"])
        if set(rule_ids) != {r.id for r in rules} or len(rules) != len(rule_ids):
            raise ValueError("rules must hold exactly one result per Cedar rule of the control set.")
        for r in rules:
            if r.result not in _RANK:
                raise ValueError(f"Rule '{r.id}': unknown result '{r.result}'.")
            if (r.result == "PASS") != (not r.where):
                raise ValueError(f"Rule '{r.id}': where is required exactly when the result is not PASS.")

        now = _truncate((_clock or _utcnow)())
        objects: list[dict] = [copy.deepcopy(cs_node)]
        seal = [SignedObjectDigest(uri=cs_uri, hash_hex=control.object_digests[cs_uri],
                                   content_type=POLICY_CONTROL_SET_CONTENT_TYPE)]
        digests = {cs_uri: control.object_digests[cs_uri]}
        payloads = {cs_uri: bytes(doc)}

        def add(uri: str, role: str, content_type: str, data: bytes) -> None:
            hex_ = hash_bytes(data)
            objects.append({"uri": uri, "role": role, "contentType": content_type, "sizeBytes": len(data)})
            seal.append(SignedObjectDigest(uri=uri, hash_hex=hex_, content_type=content_type))
            digests[uri] = hex_
            payloads[uri] = bytes(data)
        add(new_object_uri(), "evaluation-facts", "application/json", facts.data)
        if request.approval_record is not None:
            add(new_object_uri(), "policy-approval", _POLICY_APPROVAL_CONTENT_TYPE, request.approval_record)

        policy_digests = AgentPolicy.compute_digests(doc)
        control_sig = control.signature_sha256
        if control_sig is None:
            raise ValueError("The Control Artifact carries no classical signature.")
        through_sig = last.signature_sha256
        if through_sig is None:
            raise ValueError("An event carries no classical signature.")
        subject = {"controlArtifactSignatureSha256": control_sig, "throughSignatureSha256": through_sig}
        if finalized:
            subject["runEndSignatureSha256"] = run_end.signature_sha256
        policy: dict = {
            "approvalScopeDigest": policy_digests.approval_scope_digest,
            "cedarDigest": policy_digests.cedar_digest,
            "policyStatus": request.policy_status,
            "evaluator": {"engine": request.engine, "factsVersion": FACTS_VERSION,
                          "schemaSha256": _str(cedar.get("schemaSha256"))},
            "prefix": {
                "throughSeq": facts.through_seq,
                "finalSeq": None if run_end is None else _int((_obj(run_end.envelope.get("step")) or {}).get("finalSeq")),
                "missingSeqs": list(facts.missing_seqs),
            },
            "state": "finalized" if finalized else "partial",
        }
        if request.private_controls_reported is not None:
            policy["privateControlsReported"] = request.private_controls_reported
        controls = []
        for r in rules:
            j: dict = {"id": r.id, "result": r.result}
            if r.where:
                j["where"] = list(r.where)
            if r.detail is not None:
                j["detail"] = r.detail
            controls.append(j)
        envelope = _evaluation_envelope("policy", "verifier", request.evaluator_id, request.evaluator_version, control,
                                        subject, now, request.evaluated_at, controls, [r.result for r in rules],
                                        objects, request.supersedes)
        envelope["policy"] = policy
        return _prepared(envelope, seal, [cs_uri], digests, payloads)

    @staticmethod
    def prepare_attested(request: AttestedEvaluationRequest, *,
                         _clock: Optional[Callable[[], datetime]] = None) -> PreparedEvaluation:
        """Builds an attested evaluation (``spec/control-evaluation-v2.md`` §5) ready to sign. Nothing is sent.

        :raises ValueError: the evaluation would not verify."""
        if request is None:
            raise ValueError("request is required.")
        control = request.control_artifact
        if control is None:
            raise ValueError("control_artifact is required.")
        if request.run_end is None or request.run_end.step_type != "run_end":
            raise ValueError("run_end must be the run's run_end artifact.")
        doc = request.control_set_document
        if doc is None:
            raise ValueError("control_set_document is required.")
        cs_uri, cs_node = _control_set_object(control, doc)
        parsed = json.loads(doc)
        private = parsed.get("privateControls") if isinstance(parsed, dict) else None
        declared = [x["id"] for x in (private if isinstance(private, list) else [])
                    if isinstance(x, dict) and isinstance(x.get("id"), str)]
        controls = list(request.controls or [])
        if not declared:
            raise ValueError("The control set declares no private controls.")
        if set(declared) != {c.id for c in controls} or len(controls) != len(declared):
            raise ValueError("controls must hold exactly one result per declared private control.")
        if any(c.result not in _RANK for c in controls):
            raise ValueError("A control has an unknown result.")

        control_sig = control.signature_sha256
        if control_sig is None:
            raise ValueError("The Control Artifact carries no classical signature.")
        run_end_sig = request.run_end.signature_sha256
        if run_end_sig is None:
            raise ValueError("run_end carries no classical signature.")
        subject = {"controlArtifactSignatureSha256": control_sig, "runEndSignatureSha256": run_end_sig}
        results = []
        for c in controls:
            j: dict = {"id": c.id, "result": c.result}
            if c.detail is not None:
                j["detail"] = c.detail
            results.append(j)
        envelope = _evaluation_envelope("attested", "producer", request.producer_id, request.producer_version, control,
                                        subject, _truncate((_clock or _utcnow)()), request.evaluated_at, results,
                                        [c.result for c in controls], [copy.deepcopy(cs_node)], request.supersedes)
        if request.evaluator_id is not None or request.evaluator_version is not None:
            a: dict = {}
            if request.evaluator_id is not None:
                a["evaluatorId"] = request.evaluator_id
            if request.evaluator_version is not None:
                a["evaluatorVersion"] = request.evaluator_version
            envelope["attested"] = a
        hex_ = control.object_digests[cs_uri]
        return _prepared(envelope, [SignedObjectDigest(uri=cs_uri, hash_hex=hex_,
                                                       content_type=_str(cs_node.get("contentType")))],
                         [cs_uri], {cs_uri: hex_}, {cs_uri: bytes(doc)})

    @staticmethod
    def complete(prepared: PreparedEvaluation, signature: dict) -> AgentRunArtifact:
        """The evaluation artifact, once ``signature`` (a JAdES JWS over the prepared hashes) exists."""
        return AgentRunArtifact(prepared.envelope, signature, dict(prepared.object_digests))


def _control_set_object(control: AgentRunArtifact, doc: bytes) -> tuple[str, dict]:
    objs = control.envelope.get("objects")
    node = next((o for o in (objs if isinstance(objs, list) else [])
                 if isinstance(o, dict) and o.get("role") == "control-set"), None)
    if node is None:
        raise ValueError("The Control Artifact carries no control-set object.")
    uri = _str(node.get("uri"))
    if control.object_digests.get(uri) != hash_bytes(doc):
        raise ValueError("control_set_document is not the control set sealed in the Control Artifact.")
    return uri, node


def _evaluation_envelope(kind: str, actor_type: str, actor_id: str, actor_version: str, control: AgentRunArtifact,
                         subject: dict, now: datetime, evaluated_at: Optional[datetime], controls: list[dict],
                         results: Sequence[str], objects: list[dict],
                         supersedes: Optional[EvaluationReference]) -> dict:
    envelope = {
        "schemaName": CONTROL_EVALUATION_SCHEMA,
        "schemaVersion": "2",
        "kind": kind,
        "evidenceId": str(uuid.uuid4()),
        "createdAt": _format_time(now),
        "actor": {"type": actor_type, "id": actor_id, "version": actor_version},
        "activity": copy.deepcopy(control.envelope.get("activity")),
        "subject": subject,
        "controlSet": copy.deepcopy(control.envelope.get("controlSet")),
        "controls": controls,
        "overall": _worst(results),
        "evaluatedAt": _format_time(_truncate(evaluated_at or now)),
        "objects": objects,
    }
    if supersedes is not None:
        envelope["supersedes"] = {"evidenceId": supersedes.evidence_id, "signatureSha256": supersedes.signature_sha256}
    return envelope


def _prepared(envelope: dict, seal: list[SignedObjectDigest], reused: Sequence[str], digests: dict[str, str],
              payloads: dict[str, bytes]) -> PreparedEvaluation:
    _prevalidate(envelope, CONTROL_EVALUATION_SCHEMA_V2)
    return PreparedEvaluation(envelope, hash_bytes(canonicalize(envelope)), seal, frozenset(reused), digests, payloads)


def seal_control_evaluation(client: Any, request: ControlEvaluationRequest) -> AgentRunArtifact:
    """Seals a Control Evaluation of a finished run. See :class:`ControlEvaluation`."""
    return ControlEvaluation.seal(client, request)
