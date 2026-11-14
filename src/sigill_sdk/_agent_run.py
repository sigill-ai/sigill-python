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
import time
import uuid
from dataclasses import dataclass, field, replace
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
    AgentRunDelivery,
    AgentRunObject,
    AgentTimestampPolicy,
    ApprovalCovers,
    AttestedEvaluationRequest,
    ControlEvaluationRequest,
    EvaluationReference,
    ModelCall,
    PolicyEvaluationRequest,
    PreparedEvaluation,
    QualifiedArtifacts,
)
from sigill_sdk._agent_guard import (
    Enforcement,
    EnforcementEvent,
    PolicyDenied,
    RunHalted,
    StartRefused,
    _guard_for,
    _Guard,
)
from sigill_sdk._agent_policy import FACTS_VERSION, POLICY_CONTROL_SET_CONTENT_TYPE, AgentPolicy, _build_facts, _is_v2
from sigill_sdk._agent_policy import _parse as _parse_control_set
from sigill_sdk._canonical import canonicalize, hash_bytes
from sigill_sdk._errors import SigillError
from sigill_sdk._references import new_object_uri
from sigill_sdk._sign_objects import SignedObjectDigest

# "enforcer" and "rules" too: the recorder offers no way to write an enforcement record or a guard-looking denial.
_RESERVED_STEP_FIELDS = frozenset({
    "type", "eventTime", "consequential", "timestamp", "finalSeq", "finalPrevSignatureSha256", "runDisposition",
    "delegation", "model", "vendorRefs", "usage", "covers", "enforcer", "rules",
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


# Common rules §9: the caller's free text is bounded at record time (a producer rule; the schemas are unchanged).
_MAX_DETAIL, _MAX_ACTIVITY_NAME, _MAX_APPROVER, _MAX_JSON_BYTES = 512, 255, 255, 2048


def _check_free_text(envelope: dict) -> None:
    """Refuses, before sealing, a ``detail``, activity name, approver reference, object ``metadata`` or the envelope's
    ``extensions`` over its limit. Characters are Unicode code points; metadata and extensions are the UTF-8 length of
    their JSON in the envelope. The error names the field and the limit, never the value; nothing is shortened."""
    step = envelope.get("step") if isinstance(envelope.get("step"), dict) else {}
    activity = envelope.get("activity") if isinstance(envelope.get("activity"), dict) else {}
    for name, value, limit in (("activity.name", activity.get("name"), _MAX_ACTIVITY_NAME),
                               ("step.detail", step.get("detail"), _MAX_DETAIL),
                               ("step.approver", step.get("approver"), _MAX_APPROVER)):
        if isinstance(value, str) and len(value) > limit:
            raise ValueError(f"{name} is longer than {limit} characters; the SDK refuses it (common rules §9).")
    members = [("objects[].metadata", o["metadata"]) for o in envelope.get("objects") or []
               if isinstance(o, dict) and "metadata" in o]
    if "extensions" in envelope:
        members.append(("extensions", envelope["extensions"]))
    for name, value in members:
        if len(canonicalize(value)) > _MAX_JSON_BYTES:
            raise ValueError(f"{name} is longer than {_MAX_JSON_BYTES} bytes as JSON; the SDK refuses it "
                             f"(common rules §9).")


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


@dataclass
class _Delivery:
    """What the guard sealed after one event, the event to report, and what the recording call raises."""

    sealed: list = field(default_factory=list)
    event: Optional[EnforcementEvent] = None
    error: Optional[BaseException] = None


class _IndexCursor:
    """``deliver_run``: the next artifact to upload to the evidence index (0 is the Control Artifact, k + 1 the event
    at seq k) and how the last attempt went. Uploads run in the callbacks' ordered turns; the lock keeps them in
    chain order, also for an event recorded inside a callback."""

    def __init__(self, document: Optional[bytes], clock: Callable[[], float]) -> None:
        self.lock = threading.RLock()
        self.next = 0
        self.status = "delivered"
        self.run_id: Optional[str] = None
        self.error: Optional[str] = None
        self.document = document  # the policy document, with disclose_policy: it travels on the Control Artifact
        self.clock = clock
        self.backoff = 0.0
        self.not_before = 0.0


_INDEX_TIMEOUT, _INDEX_FINAL_BUDGET, _INDEX_BACKOFF_FIRST, _INDEX_BACKOFF_MAX = 10.0, 30.0, 5.0, 300.0


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
        # v4: each tool_call useId → ("open" | "result" | "denied", its tool name) (enforcement §3.2, §5).
        self._tool_calls: dict[str, tuple[str, Optional[str]]] = {}
        # The guard (enforcement=): what it sealed after an event, kept by seq until the recording call delivers it.
        self._guard: Optional[_Guard] = None
        self._on_event: Optional[Callable[[EnforcementEvent], None]] = None
        self._decisions: dict[int, _Delivery] = {}
        self._halted = threading.Event()
        self._halt: Optional[tuple] = None  # (reason, rules, seq, record) of the halt, for every later RunHalted
        self._run_end: Optional[tuple[str, str]] = None  # (signatureSha256, runDisposition) of the sealed run_end
        self.correlation_id = _correlation_id
        """The run identifier (``activity.correlationId``)."""
        self.control_artifact: AgentRunArtifact = None  # type: ignore[assignment]
        """The run's Control Artifact, sealed before ``run_start``."""
        self.policy_disclosure: Optional[AgentIndexResult] = None
        """Outcome of ``disclose_policy=True``; None when the policy was not shared."""
        self._index: Optional[_IndexCursor] = None  # deliver_run

    @classmethod
    def start(cls, client: Any, agent: AgentDefinition, *, certificate_id: str, activity: str,
              control_set: AgentControlSet, baseline_state: Optional[bytes] = None,
              baseline_state_content_type: str = "application/json", authority: Optional[bytes] = None,
              authority_content_type: str = "application/jwt", control_actor: Optional[AgentRunActor] = None,
              timestamp_policy: Optional[AgentTimestampPolicy] = None, correlation_id: Optional[str] = None,
              start_objects: Optional[Sequence[AgentRunObject]] = None, retain_payloads: bool = False,
              qualified: bool = False, on_artifact_sealed: Optional[Callable[[AgentRunArtifact], None]] = None,
              delegating: bool = False, qualified_for: QualifiedArtifacts = QualifiedArtifacts.NONE,
              disclose_policy: bool = False, records_model_calls: bool = False,
              enforcement: Optional[Enforcement] = None, deliver_run: bool = False,
              _clock: Optional[Callable[[], datetime]] = None, _parent: Optional[AgentDelegation] = None,
              _index_clock: Optional[Callable[[], float]] = None) -> "AgentRun":
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
            once it delegates. Child runs (:meth:`start_child`) use version 2 (or 3 with ``records_model_calls``).
        :param records_model_calls: the run records model calls with the provider's own identifiers
            (:meth:`record_model_call`, ``spec/agent-model-calls-v1.md``). Every event is sealed as
            ``schemaVersion "3"`` — v3 contains v2, so such a run can also delegate. Decided at start: one run
            uses one version. A run whose ``control_set`` is a v2 policy control set (``schemaVersion "2"``) is
            sealed as ``schemaVersion "4"`` (``spec/agent-enforcement-v1.md``), which contains v3: every tool call
            then carries a unique use id.
        :param qualified_for: request qualified timestamps for these artifacts only, in addition to
            ``qualified``: the Control Artifact and ``run_end`` are the ones a declared policy rests on.
        :param disclose_policy: **preview** — share the declared policy with your Sigill organisation's evidence index:
            after the Control Artifact is sealed, upload its signed envelope (metadata and digests, no
            content) together with the control-set document, so the organisation can review, approve and
            track the policy. Requires an :class:`AgentPolicy` control set. Off by default. The upload never
            fails the run; its outcome is :attr:`policy_disclosure`. Execution events are not uploaded — unless
            ``deliver_run`` is also set: then the document travels on the Control Artifact's upload, and
            :attr:`policy_disclosure` is that upload's outcome.
        :param deliver_run: upload each artifact, as it is sealed, to your Sigill organisation's evidence index, so
            the run is shown there: its steps, the guard's refusals, alerts. Off by default, and decided per run: a
            child run delivers only when it is started with ``deliver_run=True`` itself. What leaves the machine,
            exactly: each artifact's signed envelope, signature and object digests. That is: the agent id and
            version, the activity name and run id, step types and times, tool names, operations and use ids, rule
            ids and guard reasons, model and provider request ids, token counts, approver references, sub-agent
            ids, object URIs, content types and sizes, and any ``detail`` text — that, and the names and identifiers
            you chose, are your own text and are uploaded as written. Never arguments, results, prompts, outputs or
            receipts; the policy document only with ``disclose_policy``. Each upload runs in the artifact's callback
            turn, after ``on_artifact_sealed`` (and ``on_event``), in chain order. A delivery failure never raises,
            never breaks or halts the run: a temporary failure is retried at a later step after a back-off,
            ``run_end`` makes one last attempt, and :attr:`delivery` says where it stands;
            :meth:`SigillClient.deliver_agent_run` delivers a bundle later. Requires a :class:`SigillClient`.
        :param enforcement: the guard (``spec/agent-policy-control-set-v2.md`` §7): required by a v2 policy control
            set with ``enforcement.mode: "enforce"``, which it then validates strictly before anything is sealed. Each
            event is decided after it is sealed: a denied tool call raises :class:`PolicyDenied`, a halt
            :class:`RunHalted`, a refused start :class:`StartRefused` — each after the decision is sealed. With
            any other control set the engine only reports matching rules to ``on_event``.
        :raises ValueError: an enforcing control set without ``enforcement``, or one that fails strict validation, or
            ``deliver_run`` with a client other than :class:`SigillClient`; nothing was sealed.
        :raises StartRefused: the guard refused the start (§7.4); the closed run is its ``run``.
        """
        if control_set is None:
            raise ValueError("control_set is required.")
        if isinstance(control_set.content, (bytearray, memoryview)):
            # One private copy, read from here on: the document validated, enforced and sealed is the same one.
            control_set = replace(control_set, content=bytes(control_set.content))
        policy = timestamp_policy or AgentTimestampPolicy()
        _validate_policy(policy)
        _validate_control_set(control_set, disclose_policy)
        if deliver_run:
            from sigill_sdk._client import SigillClient  # here: the client module imports this one
            if not isinstance(client, SigillClient):
                raise ValueError("deliver_run requires a SigillClient: only the SDK's own client delivers to the "
                                 "evidence index.")
        if _parent is not None and getattr(_parent, "_parent_run", None) is not None and _parent._parent_run.halted:
            raise _parent._parent_run._halted_error()  # §7.3: the child of a halted parent is never started
        guard = _guard_for(control_set, enforcement, agent.agent_id, _parent is not None)
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
                  _schema_version="4" if control_set.content_type == POLICY_CONTROL_SET_CONTENT_TYPE
                  and _is_v2(control_set.content) else "3" if records_model_calls
                  else "2" if delegating or _parent is not None else "1", _parent=_parent,
                  _qualified_for=QualifiedArtifacts(qualified_for))
        run._guard = guard
        run._on_event = enforcement.on_event if enforcement is not None else None
        if deliver_run:
            run._index = _IndexCursor(control_set.content if disclose_policy else None, _index_clock or time.monotonic)

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
            if data is not None:  # a private copy: the digests sealed and the payloads kept are of the same bytes
                objects.append(AgentRunObject(role, bytes(data) if isinstance(data, (bytearray, memoryview)) else data,
                                              ctype))

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
        _check_free_text(envelope)
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
        if disclose_policy and not deliver_run:  # with deliver_run, the document travels on the first upload
            # Sharing is a side channel: it never fails the run (the evidence is in the producer's bundle either way).
            try:
                upload = getattr(client, "_index_agent_artifact", None)
                run.policy_disclosure = upload(run.control_artifact, control_set.content) if upload else \
                    AgentIndexResult("failed", error="Only SigillClient can share a policy with the evidence index.")
            except Exception as ex:  # noqa: BLE001
                run.policy_disclosure = AgentIndexResult("failed", error=str(ex))
        # Both are delivered even when the first callback fails: later events wait for their turn in order. A
        # refused start raises StartRefused here, after both and the guard's events are delivered.
        failure = run._deliver(start, ((run.control_artifact, -1),))
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
    def delivery(self) -> Optional[AgentRunDelivery]:
        """Where delivery to the evidence index stands (``deliver_run=True``); None when it was not requested."""
        cursor = self._index
        if cursor is None:
            return None
        sealed = (self.control_artifact is not None) + len(self._artifacts)
        return AgentRunDelivery(cursor.status, cursor.next, sealed - cursor.next, cursor.run_id, cursor.error)

    @property
    def halted(self) -> bool:
        """The guard halted the run (its halting ``run_end`` is sealed): every further recording call raises
        :class:`RunHalted`, and :meth:`finish` returns the bundle."""
        return self._halted.is_set()

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
        # Check what will be sealed, not the caller's objects: a str or dict subclass can make a check on the
        # original miss a member that the JSON round trip still writes.
        step_type = json.loads(json.dumps(step_type))
        fields = json.loads(json.dumps(fields or {}))
        if step_type in ("run_start", "run_end"):
            raise ValueError(f"'{step_type}' is sealed by start() / finish().")
        if step_type in ("delegation", "delegation_result"):
            raise ValueError(f"'{step_type}' is sealed by delegate() / complete_delegation().")
        reserved = sorted(_RESERVED_STEP_FIELDS.intersection(fields if isinstance(fields, dict) else {}))
        if reserved:
            raise ValueError(f"fields uses reserved step member(s): {', '.join(reserved)}")
        return self._record_internal(step_type, objects, fields, consequential, require_timestamp)

    def _record_internal(self, step_type: str, objects: Optional[Sequence[AgentRunObject]], fields: Optional[dict],
                         consequential: bool, require_timestamp: bool = False, *,
                         call: Optional["ToolCall"] = None) -> AgentRunArtifact:
        """Seals one event whose step members are already checked (reserved members only from this class). Every
        tool_call and tool_result of the run passes here, under the lock; ``call`` is the :class:`ToolCall` a
        tool_result completes."""
        with self._lock:
            self._ensure_open()
            if call is not None and call._result is not None:
                raise RuntimeError(f"Tool call '{call.use_id}' already has its result.")
            # Keep the last slot for run_end, and one per open delegation for its result (delegation §4 rule 6),
            # so a bundle always fits MAX_ARTIFACTS and can finish. In enforce mode also one for an enforcement
            # record before the halt (enforcement §4 rule 4), and a tool_call one more for the record that may deny it.
            open_ = len(self._outstanding)
            guard = 0 if not self._enforcing else 2 if step_type == "tool_call" else 1
            if len(self._artifacts) >= MAX_ARTIFACTS - 1 - open_ - guard:
                raise RuntimeError(
                    f"The run has {len(self._artifacts)} events; the rest of the bundle limit of {MAX_ARTIFACTS} is "
                    f"reserved for run_end, the guard's enforcement record(s) and {open_} delegation result(s)."
                    if guard else
                    f"The run has {len(self._artifacts)} events; only run_end fits within the bundle limit of "
                    f"{MAX_ARTIFACTS}. Finish the run." if open_ == 0 else
                    f"The run has {len(self._artifacts)} events; the rest of the bundle limit of {MAX_ARTIFACTS} is "
                    f"reserved for run_end and {open_} delegation result(s).")
            step = json.loads(json.dumps(fields or {}))
            if require_timestamp:
                step["timestamp"] = "required"
            # v4: refuse before sealing what the verifier would report (enforcement §5): a reused call useId, a
            # result for no earlier call (orphan_result), a second result (conflicting_result), a result naming
            # another tool than its call (§3.2).
            v4_tool = self._schema_version == "4" and step_type in ("tool_call", "tool_result")
            tool = _obj(step.get("tool")) or {}
            use_id = _str(tool.get("useId")) if v4_tool else None
            state, called = self._tool_calls.get(use_id, (None, None)) if use_id is not None else (None, None)
            if use_id is not None and step_type == "tool_call" and state is not None:
                raise ValueError(f"use_id '{use_id}' is already used by a tool_call of this run; a retry is a new call "
                                 f"with a new use id (enforcement §3.2).")
            if use_id is not None and step_type == "tool_result":
                if state != "open":
                    raise ValueError(f"No tool_call of this run with use_id '{use_id}' awaits a result." if state is None
                                     else f"The tool_call with use_id '{use_id}' was denied; it has no result."
                                     if state == "denied" else
                                     f"The tool_call with use_id '{use_id}' already has its result.")
                if tool.get("name") != called:
                    raise ValueError(f"The tool_call with use_id '{use_id}' was made to tool '{called}'; its result "
                                     f"cannot name another tool.")
            artifact = self._seal_event(step_type, list(objects or []), step, consequential=consequential)
            if use_id is not None and step_type == "tool_call":
                self._tool_calls.setdefault(use_id, ("open", _str(tool.get("name"))))  # unless the guard denied it
            elif use_id is not None:
                self._tool_calls[use_id] = ("result", called)
            if call is not None:
                call._result = artifact
        self._notify_all(artifact)
        if step_type == "tool_call" and self._guard is not None:  # enforcement §4 rule 2: a callback may have
            self._ensure_not_stopped()                            # halted the run meanwhile
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
        ``use_id`` correlates the call with its result. In a ``schemaVersion "4"`` run (a v2 policy control set)
        every call has one, unique in the run: it is generated when not given. :meth:`begin_tool_call` pairs
        the result for you. In an enforced run a denied call raises :class:`PolicyDenied` after it is sealed.
        The run's state is checked once more after the call's callbacks have run and, in :meth:`invoke_tool`,
        immediately before the function is called; a halt sealed by another thread after that check does not stop
        the function."""
        if use_id is None and self._schema_version == "4":
            use_id = str(uuid.uuid4())
        return self.record("tool_call", [AgentRunObject("tool-arguments", arguments, content_type)],
                           {"tool": _tool_block(tool, operation, use_id)}, consequential=consequential)

    def record_tool_result(self, tool: str, result: bytes, *, content_type: str = "application/json",
                           use_id: Optional[str] = None) -> AgentRunArtifact:
        """The result a tool returned — context for the model's next turn. In a ``schemaVersion "4"`` run it must
        name its call's ``use_id``."""
        if use_id is None and self._schema_version == "4":
            raise ValueError("In a schemaVersion 4 run a tool_result names its call: use_id is required.")
        return self.record("tool_result", [AgentRunObject("tool-result", result, content_type)],
                           {"tool": _tool_block(tool, None, use_id)})

    def begin_tool_call(self, tool: str, arguments: bytes, *, operation: Optional[str] = None,
                        consequential: bool = False, content_type: str = "application/json",
                        use_id: Optional[str] = None, definition: Optional[bytes] = None) -> "ToolCall":
        """Seals the ``tool_call`` and returns the :class:`ToolCall` whose :meth:`ToolCall.complete` seals its
        ``tool_result`` with the same tool name and use id. ``use_id`` is generated when not given.
        ``definition`` is the tool's definition as the runtime holds it (e.g. its entry in the tool manifest),
        sealed as a digest-only ``tool-definition`` object (``schemaVersion "4"`` only).

        ::

            call = run.begin_tool_call("crm.read_customer", args_json, operation="read")
            result = execute(args_json)
            call.complete(result)

        :raises RuntimeError: ``definition`` in a run that is not ``schemaVersion "4"``.
        :raises ValueError: the call would not verify, or reuses a use id (v4); nothing was sealed and the run
            stays usable.
        :raises PolicyDenied: the guard denied the call (after sealing it and its enforcement record): do not
            execute the tool.
        :raises RunHalted: the run is halted. The run's state is checked once more after the call's callbacks have run
            and, in :meth:`invoke_tool`, immediately before the function is called; a halt sealed by another thread
            after that check does not stop the function."""
        if definition is not None and self._schema_version != "4":
            raise RuntimeError("A tool-definition object needs a v2 policy control set (schemaVersion 4).")
        use_id = use_id if use_id is not None else str(uuid.uuid4())
        objects = [AgentRunObject("tool-arguments", arguments, content_type)]
        if definition is not None:
            objects.append(AgentRunObject("tool-definition", definition, "application/json"))
        artifact = self._record_internal("tool_call", objects, {"tool": _tool_block(tool, operation, use_id)},
                                         consequential)
        return ToolCall(self, tool, use_id, artifact)

    def invoke_tool(self, tool: str, arguments: bytes, func: Callable[[], bytes], *, operation: Optional[str] = None,
                    consequential: bool = False, content_type: str = "application/json", use_id: Optional[str] = None,
                    definition: Optional[bytes] = None) -> bytes:
        """Begins the call (:meth:`begin_tool_call`), runs ``func()`` only if it is allowed, seals what it returns as
        the call's result and returns it. A denied call raises :class:`PolicyDenied` and ``func`` never runs; an
        exception from ``func`` seals no result. The run's state is checked once more after the call's callbacks
        have run and, in ``invoke_tool``, immediately before the function is called; a halt sealed by another thread
        after that check does not stop the function."""
        call = self.begin_tool_call(tool, arguments, operation=operation, consequential=consequential,
                                    content_type=content_type, use_id=use_id, definition=definition)
        self._ensure_not_stopped()  # the run may have been halted since the call was allowed (enforcement §4 rule 2)
        result = func()
        call.complete(result)
        return result

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
                              identity_assertion_content_type: str = "application/jwt",
                              covers: Optional[ApprovalCovers] = None) -> AgentRunArtifact:
        """A human approval: ``decision`` is ``approved`` or ``rejected``.
        ``approver`` is an opaque identifier — never a name or e-mail address.
        What the approval covers (the receipt) and an identity assertion (e.g.
        an IdP token) are bound as detached objects; their bytes stay local.
        ``covers`` names the call it is for — a tool and the digest of its exact arguments
        (``spec/agent-enforcement-v1.md`` §3.5); it requires ``schemaVersion "4"``.

        :raises RuntimeError: ``covers`` in a run that is not ``schemaVersion "4"``."""
        fields: dict = {"decision": decision}
        if approver is not None:
            fields["approver"] = approver
        if covers is not None:
            if self._schema_version != "4":
                raise RuntimeError("covers needs a v2 policy control set (schemaVersion 4).")
            block: dict = {"tool": covers.tool, "argumentsSha256": covers.arguments_sha256}
            if covers.use_id is not None:
                block["useId"] = covers.use_id
            if covers.expires_at is not None:
                if covers.expires_at.tzinfo is None or covers.expires_at.utcoffset() is None:
                    raise ValueError("covers.expires_at must be timezone-aware: a naive datetime names no instant.")
                try:
                    block["expiresAt"] = _format_time(_truncate(covers.expires_at))
                except OverflowError:
                    raise ValueError("covers.expires_at lies outside years 1-9999 in UTC.") from None
            fields["covers"] = block
        objects = []
        if receipt is not None:
            objects.append(AgentRunObject("approval-receipt", receipt, receipt_content_type))
        if identity_assertion is not None:
            objects.append(AgentRunObject("identity-assertion", identity_assertion, identity_assertion_content_type))
        return self._record_internal("human_approval", objects, _detail(fields, detail), False)

    def record_model_output(self, output: bytes, content_type: str = "text/plain", *,
                            consequential: bool = False) -> AgentRunArtifact:
        """What the model produced."""
        return self.record("model_output", [AgentRunObject("model-output", output, content_type)],
                           consequential=consequential)

    def record_model_call(self, call: ModelCall, request: Optional[bytes] = None, response: Optional[bytes] = None,
                          request_content_type: str = "application/json",
                          response_content_type: str = "application/json", *,
                          consequential: bool = False) -> AgentRunArtifact:
        """One model call with the provider's own identifiers (``spec/agent-model-calls-v1.md``): a
        ``model_output`` step carrying ``model``, ``vendorRefs`` and ``usage``, with the request and response as
        digest-only objects (their content never leaves the producer). Requires ``records_model_calls=True``.

        :raises RuntimeError: the run was not started with ``records_model_calls=True``.
        :raises ValueError: a value does not fit the schema; nothing was sealed and the run stays usable.
        """
        if call is None:
            raise ValueError("call is required.")
        if self._schema_version not in ("3", "4"):
            raise RuntimeError("This run was not started with records_model_calls=True; model calls use "
                               "schemaVersion 3 throughout.")
        step: dict = {}
        m = call.model
        if m is not None:
            model: dict = {"provider": m.provider, "served": m.served}
            for key, value in (("requested", m.requested), ("deployment", m.deployment), ("region", m.region)):
                if value is not None:
                    model[key] = value
            step["model"] = model
        if call.vendor_refs:
            step["vendorRefs"] = [{"provider": r.provider, "kind": r.kind, "id": r.id} for r in call.vendor_refs]
        u = call.usage
        if u is not None:
            usage = {k: v for k, v in (("inputTokens", u.input_tokens), ("outputTokens", u.output_tokens),
                                       ("cacheReadTokens", u.cache_read_tokens),
                                       ("cacheWriteTokens", u.cache_write_tokens), ("stopReason", u.stop_reason))
                     if v is not None}
            if usage:
                step["usage"] = usage
        objects = []
        if request is not None:
            objects.append(AgentRunObject("model-input", request, request_content_type))
        if response is not None:
            objects.append(AgentRunObject("model-output", response, response_content_type))
        return self._record_internal("model_output", objects, step, consequential)

    def checkpoint(self, detail: Optional[str] = None) -> AgentRunArtifact:
        """Anchors the chain head with a timestamped ``checkpoint`` — e.g. from
        a timer while a long run is idle, so the head does not wait for
        ``run_end`` to be anchored."""
        return self.record("checkpoint", fields=_detail({}, detail), require_timestamp=True)

    def finish(self, disposition: str = "completed", detail: Optional[str] = None) -> AgentRunBundle:
        """Seals ``run_end`` (always timestamped), closing the run, and returns
        the bundle. ``disposition``: completed | failed | aborted. A run the guard halted is closed already: its
        bundle is returned and nothing more is sealed. With ``deliver_run``, the ``run_end`` turn (or, on a halted run,
        this call) makes one last delivery attempt that ignores the back-off, at most 30 s in total; the outcome is
        :attr:`delivery`."""
        if disposition not in _DISPOSITIONS:
            raise ValueError("disposition must be completed, failed or aborted.")
        with self._lock:
            halted = self._halted.is_set()
            if not halted:
                self._ensure_open()
                if disposition == "completed" and self._outstanding:
                    raise RuntimeError(f"{len(self._outstanding)} delegation(s) have no result: record them first, or "
                                       f"close the run as aborted or failed (delegation §4 rule 5).")
                # finalSeq is run_end's own seq, finalPrev its own chain link (§11): closure is checkable on its own.
                step = {
                    "finalSeq": len(self._artifacts),
                    "finalPrevSignatureSha256": self._prev_signature_sha256,
                    "runDisposition": disposition,
                }
                artifact = self._seal_event("run_end", [], _detail(step, detail), consequential=False)
            bundle = self.to_bundle()
        if halted:
            if self._index is not None:  # one last attempt, past any back-off; its outcome is run.delivery
                self._index_upto(len(bundle.artifacts), final=True)
            return bundle
        self._notify_all(artifact)
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
        if self._schema_version not in ("2", "3", "4"):
            raise RuntimeError("This run was not started with delegating=True; a run that delegates uses "
                               "schemaVersion 2 (or 3) throughout.")
        child = child_correlation_id if child_correlation_id is not None else f"urn:uuid:{uuid.uuid4()}"
        if not child or child == self.correlation_id:
            raise ValueError("A run cannot delegate to itself.")
        with self._lock:
            self._ensure_open()
            if child in self._outstanding or child in self._resolved:
                raise ValueError(f"'{child}' is already delegated by this run (§4 rule 10).")
            # This event, a result for every open delegation including this one, and run_end must fit; in enforce mode
            # also an enforcement record (enforcement §4 rule 4).
            if len(self._artifacts) + 1 + len(self._outstanding) + 1 + 1 + self._enforcing > MAX_ARTIFACTS:
                raise RuntimeError(f"No room for another delegation: the bundle limit of {MAX_ARTIFACTS} is reserved "
                                   f"for run_end and the results of {len(self._outstanding)} open delegation(s)."
                                   if not self._enforcing else
                                   f"No room for another delegation: the bundle limit of {MAX_ARTIFACTS} is reserved "
                                   f"for run_end, the guard's enforcement record and the results of "
                                   f"{len(self._outstanding)} open delegation(s).")
            block: dict = {"childCorrelationId": child, "childAgentId": child_agent_id}
            if use_id is not None:
                block["useId"] = use_id
            objects = [] if instruction is None else \
                [AgentRunObject("delegation-input", instruction, instruction_content_type)]
            artifact = self._seal_event("delegation", objects, {"delegation": block}, consequential=consequential)
            self._outstanding[child] = artifact.seq
        self._notify_all(artifact)  # a halt on this delegation raises RunHalted: the child is never started
        return AgentDelegation(self.correlation_id, artifact.signature_sha256, child, child_agent_id,
                               artifact=artifact, _parent_run=self)

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
            return self.complete_delegation(child.correlation_id, *child._run_end)
        if child is None:
            raise ValueError("child is required.")
        # Enforcement §3.6: only a v4 parent can record a child its guard halted.
        if child_disposition not in _DISPOSITIONS + (("halted",) if self._schema_version == "4" else ()):
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
        self._notify_all(artifact)
        return artifact

    # ── sealing ──

    def _seal_event(self, step_type: str, objects: list[AgentRunObject], fields: dict, *,
                    consequential: bool, _by_guard: bool = False) -> AgentRunArtifact:
        """Builds, validates and seals one event. Call with the lock held (or
        before the run is published); the callback is the caller's job. Every
        event passes here, so the guard decides each one right after it is sealed."""
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
        _check_free_text(envelope)
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
                # What a parent's delegation_result records, kept apart from the artifact the caller can edit.
                self._run_end = (link, step["runDisposition"])
            if self._retain:
                self._payloads.update({o.uri: o.data for o in objects})
        except BaseException:
            self._broken = True
            raise
        if self._guard is not None:
            self._apply_guard(artifact, not _by_guard)
        return artifact

    def _apply_guard(self, artifact: AgentRunArtifact, producer: bool) -> None:
        """Control Set v2 §7, under the lock right after ``artifact`` is sealed: the guard's decision, then its record
        and the halt sealed directly after it, with no other event of the run in between. What the recording call
        must deliver and raise is kept for :meth:`_deliver`. Any failure here breaks the run: a decision that could
        not be sealed must never let the run go on."""
        if not producer:
            self._guard.after(artifact, False, self.control_artifact)  # counts the guard's own event in the facts
            return
        seq = artifact.seq
        delivery = _Delivery()
        # Decide on a private copy, taken before any caller code runs: the engine is caller code and runs under this
        # thread's (reentrant) lock, so it could reach the sealed artifact through run.artifacts and edit it.
        artifact = AgentRunArtifact(copy.deepcopy(artifact.envelope), artifact.signature, dict(artifact.object_digests))
        try:
            outcome = self._guard.after(artifact, True, self.control_artifact)
            if outcome is None:
                return
            self._decisions[seq] = delivery
            tool = _obj(artifact.envelope["step"].get("tool")) or {}
            name, use_id = _str(tool.get("name")), _str(tool.get("useId"))
            if outcome.reason is None:
                delivery.event = EnforcementEvent("observed", None, outcome.rules, name, use_id, seq)
                return
            fields: dict = {"decision": "denied"}
            if outcome.tool is not None:
                fields["tool"] = outcome.tool
            if outcome.rules:
                fields["rules"] = list(outcome.rules)
            fields["enforcer"] = {"engine": self._guard.engine_name, "factsVersion": "2", "reason": outcome.reason}
            record = self._seal_event("authorization", [], fields, consequential=False, _by_guard=True)
            delivery.sealed.append(record)
            if outcome.tool is not None:
                self._tool_calls[outcome.tool["useId"]] = ("denied", outcome.tool["name"])
            if outcome.halt:
                delivery.sealed.append(self._seal_event("run_end", [], {
                    "finalSeq": len(self._artifacts), "finalPrevSignatureSha256": self._prev_signature_sha256,
                    "runDisposition": "halted"}, consequential=False, _by_guard=True))
                self._halt = (outcome.reason, outcome.rules, seq, record)
                self._halted.set()
            start = artifact.step_type == "run_start"
            delivery.event = EnforcementEvent("start_refused" if start else "halted" if outcome.halt else "denied",
                                              outcome.reason, outcome.rules, name, use_id, seq)
            delivery.error = StartRefused(outcome.reason, self) if start else \
                PolicyDenied(outcome.reason, outcome.rules, name, use_id, seq, record, outcome.halt) \
                if outcome.tool is not None else RunHalted(outcome.reason, outcome.rules, seq, record)
        except BaseException as ex:  # noqa: BLE001 — delivered to the recording call after the sealed events
            self._broken = True
            self._decisions[seq] = _Delivery(delivery.sealed, None, ex)

    @property
    def _enforcing(self) -> bool:
        return self._guard is not None and self._guard.enforcing

    def _ensure_not_stopped(self) -> None:
        """No tool starts on a stopped run: raises :class:`RunHalted` when it is halted, else the broken-chain or the
        finished error that a later recording call raises."""
        with self._lock:
            if self._halt is not None:
                raise self._halted_error()
            if self._broken or self._finished:
                self._ensure_open()

    def _halted_error(self) -> RunHalted:
        return RunHalted(*self._halt)  # type: ignore[misc]

    def _check_uri_reuse(self, digests: Mapping[str, str]) -> None:
        """§5: a URI used again in this run must name the same content (the verifier fails it otherwise)."""
        for uri, hex_ in digests.items():
            earlier = self._sealed_digests.get(uri)
            if earlier is not None and earlier != hex_:
                raise ValueError(f"Object URI '{uri}' was already sealed in this run with different content.")

    def _notify_all(self, artifact: AgentRunArtifact) -> None:
        failure = self._deliver(artifact)
        if failure is not None:
            raise failure

    def _deliver(self, artifact: AgentRunArtifact, before: Sequence[tuple[AgentRunArtifact, int]] = ()) \
            -> Optional[BaseException]:
        """Delivers ``before``, the event and what the guard sealed after it to the callbacks, in seal order — the
        guard's :class:`EnforcementEvent` with the last of them — even when one fails. Then raises what the guard
        decided for the caller (from the callback failure, if any); otherwise returns the first callback failure."""
        delivery = self._decisions.pop(artifact.seq, None)  # set by this thread's seal; popped once, here
        if delivery is None and not before:
            self._notify(artifact, artifact.seq)
            return None
        items = [*before, (artifact, artifact.seq)] + [(a, a.seq) for a in (delivery.sealed if delivery else [])]
        failure: Optional[BaseException] = None
        try:
            for i, (a, seq) in enumerate(items):
                try:
                    self._notify(a, seq, delivery.event if delivery is not None and i == len(items) - 1 else None)
                except (Exception, asyncio.CancelledError) as ex:  # noqa: BLE001 — every failure, a cancellation
                    if failure is None:                                 # included, surfaces after all are delivered
                        failure = ex
        finally:  # a KeyboardInterrupt or SystemExit in a callback must not leave later events waiting forever
            with self._notify_cond:
                self._next_notify = max(self._next_notify, items[-1][1] + 1)
                self._notify_cond.notify_all()
        if delivery is not None and delivery.error is not None:
            if failure is not None:
                raise delivery.error from failure
            raise delivery.error
        return failure

    def _notify(self, artifact: AgentRunArtifact, seq: int, event: Optional[EnforcementEvent] = None) -> None:
        """Runs the callback outside the lock, so it may call back into the
        run, and in order (the Control Artifact as -1, then each seq):
        concurrent events wait their turn, so a crash can leave the persisted
        prefix short, never with a hole. An event recorded from inside a
        callback is delivered immediately (it is next in order, and waiting
        would deadlock on the callback that recorded it). A failing callback
        is the caller's error and does not break the run. ``event`` goes to
        ``on_event`` in the same turn, after ``on_artifact_sealed``, even when that fails."""
        nested = getattr(self._in_callback, "active", False)
        with self._notify_cond:
            if not nested:
                self._notify_cond.wait_for(lambda: self._next_notify >= seq)
        try:
            try:
                try:
                    if self._on_sealed is not None:
                        self._callback(self._on_sealed, artifact, nested)
                finally:
                    if event is not None and self._on_event is not None:
                        self._callback(self._on_event, event, nested)
            finally:  # deliver_run: after the callbacks, upload up to this artifact (never raises)
                if self._index is not None:
                    self._index_upto(seq + 1, final=artifact.step_type == "run_end")
        finally:
            with self._notify_cond:
                self._next_notify = max(self._next_notify, seq + 1)
                self._notify_cond.notify_all()

    def _index_upto(self, upto: int, final: bool) -> None:
        """Uploads the artifacts from the cursor up to position ``upto`` in chain order, unless the index rejected one
        or a back-off is running (``final`` — the run_end turn — ignores it, within a total of 30 s). Never raises."""
        cursor = self._index
        try:
            with cursor.lock:
                if cursor.status == "rejected" or (cursor.status == "pending" and not final
                                                   and cursor.clock() < cursor.not_before):
                    return
                deadline = cursor.clock() + _INDEX_FINAL_BUDGET if final else None
                while cursor.next <= upto:
                    timeout = _INDEX_TIMEOUT if deadline is None else min(_INDEX_TIMEOUT, deadline - cursor.clock())
                    if timeout <= 0:
                        return  # the last attempt's budget is spent: still pending
                    position = cursor.next
                    artifact = self.control_artifact if position == 0 else self._artifacts[position - 1]
                    document = cursor.document if position == 0 else None
                    outcome, run_id, error, code = self._client._index_send(artifact, document, timeout)
                    if document is not None:
                        self.policy_disclosure = AgentIndexResult("indexed", run_id=run_id) if outcome == "ok" \
                            else AgentIndexResult("failed", error=f"control artifact: {error}")
                        if outcome == "rejected" and code is not None and code.startswith("control_set_"):
                            cursor.document = None  # a refused policy does not block the steps: once without it
                            outcome, run_id, error, code = self._client._index_send(artifact, None, timeout)
                    if outcome == "ok":
                        cursor.next, cursor.status, cursor.error = position + 1, "delivered", None
                        cursor.backoff, cursor.run_id = 0.0, run_id or cursor.run_id
                        continue
                    cursor.error = ("control artifact" if position == 0 else f"seq {position - 1}") + f": {error}"
                    if outcome == "rejected":
                        cursor.status = "rejected"  # no further automatic attempts: the index keeps a true prefix
                        return
                    cursor.status = "pending"
                    cursor.backoff = min(_INDEX_BACKOFF_MAX, cursor.backoff * 2 or _INDEX_BACKOFF_FIRST)
                    cursor.not_before = cursor.clock() + cursor.backoff
                    return
        except Exception:  # noqa: BLE001 — a delivery failure never raises
            pass

    def _callback(self, callback: Callable[[Any], None], arg: Any, nested: bool) -> None:
        self._in_callback.active = True
        try:
            callback(arg)
        finally:
            self._in_callback.active = nested

    def _ensure_open(self) -> None:
        if self._broken:
            raise RuntimeError("The run's chain is broken by an earlier sealing failure; no further events can be "
                               "sealed.")
        if self._halt is not None:
            raise self._halted_error()
        if self._finished:
            raise RuntimeError("The run is finished.")


class ToolCall:
    """One tool call from its ``tool_call`` to its ``tool_result`` (:meth:`AgentRun.begin_tool_call`). A context
    manager that does nothing on exit: the result is sealed only by :meth:`complete`, so an exception in the body
    seals nothing."""

    def __init__(self, run: AgentRun, tool: str, use_id: str, artifact: AgentRunArtifact) -> None:
        self._run = run
        self._tool = tool
        self._use_id = use_id
        self._artifact = artifact
        self._result: Optional[AgentRunArtifact] = None  # set under the run's lock with the sealed tool_result

    @property
    def tool(self) -> str:
        return self._tool

    @property
    def use_id(self) -> str:
        """The call's ``step.tool.useId``; its result names it."""
        return self._use_id

    @property
    def artifact(self) -> AgentRunArtifact:
        """The sealed ``tool_call``."""
        return self._artifact

    def complete(self, result: bytes, *, content_type: str = "application/json") -> AgentRunArtifact:
        """Seals the call's ``tool_result`` (same tool name and use id) and returns it.

        :raises RuntimeError: the call already has its result; nothing was sealed."""
        return self._run._record_internal("tool_result", [AgentRunObject("tool-result", result, content_type)],
                                          {"tool": _tool_block(self._tool, None, self._use_id)}, False, call=self)

    def covers(self, expires_at: Optional[datetime] = None) -> ApprovalCovers:
        """An :class:`ApprovalCovers` for exactly this call: its tool, its signed ``tool-arguments`` digest and its
        use id."""
        uri = next(o["uri"] for o in self._artifact.envelope["objects"] if o["role"] == "tool-arguments")
        return ApprovalCovers(self._tool, self._artifact.object_digests[uri], self._use_id, expires_at)

    def __enter__(self) -> "ToolCall":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        return None


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
            # §4.7: an evaluation under a qualified-time requirement is itself qualified — never a best-effort stamp.
            result = _seal(client, request.envelope, request.objects, CONTROL_EVALUATION_CONTENT_TYPE,
                           str(certificate_id), timestamp=True,
                           qualified=qualified or request.requires_qualified_timestamp,
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
        if "schemaVersion" in policy_doc:
            raise ValueError("Policy evaluations of a v2 control set are not specified yet (Control Evaluation v2 "
                             "fixes factsVersion 1).")
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
        # §4.7: present exactly when the approval record requires qualified time.
        approval_doc = None
        if request.approval_record is not None:
            try:
                approval_doc = _obj(json.loads(request.approval_record))
            except ValueError:
                approval_doc = None
            if approval_doc is None:
                raise ValueError("approval_record is not a JSON object")
        requires_qualified = _str((approval_doc or {}).get("timestamps")) == "qualified"
        if requires_qualified != (request.not_qualified is not None):
            raise ValueError("not_qualified is required exactly when the approval record requires qualified "
                             "timestamps.")
        if request.not_qualified is not None:
            policy["timestamps"] = {"required": "qualified", "met": len(request.not_qualified) == 0,
                                    "where": list(request.not_qualified)}
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
        return replace(_prepared(envelope, seal, [cs_uri], digests, payloads),
                       requires_qualified_timestamp=requires_qualified)

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
        parsed = _parse_control_set(doc)  # the one strict parse; None for anything else
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
