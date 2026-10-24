"""Agent Policy Control Set v1 (spec/agent-policy-control-set-v1.md): the digests
against the cross-language vector, structural validation, and the policy options
of AgentRun. Mirrors the .NET AgentPolicyTests one-to-one.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from sigill_sdk import (
    POLICY_CONTROL_SET_CONTENT_TYPE,
    AgentControlSet,
    AgentPolicy,
    QualifiedArtifacts,
    SigillClient,
)
from sigill_sdk._agent_profiles import CONTROL_ARTIFACT_SCHEMA
from sigill_sdk._canonical import canonicalize, hash_bytes
from test_agent_run import REPO, StubSealer, _start

VECTOR = REPO / "spec" / "test-vectors" / "11-policy-control-set"
DOC = (VECTOR / "control-set.json").read_bytes()
EXPECTED = json.loads((VECTOR / "expected.json").read_text())


def _mutate(change) -> bytes:
    doc = json.loads(DOC)
    change(doc)
    return json.dumps(doc).encode()


def test_policy_digests_match_the_vector() -> None:
    d = AgentPolicy.compute_digests(DOC)
    assert d.approval_scope_digest == EXPECTED["approvalScopeDigest"]
    assert d.cedar_digest == EXPECTED["cedarDigest"]
    assert hash_bytes(DOC) == EXPECTED["objectSha256"]
    schema = json.loads((REPO / "spec" / "agent-policy-cedar-schema-v1.json").read_bytes())
    assert hash_bytes(canonicalize(schema)) == EXPECTED["schemaSha256"]


def test_approval_scope_ignores_id_and_version_but_covers_everything_else() -> None:
    version_only = (VECTOR / "control-set-version-only.json").read_bytes()
    base = AgentPolicy.compute_digests(DOC)
    assert AgentPolicy.compute_digests(version_only).approval_scope_digest \
        == EXPECTED["versionOnlyApprovalScopeDigest"] == base.approval_scope_digest
    # Removing a private control or raising the idle limit weakens oversight: a new scope (test 9a/9b).
    no_private = AgentPolicy.compute_digests(_mutate(lambda d: d.update(privateControls=[])))
    assert no_private.approval_scope_digest != base.approval_scope_digest
    assert no_private.cedar_digest == base.cedar_digest, "the rules did not change"
    assert AgentPolicy.compute_digests(_mutate(lambda d: d["coverage"].update(idleSeconds=3600))).approval_scope_digest \
        != base.approval_scope_digest


def _policy(d: dict) -> dict:
    return d["cedar"]["policies"]["staticPolicies"]["max-steps"]


def test_validate_accepts_the_vector_and_names_every_problem() -> None:
    assert AgentPolicy.validate(DOC) == []
    assert any("unknown member 'extra'" in e for e in AgentPolicy.validate(_mutate(lambda d: d.update(extra=1))))
    assert any("'max-steps' must be forbid" in e
               for e in AgentPolicy.validate(_mutate(lambda d: _policy(d).update(effect="permit"))))
    assert any('@id("max-steps")' in e
               for e in AgentPolicy.validate(_mutate(lambda d: _policy(d)["annotations"].update(id="other"))))
    assert any("schemaSha256" in e for e in AgentPolicy.validate(_mutate(lambda d: d["cedar"].update(schemaSha256="ABC"))))
    assert any("unique" in e for e in AgentPolicy.validate(_mutate(lambda d: d.update(privateControls=[{"id": "a"}, {"id": "a"}]))))
    assert any("idleSeconds" in e for e in AgentPolicy.validate(_mutate(lambda d: d["coverage"].update(idleSeconds=-1))))
    errors = AgentPolicy.validate(b'{"id":"a","id":"b","version":"1","controls":[]}')
    assert len(errors) == 1 and "not an I-JSON object" in errors[0], "a repeated name is not I-JSON"


def test_validate_rejects_every_invalid_vector_without_raising() -> None:
    for c in json.loads((VECTOR / "invalid.json").read_text())["cases"]:
        raw = c["document"].encode()
        errors = AgentPolicy.validate(raw)
        assert any(c["error"] in e for e in errors), c["name"]
        with pytest.raises(ValueError):
            AgentPolicy.compute_digests(raw)


def test_validate_refuses_integers_javascript_cannot_read() -> None:
    # 2^53 + 1: a browser re-evaluating the policy would read a different number.
    doc = _mutate(lambda d: _policy(d).update(conditions=[{"kind": "when", "body": {">": {
        "left": {".": {"left": {"Var": "context"}, "attr": "stepsSoFar"}}, "right": {"Value": 9007199254740993}}}}]))
    errors = AgentPolicy.validate(doc)
    assert len(errors) == 1 and "2^53-1" in errors[0]


def test_control_set_from_document_keeps_the_bytes() -> None:
    cs = AgentPolicy.control_set_from_document(DOC)
    assert (cs.id, cs.version, cs.content_type) == ("acme-support-agent-controls", "3", POLICY_CONTROL_SET_CONTENT_TYPE)
    assert cs.content == DOC
    with pytest.raises(ValueError, match="controls must be an array"):
        AgentPolicy.control_set_from_document(_mutate(lambda d: d.pop("controls")))


class IndexRecorder:
    """Routes index uploads to a recorder; everything else to the stub sealer."""

    def __init__(self, sealer: StubSealer, status: int = 201) -> None:
        self.sealer, self.status, self.uploads = sealer, status, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path != "/api/agent-evidence/artifacts":
            return self.sealer(request)
        self.uploads.append(json.loads(request.content))
        if self.status == 201:
            return httpx.Response(201, json={"status": "indexed", "runId": "0e0e0e0e-0000-0000-0000-000000000001"})
        return httpx.Response(self.status, json={"code": "control_set_invalid", "message": "no"})


def _client(handler) -> SigillClient:
    http = httpx.Client(base_url="https://api.example", headers={"Authorization": "Bearer fake"},
                        transport=httpx.MockTransport(handler), timeout=5)
    return SigillClient(api_key="fake", http_client=http)


def test_disclose_policy_uploads_the_control_artifact_and_document_only() -> None:
    index = IndexRecorder(StubSealer())
    run = _start(_client(index), control_set=AgentPolicy.control_set_from_document(DOC), disclose_policy=True)
    run.record_tool_call("lookup_ticket", b"{}", use_id="c1")
    run.finish("completed")
    assert len(index.uploads) == 1, "only the Control Artifact is shared — execution events are not"
    up = index.uploads[0]
    assert up["envelope"]["schemaName"] == CONTROL_ARTIFACT_SCHEMA
    assert base64.b64decode(up["controlSet"]) == DOC
    assert len(up["objectDigests"]) == len(run.control_artifact.object_digests)
    assert run.policy_disclosure.succeeded and run.policy_disclosure.run_id


def test_disclose_policy_failure_never_fails_the_run() -> None:
    index = IndexRecorder(StubSealer(), status=422)
    run = _start(_client(index), control_set=AgentPolicy.control_set_from_document(DOC), disclose_policy=True)
    assert run.policy_disclosure.status == "failed"
    assert "422" in run.policy_disclosure.error and "control_set_invalid" in run.policy_disclosure.error
    assert len(run.finish("completed").artifacts) == 2


def test_disclose_policy_requires_a_policy_control_set_and_a_malformed_policy_is_never_sealed() -> None:
    sealer = StubSealer()
    client = _client(sealer)
    with pytest.raises(ValueError, match="disclose_policy requires"):
        _start(client, disclose_policy=True)
    bad = AgentControlSet("acme-support-agent-controls", "3",
                          _mutate(lambda d: _policy(d).update(effect="permit")), POLICY_CONTROL_SET_CONTENT_TYPE)
    with pytest.raises(ValueError, match="must be forbid"):
        _start(client, control_set=bad)
    good = AgentPolicy.control_set_from_document(DOC)
    with pytest.raises(ValueError, match="must equal the document"):
        _start(client, control_set=AgentControlSet(good.id, "4", good.content, good.content_type))
    assert sealer.requests == [], "nothing is sealed before the control set is valid"


def test_qualified_for_stamps_only_the_chosen_artifacts_qualified() -> None:
    sealer = StubSealer()
    run = _start(_client(sealer), qualified_for=QualifiedArtifacts.CONTROL_ARTIFACT | QualifiedArtifacts.RUN_END)
    run.checkpoint()
    run.finish("completed")
    # control, run_start, checkpoint, run_end
    assert [r.get("qualified", False) for r in sealer.requests] == [True, False, False, True]
