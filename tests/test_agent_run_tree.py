# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Agent Delegation v1: the run-tree vectors (spec/test-vectors/agent-run-tree)
through the stub verifier, and the recorder's delegation API end-to-end
against the stub sealer.

Mirrors the .NET suite (AgentRunTreeTests.cs) one-to-one.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from test_agent_run import SECRET, StubSealer, _agent, _client, _clock, _options, stub_verify

from sigill_sdk import (
    AgentDefinition,
    AgentDelegation,
    AgentRun,
    AgentRunBundle,
    AgentRunBundleFormatError,
    AgentRunTreeBundle,
    AgentRunTreeOptions,
    SigillClient,
    verify_agent_run,
    verify_agent_run_tree,
)
from sigill_sdk._agent_profiles import MAX_ARTIFACTS

REPO = Path(__file__).resolve().parents[1]
TREES = REPO / "spec" / "test-vectors" / "agent-run-tree" / "trees"
TREE_VECTORS = sorted(p.name for p in TREES.glob("*.json"))


def _load(name: str) -> dict:
    return json.loads((TREES / name).read_text(encoding="utf-8"))


def _tree_options(o: dict | None) -> AgentRunTreeOptions | None:
    if o is None:
        return None
    return AgentRunTreeOptions(expected_root_correlation_id=o.get("expectedRootCorrelationId"),
                               expected_signers=o.get("expectedSigners"))


def _verify_vector(name: str):
    v = _load(name)
    tree = AgentRunTreeBundle.parse(json.dumps(v["tree"]))
    return verify_agent_run_tree(tree, stub_verify, _tree_options(v.get("options")))


# ── Vectors ─────────────────────────────────────────────────────────────────

def test_tree_vectors_are_all_present() -> None:
    assert len(TREE_VECTORS) == 36


@pytest.mark.parametrize("name", TREE_VECTORS)
def test_tree_vector_reproduces_expected_result(name: str) -> None:
    expected = _load(name)["expected"]
    r = _verify_vector(name)

    assert r.verdict == expected["verdict"], [f.detail for f in r.findings]
    assert sorted({f.code for f in r.findings}) == expected["findings"]
    assert sorted({f.code for f in r.open_reasons}) == expected["openReasons"]
    assert r.fingerprint == expected["fingerprint"]
    assert r.root_correlation_id == expected["root"]

    runs = expected["runs"]
    if runs:
        for run in r.runs:
            assert run.result.verdict == runs[run.correlation_id], (run.correlation_id, run.result.findings)
    else:
        assert all(run.result is None for run in r.runs)  # a limit stopped verification

    def key(p: str, c: str, b: str, k: str) -> str:
        return f"{p} → {c}: {b}/{k}"
    assert sorted(key(e.parent_correlation_id, e.child_correlation_id, e.binding, e.completion) for e in r.edges) \
        == sorted(key(e["parent"], e["child"], e["binding"], e["completion"]) for e in expected["edges"])
    for corr, affiliation in (expected.get("affiliations") or {}).items():
        assert next(x for x in r.runs if x.correlation_id == corr).affiliation == affiliation


def test_tree_fingerprint_ignores_run_order_and_covers_later_evaluations() -> None:
    finalized = _verify_vector("01-finalized.json")
    assert _verify_vector("70-reordered.json").fingerprint == finalized.fingerprint
    evaluated = _verify_vector("60-later-evaluation.json")
    assert evaluated.verdict == finalized.verdict
    assert evaluated.fingerprint != finalized.fingerprint


def test_depth_stop_keeps_the_derived_root() -> None:
    r = _verify_vector("81-depth-9.json")
    assert r.verdict == "tree_invalid"
    assert r.root_correlation_id is not None
    assert r.edges == [] and r.fingerprint is None
    assert any(run.depth == 9 for run in r.runs)


def test_mixed_versions_name_the_versions_in_the_run_finding() -> None:
    v = _load("41-mixed-versions.json")
    bundles = [AgentRunBundle.parse(b) for b in v["tree"]["runs"]]
    findings = [f for b in bundles for f in verify_agent_run(b, stub_verify).findings]
    assert "The run's execution artifacts mix schemaVersion 1 and 2; one run uses one version." in findings


def test_malformed_members_never_raise_they_make_the_tree_invalid() -> None:
    tree = copy.deepcopy(_load("01-finalized.json")["tree"])
    child = tree["runs"][1]
    child["controlArtifact"]["envelope"]["agent"] = "not an object"
    child["controlArtifact"]["envelope"]["controlSet"] = ["not", "an", "object"]
    child["artifacts"][0]["envelope"]["activity"] = 42
    child["artifacts"][1]["envelope"]["step"] = "flat"
    child["artifacts"][2]["envelope"]["chain"] = "flat"
    tree["runs"][0]["artifacts"][1]["envelope"]["step"]["delegation"] = 7
    r = verify_agent_run_tree(AgentRunTreeBundle.parse(json.dumps(tree)), stub_verify)
    assert r.verdict == "tree_invalid"


def test_tree_bundle_round_trips_and_refuses_duplicate_names() -> None:
    text = json.dumps(_load("01-finalized.json")["tree"], separators=(",", ":"))
    tree = AgentRunTreeBundle.parse(text)
    assert len(AgentRunTreeBundle.parse(tree.to_json()).runs) == 3
    dup = text.replace('{"format":"AgentRunTreeBundle"',
                       '{"format":"AgentRunTreeBundle","format":"AgentRunTreeBundle"')
    assert dup != text
    with pytest.raises(AgentRunBundleFormatError, match="duplicate member name"):
        AgentRunTreeBundle.parse(dup)


def test_tree_bundle_parse_lists_problems_per_run() -> None:
    tree = _load("01-finalized.json")["tree"]
    bad = dict(tree, format="Nope", runs=[tree["runs"][0], {"format": "AgentRunBundle"}])
    with pytest.raises(AgentRunBundleFormatError) as ei:
        AgentRunTreeBundle.parse(bad)
    assert any(e.startswith("unsupported format 'Nope'") for e in ei.value.errors)
    assert any(e.startswith("runs[1]: ") for e in ei.value.errors)
    with pytest.raises(AgentRunBundleFormatError, match="nests deeper"):
        AgentRunTreeBundle.parse("[" * 70 + "]" * 70)


def test_bundled_v2_schema_is_a_byte_exact_copy_of_the_spec() -> None:
    name = "agent-execution-evidence-v2.schema.json"
    assert (REPO / "src" / "sigill_sdk" / "_schemas" / name).read_bytes() == (REPO / "spec" / name).read_bytes()


# ── The recorder's delegation API ───────────────────────────────────────────

RESEARCHER = "urn:example:agent:researcher"


def _named(agent_id: str) -> AgentDefinition:
    a = _agent()
    return AgentDefinition(agent_id=agent_id, agent_version=a.agent_version, configuration=a.configuration,
                           tenant_id=a.tenant_id)


def _parent(client: SigillClient) -> AgentRun:
    return AgentRun.start(client, _agent(), delegating=True, _clock=_clock(), **_options())


def _child(client: SigillClient, delegation: AgentDelegation, agent_id: str = RESEARCHER) -> AgentRun:
    return AgentRun.start_child(client, _named(agent_id), delegation, _clock=_clock(), **_options())


def test_recorded_tree_verifies_as_finalized_and_only_digests_travel() -> None:
    sealer = StubSealer()
    client = _client(sealer)
    parent = _parent(client)
    parent.record_tool_call("lookup_ticket", b'{"ticket":"4411"}', operation="read")
    delegation = parent.delegate(RESEARCHER, SECRET, use_id="toolu_1")
    child = client.start_child_agent_run(_named(RESEARCHER), delegation, _clock=_clock(), **_options())
    child.record_tool_call("search", b'{"q":"reset"}', operation="read")
    child.finish()
    parent.complete_delegation(child)
    parent.finish()

    assert child.correlation_id == delegation.child_correlation_id
    assert all(a.envelope["schemaVersion"] == "2" for a in parent.artifacts + child.artifacts)
    binds = child.artifacts[0].envelope["binds"]
    assert binds["parentDelegationSignatureSha256"] == delegation.delegation_signature_sha256
    assert binds["parentCorrelationId"] == parent.correlation_id
    assert delegation.artifact is not None and delegation.artifact.step_type == "delegation"
    assert all("Jane Doe" not in json.dumps(rq) for rq in sealer.requests)

    tree = AgentRunTreeBundle(parent.correlation_id, [parent.to_bundle(), child.to_bundle()])
    r = verify_agent_run_tree(AgentRunTreeBundle.parse(tree.to_json()), stub_verify)
    assert r.verdict == "tree_finalized", [f.detail for f in r.findings]
    assert r.is_finalized and "tree_finalized means" in r.scope
    assert r.root_correlation_id == parent.correlation_id
    assert len(r.edges) == 1
    e = r.edges[0]
    assert (e.binding, e.completion, e.child_agent_id) == ("mutually_bound", "result_bound", RESEARCHER)
    assert next(x for x in r.runs if x.correlation_id == child.correlation_id).depth == 1
    assert r.fingerprint is not None


def test_parent_cannot_close_completed_with_an_open_delegation_but_may_abort() -> None:
    client = _client(StubSealer())
    parent = _parent(client)
    delegation = parent.delegate(RESEARCHER)
    assert parent.outstanding_delegations == [delegation.child_correlation_id]
    with pytest.raises(RuntimeError, match="§4 rule 5"):
        parent.finish()
    assert not parent.is_broken
    parent.finish("aborted")

    r = verify_agent_run_tree(AgentRunTreeBundle(None, [parent.to_bundle()]), stub_verify)
    assert r.verdict == "tree_open"
    assert r.edges[0].binding == "child_missing"
    assert [o.code for o in r.open_reasons] == ["parent_terminated"]


def test_delegation_api_refuses_what_would_not_verify() -> None:
    client = _client(StubSealer())
    plain = AgentRun.start(client, _agent(), _clock=_clock(), **_options())
    with pytest.raises(RuntimeError, match="delegating=True"):
        plain.delegate("urn:example:agent:x")
    with pytest.raises(ValueError):
        plain.record("delegation")
    with pytest.raises(ValueError, match="reserved"):
        plain.record("tool_call", fields={"delegation": {}})

    parent = _parent(client)
    with pytest.raises(ValueError, match="itself"):
        parent.delegate("urn:example:agent:x", child_correlation_id=parent.correlation_id)
    d = parent.delegate(RESEARCHER)
    with pytest.raises(ValueError, match="already delegated"):
        parent.delegate(RESEARCHER, child_correlation_id=d.child_correlation_id)
    with pytest.raises(ValueError, match="delegated to"):
        _child(client, d, "urn:example:agent:other")
    with pytest.raises(ValueError, match="correlationId"):
        AgentRun.start_child(client, _named(RESEARCHER), d, correlation_id="urn:uuid:other", **_options())

    child = _child(client, d)
    with pytest.raises(RuntimeError, match="not finished"):
        parent.complete_delegation(child)
    child.finish("failed")
    parent.complete_delegation(child)
    with pytest.raises(RuntimeError, match="already has its result"):
        parent.complete_delegation(child)
    with pytest.raises(RuntimeError, match="never delegated"):
        parent.complete_delegation("urn:uuid:never", "a" * 64, "completed")
    with pytest.raises(ValueError, match="child_disposition"):
        parent.complete_delegation(d.child_correlation_id, "a" * 64, "done")
    assert not parent.is_broken
    parent.finish()

    r = verify_agent_run_tree(AgentRunTreeBundle(None, [child.to_bundle(), parent.to_bundle()]), stub_verify)
    assert r.verdict == "tree_finalized", [f.detail for f in r.findings]
    assert r.edges[0].child_disposition == "failed"


def test_child_in_another_process_completes_from_explicit_values() -> None:
    client = _client(StubSealer())
    parent = _parent(client)
    d = parent.delegate(RESEARCHER)
    # The other process rebuilds the delegation from its four values, without the artifact.
    remote = AgentDelegation(d.parent_correlation_id, d.delegation_signature_sha256, d.child_correlation_id,
                             d.child_agent_id)
    child = _child(client, remote)
    child.finish()
    end = child.artifacts[-1]
    parent.complete_delegation(child.correlation_id, end.signature_sha256, "completed")
    parent.finish()
    r = verify_agent_run_tree(AgentRunTreeBundle(None, [parent.to_bundle(), child.to_bundle()]), stub_verify)
    assert r.verdict == "tree_finalized", [f.detail for f in r.findings]


def test_event_budget_keeps_room_for_every_result_and_run_end() -> None:
    client = _client(StubSealer())
    parent = _parent(client)
    first = parent.delegate(RESEARCHER)
    second = parent.delegate(RESEARCHER)
    while True:
        try:
            parent.record_model_output(b"ok")
        except RuntimeError as ex:
            assert "reserved for run_end and 2 delegation result(s)" in str(ex)
            break
    # Two results and run_end are reserved: the run stops three short of the bundle limit.
    assert len(parent.artifacts) == MAX_ARTIFACTS - 3
    assert not parent.is_broken
    with pytest.raises(RuntimeError, match="No room for another delegation"):
        parent.delegate(RESEARCHER)

    for d in (first, second):
        child = _child(client, d, d.child_agent_id)
        child.finish()
        parent.complete_delegation(child)
    bundle = parent.finish()
    assert len(bundle.artifacts) == MAX_ARTIFACTS
