"""Common rules §9: the caller's free text is bounded at record time — a step's detail 512 characters, the activity's
name and an approver reference 255, an object's metadata 2,048 bytes of JSON. Over a limit is refused before
anything is sealed or uploaded, with or without deliver_run; nothing is shortened."""

from __future__ import annotations

import pytest

from sigill_sdk import AgentAuthorization
from sigill_sdk._agent_run import _check_free_text
from test_agent_delivery import Index, _run
from test_agent_policy import _client
from test_agent_run import _start

ASTRAL = "\U0001F600"  # one code point, four UTF-8 bytes, two UTF-16 units


def _refused(index: Index, act, text: str) -> None:  # noqa: ANN001
    sealed, uploaded = len(index.sealer.requests), len(index.uploads)
    with pytest.raises(ValueError) as e:
        act()
    assert str(e.value) == text and "x" * 20 not in str(e.value) and ASTRAL not in str(e.value)
    assert (len(index.sealer.requests), len(index.uploads)) == (sealed, uploaded)


DETAIL = "step.detail is longer than 512 characters; the SDK refuses it (common rules §9)."
APPROVER = "step.approver is longer than 255 characters; the SDK refuses it (common rules §9)."
ACTIVITY = "activity.name is longer than 255 characters; the SDK refuses it (common rules §9)."


@pytest.mark.parametrize("deliver", [False, True])
@pytest.mark.parametrize("fill", ["x", ASTRAL])
def test_detail_at_512_characters_passes_and_513_is_refused_on_every_path(deliver: bool, fill: str) -> None:
    index = Index()
    run = _run(index) if deliver else _start(_client(index))
    run.record_retrieval(b"r", detail=fill * 512)
    for act in (lambda: run.record_retrieval(b"r", detail=fill * 513),
                lambda: run.record("checkpoint", fields={"detail": fill * 513}),
                lambda: run.record_authorization(AgentAuthorization("allowed", detail=fill * 513)),
                lambda: run.checkpoint(fill * 513),
                lambda: run.finish(detail=fill * 513)):
        _refused(index, act, DETAIL)
    assert not run.is_broken and not run.is_finished
    run.finish(detail=fill * 512)


@pytest.mark.parametrize("fill", ["x", "é", ASTRAL])
def test_an_approver_reference_is_at_most_255_characters(fill: str) -> None:
    index = Index()
    run = _run(index)
    run.record_human_approval("approved", approver=fill * 255)
    _refused(index, lambda: run.record_human_approval("approved", approver=fill * 256), APPROVER)


@pytest.mark.parametrize("fill", ["x", ASTRAL])
def test_an_activity_name_is_at_most_255_characters_before_anything_is_sealed(fill: str) -> None:
    index = Index()
    _run(index, activity=fill * 255).finish()
    index = Index()
    _refused(index, lambda: _run(index, activity=fill * 256), ACTIVITY)
    assert index.sealer.requests == [] and index.uploads == []


@pytest.mark.parametrize("member", ["objects[].metadata", "extensions"])
@pytest.mark.parametrize("value, ok", [("a" * 2040, True), ("a" * 2041, False),  # {"k":"…"} is 8 bytes more
                                       ("é" * 1020, True), ("é" * 1021, False)])  # two UTF-8 bytes each
def test_metadata_and_extensions_are_measured_in_bytes_of_their_json(member: str, value: str, ok: bool) -> None:
    envelope: dict = {"activity": {"name": "a"}, "step": {}}
    if member == "extensions":
        envelope["extensions"] = {"k": value}
    else:
        envelope["objects"] = [{"uri": "objects/1", "metadata": {"k": value}}]
    if ok:
        _check_free_text(envelope)
    else:
        with pytest.raises(ValueError) as e:
            _check_free_text(envelope)
        assert str(e.value) == f"{member} is longer than 2048 bytes as JSON; the SDK refuses it (common rules §9)."

