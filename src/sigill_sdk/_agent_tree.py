# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Agent Delegation v1 — verify a run tree (``spec/agent-delegation-v1.md`` §6).

A run tree is a root run plus every run it delegated to, recursively. Every
run is verified on its own (common rules §8); then the structure and the
delegation edges between them are derived from the signed envelopes only.
Mirrors the .NET SDK's ``AgentRunTreeVerifier`` one-to-one: same limits, same
finding codes, same edges, same verdicts, same fingerprint.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, ClassVar, Mapping, Optional, Sequence

from sigill_sdk._agent_profiles import MAX_DEPTH as _RUN_MAX_DEPTH
from sigill_sdk._agent_profiles import (
    _DuplicateMember,
    _int,
    _obj,
    _reject_constant,
    _reject_duplicates,
    _str,
    signature_sha256,
)
from sigill_sdk._agent_types import AgentRunBundle, AgentRunBundleFormatError, _depth
from sigill_sdk._agent_verify import (
    AgentRunVerificationResult,
    BlindObjectsVerifier,
    _n,
    verify_agent_run,
)
from sigill_sdk._canonical import canonicalize, hash_bytes

TREE_SCOPE = (
    "tree_finalized means: the root's control basis was sealed first; each child's run_start was sealed after its "
    "parent's delegation signature existed; each child's run_end signature existed before its parent's "
    "delegation_result was sealed; and the signed envelopes of every run are unchanged since the root's run_end was "
    "timestamped. It does not prove that every sub-agent the system started was recorded, when any child actually "
    "acted, that children did only what the parent intended, that evaluations are complete, or who operates a shared "
    "certificate."
)
"""What a tree verdict does and does not establish (§6.9). Show it next to the verdict."""


# ── The container (§6.1) ────────────────────────────────────────────────────

@dataclass(frozen=True)
class AgentRunTreeBundle:
    """A run tree as one container (§6.1): a root run and every run it
    delegated to, each an ordinary :class:`AgentRunBundle`.
    ``root_correlation_id`` and the order of ``runs`` are hints for humans;
    the verifier derives the tree from signed envelopes."""

    FORMAT: ClassVar[str] = "AgentRunTreeBundle"
    VERSION: ClassVar[str] = "1"
    # §6.1 limits. Exceeding one makes the tree tree_invalid; the parser does not refuse them.
    MAX_RUNS: ClassVar[int] = 256
    MAX_DEPTH: ClassVar[int] = 8
    MAX_ARTIFACTS: ClassVar[int] = 20_000
    MAX_PAYLOAD_ENTRIES: ClassVar[int] = 50_000
    MAX_PAYLOAD_BYTES: ClassVar[int] = 512 * 1024 * 1024
    _MAX_NESTING: ClassVar[int] = _RUN_MAX_DEPTH + 2  # the tree adds runs[] around each run bundle

    root_correlation_id: Optional[str]
    runs: list[AgentRunBundle]

    def __post_init__(self) -> None:
        if self.runs is None:
            raise TypeError("runs is required")
        if not all(isinstance(r, AgentRunBundle) for r in self.runs):
            raise TypeError("runs must be AgentRunBundle instances")

    def to_dict(self) -> dict:
        return {
            "format": self.FORMAT,
            "bundleVersion": self.VERSION,
            "rootCorrelationId": self.root_correlation_id,
            "runs": [r.to_dict() for r in self.runs],
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def parse(cls, value: Any) -> "AgentRunTreeBundle":
        """Strict parse of a JSON string, bytes or already-parsed dict. Every
        run is parsed as a strict :class:`AgentRunBundle`; a malformed
        container raises :class:`AgentRunBundleFormatError` listing every
        problem, prefixed ``runs[i]:`` per run."""
        if isinstance(value, (str, bytes)):
            try:
                value = json.loads(value, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
            except _DuplicateMember as ex:
                raise AgentRunBundleFormatError([f"tree bundle repeats a duplicate member name '{ex.name}'"]) from None
            except RecursionError:
                raise AgentRunBundleFormatError([f"tree bundle nests deeper than {cls._MAX_NESTING} levels"]) from None
            except ValueError as ex:
                raise AgentRunBundleFormatError([f"tree bundle is not valid JSON: {ex}"]) from None
            if _depth(value) > cls._MAX_NESTING:
                raise AgentRunBundleFormatError([f"tree bundle nests deeper than {cls._MAX_NESTING} levels"])
        if not isinstance(value, dict):
            raise AgentRunBundleFormatError(["tree bundle must be a JSON object"])
        errors: list[str] = []

        def shown(key: str) -> str:
            v = value.get(key)
            return v if isinstance(v, str) else json.dumps(v) if v is not None else "None"
        if value.get("format") != cls.FORMAT:
            errors.append(f"unsupported format '{shown('format')}' (expected {cls.FORMAT})")
        if value.get("bundleVersion") != cls.VERSION:
            errors.append(f"unsupported bundleVersion '{shown('bundleVersion')}' (expected {cls.VERSION})")
        runs: list[AgentRunBundle] = []
        arr = value.get("runs")
        if not isinstance(arr, list):
            errors.append("runs[] missing or not an array")
        else:
            for i, r in enumerate(arr):
                try:
                    runs.append(AgentRunBundle.parse(r))
                except AgentRunBundleFormatError as ex:
                    errors.extend(f"runs[{i}]: {e}" for e in ex.errors)
        if errors:
            raise AgentRunBundleFormatError(errors)
        return cls(_str(value.get("rootCorrelationId")), runs)


# ── Options and results ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class AgentRunTreeOptions:
    """What the relying party expects of a tree (§5, §6.7). All optional."""

    expected_root_correlation_id: Optional[str] = None
    """The root run's correlationId."""
    expected_root_run_end_signature_sha256: Optional[str] = None
    """The ``signatureSha256`` of the root's ``run_end``."""
    expected_root_signer: Optional[str] = None
    """The root's signer (``x5t#S256``)."""
    expected_signers: Optional[Mapping[str, Sequence[str]]] = None
    """Attribution policy for one organisation context (§5): ``agent.id`` → expected signers (``x5t#S256``).
    A run whose agent is listed and whose signer is not fails ``signatures``."""
    expected_evaluation_signers: Optional[Sequence[str]] = None
    """Expected signers of Control Evaluations, passed to every run."""


@dataclass(frozen=True)
class AgentRunTreeFinding:
    """One finding of the tree layer: a §6.3 code (or an open-reason code) and what it is about."""

    code: str
    detail: str


@dataclass(frozen=True)
class AgentRunTreeRun:
    """One run of the tree, with its own verdict (§6.2; the tree never changes it)."""

    correlation_id: Optional[str] = None
    agent_id: Optional[str] = None
    parent_correlation_id: Optional[str] = None
    """The parent named by this run's ``run_start``; None for a root."""
    depth: Optional[int] = None
    """Distance from the root through edges; None when unreachable."""
    affiliation: str = "unknown"
    """confirmed | unknown | mismatch — against the attribution policy (§5)."""
    result: Optional[AgentRunVerificationResult] = None
    """The run's own verification; None when a limit stopped verification (§6.1)."""


@dataclass(frozen=True)
class AgentRunTreeEdge:
    """One delegation edge (§6.4)."""

    parent_correlation_id: str
    child_correlation_id: str
    binding: str
    """mutually_bound | child_missing | parent_missing | unbound."""
    completion: str
    """result_bound | result_mismatch | result_unresolved | no_result."""
    child_agent_id: Optional[str] = None
    delegation_seq: Optional[int] = None
    """Seq of the parent's ``delegation``; None when the parent declares none."""
    result_seq: Optional[int] = None
    """Seq of the parent's ``delegation_result``; None when there is none."""
    child_disposition: Optional[str] = None
    """The disposition the parent's ``delegation_result`` records."""


@dataclass(frozen=True)
class AgentRunTreeVerificationResult:
    """The tree verdict (§6.5) with every run, edge and finding."""

    verdict: str
    """tree_finalized | tree_open | tree_invalid."""
    root_correlation_id: Optional[str]
    """The root derived from signed envelopes; None when there is not exactly one."""
    runs: list[AgentRunTreeRun]
    edges: list[AgentRunTreeEdge]
    findings: list[AgentRunTreeFinding]
    open_reasons: list[AgentRunTreeFinding]
    """Why the tree is open (§6.5 step 8): run_open | delegation_pending | parent_terminated, each with its subject."""
    fingerprint: Optional[str] = None
    """The §6.8 tree fingerprint; None when a run fingerprint is None or no root can be derived."""

    @property
    def scope(self) -> str:
        return TREE_SCOPE

    @property
    def is_finalized(self) -> bool:
        return self.verdict == "tree_finalized"


# ── What one run says about the tree ────────────────────────────────────────

@dataclass(eq=False)
class _Summary:
    index: int
    bundle: AgentRunBundle
    correlation: Optional[str] = None
    agent_id: Optional[str] = None
    parent_correlation: Optional[str] = None
    parent_delegation_sig: Optional[str] = None
    run_end_sig: Optional[str] = None
    run_end_disposition: Optional[str] = None
    has_start: bool = False
    is_child: bool = False
    delegations: list = field(default_factory=list)  # (seq, sig, child, agent_id)
    results: list = field(default_factory=list)      # (seq, child, run_end_sig, disposition)
    depth: Optional[int] = None


def _s(root: Any, *path: str) -> Optional[str]:
    """A string at ``path``; a member of the wrong JSON type reads as absent."""
    n = root
    for key in path:
        n = _obj(n).get(key) if _obj(n) is not None else None
    return _str(n)


def _summarize(bundle: AgentRunBundle, index: int) -> _Summary:
    """Read from the run's envelopes without any cryptography. Malformed evidence never raises here."""
    s = _Summary(index=index, bundle=bundle)
    big = 2 ** 31 - 1
    events = []
    for a in bundle.artifacts:
        seq = _int((_obj(a.envelope.get("chain")) or {}).get("seq"))
        events.append((a, seq))
    events.sort(key=lambda x: x[1] if x[1] is not None else big)  # stable, like OrderBy
    start = next((a for a, _ in events if _s(a.envelope, "step", "type") == "run_start"), None)
    ctl_env = bundle.control_artifact.envelope if bundle.control_artifact is not None else None
    s.correlation = _s(start.envelope if start else None, "activity", "correlationId")
    if s.correlation is None:
        s.correlation = next((c for c in (_s(a.envelope, "activity", "correlationId") for a, _ in events) if c), None)
    if s.correlation is None:
        s.correlation = _s(ctl_env, "activity", "correlationId")
    if start is not None:
        s.has_start = True
        s.parent_correlation = _s(start.envelope, "binds", "parentCorrelationId")
        s.parent_delegation_sig = _s(start.envelope, "binds", "parentDelegationSignatureSha256")
        s.is_child = s.parent_correlation is not None or s.parent_delegation_sig is not None
    s.agent_id = _s(ctl_env, "agent", "id")
    if s.agent_id is None:
        s.agent_id = _s(start.envelope if start else None, "actor", "id")
    for a, seq in events:
        step = _obj(a.envelope.get("step"))
        if seq is None or step is None:
            continue
        t = _s(step, "type")
        child = _s(step, "delegation", "childCorrelationId")
        if t == "delegation" and child is not None and (sig := signature_sha256(a.signature)) is not None:
            s.delegations.append((seq, sig, child, _s(step, "delegation", "childAgentId")))
        elif t == "delegation_result" and child is not None:
            s.results.append((seq, child, _s(step, "delegation", "childRunEndSignatureSha256"),
                              _s(step, "delegation", "childDisposition")))
        elif t == "run_end":
            s.run_end_sig = signature_sha256(a.signature)
            s.run_end_disposition = _s(step, "runDisposition")
    return s


# ── The verifier ────────────────────────────────────────────────────────────

def verify_agent_run_tree(tree: AgentRunTreeBundle, verifier: BlindObjectsVerifier,
                          options: Optional[AgentRunTreeOptions] = None) -> AgentRunTreeVerificationResult:
    """Verifies a run tree (§6): every run on its own (common rules §8), then
    the structure and the delegation edges between them, from signed
    envelopes only. Never raises for malformed evidence: that is an invalid
    verdict."""
    if tree is None:
        raise ValueError("tree is required")
    if verifier is None:
        raise ValueError("verifier is required")
    options = options or AgentRunTreeOptions()
    findings: list[AgentRunTreeFinding] = []

    def find(code: str, detail: str) -> None:
        findings.append(AgentRunTreeFinding(code, detail))

    # ── §6.1 limits, before anything else
    runs = tree.runs
    T = AgentRunTreeBundle
    artifacts = sum(len(r.artifacts) for r in runs)
    payload_entries = sum(len(r.payloads) for r in runs)
    payload_bytes = sum(len(v) for r in runs for v in r.payloads.values())
    if len(runs) == 0 or len(runs) > T.MAX_RUNS:
        find("limit_exceeded", f"{len(runs)} runs (1–{T.MAX_RUNS} allowed).")
    if artifacts > T.MAX_ARTIFACTS:
        find("limit_exceeded", f"{artifacts} execution artifacts in the tree (at most {T.MAX_ARTIFACTS}).")
    if payload_entries > T.MAX_PAYLOAD_ENTRIES:
        find("limit_exceeded", f"{payload_entries} payload entries in the tree (at most {T.MAX_PAYLOAD_ENTRIES}).")
    if payload_bytes > T.MAX_PAYLOAD_BYTES:
        find("limit_exceeded", f"{payload_bytes} payload bytes in the tree (at most {T.MAX_PAYLOAD_BYTES}).")
    if findings:
        return _stopped(findings, [_summarize(r, i) for i, r in enumerate(runs)])

    # ── structure, from signed envelopes (§6.3)
    sums = [_summarize(r, i) for i, r in enumerate(runs)]
    groups: dict[str, list[_Summary]] = {}
    for s in sums:
        if s.correlation is not None:
            groups.setdefault(s.correlation, []).append(s)
    by_corr: dict[str, _Summary] = {}
    for key, g in groups.items():
        by_corr[key] = g[0]
        if len(g) > 1:
            find("duplicate_run", f"{len(g)} supplied runs sign correlationId {key}.")
    roots = [s for s in sums if s.has_start and not s.is_child]
    if not roots:
        find("no_root", "No supplied run's run_start is free of a parent binding.")
    elif len(roots) > 1:
        find("multiple_roots", f"{len(roots)} runs are roots: {', '.join(r.correlation or '?' for r in roots)}.")
    root = roots[0] if len(roots) == 1 else None

    for s in sums:
        if s.correlation is None:
            continue
        if any(d[2] == s.correlation for d in s.delegations):
            find("self_delegation", f"{s.correlation} declares itself as a child.")
        if s.is_child and s.parent_correlation == s.correlation:
            find("self_delegation", f"{s.correlation} names itself as its parent.")
        counts: dict[str, int] = {}
        for d in s.delegations:
            counts[d[2]] = counts.get(d[2], 0) + 1
        for child, n in counts.items():
            if n > 1:
                find("duplicate_delegation", f"{s.correlation} declares child {child} in {n} delegation events.")
        for r_seq, r_child, _, _ in s.results:
            decl = next((d[0] for d in s.delegations if d[2] == r_child), None)
            if decl is None:
                find("orphan_result", f"{s.correlation} seq {r_seq} reports a result for {r_child}, which it never "
                                      f"delegated to.")
            elif r_seq < decl:
                find("result_before_delegation", f"{s.correlation} seq {r_seq} reports a result for {r_child} before "
                                                 f"its delegation (seq {decl}).")
        result_counts: dict[str, int] = {}
        for r in s.results:
            result_counts[r[1]] = result_counts.get(r[1], 0) + 1
        for child, n in result_counts.items():
            if n > 1:
                find("duplicate_result", f"{s.correlation} reports {n} results for {child}.")
    declared: dict[str, list[str]] = {}
    for s in sums:
        if s.correlation is None:
            continue
        for d in s.delegations:
            parents = declared.setdefault(d[2], [])
            if s.correlation not in parents:
                parents.append(s.correlation)
    for child, parents in declared.items():
        if len(parents) > 1:
            find("child_two_parents", f"{child} is declared by {' and '.join(parents)}.")
    for s in sums:
        for d_seq, _, d_child, d_agent in s.delegations:
            child_run = by_corr.get(d_child)
            if child_run is not None and child_run.agent_id != d_agent:
                find("agent_mismatch", f"{_n(s.correlation)} seq {d_seq} delegates to agent {_n(d_agent)}, but "
                                       f"{d_child} is agent {child_run.agent_id or 'unknown'}.")

    # Cycles through parent bindings.
    on_cycle: set[str] = set()
    for s in sums:
        if s.correlation is None or not s.is_child:
            continue
        seen = [s.correlation]
        cur = s
        while cur.is_child and cur.parent_correlation is not None and cur.parent_correlation in by_corr \
                and by_corr[cur.parent_correlation].correlation != cur.correlation:
            p = cur.parent_correlation
            if p in seen:
                on_cycle.update(seen[seen.index(p):])
                break
            seen.append(p)
            cur = by_corr[p]
    if on_cycle:
        find("cycle", f"Parent bindings form a cycle through {', '.join(sorted(on_cycle))}.")

    # Reachability and depth from the root (declared children, and runs binding a reachable parent).
    if root is not None:
        root.depth = 0
        queue = [root]
        while queue:
            cur = queue.pop(0)
            nxt = [by_corr.get(d[2]) for d in cur.delegations] + \
                [s for s in sums if s.is_child and s.parent_correlation is not None
                 and s.parent_correlation == cur.correlation]
            for n in nxt:
                if n is not None and n.depth is None:
                    n.depth = cur.depth + 1
                    queue.append(n)
        for s in sums:
            if s.depth is None:
                find("unreachable_run", f"{s.correlation if s.correlation is not None else f'runs[{s.index}]'} is not "
                                        f"reachable from the root {_n(root.correlation)}.")
        depth = max(s.depth or 0 for s in sums)
        if depth > T.MAX_DEPTH:
            find("limit_exceeded", f"The tree is {depth} levels deep (at most {T.MAX_DEPTH}).")
            return _stopped(findings, sums, root.correlation)

    # ── every run on its own (§6.2)
    results: dict[int, AgentRunVerificationResult] = {}
    for s in sums:
        expected = None
        if s.agent_id is not None and options.expected_signers is not None and s.agent_id in options.expected_signers:
            expected = list(options.expected_signers[s.agent_id])
        results[s.index] = verify_agent_run(
            s.bundle, verifier, expected_signers=expected,
            expected_evaluation_signers=list(options.expected_evaluation_signers)
            if options.expected_evaluation_signers is not None else None)

    # ── §6.7 expected root
    if options.expected_root_correlation_id is not None or options.expected_root_run_end_signature_sha256 is not None \
            or options.expected_root_signer is not None:
        problems: list[str] = []
        if root is None:
            problems.append("no root could be derived")
        else:
            c = options.expected_root_correlation_id
            if c is not None and root.correlation != c:
                problems.append(f"its correlationId is {_n(root.correlation)}, not {c}")
            h = options.expected_root_run_end_signature_sha256
            if h is not None and root.run_end_sig != h:
                problems.append("its run_end is not the expected one")
            sg = options.expected_root_signer
            if sg is not None and results[root.index].signer != sg:
                problems.append("it is not signed by the expected signer")
        if problems:
            find("unexpected_root", "The derived root does not match the expected root: " + "; ".join(problems) + ".")

    # ── edges (§6.4)
    edges: list[AgentRunTreeEdge] = []
    for p in sums:
        if p.correlation is None:
            continue
        for d_seq, d_sig, d_child, d_agent in p.delegations:
            child_run = by_corr.get(d_child)
            if child_run is None:
                binding = "child_missing"
            elif (child_run.is_child and child_run.parent_delegation_sig == d_sig
                  and child_run.parent_correlation == p.correlation and child_run.agent_id == d_agent):
                binding = "mutually_bound"
            else:
                binding = "unbound"
            result = min((r for r in p.results if r[1] == d_child and r[0] > d_seq), key=lambda r: r[0], default=None)
            if result is None:
                completion = "no_result"
            elif child_run is None or child_run.run_end_sig is None:
                completion = "result_unresolved"
            elif result[2] == child_run.run_end_sig and result[3] == child_run.run_end_disposition:
                completion = "result_bound"
            else:
                completion = "result_mismatch"
            edges.append(AgentRunTreeEdge(
                parent_correlation_id=p.correlation, child_correlation_id=d_child, child_agent_id=d_agent,
                delegation_seq=d_seq, result_seq=result[0] if result else None, binding=binding,
                completion=completion, child_disposition=result[3] if result else None))
    for c in sums:
        if not c.is_child or c.correlation is None or c.parent_correlation is None:
            continue
        if any(e.parent_correlation_id == c.parent_correlation and e.child_correlation_id == c.correlation
               for e in edges):
            continue
        edges.append(AgentRunTreeEdge(
            parent_correlation_id=c.parent_correlation, child_correlation_id=c.correlation, child_agent_id=c.agent_id,
            binding="unbound" if c.parent_correlation in by_corr else "parent_missing", completion="no_result"))

    # ── §6.5 decision
    def closed(parent: str) -> Optional[str]:
        s = by_corr.get(parent)
        if s is None:
            return None
        r = results.get(s.index)
        if r is not None and r.verdict != "run_invalid":
            return r.disposition
        return s.run_end_disposition

    open_reasons: list[AgentRunTreeFinding] = []
    if findings:
        verdict = "tree_invalid"
    elif any(r.verdict == "run_invalid" for r in results.values()):
        verdict = "tree_invalid"
    elif any(e.binding in ("unbound", "parent_missing") or e.completion == "result_mismatch" for e in edges):
        verdict = "tree_invalid"
    elif any(e.completion == "result_unresolved"
             or (e.binding == "child_missing" and closed(e.parent_correlation_id) == "completed") for e in edges):
        verdict = "tree_invalid"
    elif any(e.completion == "no_result" and closed(e.parent_correlation_id) == "completed" for e in edges):
        verdict = "tree_invalid"
    elif all(r.verdict == "run_finalized" for r in results.values()) \
            and all(e.binding == "mutually_bound" and e.completion == "result_bound" for e in edges):
        verdict = "tree_finalized"
    else:
        verdict = "tree_open"
        for s in sums:
            if results[s.index].verdict == "run_open":
                open_reasons.append(AgentRunTreeFinding("run_open", f"{_n(s.correlation)} has no run_end yet."))
        for e in edges:
            if e.completion != "no_result" and e.binding != "child_missing":
                continue
            state = closed(e.parent_correlation_id)
            if state is None:
                open_reasons.append(AgentRunTreeFinding(
                    "delegation_pending", f"{e.parent_correlation_id} → {e.child_correlation_id}: no result yet."))
            elif state in ("aborted", "failed"):
                open_reasons.append(AgentRunTreeFinding(
                    "parent_terminated", f"{e.parent_correlation_id} closed {state} with {e.child_correlation_id} "
                                         f"unresolved: parent terminated; evidence incomplete."))

    tree_runs = [AgentRunTreeRun(
        correlation_id=s.correlation, agent_id=s.agent_id,
        parent_correlation_id=s.parent_correlation if s.is_child else None, depth=s.depth,
        result=results[s.index], affiliation=_affiliation(s, results[s.index], options)) for s in sums]
    return AgentRunTreeVerificationResult(
        verdict=verdict, root_correlation_id=root.correlation if root is not None else None, runs=tree_runs,
        edges=edges, findings=findings, open_reasons=open_reasons,
        fingerprint=_fingerprint(root.correlation if root is not None else None, tree_runs))


def _affiliation(s: _Summary, r: AgentRunVerificationResult, o: AgentRunTreeOptions) -> str:
    if s.agent_id is None or o.expected_signers is None or s.agent_id not in o.expected_signers:
        return "unknown"
    return "confirmed" if r.signer is not None and r.signer in o.expected_signers[s.agent_id] else "mismatch"


def _stopped(findings: list[AgentRunTreeFinding], sums: list[_Summary],
             root: Optional[str] = None) -> AgentRunTreeVerificationResult:
    return AgentRunTreeVerificationResult(
        verdict="tree_invalid", root_correlation_id=root,
        runs=[AgentRunTreeRun(correlation_id=s.correlation, agent_id=s.agent_id,
                              parent_correlation_id=s.parent_correlation if s.is_child else None, depth=s.depth)
              for s in sums],
        edges=[], findings=findings, open_reasons=[])


def _fingerprint(root: Optional[str], runs: Sequence[AgentRunTreeRun]) -> Optional[str]:
    """The §6.8 tree fingerprint over the derived root and every run's §8.2 fingerprint."""
    if root is None or any(r.correlation_id is None or r.result is None or r.result.fingerprint is None for r in runs):
        return None
    entries = sorted((r.correlation_id, r.result.fingerprint) for r in runs)  # by c, then f
    return hash_bytes(canonicalize({
        "format": AgentRunTreeBundle.FORMAT,
        "bundleVersion": AgentRunTreeBundle.VERSION,
        "root": root,
        "runs": [{"c": c, "f": f} for c, f in entries],
    }))
