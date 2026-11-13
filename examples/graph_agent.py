"""(b) A graph-shaped agent: two branches record concurrently on one run, plus one delegated child run.

Branch "research" searches and finishes; branch "cleanup" tries to delete a file, is denied and stops. A child run
(its own enforced run, under the same control set) does a search. One denial does not halt the run (the limit is 3),
so the parent records the child's result and finishes.

    SIGILL_BASE_URL=... SIGILL_API_KEY=... SIGILL_CERTIFICATE_ID=... python examples/graph_agent.py
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from _shared import AGENT, CONTROL_SET, RESEARCHER, client_from_env, report

from sigill_sdk import AgentRunBundle, CedarEngine, Enforcement, PolicyDenied, PolicyEngine, SigillClient


def scenario(client: SigillClient, certificate_id: str, engine: PolicyEngine) -> tuple[AgentRunBundle, AgentRunBundle]:
    run = client.start_agent_run(AGENT, certificate_id=certificate_id, activity="order-help", control_set=CONTROL_SET,
                                 enforcement=Enforcement(engine))

    def research() -> str:
        for q in (b'{"q":"refund policy"}', b'{"q":"delivery times"}'):
            run.invoke_tool("docs.search", q, lambda: b'{"hits":3}', operation="read")
        return "research: done"

    def cleanup() -> str:
        try:
            run.invoke_tool("fs.delete", b'{"path":"/tmp/order-cache"}', lambda: b'{"ok":true}', consequential=True)
            return "cleanup: done"
        except PolicyDenied as denied:
            return f"cleanup: denied ({denied.reason}: {', '.join(denied.rules)}), branch stopped"

    with ThreadPoolExecutor(2) as pool:
        for line in pool.map(lambda branch: branch(), (research, cleanup)):
            print(line)

    delegation = run.delegate(RESEARCHER.agent_id, b'{"task":"find the return address"}')
    child = client.start_child_agent_run(RESEARCHER, delegation, certificate_id=certificate_id, activity="order-help",
                                         control_set=CONTROL_SET, enforcement=Enforcement(engine))
    child.invoke_tool("docs.search", b'{"q":"return address"}', lambda: b'{"hits":1}', operation="read")
    child_bundle = child.finish()
    run.complete_delegation(child)
    return run.finish(), child_bundle


if __name__ == "__main__":
    client, certificate_id = client_from_env()
    engine = CedarEngine()
    parent, child = scenario(client, certificate_id, engine)
    report(client, parent, engine)
    report(client, child, engine)
