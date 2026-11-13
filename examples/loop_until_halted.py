"""(a) A looped agent that keeps retrying a forbidden call until its run is halted.

The scripted "agent" wants to delete a file. The policy denies fs.delete; every retry is a new call with a new use
id, and the third denial halts the run (haltAfterDenials: 3). The tool body never runs.

    SIGILL_BASE_URL=... SIGILL_API_KEY=... SIGILL_CERTIFICATE_ID=... python examples/loop_until_halted.py
"""

from __future__ import annotations

from _shared import AGENT, CONTROL_SET, client_from_env, report

from sigill_sdk import AgentRunBundle, CedarEngine, Enforcement, PolicyDenied, PolicyEngine, SigillClient


def scenario(client: SigillClient, certificate_id: str, engine: PolicyEngine) -> AgentRunBundle:
    run = client.start_agent_run(AGENT, certificate_id=certificate_id, activity="cleanup", control_set=CONTROL_SET,
                                 enforcement=Enforcement(engine))
    deleted = []
    for attempt in range(1, 10):
        try:
            run.invoke_tool("fs.delete", b'{"path":"/var/log/app"}', lambda: deleted.append(1) or b'{"ok":true}',
                            consequential=True)
        except PolicyDenied as denied:
            print(f"attempt {attempt}: denied ({denied.reason}: {', '.join(denied.rules)})"
                  + (", run halted" if denied.halted else ""))
            if denied.halted:
                break
    assert run.halted and not deleted
    return run.finish()  # the halted run is closed already: its bundle, nothing more sealed


if __name__ == "__main__":
    client, certificate_id = client_from_env()
    engine = CedarEngine()
    report(client, scenario(client, certificate_id, engine), engine)
