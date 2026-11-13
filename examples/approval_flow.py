"""(c) An approval flow: a refund is denied, a human approves exactly that refund, the retry is allowed.

The policy denies a payments tool call unless an approval is bound to it. The approval names the tool and the digest
of the exact arguments (ApprovalCovers); the retry is a new call with a new use id, and the approval binds it once.

    SIGILL_BASE_URL=... SIGILL_API_KEY=... SIGILL_CERTIFICATE_ID=... python examples/approval_flow.py
"""

from __future__ import annotations

from _shared import AGENT, CONTROL_SET, client_from_env, report

from sigill_sdk import (
    AgentRunBundle,
    ApprovalCovers,
    CedarEngine,
    Enforcement,
    PolicyDenied,
    PolicyEngine,
    SigillClient,
)

REFUND = b'{"amount":120,"order":"o-1"}'


def scenario(client: SigillClient, certificate_id: str, engine: PolicyEngine) -> AgentRunBundle:
    run = client.start_agent_run(AGENT, certificate_id=certificate_id, activity="refund", control_set=CONTROL_SET,
                                 enforcement=Enforcement(engine))
    try:
        run.invoke_tool("payments.refund", REFUND, lambda: b'{"refunded":true}', consequential=True)
        raise AssertionError("a refund without approval must be denied")
    except PolicyDenied as denied:
        print(f"refund denied ({denied.reason}: {', '.join(denied.rules)}); asking a human")
    run.record_human_approval("approved", approver="urn:example:approver:1",
                              covers=ApprovalCovers.for_arguments("payments.refund", REFUND))
    result = run.invoke_tool("payments.refund", REFUND, lambda: b'{"refunded":true}', consequential=True)
    print(f"retry allowed: {result.decode()}")
    return run.finish()


if __name__ == "__main__":
    client, certificate_id = client_from_env()
    engine = CedarEngine()
    report(client, scenario(client, certificate_id, engine), engine)
