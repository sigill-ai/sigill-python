"""Shared by the examples: the client from the environment, the agents and the example control set.

Environment: SIGILL_API_KEY, SIGILL_CERTIFICATE_ID, SIGILL_BASE_URL (default: the SDK's default endpoint), and
SIGILL_CA_BUNDLE (a PEM file) when the endpoint uses a private certificate authority. The engine needs the policy extra: pip install "sigill-sdk[policy]".
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path

import httpx

from sigill_sdk import AgentConfiguration, AgentDefinition, AgentPolicy, AgentRunBundle, SigillClient

CONTROL_SET = AgentPolicy.control_set_from_document((Path(__file__).parent / "control-set.json").read_bytes())
"""Denies fs.delete, refunds without a bound approval; halts at the third denial; observes repeated searches."""

AGENT = AgentDefinition("urn:example:agent:support", "1.0.0", AgentConfiguration(
    instruction_set=b"You help customers with their orders.",
    tool_manifest=b'{"tools":["docs.search","fs.delete","payments.refund"]}'))
RESEARCHER = AgentDefinition("urn:example:agent:researcher", "1.0.0", AgentConfiguration(
    instruction_set=b"You look things up.", tool_manifest=b'{"tools":["docs.search"]}'))


def client_from_env() -> tuple[SigillClient, str]:
    """The client and the certificate id the examples seal with."""
    # Without SIGILL_BASE_URL: the SDK's default endpoint, the one SigillClient(api_key) uses.
    base_url = os.environ.get("SIGILL_BASE_URL") or inspect.signature(SigillClient).parameters["base_url"].default
    api_key = os.environ["SIGILL_API_KEY"]
    http = httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {api_key}"}, timeout=30,
                        verify=os.environ.get("SIGILL_CA_BUNDLE") or True)
    return SigillClient(api_key, base_url=base_url, http_client=http), os.environ["SIGILL_CERTIFICATE_ID"]


def report(client: SigillClient, bundle: AgentRunBundle, engine: object) -> None:
    """Prints the run's steps and its verification."""
    steps = []
    for a in bundle.artifacts:
        step = a.envelope["step"]
        tool = (step.get("tool") or {}).get("name")
        reason = (step.get("enforcer") or {}).get("reason")
        steps.append(step["type"] + (f"({tool})" if tool else "") + (f"[{reason}]" if reason else "")
                     + (f"[{step['runDisposition']}]" if step["type"] == "run_end" else ""))
    print(f"run {bundle.correlation_id}: " + " ".join(steps))
    result = client.verify_agent_run(bundle, engine=engine)
    print(f"  verdict {result.verdict}, enforcement {result.checks.get('enforcement')}, "
          f"findings {len(result.findings)}")
