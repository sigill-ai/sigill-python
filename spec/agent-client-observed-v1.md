# Client-Observed Conversations v1 — Producer Conventions

**Status:** v1.0, normative for producers that claim it.
**Builds on:** [Agent Evidence Profiles v1 common rules](./agent-profiles-common-v1.md),
[AgentControlArtifact v1](./agent-control-artifact-v1.md),
[AgentExecutionEvidence v1](./agent-execution-evidence-v1.md).

A **client-observed conversation** is a conversation with a hosted AI assistant (claude.ai,
chatgpt.com, gemini.google.com, …) recorded by a recorder that sits on the user's side,
such as the Sigill browser extension. The recorder does not run the assistant. It sees only
what reaches the user's client: the prompt sent, files attached, the answer streamed back,
and files the user downloads.

This document defines how such a conversation maps onto the existing profiles. **It adds no
new schema, content type or verification rule.** A client-observed run is an ordinary agent
run: it validates against the v1 schemas and verifies under common rules §8 as is, and the
cross-language vectors in [`test-vectors/agent-run/`](./test-vectors/agent-run/README.md)
apply unchanged. What this document fixes is what the fields *mean*, so that a verdict on such
a run can be read correctly.

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Mapping

| Conversation | Profile element |
|---|---|
| One conversation | One run (`activity.correlationId`). A conversation MAY span several runs (§4). |
| The recorder's configuration | Control Artifact |
| One completed assistant answer | One `model_output` event |
| A file the assistant produced and the user downloaded | One `model_output` event, `detail: "generated file"` |
| End of the conversation as observed | `run_end` |

## 2. Identities

- **Control Artifact `actor`**: `{ "type": "system", "id": <recorder id>, "version": <recorder
  version> }`. The recorder id is a stable URN for the recorder product, for example
  `urn:sigill:recorder:browser-extension`.
- **Agent**: the observed assistant service. `agent.id` and every event's `actor.id` are
  `urn:sigill:assistant:<host>` (for example `urn:sigill:assistant:claude.ai`), with
  `actor.type: "agent"`. Common rules §8 (`control`) require the Control Artifact's `agent` to be
  the run's actor; this choice satisfies it.
- **`agent.version`** and every event's `actor.version` are the constant `"web"`. The model
  can change within a conversation, but the run's actor version cannot (common rules §8,
  `envelope`); the model a turn reports goes in the producer's `extensions` block (§5).
- **The user is never the actor** and is never named. Producers MUST NOT put an email address,
  account name, platform user id or organisation name anywhere in an envelope. Who recorded the
  run is established by the organisation the seals belong to, not by the envelope.

## 3. Events

- **`model_output`** carries, in this order: a `model-input` object for the prompt text when the
  turn had one (regenerated answers have none), one `model-input` object per attached file the
  recorder hashed, and one `model-output` object for the answer text.
- An attachment is a **digest object**: the recorder hashed the file in the client and never
  holds its bytes afterwards. Its `sha256` is the digest of the file as the client read it.
  `sizeBytes` is included when known.
- A **generated file** is recorded only when the recorder obtained its digest (for example from
  the bytes the client assembled, or by re-reading the downloaded file from the assistant's
  host). A download whose bytes the recorder could not hash is not recorded: there is nothing to
  bind.
- A turn the recorder could not observe completely (an interrupted stream, an unparseable
  response) MUST NOT be sealed. It is simply absent from the run.

## 4. Lifetime, segments and closure

Hosted conversations have no end signal. A run is closed with `run_end` (`runDisposition:
"completed"`) when one of the following happens:

- the conversation has been idle for the period stated in the control set (§6);
- the run reaches the bundle limit (common rules §7): ordinary events stop at `seq` 1998, so
  `run_end` fits at 1999.

A later turn in the same conversation starts a **new run** (a segment). Its `run_start`
carries `segmentOf: <correlationId of the previous run>` in the producer's `extensions` block,
so the segments can be shown together. A segment is a run in its own right: it is verified on
its own, and `segmentOf` is a display hint, not a binding.

After a sealing failure, or when the recorder cannot tell whether a seal request was processed
(for example the client was stopped while the request was in flight), the run MUST NOT be
continued (common rules §6.3). It verifies as `run_open`; the next turn starts a new segment.

## 5. Producer extensions

The `extensions` block of a client-observed run holds, under one producer key (the Sigill
browser extension uses `ai.sigill.browser-extension`):

| Field | Event | Meaning |
|---|---|---|
| `platform` | `run_start` | The assistant host, e.g. `claude.ai`. |
| `conversation` | `run_start` | A one-way reference to the platform's conversation id: the first 32 hex characters of SHA-256 over `<platform key>` + `"\n"` + `<conversation id>`. It lets the producer find the run again; it reveals neither the conversation nor its user. |
| `capture` | `run_start` | `"client-observed"`. |
| `segmentOf` | `run_start` | §4. |
| `model` | `model_output` | The model identifier the platform reported for the turn, when it reported one. |

Platform conversation ids and message ids MUST NOT appear in envelopes in clear: they are
account-linked identifiers at the platform.

## 6. Control basis and timestamp policy

The Control Artifact carries:

- an `execution-policy` object: the recorder's own settings that decide what is recorded (for
  example which platforms are enabled), with the recorder id and version;
- a `control-set` object that states what the recorder does, including the idle period after
  which a conversation is closed.

There is no `instruction-set`: the assistant's instructions are not visible to the client, and a
recorder MUST NOT seal a digest over something it did not see.

The timestamp policy SHOULD be `per-event`: each answer is then individually timestamped, so the
time an answer existed is proven per turn, not only at `run_end`. A producer MAY choose
`throughput` with a cadence; the verifier recomputes the required timestamps from the signed
policy either way (common rules §4).

## 7. What a verdict on a client-observed run proves

`run_finalized` means: the recorded answers, prompts and files (by digest) are unchanged since
they were sealed and timestamped, in the recorded order, under one signer, and the recorder's
control basis was sealed before the first event.

It does **not** establish:

- that every turn of the conversation was recorded: the recorder may have been disabled, the
  client closed, or a turn unparseable (§3);
- that the assistant service actually produced the answer as recorded beyond what the client
  received: the evidence is of what reached the user's client;
- that the model reported in `extensions` is the model that answered;
- who the user was (§2).

Verifiers SHOULD show this scope next to the verdict, in addition to the scope of common rules §8.

## 8. Design decisions (record)

- **No new profile** (2026-10-11): a client-observed conversation fits the run model exactly;
  a new content type would fork verification for no gain. Conventions only.
- **The assistant is the agent, the recorder is the system** (2026-10-11): the run describes
  what the assistant did as observed; the recorder's identity is in the Control Artifact.
- **Constant agent version** (2026-10-11): the model can change per turn, the run's actor
  version cannot; the model is producer-reported metadata.
- **Idle closure plus segments** (2026-10-11): hosted conversations never end explicitly; a run
  left open forever would never finalize.
