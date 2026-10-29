# Agent Model Calls v1 — Specification (DRAFT)

**Status:** draft for review — field names may still change before the first release.
**Extends:** [AgentExecutionEvidence](./agent-execution-evidence-v1.md) (`schemaVersion "3"`)
**Common rules:** [`agent-profiles-common-v1.md`](./agent-profiles-common-v1.md)

## 1. Problem

An Agent Execution Evidence run proves *when* each step happened (RFC 3161
timestamps) and *that* nothing was removed, inserted or reordered (the signed
chain). It does not let a third party tie a model call to the provider that
served it: the agent's name and model are the producer's statements.

A provider assigns its own identifiers to every API call — a message or response
id in the body, a request id in the response headers. If those identifiers are
sealed into the step that records the call, the provider can confirm the call
against its own logs, and anyone can verify when it was sealed and in which run.
The organisation that ran the agent can then show a vendor, an auditor or a
counterparty that *the vendor's* model was called at a given time and what the
agent did with the answer — without disclosing prompts or responses.

## 2. Model

Version 3 is version 2 plus three optional members of `step`, allowed on
`model_output`:

- `model` — which model served the call, as the provider's response states it.
- `vendorRefs` — the provider's own identifiers for the call.
- `usage` — token counts and the stop reason the provider reported.

The call's input and output stay digest-only objects (`model-input`,
`model-output`), as in every version: content never enters the envelope.

These members are the producer's statement of what the provider *returned*. A
verifier checks their shape only. Whether an identifier is genuine is confirmed
by the provider (§6), not by the verifier.

## 3. Schema changes

### 3.1 Versions

| Execution artifacts of one run | all `"1"`, all `"2"` or all `"3"`; never mixed |
|---|---|

- `AgentExecutionEvidence` gains `schemaVersion: "3"`: v2 plus the members below.
- A run whose producer records model calls with any of these members MUST use
  `"3"` for every event, including runs that also delegate (v3 contains v2).
- Verifiers dispatch the execution schema on `schemaVersion` and accept 1, 2 and 3.
  A v3 member in a v1 or v2 artifact is a schema violation.

### 3.2 `step.model`

```json
"model": {
  "provider": "anthropic",
  "served": "claude-sonnet-5-20261015",
  "requested": "claude-sonnet-5",
  "deployment": "arn:aws:bedrock:eu-north-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-5",
  "region": "eu-north-1"
}
```

| Member | | Rule |
|---|---|---|
| `provider` | REQUIRED | Lowercase identifier of the API that served the call: `^[a-z0-9][a-z0-9.-]{0,63}$`. Registered values in §7; others allowed |
| `served` | REQUIRED | The model identifier from the provider's response, 1–128 characters |
| `requested` | optional | The identifier the producer asked for (an alias or family), 1–128 characters |
| `deployment` | optional | Deployment, endpoint or inference-profile identifier where the provider uses one (e.g. a cloud ARN), 1–255 characters |
| `region` | optional | Provider region of the call, 1–32 characters |

### 3.3 `step.vendorRefs`

```json
"vendorRefs": [
  { "provider": "anthropic", "kind": "message", "id": "msg_01XyZ8kq3VcR2mWd9TfLpA7e" },
  { "provider": "anthropic", "kind": "request", "id": "req_011CabcQx7Nn4Tz2Pf8Rk1Ws" }
]
```

An array of 1–8 entries, each `{ provider, kind, id }`:

| Member | Rule |
|---|---|
| `provider` | As `model.provider` |
| `kind` | `message`, `response`, `request`, `completion` or `trace` — what the identifier names (§7) |
| `id` | The identifier exactly as the provider returned it: 1–255 printable ASCII characters (`^[\x21-\x7E]{1,255}$`) |

`vendorRefs` without `model` is allowed (a producer that sees identifiers but not
the model). Entries are recorded in the order the producer received them.

### 3.4 `step.usage`

```json
"usage": { "inputTokens": 2960, "outputTokens": 488, "cacheReadTokens": 1200, "stopReason": "tool_use" }
```

| Member | Rule |
|---|---|
| `inputTokens`, `outputTokens`, `cacheReadTokens`, `cacheWriteTokens` | optional integers ≥ 0 |
| `stopReason` | optional, the provider's value, 1–64 characters |

At least one member is present when `usage` is present.

## 4. Producer rules

1. Take every value from the provider's **response** (body or headers), never
   from configuration. `requested` is the only member that comes from the request.
2. Record one `model_output` step per provider call. A streamed call is one step,
   sealed when the stream completes.
3. A call that failed at the provider is recorded as `model_output` with
   `detail` describing the failure only if the provider returned identifiers;
   otherwise it is not recorded as a model call.
4. Never put prompt, response or user text in `detail`, `vendorRefs` or `model`.
5. Recorders that observe an application rather than calling the API (a browser
   extension, a coding-agent hook) record only identifiers they actually see, with
   the `kind` that names them. They do not invent `request` ids.

## 5. Verification

- Schema: v3 artifacts are validated against
  [`agent-execution-evidence-v3.schema.json`](./agent-execution-evidence-v3.schema.json);
  all common-rules checks apply unchanged.
- The members never affect the run verdict beyond schema validity.
- Verifiers report, per run, the number of `model_output` steps and how many carry
  `vendorRefs` — so a viewer can state "N of M model calls carry the provider's
  identifiers" without implying the provider has confirmed them.

## 6. How a provider confirms a call (informative)

Given an exported run (bundle or ETSI export), the provider:

1. verifies the run offline with any conforming verifier — the step is intact, in
   order, and was timestamped by an independent authority at the stated time;
2. looks up each `vendorRefs.id` in its own logs and checks that the call exists,
   belongs to the customer's account, was served by `model.served` and falls
   before the step's timestamp;
3. optionally compares `usage` with its billing record.

The customer can later prove which prompt and response a call carried by
disclosing the `model-input` / `model-output` content, whose digests the step
already sealed.

What this does not prove: that the provider's identifiers were not copied from
another call. The provider's own lookup (step 2) closes that gap.

## 7. Registered values (informative)

| `provider` | API | `vendorRefs` kinds |
|---|---|---|
| `anthropic` | Anthropic Messages API | `message` (body `id`, `msg_…`), `request` (`request-id` header) |
| `openai` | OpenAI Responses / Chat Completions | `response` (body `id`), `completion` (`chatcmpl-…`), `request` (`x-request-id`) |
| `aws-bedrock` | Amazon Bedrock Runtime | `request` (`x-amzn-requestid`), `message` (body id where present) |
| `azure-openai` | Azure OpenAI (`*.openai.azure.com`, `*.cognitiveservices.azure.com`, `*.services.ai.azure.com`) | `completion`, `response`, `request` (`apim-request-id`) |
| `google` | Gemini API | `response` (`responseId`) |
| `google-vertex` | Vertex AI | `response` (`responseId`) |

Any other provider uses its own lowercase identifier. A gateway or proxy in front of a
provider records the identifiers it actually returns under its own `provider` value: they
name the gateway's request, not the upstream provider's, unless the gateway passes the
upstream identifiers through unchanged.

## 8. Privacy

Identifiers, model names and token counts are not content and contain no personal
data by themselves. A provider can link an identifier to the customer's account
with that provider; that link is the purpose of the field. Producers that must not
reveal which provider they use should not record these members.

## 9. Test vectors

Additions to `spec/test-vectors/agent-run/`:

- a valid v3 run with three `model_output` steps carrying `model`, `vendorRefs`
  and `usage`;
- a v3 member in a v2 artifact → `envelope` bad;
- a run mixing v2 and v3 artifacts → `bad`;
- a `vendorRefs.id` with a space, and with 256 characters → `envelope` bad;
- an unknown `kind` → `envelope` bad.

## 10. Decisions and open questions

- **Why a profile version, not `extensions`:** extensions never carry profile
  semantics (common rules), so a provider or auditor could not rely on them. The
  identifiers are the point of the record and belong in the profile.
- **Why on `model_output` only:** a model call is one step; tool calls made by the
  model are separate `tool_call` steps as today. Open: whether `tool_call` should
  allow `vendorRefs` for provider-hosted tools.
- **SDK surface (informative):** `AgentRun.RecordModelCallAsync(ModelCall)` in the
  core SDKs, and optional client wrappers in separate packages so the core SDK
  takes no provider dependencies.
