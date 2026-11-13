# Vector 13 — policy control set v2 (draft)

A v2 policy control set (`agent-policy-control-set-v2.md`) with `enforcement` in `enforce` mode
and `cedar.entities` (an agent in an agent group, six tools, nested tool groups), built from
the rules in `rules.cedar`.

| File | Content |
|---|---|
| `rules.cedar` | The rules in Cedar's text form: the source. |
| `control-set.json` | The document, Cedar JSON policies keyed by `@id`. |
| `expected.json` | `objectSha256` (the file's bytes), `cedarDigest`, `approvalScopeDigest`, `schemaSha256` (of `agent-policy-cedar-schema-v2.json`), the rule ids and each rule's effective effect. |
| `invalid.json` | Documents every implementation must reject. `error` is a word the validation error must mention: the member or rule that is wrong. |

The rules validate against schema v2 in Cedar's strict mode and the entities validate against
it in the Cedar core; the generator fails otherwise. The rule without an `effect` annotation
(`restricted-needs-bound-approval`) takes `defaultEffect` (`deny`). `export-weight` (a `deny`
rule) and `preview-weight` (an `observe` rule) overflow Cedar's Long on purpose, so that
vector 14 has rule errors of both kinds. The `tool-manifest` digest in `lockedConfiguration` is
the SHA-256 of the UTF-8 bytes `tool-manifest v1`.

| Invalid case | Why |
|---|---|
| `enforcement-unknown-member`, `on-unavailable-removed`, `require-approval-not-in-v2` | no other member (§6) |
| `enforcement-without-mode`, `default-effect-observe`, `unknown-tools-unknown-value`, `on-rule-error-unknown-value`, `halt-after-denials-negative`, `halt-after-denials-fraction` | member values (§6) |
| `locked-configuration-unknown-role`, `locked-configuration-not-hex` | roles and digests of `lockedConfiguration` (§6) |
| `annotation-unknown-key`, `effect-unknown-value` | annotations (§4 rules 6–7) |
| `too-many-policies` | at most 256 policies (§4 rule 8) |
| `entity-of-another-type`, `entity-duplicate-uid`, `entity-id-too-long`, `tool-unknown-attribute`, `group-with-attribute`, `too-many-entities` | entities (§5) |
| `parent-of-wrong-type`, `parent-not-declared`, `parent-cycle` | parents (§5) |
| `schema-v1-digest` | `schemaSha256` must be schema v2's (§4) |
| `schema-version-1`, `v1-document-with-enforcement` | recognition (§1): v1 has no `enforcement` member |

Regenerate from the repository root (Docker, no host Node):

```bash
docker run --rm -v "$PWD":/w -w /w/spec/test-vectors/13-policy-control-set-v2 node:22 \
  sh -c 'npm i --no-save --prefix /tmp/c @cedar-policy/cedar-wasm@4.14.0 >/dev/null && NODE_PATH=/tmp/c/node_modules node _generate.mjs'
```

Regenerate vector 14 afterwards: it reads this vector's output.
