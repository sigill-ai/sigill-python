// The rules of control-set.json, in Cedar's text form. _generate.mjs converts each policy to
// Cedar JSON with the official core and keys it by its @id.

@id("no-web-search")
@effect("deny")
forbid (principal in AgentGroup::"tier1", action == Action::"tool_call", resource == Tool::"search.web");

// No effect annotation: takes enforcement.defaultEffect ("deny"). Membership is transitive:
// payments.refund is in ToolGroup::"payments", which is in ToolGroup::"restricted".
@id("restricted-needs-bound-approval")
forbid (principal, action == Action::"tool_call", resource in ToolGroup::"restricted")
unless { context.approval == "bound" };

@id("rejected-is-final")
@effect("deny")
forbid (principal, action == Action::"tool_call", resource)
when { context.approval == "rejected" };

@id("read-loop-limit")
@effect("deny")
forbid (principal, action == Action::"tool_call", resource == Tool::"crm.read_customer")
when { context.callsOfThisTool > 3 };

// A shadow rule: evaluated and reported, never denies.
@id("shadow-repeat-read")
@effect("observe")
forbid (principal, action == Action::"tool_call", resource == Tool::"crm.read_customer")
when { context.callsOfThisTool > 1 };

@id("halt-retrieval-after-denial")
@effect("halt")
forbid (principal, action == Action::"retrieval", resource)
when { context.denialsSoFar > 0 };

// Deliberately overflows Cedar's Long for any call of ledger.export, to exercise rule errors.
@id("export-weight")
@effect("deny")
forbid (principal, action == Action::"tool_call", resource == Tool::"ledger.export")
when { context.toolCallsSoFar * 9007199254740991 * 2048 > 0 };

// An erroring observe rule: reported INDETERMINATE by an evaluator, never denies.
@id("preview-weight")
@effect("observe")
forbid (principal, action == Action::"tool_call", resource == Tool::"ledger.preview")
when { context.toolCallsSoFar * 9007199254740991 * 2048 > 0 };

// Matches together with restricted-needs-bound-approval: one record with both ids, then halted.
@id("halt-refund-loop")
@effect("halt")
forbid (principal, action == Action::"tool_call", resource == Tool::"payments.refund")
when { context.callsOfThisTool > 2 };

// Halt rules that match calls denied for another reason: they still halt the run.
@id("halt-fs-wipe")
@effect("halt")
forbid (principal, action == Action::"tool_call", resource == Tool::"fs.wipe");

@id("halt-consequential-export")
@effect("halt")
forbid (principal, action == Action::"tool_call", resource == Tool::"ledger.export")
when { context.consequential };

// This run never delegates: the guard halts right after a delegation event; no child is started.
@id("no-delegation")
@effect("halt")
forbid (principal, action == Action::"delegation", resource);

@id("no-unpaired-consequential")
@effect("observe")
forbid (principal, action == Action::"run", resource)
when { context.unpairedConsequential > 0 };
