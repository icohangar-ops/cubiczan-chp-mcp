# Change: Structured deny telemetry + signed receipts

## Why

MCP servers typically return a bare error string when a tool is refused.
Those strings never land in a durable, hash-chained log, so a denied
high-consequence action is invisible after the fact. Demos usually wrap
weather or todo APIs, which hides the real problem: scoped permissions
and approval gates on capital-moving tools.

## What Changes

- Every gated deny is a structured event with a closed reason-code set
  (`policy_deny`, `expired`, `replay`, `args_changed`, `missing_receipt`,
  `ambiguous_policy`) and is appended to a CHP-signed audit ledger
  *before* the caller sees the deny.
- Authorization and deny receipts are content-hashed with `@cubiczan/chp`
  and bound to tool + canonical args. Ledger entries are chain-hashed.
- A synthetic finance/trading reference (equity order, treasury wire,
  portfolio rebalance) shows scopes and HITL gates — not a weather API.
- Tests prove: an unlogged deny is impossible; changed args after approve
  deny; a receipt is required.
- README cookbook documents the flow.

## Capabilities

### New Capabilities

- `deny-telemetry`: structured, durable, signed deny events
- `authorization-receipts`: signed authorize/deny receipts with replay,
  expiry, and args binding
- `real-permissions`: synthetic scoped trading/treasury tools

### Modified Capabilities

- None. Existing `evaluate_spend_gate` / `approve_spend` responses stay
  valid; ledger + optional receipt fields are additive.

## Impact

- New MCP tools and additive fields on existing tools
- New `CHP_AUDIT_LEDGER` env for the JSONL ledger path
- New unit tests (`tsx` + `node --test`); no CI added on this mirror
