# Change: Tool-approval receipts (allowlist ≠ authorization)

## Why

Managed MCP allowlists in Claude / Cursor only answer whether a tool
name is installed. That is not authorization. A caller can keep the
allowlisted name and change tenant, arguments, or replay a stale grant.

## What Changes

- Signed approval receipts bind actor, tool, resource, normalized args
  hash, policy version, risk, expiry, decision, and nonce.
- HMAC-SHA256 over CHP canonical JSON (existing Profile B / ledger
  pattern). Args hash is `contentHash(..., { floatAware: true })`.
- Policy treats allowlist membership as a pre-filter. Execution requires
  a receipt that still matches. Ambiguity, expiry, replay, and argument
  drift deny.
- Human allow/deny is written to an in-process decision log.
- MCP tools: `evaluate_tool_approval`, `issue_approval_receipt`,
  `authorize_tool_call`.
- README cookbook + `examples/tool-approval-policy.json`.
- Package name stays `@cubiczan/chp-mcp`.

## Impact

- Additive MCP tools and library modules. Existing spend-gate tools are
  unchanged.
- Clients that only allowlist tools still cannot execute those tools
  through this gate without a receipt.
