# Project: @cubiczan/chp-mcp

## Purpose

MCP transport for CHP Profile B spend / capital gates, HMAC tool-approval
receipts (allowlist is not authorization), and a structured deny ledger.
The server wraps `@cubiczan/chp` so clients can evaluate and approve
high-consequence actions without vendoring protocol code.

## Conventions

- TypeScript ESM (`NodeNext`), Zod schemas on MCP tool inputs
- Signing and canonicalization come from `@cubiczan/chp` (`contentHash`,
  `chainHash`) — do not invent a parallel hash scheme
- Host-injected `_meta.cubiczan` is a documented contract with
  `@cubiczan/governed-mcp-gateway`, not a runtime dependency
- Keep the published tool names `evaluate_spend_gate` and `approve_spend`
  backward compatible; new fields are additive
- Gated reference tools are synthetic (no live brokerage or bank rails)
- Tests use Node's built-in test runner

## Domain

Finance / trading-style agent permissions: scopes, human approval, signed
receipts, and a durable deny ledger. Not weather, todos, or other toy APIs.
