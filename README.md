# `@cubiczan/chp-mcp`

[![icohangar-ops/cubiczan-chp-mcp MCP server](https://glama.ai/mcp/servers/icohangar-ops/cubiczan-chp-mcp/badges/score.svg)](https://glama.ai/mcp/servers/icohangar-ops/cubiczan-chp-mcp)


One-command MCP install for **CHP Profile B** spend / capital gates and
**tool-approval receipts** (an allowlist is not authorization).

[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.icohangar--ops%2Fchp--mcp-00C4B4)](https://registry.modelcontextprotocol.io)
[![npm](https://img.shields.io/npm/v/@cubiczan/chp-mcp)](https://www.npmjs.com/package/@cubiczan/chp-mcp)
[![Conformance](https://img.shields.io/badge/CHP_Profile_B-30%2F30-brightgreen)](https://github.com/icohangar-ops/cubiczan-chp)

Wraps [`@cubiczan/chp`](https://www.npmjs.com/package/@cubiczan/chp) so Cursor,
Claude Code, or any MCP client can call `evaluate_spend_gate` without vendoring
protocol code. Engine digests match the normative golden vectors
(**Profile B 30/30**).

## How the pieces fit

```text
MCP client (Cursor / Claude / …)
        │  tools/call
        ▼
┌───────────────────────────┐
│  MCP server (transport)   │  ← you are here (@cubiczan/chp-mcp)
│  evaluate_spend_gate      │
│  approve_spend            │
│  evaluate_tool_approval   │
│  issue_approval_receipt   │
│  authorize_tool_call      │
│  chp_content_hash         │
└─────────────┬─────────────┘
              │ depends on
              ▼
┌───────────────────────────┐
│  Published CHP packages   │
│  npm:  @cubiczan/chp                 (Profile B)
│  PyPI: consensus-hardening-protocol  (Profile A)
└───────────────────────────┘
```

For AGENTS.md + skills + Profile A `decision_gate` / `decision_adversary`, use
[agent-conductor](https://github.com/icohangar-ops/agent-conductor) instead.

## Install

```bash
npm install -g @cubiczan/chp-mcp
# or one-shot
npx -y @cubiczan/chp-mcp
```

### Cursor / Claude Desktop

```json
{
  "mcpServers": {
    "chp": {
      "command": "npx",
      "args": ["-y", "@cubiczan/chp-mcp"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add chp -- npx -y @cubiczan/chp-mcp
```

## Tools

| Tool | Maps to | Purpose |
|------|---------|---------|
| `evaluate_spend_gate` | `evaluateGate` | LOCKED / HITL_REQUIRED / BLOCKED + claims + content hash |
| `approve_spend` | `approveHuman` | Human lock when HITL_REQUIRED (cannot override hard fails) |
| `evaluate_tool_approval` | `evaluateToolApproval` | Allowlist is a pre-filter; a bound receipt is still required |
| `issue_approval_receipt` | `issueApprovalReceipt` | Human allow/deny → HMAC-signed receipt + decision log |
| `authorize_tool_call` | `authorizeToolCall` | Consume a receipt; deny on drift, expiry, replay, or a bad MAC |
| `chp_content_hash` | `contentHash` | Float-aware canonical SHA-256 |
| `chp_version` | — | Server + protocol versions |

### Example — evaluate a spend

```jsonc
// tools/call evaluate_spend_gate
{
  "action": { "action": "LONG", "asset": "ETH", "notional": 300, "confidence": 0.9 },
  "policy": {
    "max_notional": 500,
    "daily_cap": 2500,
    "hitl_threshold": 250,
    "min_confidence": 0.55,
    "allowed_actions": ["LONG", "SHORT"]
  }
}
```

## Cookbook — Claude / Cursor tool approval

Managed MCP allowlists (Cursor `mcpServers`, Claude Desktop, Claude Code)
only answer *“is this tool name installed?”*. They do not bind tenant,
arguments, risk, or a human decision. This server treats that gap as a
hard deny unless a signed **approval receipt** still matches the call
that is about to run.

Receipts are HMAC-SHA256 over [CHP canonical JSON](https://www.npmjs.com/package/@cubiczan/chp)
(the same payload discipline as Profile B `contentHash` / audit-ledger
`sig`). The MAC covers:

| Field | Role |
|-------|------|
| `actor` | Human who allowed or denied |
| `tool` | Concrete tool name (no `*`) |
| `resource` | Tenant / resource binding (no `*`) |
| `args_hash` | `contentHash(arguments, { floatAware: true })` |
| `policy_version` | Policy the human saw |
| `risk` | Policy risk for that tool |
| `issued_at` / `expiry` | Lifetime |
| `decision` | `allow` or `deny` |
| `nonce` | Single-use; replay denies |
| `signature` | HMAC-SHA256 hex |

Set `CHP_RECEIPT_KEY` (or `AUDIT_LEDGER_KEY`) in the MCP server env.
Without it the process falls back to a documented insecure default —
fine for the local cookbook, not for production.

Example policy: [`examples/tool-approval-policy.json`](examples/tool-approval-policy.json).
`stripe.create_charge` is **on the allowlist** and still cannot run
without a receipt bound to `acct_live_acme` and the exact charge args.

```json
{
  "mcpServers": {
    "chp": {
      "command": "npx",
      "args": ["-y", "@cubiczan/chp-mcp"],
      "env": { "CHP_RECEIPT_KEY": "replace-me" }
    }
  }
}
```

### 1. Allowlist alone — denied

Claude/Cursor has `stripe.create_charge` enabled. That is not a grant.

```jsonc
// tools/call evaluate_tool_approval
{
  "call": {
    "tool": "stripe.create_charge",
    "resource": "acct_live_acme",
    "arguments": { "amount": 2500, "currency": "usd", "customer": "cus_123" }
  },
  "policy": { "$ref": "examples/tool-approval-policy.json" }
}
```

Result: `RECEIPT_REQUIRED`, `deny_code: "allowlist_is_not_authorization"`.

Calling `authorize_tool_call` with the same payload and **no receipt**
returns `DENIED` / `allowlist_is_not_authorization`.

### 2. Human allow — then authorize

```jsonc
// tools/call issue_approval_receipt
{
  "actor": "cfo@acme.example",
  "decision": "allow",
  "reason": "invoice INV-104 matches amount",
  "ttl_seconds": 120,
  "call": { /* same as above */ },
  "policy": { /* same as above */ }
}
```

The response includes `receipt` (take the whole object) and
`decision_log` (actor, decision, args hash, nonce). Pass that receipt
into `authorize_tool_call` with the **same** call. Result: `AUTHORIZED`.

### 3. Human deny

Issue with `"decision": "deny"`. The decision is logged. Authorizing
with that receipt returns `DENIED` / `human_denied`. A deny receipt
cannot be flipped to allow by editing `decision` — the MAC breaks.

### 4. Changed arguments after approval — denied

Approve `{ "amount": 2500, ... }`, then authorize with
`{ "amount": 2500000, ... }`. Result: `DENIED` / `changed_arguments`.
Key order does not matter; the hash is CHP canonical. The original
receipt remains valid for the args that were approved (until expiry or
a successful consume).

### 5. Expired receipt — denied

Issue with `ttl_seconds: 30`. After the expiry instant,
`authorize_tool_call` returns `DENIED` / `expired_receipt`. The nonce is
consumed so a clock rewind cannot resurrect it.

### 6. Replayed receipt — denied

A successful `AUTHORIZED` consume burns the nonce. Presenting the same
receipt again returns `DENIED` / `replayed_receipt`.

### 7. Ambiguity — denied

These never produce a usable allow receipt:

- `resource: "*"`, `any`, `all`, or an empty string
- missing `arguments`
- policy without a concrete `version`
- actor / tool wildcards
- extra keys on a receipt (strict parse)

Fail-closed: `deny_on_ambiguity` cannot be turned off.

```bash
npm test
```

This Cubiczan mirror may omit GitHub Actions; run the suite locally
(`npm test` builds, then `node --test dist/*.test.js`).

## Related

| Package / repo | Role |
|----------------|------|
| [`@cubiczan/chp`](https://www.npmjs.com/package/@cubiczan/chp) | Profile B library (this server’s dependency) |
| [`consensus-hardening-protocol`](https://pypi.org/project/consensus-hardening-protocol/) | Profile A + normative spec |
| [`@cubiczan/agent-conductor`](https://www.npmjs.com/package/@cubiczan/agent-conductor) | Full MCP: contracts, skills, Profile A gates |
| [`@cubiczan/governed-mcp-gateway`](https://www.npmjs.com/package/@cubiczan/governed-mcp-gateway) | HTTP MCP control plane |
| [`@cubiczan/codesentinel-mcp`](https://www.npmjs.com/package/@cubiczan/codesentinel-mcp) | Codebase health MCP |
| [`cubiczan-resilience`](https://pypi.org/project/cubiczan-resilience/) / [`@cubiczan/resilience`](https://www.npmjs.com/package/@cubiczan/resilience) | Shared retry / timeout / audit primitives |

## Licence

MIT.
