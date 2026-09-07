# `@cubiczan/chp-mcp`

[![icohangar-ops/cubiczan-chp-mcp MCP server](https://glama.ai/mcp/servers/icohangar-ops/cubiczan-chp-mcp/badges/score.svg)](https://glama.ai/mcp/servers/icohangar-ops/cubiczan-chp-mcp)


One-command MCP install for **CHP Profile B** spend / capital gates and
**tool-approval receipts** (an allowlist is not authorization), plus a
**structured deny ledger** and receipt-gated finance tools.

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
│  evaluate_tool_approval   │  allowlist ≠ authorization
│  issue_approval_receipt   │
│  authorize_tool_call      │
│  request_authorization    │  finance-tool receipt / HITL / deny
│  place_equity_order       │  scoped + receipt-gated (synthetic)
│  wire_treasury_transfer   │
│  rebalance_portfolio      │
│  inspect_audit_ledger     │  CHP-signed deny / authorize / execute
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
| `evaluate_spend_gate` | `evaluateGate` | LOCKED / HITL_REQUIRED / BLOCKED + claims + content hash. `BLOCKED` is also a ledgered `policy_deny`. |
| `approve_spend` | `approveHuman` | Human lock when HITL_REQUIRED (cannot override hard fails). Optional `tool` + `bound_args` mint a signed receipt. |
| `evaluate_tool_approval` | `evaluateToolApproval` | Allowlist is a pre-filter; host-bound fields merge into `args_hash`; a receipt is still required |
| `issue_approval_receipt` | `issueApprovalReceipt` | Human allow/deny → HMAC-signed receipt + decision log |
| `authorize_tool_call` | `authorizeToolCall` | Consume a receipt; deny on drift, host-bound override, expiry, replay, or a bad MAC |
| `request_authorization` | runtime | Mint a receipt bound to a scoped reference tool, or return HITL / structured deny |
| `place_equity_order` | reference | Synthetic equity order — scope `trading:equities:place`, receipt required |
| `wire_treasury_transfer` | reference | Synthetic treasury wire — scope `treasury:wire`, always HITL |
| `rebalance_portfolio` | reference | Synthetic rebalance — scope `portfolio:rebalance` |
| `inspect_audit_ledger` | ledger | Trailing CHP-chained deny / authorize / execute entries |
| `chp_content_hash` | `contentHash` | Float-aware canonical SHA-256 |
| `chp_version` | — | Server + protocol versions + deny reason codes + receipt schema |

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
| `args_hash` | `contentHash(host ∪ model arguments, { floatAware: true })` |
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
Host-injected tenant/index bindings use
[`examples/host-injected-policy.json`](examples/host-injected-policy.json)
(see the host-injected args cookbook below).

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

## Cookbook — host-injected args + gateway `_meta`

Semantic Kernel and other hosts need to pass **index, key, and tenant**
without letting the model choose them
([SO-style routing](https://stackoverflow.com/questions/79748920/how-to-pass-dynamic-parameters-eg-index-name-key-from-semantic-kernel-to-mcp)).
Putting those fields on the tool schema so the LLM can “decide” is the
bug. An MCP allowlist does not fix it: the tool name can stay
allowlisted while the model swaps `index_name` to another tenant.

The host (or a gateway in front of this server) injects bound fields.
This package hashes **host ∪ model** arguments into the receipt and
denies when the model overrides a host-bound field. The allowlist is
still only a pre-filter.

### Contract — `_meta.cubiczan` (no hard dependency)

[`@cubiczan/governed-mcp-gateway`](https://www.npmjs.com/package/@cubiczan/governed-mcp-gateway)
already injects identity on every `tools/call` and SSE frame:

```json
{
  "_meta": {
    "cubiczan": {
      "principal": {
        "id": "agt_search",
        "kind": "agent",
        "orgId": "org_acme",
        "displayName": "Search Runner"
      }
    }
  }
}
```

This server does **not** import that package. It reads the same
envelope. Hosts MAY add `host_bound` next to `principal`. A trusted
gateway should overwrite `_meta.cubiczan` so the model cannot self-attest.

```json
{
  "_meta": {
    "cubiczan": {
      "principal": { "id": "agt_search", "kind": "agent", "orgId": "org_acme" },
      "host_bound": { "tenant_id": "acme", "index_name": "prod-docs" }
    }
  }
}
```

Library callers can also pass `host_bound` on the proposed call
(explicit keys overlay `_meta`). Policy
[`examples/host-injected-policy.json`](examples/host-injected-policy.json)
declares `host_bound_fields` so `index_name` and `tenant_id` must be
host-injected and concrete. If `tenant_id` is declared and omitted,
`_meta.cubiczan.principal.orgId` may fill it.

```text
model args ──┐
             ├─ override check ─→ deny host_bound_override
host_bound ──┘         │
                       ▼
              merged args → args_hash → receipt MAC
                       │
allowlist ──── pre-filter only (never a grant)
```

### 1. Host injects index + tenant — allowlist still denied

The model chose `query` / `top_k`. The host chose the index.

```jsonc
// tools/call evaluate_tool_approval
{
  "call": {
    "tool": "search.azure_ai",
    "resource": "tenant:acme",
    "arguments": { "query": "Q3 revenue", "top_k": 5 },
    "_meta": {
      "cubiczan": {
        "principal": { "id": "agt_search", "kind": "agent", "orgId": "org_acme" },
        "host_bound": { "tenant_id": "acme", "index_name": "prod-docs" }
      }
    }
  },
  "policy": { "$ref": "examples/host-injected-policy.json" }
}
```

Result: `RECEIPT_REQUIRED`, `deny_code: "allowlist_is_not_authorization"`.
`args_hash` is `contentHash` of
`{ query, top_k, tenant_id, index_name }` — not the model object alone.

### 2. Model changes a host-bound field — denied

Same host `_meta`, but the model adds `"index_name": "other-index"`.

```jsonc
"arguments": { "query": "Q3 revenue", "top_k": 5, "index_name": "other-index" }
```

`evaluate_tool_approval`, `issue_approval_receipt` (`decision: "allow"`),
and `authorize_tool_call` all return `DENIED` /
`host_bound_override`. Matching the host value is not an override.

### 3. Human allow — then authorize the merged args

Issue a receipt for the host-injected call. Authorize with the **same**
`arguments` and `_meta`. Result: `AUTHORIZED`. Change `query` after
approve → `changed_arguments`. Change `index_name` in model args →
`host_bound_override`. Omit declared host fields → `ambiguous`.

### 4. Semantic Kernel / host wiring

Do the routing in the host, not the model: disable auto-invoke, then
inject index/tenant (or put a gateway in front that writes
`_meta.cubiczan.host_bound`) before `evaluate_tool_approval` /
`authorize_tool_call`. Secrets such as API keys belong in the host or
the gateway vault — not in the tool schema the LLM sees.

## Cookbook — deny telemetry and receipts

MCP denials are usually a bare error string. That string is gone when the
client disconnects. This server treats a refuse as a **structured event**
that must hit a CHP-signed ledger *before* the caller sees it.

Finance tools (`place_equity_order`, `wire_treasury_transfer`,
`rebalance_portfolio`) are synthetic — no live venue or bank rail — and
use a separate `kind: "authorization"` receipt bound to tool, scope, and
args hash. That is not the same object as a `chp.tool_approval_receipt`.

### Reason codes

| Code | When |
|------|------|
| `policy_deny` | Hard CHP rule failed (`max_notional`, daily cap, …) |
| `expired` | Receipt `expires_at` is in the past |
| `replay` | Receipt already consumed by a successful execute |
| `args_changed` | Tool, scope, or args hash no longer matches the receipt |
| `missing_receipt` | No receipt, or the content hash does not verify |
| `ambiguous_policy` | Unknown tool, scope mismatch, or incomplete policy |

Signing is the existing Profile B primitives: `contentHash` on the
receipt / ledger payload, `chainHash` between ledger rows. Set
`CHP_AUDIT_LEDGER` to a JSONL path (default `./data/chp-audit.jsonl`),
or `:memory:` for tests.

### 1. Request a bound receipt

Under the HITL threshold the gate auto-locks and mints a receipt. At or
above it, pass `approver` (or call `approve_spend` with `tool` +
`bound_args`).

```jsonc
// tools/call request_authorization
{
  "tool": "place_equity_order",
  "args": {
    "symbol": "AAPL",
    "side": "BUY",
    "quantity": 10,
    "notional": 300,
    "confidence": 0.9
  },
  "approver": "cfo@example.com"
}
```

Treasury wires use `hitl_threshold: 0`. A request without `approver`
returns `HITL_REQUIRED` and **no** receipt — that is the approval gate,
not a weather-API demo.

### 2. Execute only with that receipt

`receipt` is optional on the wire so a missing token is a logged
`missing_receipt` deny, not a schema 400 that never hits the ledger.

```jsonc
// tools/call place_equity_order
{
  "symbol": "AAPL",
  "side": "BUY",
  "quantity": 10,
  "notional": 300,
  "confidence": 0.9,
  "receipt": { "kind": "authorization", "receipt_id": "…", "content_hash": "…" }
}
```

Change `notional` or `quantity` after approve → `args_changed`, and the
ledger has the deny. Call again with the same receipt → `replay`.
Call with no receipt → `missing_receipt`. All three are durable.

### 3. Inspect the chain

```jsonc
// tools/call inspect_audit_ledger
{ "limit": 20 }
```

Each row carries `content_hash` and `sig = chainHash(prev_sig, { seq, ts, event, content_hash })`.
`chain.ok` is false if anyone rewrote history.

### Tests

```bash
npm test
```

This Cubiczan mirror may omit GitHub Actions; run the suite locally.
`npm test` builds, then runs `node --test dist/*.test.js` (approval
receipts + host-injected bindings) and
`node --import tsx --test test/**/*.test.ts` (deny ledger). Invariants
covered: an unlogged deny is impossible (ledger failure throws instead
of returning a deny object); changed args after approve deny; a receipt
is required for every gated reference tool; allowlist is not
authorization; host-bound tenant/index cannot be overridden by the
model; receipt `args_hash` covers host ∪ model args.

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
