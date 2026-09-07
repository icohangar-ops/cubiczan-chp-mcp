# Change: Host-injected args hash (allowlist ≠ authorization)

## Why

Semantic Kernel and other hosts need to pass index, key, and tenant
identifiers without letting the model choose them. A managed MCP
allowlist still only answers *“is this tool name installed?”*. Host
injection without a bound receipt is not authorization; a receipt that
hashes only model-chosen args lets the model swap the host’s index or
tenant after approval.

## What Changes

- Hosts inject bound fields on the proposed call (`host_bound`) and/or
  MCP `_meta.cubiczan.host_bound` (same `_meta.cubiczan` envelope the
  [governed-mcp-gateway](https://www.npmjs.com/package/@cubiczan/governed-mcp-gateway)
  uses for `principal`).
- `args_hash` is `contentHash` of the **merged** host ∪ model arguments.
- If the model supplies a host-bound field with a different value, deny
  (`host_bound_override`). The allowlist remains a pre-filter only.
- Policy may declare `host_bound_fields` per tool (e.g. `index_name`,
  `tenant_id`). Declared fields must be host-injected and concrete.
- Example policy + tests + README cookbook. No new npm dependency on
  the gateway — the `_meta` contract is documented.

## Impact

- Additive fields on `ProposedToolCall` and `ToolApprovalPolicy`.
- Existing `evaluate_tool_approval` / `issue_approval_receipt` /
  `authorize_tool_call` and deny-ledger tools keep their names and
  fail-closed behavior.
- Calls with no host injection behave as before.
