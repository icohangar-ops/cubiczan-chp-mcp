# Design: Tool-approval receipts

## Binding tuple

A receipt is authorization for exactly one call:

`actor + tool + resource + args_hash + policy_version + risk + expiry + decision + nonce`

`args_hash` is CHP float-aware SHA-256. The MAC is HMAC-SHA256 over
`canonicalJson` of the body with `signature` omitted — the same
canonicalization the audit ledger uses for `sig`.

## Fail-closed

Wildcards (`*`, `any`, `all`), empty bindings, missing arguments, extra
receipt keys, and unparseable policy/timestamps are `ambiguous` and
deny. `deny_on_ambiguity: false` is ignored.

## Replay

An in-process nonce store consumes on successful authorize, human deny,
and expiry. Binding mismatches (wrong args/tool/resource) do not consume
so the original grant can still be used once.

## Allowlist

Necessary, never sufficient. `authorize_tool_call` without a receipt
returns `allowlist_is_not_authorization` even when the tool is listed.
A human cannot issue an **allow** receipt for a tool that is not
allowlisted (same rule as `approveHuman` vs hard BLOCKED).
