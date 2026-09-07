# Design: Host-injected args hash

## Context

`evaluateToolApproval` / `issueApprovalReceipt` / `authorizeToolCall`
already bind `actor + tool + resource + args_hash + policy + risk +
expiry + nonce`. `args_hash` is CHP float-aware `contentHash` of
`call.arguments`. Hosts such as Semantic Kernel and
`@cubiczan/governed-mcp-gateway` inject identifiers the model must not
decide. Those values have to enter the same hash, or a receipt for
`{ query }` authorizes `{ query, index_name: "other-tenant" }`.

## Goals / Non-Goals

**Goals**

- Merge host-injected fields with model args before hashing.
- Deny when the model overrides a host-bound field.
- Keep allowlist membership a pre-filter (`RECEIPT_REQUIRED` /
  `allowlist_is_not_authorization`).
- Document the gateway `_meta.cubiczan` contract without depending on
  that package.

**Non-Goals**

- Cryptographic attestation of `_meta` inside this stdio server (the
  trusted host/gateway overwrites `_meta` on the wire).
- Changing the receipt schema (`kind`, MAC fields).
- Live Azure AI Search / Pinecone connections.

## Decisions

1. **Extraction order.** `call.host_bound` overlays
   `_meta.cubiczan.host_bound`. Missing `tenant_id` may be filled from
   `_meta.cubiczan.principal.orgId` when the policy declares `tenant_id`.
2. **Override check before merge.** Canonical-JSON inequality between a
   model value and the host value on the same key is `host_bound_override`.
   Matching values are not an override.
3. **Declared fields are mandatory.** `policy.host_bound_fields[tool]`
   must all be present and concrete after extraction; otherwise
   `ambiguous`.
4. **Ad-hoc host keys.** If the host injects keys that are not listed,
   those keys are still host-bound and hashed.
5. **No host injection → unchanged path.** Existing cookbook calls keep
   hashing `call.arguments` only.

## Contract (`_meta.cubiczan`)

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

`governed-mcp-gateway` already writes `principal` on every `tools/call`
and SSE frame. Hosts MAY add `host_bound`. This package reads both; it
does not import the gateway.
