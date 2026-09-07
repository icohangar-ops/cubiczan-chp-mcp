import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { contentHash } from "@cubiczan/chp";
import {
  InMemoryDecisionLog,
  authorizeToolCall,
  evaluateToolApproval,
  issueApprovalReceipt,
  parseToolApprovalPolicy,
} from "./approval.js";
import {
  bindHostInjectedArgs,
  extractHostBound,
  readCubiczanMeta,
} from "./host-bind.js";
import { hashToolArgs } from "./receipt.js";
import { InMemoryReplayStore } from "./replay.js";

const hostPolicy = parseToolApprovalPolicy(
  JSON.parse(
    readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "..", "examples", "host-injected-policy.json"),
      "utf8",
    ),
  ),
);

assert.ok(hostPolicy, "host-injected example policy must parse");

const key = "test-receipt-key";
const frozen = 1_704_067_200_000;
const clock = { now: () => frozen };

const hostMeta = {
  cubiczan: {
    principal: { id: "agt_search", kind: "agent", orgId: "org_acme", displayName: "Search Runner" },
    host_bound: { tenant_id: "acme", index_name: "prod-docs" },
  },
};

const searchCall = {
  tool: "search.azure_ai",
  resource: "tenant:acme",
  arguments: { query: "Q3 revenue", top_k: 5 },
  _meta: hostMeta,
};

test("reads governed-mcp-gateway _meta.cubiczan principal and host_bound", () => {
  const meta = readCubiczanMeta(hostMeta);
  assert.equal(meta.principal?.id, "agt_search");
  assert.equal(meta.principal?.orgId, "org_acme");
  assert.deepEqual(meta.host_bound, { tenant_id: "acme", index_name: "prod-docs" });
});

test("args hash covers host-injected ∪ model arguments", () => {
  const bound = bindHostInjectedArgs(searchCall, hostPolicy);
  assert.equal(bound.ok, true);
  assert.ok(bound.ok);
  assert.deepEqual(bound.merged, {
    query: "Q3 revenue",
    top_k: 5,
    tenant_id: "acme",
    index_name: "prod-docs",
  });

  const mergedHash = hashToolArgs(bound.merged);
  const modelOnly = hashToolArgs(searchCall.arguments);
  assert.equal(mergedHash, contentHash(bound.merged, { floatAware: true }));
  assert.notEqual(mergedHash, modelOnly);

  const issued = issueApprovalReceipt({
    actor: "search-ops@acme.example",
    call: searchCall,
    policy: hostPolicy,
    decision: "allow",
    signing_key: key,
    clock,
    log: new InMemoryDecisionLog(),
  });
  assert.ok(issued.receipt);
  assert.equal(issued.args_hash, mergedHash);
  assert.notEqual(issued.receipt.args_hash, modelOnly);
});

test("explicit host_bound overlays _meta and matching model values are not an override", () => {
  const call = {
    ...searchCall,
    host_bound: { index_name: "prod-docs", tenant_id: "acme" },
    arguments: { query: "Q3 revenue", top_k: 5, index_name: "prod-docs" },
  };
  const bound = bindHostInjectedArgs(call, hostPolicy);
  assert.equal(bound.ok, true);
  assert.ok(bound.ok);
  assert.equal((bound.merged as { index_name: string }).index_name, "prod-docs");
});

test("model cannot override a host-bound index or tenant", () => {
  const swappedIndex = {
    ...searchCall,
    arguments: { query: "Q3 revenue", top_k: 5, index_name: "other-index" },
  };
  const evaluated = evaluateToolApproval(swappedIndex, hostPolicy);
  assert.equal(evaluated.state, "DENIED");
  assert.equal(evaluated.deny_code, "host_bound_override");
  assert.match(evaluated.reason, /index_name/);

  const issued = issueApprovalReceipt({
    actor: "search-ops@acme.example",
    call: swappedIndex,
    policy: hostPolicy,
    decision: "allow",
    signing_key: key,
    clock,
    log: new InMemoryDecisionLog(),
  });
  assert.equal(issued.deny_code, "host_bound_override");
  assert.equal(issued.receipt, undefined);

  const good = issueApprovalReceipt({
    actor: "search-ops@acme.example",
    call: searchCall,
    policy: hostPolicy,
    decision: "allow",
    signing_key: key,
    clock,
    log: new InMemoryDecisionLog(),
  });
  const authorizeSwap = authorizeToolCall({
    call: swappedIndex,
    policy: hostPolicy,
    receipt: good.receipt,
    signing_key: key,
    clock,
    replay: new InMemoryReplayStore(),
  });
  assert.equal(authorizeSwap.deny_code, "host_bound_override");
});

test("allowlist + correct host tenant is still not authorization", () => {
  const evaluated = evaluateToolApproval(searchCall, hostPolicy);
  assert.equal(evaluated.state, "RECEIPT_REQUIRED");
  assert.equal(evaluated.allowed, false);
  assert.equal(evaluated.deny_code, "allowlist_is_not_authorization");

  const withoutReceipt = authorizeToolCall({
    call: searchCall,
    policy: hostPolicy,
    signing_key: key,
    clock,
    replay: new InMemoryReplayStore(),
  });
  assert.equal(withoutReceipt.state, "DENIED");
  assert.equal(withoutReceipt.deny_code, "allowlist_is_not_authorization");
});

test("matching host-bound identifier authorizes once; changing it after approve denies", () => {
  const replay = new InMemoryReplayStore();
  const issued = issueApprovalReceipt({
    actor: "search-ops@acme.example",
    call: searchCall,
    policy: hostPolicy,
    decision: "allow",
    ttl_seconds: 120,
    signing_key: key,
    clock,
    log: new InMemoryDecisionLog(),
  });
  assert.ok(issued.receipt);

  const authorized = authorizeToolCall({
    call: searchCall,
    policy: hostPolicy,
    receipt: issued.receipt,
    signing_key: key,
    clock,
    replay,
  });
  assert.equal(authorized.state, "AUTHORIZED");
  assert.equal(authorized.allowed, true);

  const replayed = authorizeToolCall({
    call: searchCall,
    policy: hostPolicy,
    receipt: issued.receipt,
    signing_key: key,
    clock,
    replay,
  });
  assert.equal(replayed.deny_code, "replayed_receipt");

  const freshReplay = new InMemoryReplayStore();
  const fresh = issueApprovalReceipt({
    actor: "search-ops@acme.example",
    call: searchCall,
    policy: hostPolicy,
    decision: "allow",
    signing_key: key,
    clock,
    log: new InMemoryDecisionLog(),
  });
  const changedQuery = authorizeToolCall({
    call: {
      ...searchCall,
      arguments: { query: "exfiltrate payroll", top_k: 5 },
    },
    policy: hostPolicy,
    receipt: fresh.receipt,
    signing_key: key,
    clock,
    replay: freshReplay,
  });
  assert.equal(changedQuery.deny_code, "changed_arguments");
});

test("declared host-bound fields are required and must be concrete", () => {
  const missing = evaluateToolApproval(
    {
      tool: "search.azure_ai",
      resource: "tenant:acme",
      arguments: { query: "Q3 revenue", top_k: 5 },
    },
    hostPolicy,
  );
  assert.equal(missing.deny_code, "ambiguous");
  assert.match(missing.reason, /index_name|tenant_id/);

  const wildcard = evaluateToolApproval(
    {
      tool: "search.azure_ai",
      resource: "tenant:acme",
      arguments: { query: "Q3 revenue" },
      host_bound: { tenant_id: "acme", index_name: "*" },
    },
    hostPolicy,
  );
  assert.equal(wildcard.deny_code, "ambiguous");
});

test("tenant_id may be derived from gateway principal.orgId when declared", () => {
  const call = {
    tool: "search.azure_ai",
    resource: "tenant:acme",
    arguments: { query: "roadmap" },
    host_bound: { index_name: "prod-docs" },
    _meta: {
      cubiczan: {
        principal: { id: "agt_search", kind: "agent", orgId: "acme" },
      },
    },
  };
  const extracted = extractHostBound(call, ["index_name", "tenant_id"]);
  assert.equal(extracted.host_bound.tenant_id, "acme");
  assert.ok(extracted.sources.includes("_meta.cubiczan.principal.orgId"));

  const bound = bindHostInjectedArgs(call, hostPolicy);
  assert.equal(bound.ok, true);
});
