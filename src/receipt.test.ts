import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { CHP_VERSION, canonicalJson, contentHash } from "@cubiczan/chp";
import {
  InMemoryDecisionLog,
  authorizeToolCall,
  evaluateToolApproval,
  issueApprovalReceipt,
  parseToolApprovalPolicy,
} from "./approval.js";
import {
  DEFAULT_RECEIPT_KEY,
  hashToolArgs,
  isAmbiguousBinding,
  issueSignedReceipt,
  parseApprovalReceipt,
  signReceipt,
  verifyReceiptSignature,
  type ApprovalReceipt,
} from "./receipt.js";
import { InMemoryReplayStore } from "./replay.js";

const examplePolicy = parseToolApprovalPolicy(
  JSON.parse(
    readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "..", "examples", "tool-approval-policy.json"),
      "utf8",
    ),
  ),
);

assert.ok(examplePolicy, "example policy must parse");

const stripeCall = {
  tool: "stripe.create_charge",
  resource: "acct_live_acme",
  arguments: { amount: 2500, currency: "usd", customer: "cus_123" },
};

const key = "test-receipt-key";
const frozen = 1_704_067_200_000; // 2024-01-01T00:00:00.000Z
const clock = { now: () => frozen };

test("receipt schema binds actor/tool/resource/args/policy/risk/expiry/decision and HMAC", () => {
  const receipt = issueSignedReceipt(
    {
      actor: "cfo@acme.example",
      tool: stripeCall.tool,
      resource: stripeCall.resource,
      args_hash: hashToolArgs(stripeCall.arguments),
      policy_version: examplePolicy.version,
      risk: "critical",
      decision: "allow",
      issued_at: new Date(frozen).toISOString(),
      expiry: new Date(frozen + 60_000).toISOString(),
      nonce: "nonce-1",
    },
    key,
  );

  assert.equal(receipt.kind, "chp.tool_approval_receipt");
  assert.equal(receipt.schema_version, "1");
  assert.equal(receipt.chp_version, CHP_VERSION);
  assert.equal(receipt.actor, "cfo@acme.example");
  assert.equal(receipt.tool, stripeCall.tool);
  assert.equal(receipt.resource, stripeCall.resource);
  assert.equal(receipt.args_hash, hashToolArgs(stripeCall.arguments));
  assert.equal(receipt.policy_version, "tool-approval-1");
  assert.equal(receipt.risk, "critical");
  assert.equal(receipt.decision, "allow");
  assert.match(receipt.expiry, /^2024-01-01T00:01:00/);
  assert.equal(receipt.signature.length, 64);
  assert.equal(verifyReceiptSignature(receipt, key), true);
  assert.equal(verifyReceiptSignature(receipt, "wrong-key"), false);

  const { signature: _sig, ...body } = receipt;
  const expected = createHmac("sha256", key)
    .update(canonicalJson(body), "utf8")
    .digest("hex");
  assert.equal(receipt.signature, expected);
  assert.equal(signReceipt(body, key), expected);
});

test("args hash is CHP float-aware contentHash and ignores key order", () => {
  const a = hashToolArgs({ currency: "usd", amount: 10.0, customer: "cus_123" });
  const b = hashToolArgs({ customer: "cus_123", amount: 10, currency: "usd" });
  assert.equal(a, b);
  assert.equal(a, contentHash({ customer: "cus_123", amount: 10, currency: "usd" }, { floatAware: true }));
});

test("example policy: allowlist alone is not authorization", () => {
  const evaluated = evaluateToolApproval(stripeCall, examplePolicy);
  assert.equal(evaluated.state, "RECEIPT_REQUIRED");
  assert.equal(evaluated.allowed, false);
  assert.equal(evaluated.deny_code, "allowlist_is_not_authorization");
  assert.match(evaluated.reason, /allowlist is not authorization/);

  const withoutReceipt = authorizeToolCall({
    call: stripeCall,
    policy: examplePolicy,
    signing_key: key,
    clock,
    replay: new InMemoryReplayStore(),
  });
  assert.equal(withoutReceipt.state, "DENIED");
  assert.equal(withoutReceipt.deny_code, "allowlist_is_not_authorization");
  assert.equal(withoutReceipt.allowed, false);
});

test("valid receipt authorizes once", () => {
  const replay = new InMemoryReplayStore();
  const log = new InMemoryDecisionLog();
  const issued = issueApprovalReceipt({
    actor: "cfo@acme.example",
    call: stripeCall,
    policy: examplePolicy,
    decision: "allow",
    ttl_seconds: 120,
    signing_key: key,
    clock,
    log,
  });
  assert.ok(issued.receipt);
  assert.equal(log.list().length, 1);
  assert.equal(log.list()[0]?.decision, "allow");
  assert.equal(log.list()[0]?.actor, "cfo@acme.example");

  const authorized = authorizeToolCall({
    call: stripeCall,
    policy: examplePolicy,
    receipt: issued.receipt,
    signing_key: key,
    clock,
    replay,
  });
  assert.equal(authorized.state, "AUTHORIZED");
  assert.equal(authorized.allowed, true);
  assert.equal(authorized.receipt_hash, issued.receipt_hash);
});

test("changed arguments after approval deny", () => {
  const replay = new InMemoryReplayStore();
  const issued = issueApprovalReceipt({
    actor: "cfo@acme.example",
    call: stripeCall,
    policy: examplePolicy,
    decision: "allow",
    signing_key: key,
    clock,
    log: new InMemoryDecisionLog(),
  });

  const mutated = authorizeToolCall({
    call: {
      ...stripeCall,
      arguments: { ...stripeCall.arguments, amount: 2_500_000 },
    },
    policy: examplePolicy,
    receipt: issued.receipt,
    signing_key: key,
    clock,
    replay,
  });
  assert.equal(mutated.state, "DENIED");
  assert.equal(mutated.deny_code, "changed_arguments");
  assert.match(mutated.reason, /changed arguments/);

  const original = authorizeToolCall({
    call: stripeCall,
    policy: examplePolicy,
    receipt: issued.receipt,
    signing_key: key,
    clock,
    replay,
  });
  assert.equal(original.state, "AUTHORIZED");
});

test("expired receipt denies and cannot be reused after the clock advances", () => {
  const replay = new InMemoryReplayStore();
  let now = frozen;
  const issued = issueApprovalReceipt({
    actor: "cfo@acme.example",
    call: stripeCall,
    policy: examplePolicy,
    decision: "allow",
    ttl_seconds: 30,
    signing_key: key,
    clock: { now: () => now },
    log: new InMemoryDecisionLog(),
  });

  now = frozen + 31_000;
  const expired = authorizeToolCall({
    call: stripeCall,
    policy: examplePolicy,
    receipt: issued.receipt,
    signing_key: key,
    clock: { now: () => now },
    replay,
  });
  assert.equal(expired.state, "DENIED");
  assert.equal(expired.deny_code, "expired_receipt");

  now = frozen;
  const replayAfterExpiry = authorizeToolCall({
    call: stripeCall,
    policy: examplePolicy,
    receipt: issued.receipt,
    signing_key: key,
    clock: { now: () => now },
    replay,
  });
  assert.equal(replayAfterExpiry.deny_code, "replayed_receipt");
});

test("replayed receipt denies", () => {
  const replay = new InMemoryReplayStore();
  const issued = issueApprovalReceipt({
    actor: "cfo@acme.example",
    call: stripeCall,
    policy: examplePolicy,
    decision: "allow",
    signing_key: key,
    clock,
    log: new InMemoryDecisionLog(),
  });

  const first = authorizeToolCall({
    call: stripeCall,
    policy: examplePolicy,
    receipt: issued.receipt,
    signing_key: key,
    clock,
    replay,
  });
  assert.equal(first.state, "AUTHORIZED");

  const second = authorizeToolCall({
    call: stripeCall,
    policy: examplePolicy,
    receipt: issued.receipt,
    signing_key: key,
    clock,
    replay,
  });
  assert.equal(second.state, "DENIED");
  assert.equal(second.deny_code, "replayed_receipt");
});

test("human deny is logged and cannot authorize", () => {
  const replay = new InMemoryReplayStore();
  const log = new InMemoryDecisionLog();
  const issued = issueApprovalReceipt({
    actor: "cfo@acme.example",
    call: stripeCall,
    policy: examplePolicy,
    decision: "deny",
    reason: "amount looks like a fat-finger",
    signing_key: key,
    clock,
    log,
  });
  assert.equal(issued.deny_code, "human_denied");
  assert.equal(log.list()[0]?.decision, "deny");
  assert.match(log.list()[0]?.reason ?? "", /fat-finger/);

  const authorized = authorizeToolCall({
    call: stripeCall,
    policy: examplePolicy,
    receipt: issued.receipt,
    signing_key: key,
    clock,
    replay,
  });
  assert.equal(authorized.state, "DENIED");
  assert.equal(authorized.deny_code, "human_denied");
});

test("deny on ambiguity: wildcard resource, missing args, unparseable policy", () => {
  const wildcard = evaluateToolApproval(
    { tool: "stripe.create_charge", resource: "*", arguments: { amount: 1 } },
    examplePolicy,
  );
  assert.equal(wildcard.deny_code, "ambiguous");

  const missingArgs = evaluateToolApproval(
    { tool: "stripe.create_charge", resource: "acct_live_acme", arguments: undefined },
    examplePolicy,
  );
  assert.equal(missingArgs.deny_code, "ambiguous");

  const badPolicy = evaluateToolApproval(stripeCall, { allowed_tools: ["stripe.create_charge"] });
  assert.equal(badPolicy.deny_code, "ambiguous");

  assert.equal(isAmbiguousBinding("*"), true);
  assert.equal(isAmbiguousBinding("acct_live_acme"), false);
});

test("human cannot allow a tool that is not on the allowlist", () => {
  const issued = issueApprovalReceipt({
    actor: "cfo@acme.example",
    call: { tool: "shell.exec", resource: "prod", arguments: { cmd: "rm -rf /" } },
    policy: examplePolicy,
    decision: "allow",
    signing_key: key,
    clock,
    log: new InMemoryDecisionLog(),
  });
  assert.equal(issued.state, "DENIED");
  assert.equal(issued.deny_code, "tool_not_allowlisted");
  assert.equal(issued.receipt, undefined);
});

test("tampered receipt fields fail the MAC", () => {
  const issued = issueApprovalReceipt({
    actor: "cfo@acme.example",
    call: stripeCall,
    policy: examplePolicy,
    decision: "allow",
    signing_key: key,
    clock,
    log: new InMemoryDecisionLog(),
  });
  const tampered = { ...issued.receipt!, amount_override: 1, tool: "stripe.refund" } as ApprovalReceipt;
  assert.equal(verifyReceiptSignature(tampered, key), false);
  assert.equal(parseApprovalReceipt({ ...issued.receipt, extra: true }), undefined);

  const result = authorizeToolCall({
    call: stripeCall,
    policy: examplePolicy,
    receipt: { ...issued.receipt, tool: "stripe.refund" },
    signing_key: key,
    clock,
    replay: new InMemoryReplayStore(),
  });
  assert.equal(result.deny_code, "invalid_signature");
});

test("wrong tenant and stale policy version deny", () => {
  const issued = issueApprovalReceipt({
    actor: "cfo@acme.example",
    call: stripeCall,
    policy: examplePolicy,
    decision: "allow",
    signing_key: key,
    clock,
    log: new InMemoryDecisionLog(),
  });

  const otherTenant = authorizeToolCall({
    call: { ...stripeCall, resource: "acct_live_other" },
    policy: examplePolicy,
    receipt: issued.receipt,
    signing_key: key,
    clock,
    replay: new InMemoryReplayStore(),
  });
  assert.equal(otherTenant.deny_code, "resource_not_allowlisted");

  const stalePolicy = authorizeToolCall({
    call: stripeCall,
    policy: { ...examplePolicy, version: "tool-approval-2" },
    receipt: issued.receipt,
    signing_key: key,
    clock,
    replay: new InMemoryReplayStore(),
  });
  assert.equal(stalePolicy.deny_code, "policy_version_mismatch");
});

test("default key matches documented insecure fallback", () => {
  const receipt = issueSignedReceipt(
    {
      actor: "cfo@acme.example",
      tool: "github.create_issue",
      resource: "github.com/acme/app",
      args_hash: hashToolArgs({ title: "n" }),
      policy_version: "tool-approval-1",
      risk: "medium",
      decision: "allow",
      issued_at: "2024-01-01T00:00:00.000Z",
      expiry: "2024-01-01T00:05:00.000Z",
      nonce: "fixed-nonce",
    },
    DEFAULT_RECEIPT_KEY,
  );
  assert.equal(verifyReceiptSignature(receipt, DEFAULT_RECEIPT_KEY), true);
});
