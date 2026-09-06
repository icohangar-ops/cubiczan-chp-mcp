/**
 * CHP Profile B MCP server — thin transport over @cubiczan/chp.
 *
 * Tools:
 *   evaluate_spend_gate      — policy gate on a proposed action
 *   approve_spend            — human approval when HITL_REQUIRED
 *   evaluate_tool_approval   — allowlist ≠ authorization; bind a proposed call
 *   issue_approval_receipt   — human allow/deny → signed receipt
 *   authorize_tool_call      — consume a receipt (deny on drift/expiry/replay)
 *   chp_content_hash         — float-aware canonical content hash
 *   chp_version              — package / protocol versions
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// Read the version from package.json so serverInfo cannot drift from the
// published package. createRequire keeps this working under ESM/NodeNext,
// where a bare require is unavailable and JSON import assertions vary by
// Node version.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require("../package.json") as { version: string };
import {
  CHP_VERSION,
  approveHuman,
  contentHash,
  evaluateGate,
  type GatePolicy,
  type ProposedAction,
} from "@cubiczan/chp";
import {
  authorizeToolCall,
  defaultDecisionLog,
  defaultReplayStore,
  evaluateToolApproval,
  issueApprovalReceipt,
} from "./approval.js";
import { RECEIPT_KEY_ENV } from "./receipt.js";

function jsonContent(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function errorContent(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return {
    content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }],
    isError: true,
  };
}

const policySchema = z.object({
  version: z.string().optional(),
  max_notional: z.number(),
  daily_cap: z.number(),
  hitl_threshold: z.number(),
  min_confidence: z.number(),
  allowed_actions: z.array(z.string()).optional(),
  per_asset_limits: z.record(z.number()).optional(),
});

const actionSchema = z.object({
  action: z.string(),
  asset: z.string(),
  notional: z.number(),
  confidence: z.number().nullable().optional(),
  rationale: z.string().optional(),
});

const toolApprovalPolicySchema = z.object({
  version: z.string(),
  allowed_tools: z.array(z.string()),
  always_require_receipt: z.array(z.string()).optional(),
  tool_risk: z.record(z.enum(["low", "medium", "high", "critical"])).optional(),
  default_risk: z.enum(["low", "medium", "high", "critical"]).optional(),
  max_ttl_seconds: z.number().optional(),
  allowed_resources: z.record(z.array(z.string())).optional(),
  deny_on_ambiguity: z.boolean().optional(),
});

const proposedToolCallSchema = z.object({
  tool: z.string().describe("Concrete MCP tool name (no wildcards)"),
  resource: z.string().describe("Tenant / resource binding (no wildcards)"),
  arguments: z.unknown().describe("Tool arguments; hashed with CHP float-aware canonical JSON"),
});

const approvalReceiptSchema = z
  .object({
    kind: z.literal("chp.tool_approval_receipt"),
    schema_version: z.string(),
    chp_version: z.string(),
    actor: z.string(),
    tool: z.string(),
    resource: z.string(),
    args_hash: z.string(),
    policy_version: z.string(),
    risk: z.enum(["low", "medium", "high", "critical"]),
    issued_at: z.string(),
    expiry: z.string(),
    decision: z.enum(["allow", "deny"]),
    nonce: z.string(),
    signature: z.string(),
  })
  .strict();

export function createServer(): McpServer {
  const server = new McpServer({
    name: "chp-mcp",
    version: PKG_VERSION,
  });

  server.tool(
    "evaluate_spend_gate",
    "Run CHP Profile B capital/spend gate on a proposed action. Returns LOCKED, " +
      "HITL_REQUIRED, or BLOCKED with claims and a content hash. Hard policy " +
      "violations cannot be overridden by a human.",
    {
      action: actionSchema.describe("Proposed trade / spend / mandate action"),
      policy: policySchema.describe("Gate policy (limits, HITL threshold, confidence floor)"),
      committed_today: z
        .number()
        .optional()
        .describe("Notional already committed today toward daily_cap (default 0)"),
    },
    async ({ action, policy, committed_today }) => {
      try {
        const result = evaluateGate(
          action as ProposedAction,
          policy as GatePolicy,
          committed_today ?? 0,
        );
        return jsonContent(result);
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  server.tool(
    "approve_spend",
    "Human-in-the-loop approval for a proposal that returned HITL_REQUIRED. " +
      "Cannot approve BLOCKED / hard-rule failures (spec §6.3 / §6.5).",
    {
      action: actionSchema,
      policy: policySchema,
      approver: z.string().describe("Human approver identity (email or handle)"),
      committed_today: z.number().optional(),
    },
    async ({ action, policy, approver, committed_today }) => {
      try {
        const result = approveHuman(
          action as ProposedAction,
          policy as GatePolicy,
          approver,
          committed_today ?? 0,
        );
        return jsonContent(result);
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  server.tool(
    "evaluate_tool_approval",
    "Evaluate a proposed MCP tool call. A managed allowlist is not a grant — " +
      "allowlisted tools still return RECEIPT_REQUIRED. Wildcards, missing " +
      "resource, or unparseable arguments deny on ambiguity.",
    {
      call: proposedToolCallSchema.describe("Proposed tool, tenant/resource, and arguments"),
      policy: toolApprovalPolicySchema.describe(
        "Tool-approval policy (allowlist is a pre-filter, not authorization)",
      ),
    },
    async ({ call, policy }) => {
      try {
        return jsonContent(evaluateToolApproval(call, policy));
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  server.tool(
    "issue_approval_receipt",
    "Record a human allow/deny and return a signed approval receipt. The MAC " +
      `covers actor, tool, resource, args hash, policy version, risk, expiry, ` +
      "decision, and nonce (HMAC-SHA256 over CHP canonical JSON). Signing key " +
      `from ${RECEIPT_KEY_ENV} / AUDIT_LEDGER_KEY, or the documented insecure default.`,
    {
      actor: z.string().describe("Human approver identity (email or handle)"),
      call: proposedToolCallSchema,
      policy: toolApprovalPolicySchema,
      decision: z.enum(["allow", "deny"]).describe("Human decision — logged on every issue"),
      reason: z.string().optional().describe("Why the human allowed or denied"),
      ttl_seconds: z
        .number()
        .optional()
        .describe("Receipt lifetime; must not exceed policy.max_ttl_seconds"),
      signing_key: z.string().optional().describe("Override HMAC key (tests / local only)"),
    },
    async ({ actor, call, policy, decision, reason, ttl_seconds, signing_key }) => {
      try {
        return jsonContent(
          issueApprovalReceipt({
            actor,
            call,
            policy,
            decision,
            reason,
            ttl_seconds,
            signing_key,
            log: defaultDecisionLog,
          }),
        );
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  server.tool(
    "authorize_tool_call",
    "Authorize a tool call against a previously issued receipt. Changed " +
      "arguments, expired or replayed receipts, MAC failure, and binding " +
      "mismatch all deny. Presenting only an allowlist match denies with " +
      "allowlist_is_not_authorization.",
    {
      call: proposedToolCallSchema.describe("Call about to execute — args are re-hashed"),
      policy: toolApprovalPolicySchema,
      receipt: approvalReceiptSchema
        .optional()
        .describe("Signed receipt; omit to demonstrate that allowlisting is not enough"),
      signing_key: z.string().optional(),
    },
    async ({ call, policy, receipt, signing_key }) => {
      try {
        return jsonContent(
          authorizeToolCall({
            call,
            policy,
            receipt,
            signing_key,
            replay: defaultReplayStore,
          }),
        );
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  server.tool(
    "chp_content_hash",
    "SHA-256 over float-aware canonical JSON (CHP §3.1) — matches Python " +
      "consensus-hardening-protocol digests for the same object.",
    {
      value: z.unknown().describe("JSON-serializable value to hash"),
    },
    async ({ value }) => {
      try {
        return jsonContent({ content_hash: contentHash(value) });
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  server.tool(
    "chp_version",
    "Report MCP server and CHP Profile B protocol versions.",
    {},
    async () =>
      jsonContent({
        mcp: `@cubiczan/chp-mcp@${PKG_VERSION}`,
        chp_profile: "B",
        chp_version: CHP_VERSION,
        engine: "@cubiczan/chp",
        receipt_schema: "chp.tool_approval_receipt/1",
        receipt_key_env: RECEIPT_KEY_ENV,
      }),
  );

  return server;
}
