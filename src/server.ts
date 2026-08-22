/**
 * CHP Profile B MCP server — thin transport over @cubiczan/chp.
 *
 * Tools:
 *   evaluate_spend_gate — policy gate on a proposed action
 *   approve_spend       — human approval when HITL_REQUIRED
 *   chp_content_hash    — float-aware canonical content hash
 *   chp_version         — package / protocol versions
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
      }),
  );

  return server;
}
