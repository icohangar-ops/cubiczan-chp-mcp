/**
 * Synthetic high-consequence reference tools — scopes + approval gates.
 *
 * These never touch a live venue, custodian, or bank rail. They exist so
 * the MCP surface demonstrates real permission shapes instead of weather
 * or todo toys.
 */

import { contentHash, type GatePolicy, type ProposedAction } from "@cubiczan/chp";

export const REFERENCE_TOOL_NAMES = [
  "place_equity_order",
  "wire_treasury_transfer",
  "rebalance_portfolio",
] as const;

export type ReferenceToolName = (typeof REFERENCE_TOOL_NAMES)[number];

export interface ReferenceToolSpec {
  name: ReferenceToolName;
  scope: string;
  description: string;
  policy: GatePolicy;
  boundArgs(args: Record<string, unknown>): Record<string, unknown>;
  toAction(args: Record<string, unknown>): ProposedAction;
  execute(args: Record<string, unknown>, receiptId: string): Record<string, unknown>;
}

function num(args: Record<string, unknown>, key: string): number {
  const value = args[key];
  return typeof value === "number" ? value : Number.NaN;
}

function str(args: Record<string, unknown>, key: string, fallback = ""): string {
  const value = args[key];
  return typeof value === "string" ? value : fallback;
}

export const REFERENCE_TOOLS: Record<ReferenceToolName, ReferenceToolSpec> = {
  place_equity_order: {
    name: "place_equity_order",
    scope: "trading:equities:place",
    description:
      "Synthetic equity order at a simulated venue. Requires scope trading:equities:place " +
      "and a signed authorization receipt. HITL at/above the default $250 notional.",
    policy: {
      max_notional: 500,
      daily_cap: 2500,
      hitl_threshold: 250,
      min_confidence: 0.55,
      allowed_actions: ["BUY", "SELL"],
    },
    boundArgs(args) {
      return {
        symbol: str(args, "symbol"),
        side: str(args, "side"),
        quantity: num(args, "quantity"),
        notional: num(args, "notional"),
        limit_price: args.limit_price ?? null,
        confidence: args.confidence ?? null,
      };
    },
    toAction(args) {
      return {
        action: str(args, "side"),
        asset: str(args, "symbol"),
        notional: num(args, "notional"),
        confidence: typeof args.confidence === "number" ? args.confidence : null,
        rationale: typeof args.rationale === "string" ? args.rationale : undefined,
      };
    },
    execute(args, receiptId) {
      return {
        synthetic: true,
        status: "accepted",
        venue: "SIM-EQUITY",
        symbol: str(args, "symbol"),
        side: str(args, "side"),
        quantity: num(args, "quantity"),
        notional: num(args, "notional"),
        order_id: `sim-eq-${receiptId.slice(0, 8)}`,
      };
    },
  },
  wire_treasury_transfer: {
    name: "wire_treasury_transfer",
    scope: "treasury:wire",
    description:
      "Synthetic treasury wire. Scope treasury:wire. Default hitl_threshold is 0 — " +
      "a human approval receipt is always required before the simulated rail queues.",
    policy: {
      max_notional: 10_000,
      daily_cap: 25_000,
      hitl_threshold: 0,
      min_confidence: 0.7,
      allowed_actions: ["WIRE"],
    },
    boundArgs(args) {
      return {
        from_account: str(args, "from_account"),
        to_account: str(args, "to_account"),
        amount: num(args, "amount"),
        currency: str(args, "currency", "USD"),
        memo: args.memo ?? null,
      };
    },
    toAction(args) {
      return {
        action: "WIRE",
        asset: str(args, "currency", "USD"),
        notional: num(args, "amount"),
        confidence: typeof args.confidence === "number" ? args.confidence : 0.85,
        rationale: typeof args.memo === "string" ? args.memo : undefined,
      };
    },
    execute(args, receiptId) {
      return {
        synthetic: true,
        status: "queued",
        rail: "SIM-WIRE",
        from_account: str(args, "from_account"),
        to_account: str(args, "to_account"),
        amount: num(args, "amount"),
        currency: str(args, "currency", "USD"),
        transfer_id: `sim-wire-${receiptId.slice(0, 8)}`,
      };
    },
  },
  rebalance_portfolio: {
    name: "rebalance_portfolio",
    scope: "portfolio:rebalance",
    description:
      "Synthetic portfolio rebalance. Scope portfolio:rebalance. HITL at/above $1,000 notional.",
    policy: {
      max_notional: 50_000,
      daily_cap: 100_000,
      hitl_threshold: 1000,
      min_confidence: 0.6,
      allowed_actions: ["REBALANCE"],
    },
    boundArgs(args) {
      return {
        portfolio_id: str(args, "portfolio_id"),
        target_weights: args.target_weights ?? null,
        notional: num(args, "notional"),
        confidence: args.confidence ?? null,
      };
    },
    toAction(args) {
      return {
        action: "REBALANCE",
        asset: str(args, "portfolio_id"),
        notional: num(args, "notional"),
        confidence: typeof args.confidence === "number" ? args.confidence : null,
      };
    },
    execute(args, receiptId) {
      return {
        synthetic: true,
        status: "scheduled",
        desk: "SIM-PORTFOLIO",
        portfolio_id: str(args, "portfolio_id"),
        target_weights: args.target_weights ?? null,
        notional: num(args, "notional"),
        rebalance_id: `sim-rb-${receiptId.slice(0, 8)}`,
      };
    },
  },
};

export function isReferenceTool(name: string): name is ReferenceToolName {
  return name in REFERENCE_TOOLS;
}

export function listReferenceTools(): Array<{
  tool: ReferenceToolName;
  scope: string;
  description: string;
  policy: GatePolicy;
  synthetic: true;
}> {
  return REFERENCE_TOOL_NAMES.map((name) => {
    const spec = REFERENCE_TOOLS[name];
    return {
      tool: spec.name,
      scope: spec.scope,
      description: spec.description,
      policy: spec.policy,
      synthetic: true as const,
    };
  });
}

export function argsHash(tool: string, args: Record<string, unknown>): string {
  const spec = isReferenceTool(tool) ? REFERENCE_TOOLS[tool] : undefined;
  const bound = spec ? spec.boundArgs(args) : { ...args };
  return contentHash({ tool, ...bound });
}

export function isCompletePolicy(policy: Partial<GatePolicy> | undefined): policy is GatePolicy {
  if (!policy) return false;
  return (
    typeof policy.max_notional === "number" &&
    Number.isFinite(policy.max_notional) &&
    typeof policy.daily_cap === "number" &&
    Number.isFinite(policy.daily_cap) &&
    typeof policy.hitl_threshold === "number" &&
    Number.isFinite(policy.hitl_threshold) &&
    typeof policy.min_confidence === "number" &&
    Number.isFinite(policy.min_confidence)
  );
}

export function resolveReferencePolicy(input: {
  tool: string;
  scope?: string;
  policy?: Partial<GatePolicy>;
}):
  | { ok: true; spec: ReferenceToolSpec; policy: GatePolicy }
  | { ok: false; detail: string } {
  if (!isReferenceTool(input.tool)) {
    return { ok: false, detail: `unknown gated tool: ${input.tool}` };
  }
  const spec = REFERENCE_TOOLS[input.tool];
  if (input.scope && input.scope !== spec.scope) {
    return {
      ok: false,
      detail: `scope ${input.scope} does not match tool ${spec.name} (${spec.scope})`,
    };
  }
  if (input.policy !== undefined && !isCompletePolicy(input.policy)) {
    return { ok: false, detail: "incomplete policy: need max_notional, daily_cap, hitl_threshold, min_confidence" };
  }
  return { ok: true, spec, policy: input.policy && isCompletePolicy(input.policy) ? input.policy : spec.policy };
}
