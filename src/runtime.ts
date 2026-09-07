/**
 * Receipt-aware CHP runtime: evaluate / approve / execute with a durable ledger.
 */

import { approveHuman, evaluateGate, type GatePolicy, type GateResult, type ProposedAction } from "@cubiczan/chp";
import {
  type AuditLedger,
  type AuthorizationReceipt,
  type Clock,
  type DenyReceipt,
  type LedgerEntry,
  MemoryLedger,
  ReceiptStore,
  issueAuthorizationReceipt,
  recordDeny,
  systemClock,
  verifyAuthorizationReceipt,
  verifyLedgerChain,
} from "./audit.js";
import {
  argsHash,
  listReferenceTools,
  resolveReferencePolicy,
  type ReferenceToolName,
} from "./permissions.js";

const DEFAULT_TTL_SECONDS = 300;

export interface CreateRuntimeOptions {
  ledger?: AuditLedger;
  clock?: Clock;
  receipts?: ReceiptStore;
  defaultTtlSeconds?: number;
}

export type SpendEvaluation = GateResult & {
  deny?: DenyReceipt;
  authorization?: AuthorizationReceipt;
};

export type AuthorizationRequest =
  | {
      ok: true;
      state: "LOCKED";
      authorization: AuthorizationReceipt;
      gate: GateResult;
    }
  | {
      ok: false;
      pending: true;
      state: "HITL_REQUIRED";
      gate: GateResult;
    }
  | {
      ok: false;
      pending?: false;
      deny: DenyReceipt;
      gate?: GateResult;
    };

export type GatedExecuteResult =
  | { ok: true; result: Record<string, unknown>; receipt_id: string; ledger_seq: number }
  | { ok: false; deny: DenyReceipt };

export class ChpRuntime {
  readonly ledger: AuditLedger;
  readonly receipts: ReceiptStore;
  readonly clock: Clock;
  readonly defaultTtlSeconds: number;

  constructor(options: CreateRuntimeOptions = {}) {
    this.ledger = options.ledger ?? new MemoryLedger();
    this.receipts = options.receipts ?? new ReceiptStore();
    this.clock = options.clock ?? systemClock;
    this.defaultTtlSeconds = options.defaultTtlSeconds ?? DEFAULT_TTL_SECONDS;
    this.receipts.hydrateFromLedger(this.ledger.entries());
  }

  evaluateSpend(
    action: ProposedAction,
    policy: GatePolicy,
    committedToday = 0,
  ): SpendEvaluation {
    const gate = evaluateGate(action, policy, committedToday);
    if (gate.state !== "BLOCKED") return gate;
    const deny = this.deny({
      tool: "evaluate_spend_gate",
      reason_code: "policy_deny",
      detail: gate.reason,
      args_hash: argsHash("evaluate_spend_gate", action as unknown as Record<string, unknown>),
    });
    return { ...gate, deny };
  }

  approveSpend(
    action: ProposedAction,
    policy: GatePolicy,
    approver: string,
    committedToday = 0,
    bind?: { tool: string; scope?: string; args: Record<string, unknown>; ttlSeconds?: number },
  ): SpendEvaluation {
    const gate = approveHuman(action, policy, approver, committedToday);
    if (gate.state === "BLOCKED") {
      const deny = this.deny({
        tool: bind?.tool ?? "approve_spend",
        scope: bind?.scope,
        reason_code: "policy_deny",
        detail: gate.reason,
        args_hash: argsHash(bind?.tool ?? "approve_spend", (bind?.args ?? action) as Record<string, unknown>),
      });
      return { ...gate, deny };
    }
    if (!bind) return gate;
    const resolved = resolveReferencePolicy({ tool: bind.tool, scope: bind.scope, policy });
    if (!resolved.ok) {
      const deny = this.deny({
        tool: bind.tool,
        scope: bind.scope,
        reason_code: "ambiguous_policy",
        detail: resolved.detail,
        args_hash: argsHash(bind.tool, bind.args),
      });
      return { ...gate, deny };
    }
    const authorization = this.issueAuthorization({
      tool: resolved.spec.name,
      scope: resolved.spec.scope,
      args: bind.args,
      approver,
      ttlSeconds: bind.ttlSeconds,
    });
    return { ...gate, authorization };
  }

  requestAuthorization(input: {
    tool: string;
    args: Record<string, unknown>;
    policy?: Partial<GatePolicy>;
    scope?: string;
    approver?: string;
    committedToday?: number;
    ttlSeconds?: number;
  }): AuthorizationRequest {
    const resolved = resolveReferencePolicy(input);
    if (!resolved.ok) {
      return {
        ok: false,
        deny: this.deny({
          tool: input.tool,
          scope: input.scope,
          reason_code: "ambiguous_policy",
          detail: resolved.detail,
          args_hash: argsHash(input.tool, input.args),
        }),
      };
    }
    const action = resolved.spec.toAction(input.args);
    const committedToday = input.committedToday ?? 0;
    const gate = evaluateGate(action, resolved.policy, committedToday);
    if (gate.state === "BLOCKED") {
      return {
        ok: false,
        deny: this.deny({
          tool: resolved.spec.name,
          scope: resolved.spec.scope,
          reason_code: "policy_deny",
          detail: gate.reason,
          args_hash: argsHash(resolved.spec.name, input.args),
        }),
        gate,
      };
    }
    if (gate.state === "HITL_REQUIRED" && !input.approver) {
      return { ok: false, pending: true, state: "HITL_REQUIRED", gate };
    }
    const approver = input.approver ?? "auto-lock";
    if (gate.state === "HITL_REQUIRED" && input.approver) {
      const approved = approveHuman(action, resolved.policy, input.approver, committedToday);
      if (approved.state === "BLOCKED") {
        return {
          ok: false,
          deny: this.deny({
            tool: resolved.spec.name,
            scope: resolved.spec.scope,
            reason_code: "policy_deny",
            detail: approved.reason,
            args_hash: argsHash(resolved.spec.name, input.args),
          }),
          gate: approved,
        };
      }
    }
    const authorization = this.issueAuthorization({
      tool: resolved.spec.name,
      scope: resolved.spec.scope,
      args: input.args,
      approver,
      ttlSeconds: input.ttlSeconds,
    });
    return { ok: true, state: "LOCKED", authorization, gate };
  }

  executeGated(
    tool: string,
    args: Record<string, unknown>,
    receipt?: AuthorizationReceipt,
    options?: { policy?: Partial<GatePolicy>; scope?: string; committedToday?: number },
  ): GatedExecuteResult {
    const resolved = resolveReferencePolicy({
      tool,
      scope: options?.scope ?? (typeof args.scope === "string" ? args.scope : undefined),
      policy: options?.policy,
    });
    if (!resolved.ok) {
      return {
        ok: false,
        deny: this.deny({
          tool,
          scope: options?.scope,
          reason_code: "ambiguous_policy",
          detail: resolved.detail,
          args_hash: argsHash(tool, args),
        }),
      };
    }

    const hash = argsHash(resolved.spec.name, args);

    if (!receipt || !verifyAuthorizationReceipt(receipt)) {
      return {
        ok: false,
        deny: this.deny({
          tool: resolved.spec.name,
          scope: resolved.spec.scope,
          reason_code: "missing_receipt",
          detail: receipt ? "authorization receipt signature invalid" : "authorization receipt required",
          args_hash: hash,
        }),
      };
    }

    if (this.receipts.isConsumed(receipt.receipt_id)) {
      return {
        ok: false,
        deny: this.deny({
          tool: resolved.spec.name,
          scope: resolved.spec.scope,
          reason_code: "replay",
          detail: `receipt ${receipt.receipt_id} already consumed`,
          args_hash: hash,
        }),
      };
    }

    if (Date.parse(receipt.expires_at) <= this.clock.now().getTime()) {
      return {
        ok: false,
        deny: this.deny({
          tool: resolved.spec.name,
          scope: resolved.spec.scope,
          reason_code: "expired",
          detail: `receipt expired at ${receipt.expires_at}`,
          args_hash: hash,
        }),
      };
    }

    if (
      receipt.tool !== resolved.spec.name ||
      receipt.scope !== resolved.spec.scope ||
      receipt.args_hash !== hash
    ) {
      return {
        ok: false,
        deny: this.deny({
          tool: resolved.spec.name,
          scope: resolved.spec.scope,
          reason_code: "args_changed",
          detail: "receipt tool, scope, or args_hash does not match this call",
          args_hash: hash,
        }),
      };
    }

    const gate = evaluateGate(
      resolved.spec.toAction(args),
      resolved.policy,
      options?.committedToday ?? 0,
    );
    if (gate.state === "BLOCKED") {
      return {
        ok: false,
        deny: this.deny({
          tool: resolved.spec.name,
          scope: resolved.spec.scope,
          reason_code: "policy_deny",
          detail: gate.reason,
          args_hash: hash,
        }),
      };
    }

    this.receipts.consume(receipt.receipt_id);
    const entry = this.ledger.append({
      event: "execute",
      ts: this.clock.now().toISOString(),
      tool: resolved.spec.name,
      scope: resolved.spec.scope,
      receipt_id: receipt.receipt_id,
      args_hash: hash,
      body: { receipt_id: receipt.receipt_id, args: resolved.spec.boundArgs(args) },
    });
    return {
      ok: true,
      result: resolved.spec.execute(args, receipt.receipt_id),
      receipt_id: receipt.receipt_id,
      ledger_seq: entry.seq,
    };
  }

  inspectLedger(limit = 50): {
    entries: LedgerEntry[];
    chain: ReturnType<typeof verifyLedgerChain>;
    tools: ReturnType<typeof listReferenceTools>;
  } {
    const all = this.ledger.entries();
    const start = Math.max(0, all.length - limit);
    return {
      entries: all.slice(start),
      chain: verifyLedgerChain(all),
      tools: listReferenceTools(),
    };
  }

  private issueAuthorization(input: {
    tool: ReferenceToolName;
    scope: string;
    args: Record<string, unknown>;
    approver: string;
    ttlSeconds?: number;
  }): AuthorizationReceipt {
    const now = this.clock.now();
    const ttl = (input.ttlSeconds ?? this.defaultTtlSeconds) * 1000;
    const hash = argsHash(input.tool, input.args);
    const authorization = issueAuthorizationReceipt({
      tool: input.tool,
      scope: input.scope,
      args_hash: hash,
      approver: input.approver,
      issued_at: now.toISOString(),
      expires_at: new Date(now.getTime() + ttl).toISOString(),
    });
    this.ledger.append({
      event: "authorize",
      ts: authorization.issued_at,
      tool: authorization.tool,
      scope: authorization.scope,
      receipt_id: authorization.receipt_id,
      args_hash: authorization.args_hash,
      body: authorization,
    });
    return authorization;
  }

  private deny(input: {
    tool: string;
    scope?: string | null;
    reason_code: Parameters<typeof recordDeny>[1]["reason_code"];
    detail: string;
    args_hash: string;
  }): DenyReceipt {
    return recordDeny(this.ledger, {
      ...input,
      issued_at: this.clock.now().toISOString(),
    });
  }
}

export function createRuntime(options?: CreateRuntimeOptions): ChpRuntime {
  return new ChpRuntime(options);
}
