/**
 * Tool-approval policy: allowlist ≠ authorization.
 *
 * Being on `allowed_tools` is a necessary pre-filter, never a grant.
 * Execution requires a signed receipt whose bindings still match the
 * call that is about to run. Ambiguity, expiry, replay, and argument
 * drift all deny.
 */

import type { Claim } from "@cubiczan/chp";
import { CHP_VERSION } from "@cubiczan/chp";
import {
  hashToolArgs,
  isAmbiguousBinding,
  isReceiptRisk,
  issueSignedReceipt,
  parseApprovalReceipt,
  parseIsoTime,
  receiptContentHash,
  resolveReceiptKey,
  verifyReceiptSignature,
  type ApprovalReceipt,
  type ReceiptDecision,
  type ReceiptRisk,
} from "./receipt.js";
import { InMemoryReplayStore, type ReplayStore } from "./replay.js";

export type AuthorizationState = "AUTHORIZED" | "RECEIPT_REQUIRED" | "DENIED";

export type DenyCode =
  | "ambiguous"
  | "allowlist_is_not_authorization"
  | "tool_not_allowlisted"
  | "resource_not_allowlisted"
  | "changed_arguments"
  | "expired_receipt"
  | "replayed_receipt"
  | "invalid_signature"
  | "policy_version_mismatch"
  | "binding_mismatch"
  | "risk_mismatch"
  | "human_denied"
  | "missing_receipt"
  | "ttl_exceeds_policy";

export interface ToolApprovalPolicy {
  version: string;
  allowed_tools: string[];
  /** Tools that may never auto-run from the allowlist alone. */
  always_require_receipt?: string[];
  tool_risk?: Record<string, ReceiptRisk>;
  default_risk?: ReceiptRisk;
  /** Upper bound on receipt lifetime. Default 300s. */
  max_ttl_seconds?: number;
  /** Optional per-tool tenant/resource allowlist. */
  allowed_resources?: Record<string, string[]>;
  /** Always treated as true; present so example policies document fail-closed. */
  deny_on_ambiguity?: boolean;
}

export interface HumanDecisionLog {
  at: string;
  actor: string;
  tool: string;
  resource: string;
  args_hash: string;
  decision: ReceiptDecision;
  reason: string;
  nonce: string;
  policy_version: string;
  receipt_hash: string;
}

export interface AuthorizationResult {
  state: AuthorizationState;
  allowed: boolean;
  requires_receipt: boolean;
  reason: string;
  deny_code?: DenyCode;
  args_hash?: string;
  risk?: ReceiptRisk;
  policy_version?: string;
  claims: Claim[];
  receipt?: ApprovalReceipt;
  receipt_hash?: string;
  decision_log?: HumanDecisionLog;
}

export interface DecisionLogSink {
  append(entry: HumanDecisionLog): void;
  list(): readonly HumanDecisionLog[];
}

export class InMemoryDecisionLog implements DecisionLogSink {
  private readonly entries: HumanDecisionLog[] = [];

  append(entry: HumanDecisionLog): void {
    this.entries.push(entry);
  }

  list(): readonly HumanDecisionLog[] {
    return this.entries;
  }
}

/** Process-wide defaults so MCP tool calls share replay + the human log. */
export const defaultReplayStore = new InMemoryReplayStore();
export const defaultDecisionLog = new InMemoryDecisionLog();

const DEFAULT_MAX_TTL_SECONDS = 300;
const DEFAULT_RISK: ReceiptRisk = "high";

export interface ApprovalClock {
  now(): number;
}

const systemClock: ApprovalClock = { now: () => Date.now() };

function claim(rule: string, passed: boolean, detail: string): Claim {
  return { rule, passed, detail };
}

function denied(
  claims: Claim[],
  deny_code: DenyCode,
  reason: string,
  extra: Partial<AuthorizationResult> = {},
): AuthorizationResult {
  return {
    state: "DENIED",
    allowed: false,
    requires_receipt: deny_code === "allowlist_is_not_authorization" || deny_code === "missing_receipt",
    reason,
    deny_code,
    claims,
    ...extra,
  };
}

export function riskRank(risk: ReceiptRisk): number {
  return { low: 1, medium: 2, high: 3, critical: 4 }[risk];
}

export function policyRiskFor(policy: ToolApprovalPolicy, tool: string): ReceiptRisk {
  const configured = policy.tool_risk?.[tool];
  if (configured && isReceiptRisk(configured)) return configured;
  if (policy.default_risk && isReceiptRisk(policy.default_risk)) return policy.default_risk;
  return DEFAULT_RISK;
}

export function maxTtlSeconds(policy: ToolApprovalPolicy): number {
  const raw = policy.max_ttl_seconds;
  if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) return raw;
  return DEFAULT_MAX_TTL_SECONDS;
}

export function parseToolApprovalPolicy(value: unknown): ToolApprovalPolicy | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const rec = value as Record<string, unknown>;
  if (typeof rec.version !== "string" || isAmbiguousBinding(rec.version)) return undefined;
  if (!Array.isArray(rec.allowed_tools) || rec.allowed_tools.some((t) => typeof t !== "string")) {
    return undefined;
  }
  if (rec.default_risk !== undefined && !isReceiptRisk(rec.default_risk)) return undefined;
  if (rec.max_ttl_seconds !== undefined) {
    if (typeof rec.max_ttl_seconds !== "number" || !Number.isFinite(rec.max_ttl_seconds) || rec.max_ttl_seconds <= 0) {
      return undefined;
    }
  }
  if (rec.tool_risk !== undefined) {
    if (rec.tool_risk === null || typeof rec.tool_risk !== "object" || Array.isArray(rec.tool_risk)) {
      return undefined;
    }
    for (const risk of Object.values(rec.tool_risk as Record<string, unknown>)) {
      if (!isReceiptRisk(risk)) return undefined;
    }
  }
  if (rec.always_require_receipt !== undefined) {
    if (
      !Array.isArray(rec.always_require_receipt) ||
      rec.always_require_receipt.some((t) => typeof t !== "string")
    ) {
      return undefined;
    }
  }
  if (rec.allowed_resources !== undefined) {
    if (
      rec.allowed_resources === null ||
      typeof rec.allowed_resources !== "object" ||
      Array.isArray(rec.allowed_resources)
    ) {
      return undefined;
    }
    for (const list of Object.values(rec.allowed_resources as Record<string, unknown>)) {
      if (!Array.isArray(list) || list.some((item) => typeof item !== "string")) return undefined;
    }
  }

  return {
    version: rec.version,
    allowed_tools: rec.allowed_tools as string[],
    always_require_receipt: rec.always_require_receipt as string[] | undefined,
    tool_risk: rec.tool_risk as Record<string, ReceiptRisk> | undefined,
    default_risk: rec.default_risk as ReceiptRisk | undefined,
    max_ttl_seconds: rec.max_ttl_seconds as number | undefined,
    allowed_resources: rec.allowed_resources as Record<string, string[]> | undefined,
    deny_on_ambiguity: rec.deny_on_ambiguity === false ? false : true,
  };
}

export interface ProposedToolCall {
  tool: string;
  resource: string;
  arguments?: unknown;
}

function inspectCall(
  call: ProposedToolCall,
  policy: ToolApprovalPolicy,
): { claims: Claim[]; args_hash?: string; risk?: ReceiptRisk; deny?: AuthorizationResult } {
  const claims: Claim[] = [];

  if (policy.deny_on_ambiguity === false) {
    claims.push(claim("deny-on-ambiguity", false, "policy attempted to disable fail-closed; ignored"));
  } else {
    claims.push(claim("deny-on-ambiguity", true, "ambiguous bindings deny"));
  }

  if (isAmbiguousBinding(policy.version)) {
    return {
      claims,
      deny: denied(claims, "ambiguous", "ambiguous policy version — deny on ambiguity"),
    };
  }
  claims.push(claim("policy-version", true, `policy ${policy.version}`));

  if (isAmbiguousBinding(call.tool)) {
    claims.push(claim("concrete-tool", false, "tool is missing or a wildcard"));
    return { claims, deny: denied(claims, "ambiguous", "ambiguous tool — deny on ambiguity") };
  }
  claims.push(claim("concrete-tool", true, `tool ${call.tool}`));

  if (isAmbiguousBinding(call.resource)) {
    claims.push(claim("concrete-resource", false, "resource is missing or a wildcard"));
    return { claims, deny: denied(claims, "ambiguous", "ambiguous resource — deny on ambiguity") };
  }
  claims.push(claim("concrete-resource", true, `resource ${call.resource}`));

  if (call.arguments === undefined) {
    claims.push(claim("concrete-args", false, "arguments missing"));
    return { claims, deny: denied(claims, "ambiguous", "ambiguous arguments — deny on ambiguity") };
  }
  claims.push(claim("concrete-args", true, "arguments present"));

  let args_hash: string;
  try {
    args_hash = hashToolArgs(call.arguments);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    claims.push(claim("args-hash", false, message));
    return { claims, deny: denied(claims, "ambiguous", `cannot canonicalize arguments: ${message}`) };
  }
  claims.push(claim("args-hash", true, args_hash));

  const allowlisted = policy.allowed_tools.includes(call.tool);
  claims.push(
    claim(
      "tool-allowlist",
      allowlisted,
      allowlisted
        ? `${call.tool} is on the allowlist (not a grant)`
        : `${call.tool} is not on the allowlist`,
    ),
  );
  if (!allowlisted) {
    return {
      claims,
      args_hash,
      deny: denied(claims, "tool_not_allowlisted", `tool ${call.tool} is not allowlisted`, {
        args_hash,
        policy_version: policy.version,
      }),
    };
  }

  const permitted = policy.allowed_resources?.[call.tool];
  if (permitted) {
    const resourceOk = permitted.includes(call.resource);
    claims.push(
      claim(
        "resource-allowlist",
        resourceOk,
        resourceOk
          ? `${call.resource} permitted for ${call.tool}`
          : `${call.resource} is not a permitted resource for ${call.tool}`,
      ),
    );
    if (!resourceOk) {
      return {
        claims,
        args_hash,
        deny: denied(claims, "resource_not_allowlisted", `resource ${call.resource} is not permitted`, {
          args_hash,
          policy_version: policy.version,
        }),
      };
    }
  }

  const risk = policyRiskFor(policy, call.tool);
  claims.push(claim("risk", true, `${call.tool} risk ${risk}`));

  return { claims, args_hash, risk };
}

/**
 * First look at a proposed tool call. Allowlisted tools still require a
 * receipt — the allowlist is not a grant.
 */
export function evaluateToolApproval(
  call: ProposedToolCall,
  policyInput: unknown,
): AuthorizationResult {
  const policy = parseToolApprovalPolicy(policyInput);
  if (!policy) {
    return denied(
      [claim("policy", false, "policy missing or unparseable")],
      "ambiguous",
      "ambiguous policy — deny on ambiguity",
    );
  }

  const inspected = inspectCall(call, policy);
  if (inspected.deny) return inspected.deny;

  const claims = [
    ...inspected.claims,
    claim(
      "allowlist-is-not-authorization",
      false,
      "allowlist membership is not a grant; a bound receipt is required",
    ),
  ];

  return {
    state: "RECEIPT_REQUIRED",
    allowed: false,
    requires_receipt: true,
    reason: `allowlist is not authorization: ${call.tool} requires a bound approval receipt`,
    deny_code: "allowlist_is_not_authorization",
    args_hash: inspected.args_hash,
    risk: inspected.risk,
    policy_version: policy.version,
    claims,
  };
}

export interface IssueApprovalOptions {
  actor: string;
  call: ProposedToolCall;
  policy: unknown;
  decision: ReceiptDecision;
  reason?: string;
  ttl_seconds?: number;
  signing_key?: string;
  clock?: ApprovalClock;
  log?: DecisionLogSink;
}

export function issueApprovalReceipt(options: IssueApprovalOptions): AuthorizationResult {
  const policy = parseToolApprovalPolicy(options.policy);
  if (!policy) {
    return denied(
      [claim("policy", false, "policy missing or unparseable")],
      "ambiguous",
      "ambiguous policy — deny on ambiguity",
    );
  }

  if (isAmbiguousBinding(options.actor)) {
    return denied(
      [claim("actor", false, "actor is missing or a wildcard")],
      "ambiguous",
      "ambiguous actor — deny on ambiguity",
    );
  }

  if (options.decision !== "allow" && options.decision !== "deny") {
    return denied(
      [claim("decision", false, "decision must be allow or deny")],
      "ambiguous",
      "ambiguous decision — deny on ambiguity",
    );
  }

  const inspected = inspectCall(options.call, policy);
  if (inspected.deny && options.decision === "allow") {
    return inspected.deny;
  }
  if (!inspected.args_hash || !inspected.risk) {
    if (options.decision === "deny" && !isAmbiguousBinding(options.call.tool) && !isAmbiguousBinding(options.call.resource)) {
      // A human may record a deny even when the call would never authorize,
      // as long as the bindings themselves are concrete.
    } else if (inspected.deny) {
      return inspected.deny;
    }
  }

  if (options.decision === "allow" && !policy.allowed_tools.includes(options.call.tool)) {
    return denied(
      [...inspected.claims, claim("human-allow", false, "human cannot grant a tool that is not allowlisted")],
      "tool_not_allowlisted",
      `approval by ${options.actor} rejected: tool is not allowlisted`,
      { args_hash: inspected.args_hash, policy_version: policy.version },
    );
  }

  const ttlCap = maxTtlSeconds(policy);
  const ttl = options.ttl_seconds ?? ttlCap;
  if (typeof ttl !== "number" || !Number.isFinite(ttl) || ttl <= 0) {
    return denied(
      [...inspected.claims, claim("ttl", false, "ttl is missing or not a positive number")],
      "ambiguous",
      "ambiguous ttl — deny on ambiguity",
    );
  }
  if (ttl > ttlCap) {
    return denied(
      [...inspected.claims, claim("ttl", false, `ttl ${ttl}s exceeds policy max ${ttlCap}s`)],
      "ttl_exceeds_policy",
      `requested ttl ${ttl}s exceeds policy max ${ttlCap}s`,
      { args_hash: inspected.args_hash, policy_version: policy.version },
    );
  }

  const clock = options.clock ?? systemClock;
  const issuedMs = clock.now();
  const issued_at = new Date(issuedMs).toISOString();
  const expiry = new Date(issuedMs + ttl * 1000).toISOString();
  const args_hash = inspected.args_hash ?? hashToolArgs(options.call.arguments ?? {});
  const risk = inspected.risk ?? policyRiskFor(policy, options.call.tool);
  const key = resolveReceiptKey(options.signing_key);

  const receipt = issueSignedReceipt(
    {
      actor: options.actor,
      tool: options.call.tool,
      resource: options.call.resource,
      args_hash,
      policy_version: policy.version,
      risk,
      decision: options.decision,
      issued_at,
      expiry,
      chp_version: CHP_VERSION,
    },
    key,
  );

  const receipt_hash = receiptContentHash(receipt);
  const reason =
    options.reason ??
    (options.decision === "allow"
      ? `human-approved by ${options.actor}`
      : `human-denied by ${options.actor}`);

  const decision_log: HumanDecisionLog = {
    at: issued_at,
    actor: options.actor,
    tool: options.call.tool,
    resource: options.call.resource,
    args_hash,
    decision: options.decision,
    reason,
    nonce: receipt.nonce,
    policy_version: policy.version,
    receipt_hash,
  };
  (options.log ?? defaultDecisionLog).append(decision_log);

  return {
    state: options.decision === "allow" ? "RECEIPT_REQUIRED" : "DENIED",
    allowed: false,
    requires_receipt: options.decision === "allow",
    reason,
    deny_code: options.decision === "deny" ? "human_denied" : undefined,
    args_hash,
    risk,
    policy_version: policy.version,
    claims: [
      ...inspected.claims,
      claim("human-decision", true, `${options.decision} by ${options.actor}`),
    ],
    receipt,
    receipt_hash,
    decision_log,
  };
}

export interface AuthorizeOptions {
  call: ProposedToolCall;
  policy: unknown;
  receipt?: unknown;
  signing_key?: string;
  clock?: ApprovalClock;
  replay?: ReplayStore;
}

/**
 * Consume a receipt against the call that is about to run.
 * Changed arguments, expiry, replay, and MAC failure all deny.
 */
export function authorizeToolCall(options: AuthorizeOptions): AuthorizationResult {
  const policy = parseToolApprovalPolicy(options.policy);
  if (!policy) {
    return denied(
      [claim("policy", false, "policy missing or unparseable")],
      "ambiguous",
      "ambiguous policy — deny on ambiguity",
    );
  }

  const inspected = inspectCall(options.call, policy);
  if (inspected.deny) return inspected.deny;

  if (options.receipt === undefined || options.receipt === null) {
    return denied(
      [
        ...inspected.claims,
        claim("allowlist-is-not-authorization", false, "no receipt presented"),
      ],
      "allowlist_is_not_authorization",
      `allowlist is not authorization: ${options.call.tool} has no approval receipt`,
      { args_hash: inspected.args_hash, risk: inspected.risk, policy_version: policy.version },
    );
  }

  const receipt = parseApprovalReceipt(options.receipt);
  if (!receipt) {
    return denied(
      [...inspected.claims, claim("receipt-schema", false, "receipt missing required bindings")],
      "ambiguous",
      "ambiguous receipt — deny on ambiguity",
      { args_hash: inspected.args_hash, policy_version: policy.version },
    );
  }

  const key = resolveReceiptKey(options.signing_key);
  const macOk = verifyReceiptSignature(receipt, key);
  inspected.claims.push(claim("receipt-mac", macOk, macOk ? "HMAC-SHA256 verified" : "HMAC-SHA256 mismatch"));
  if (!macOk) {
    return denied(inspected.claims, "invalid_signature", "receipt signature is invalid", {
      args_hash: inspected.args_hash,
      policy_version: policy.version,
    });
  }

  const replay = options.replay ?? defaultReplayStore;
  if (replay.seen(receipt.nonce)) {
    inspected.claims.push(claim("replay", false, `nonce ${receipt.nonce} already consumed`));
    return denied(inspected.claims, "replayed_receipt", "replayed receipt — nonce already consumed", {
      args_hash: inspected.args_hash,
      receipt,
      receipt_hash: receiptContentHash(receipt),
      policy_version: policy.version,
    });
  }

  const clock = options.clock ?? systemClock;
  const now = clock.now();
  const expiryMs = parseIsoTime(receipt.expiry);
  const issuedMs = parseIsoTime(receipt.issued_at);
  if (expiryMs === undefined || issuedMs === undefined) {
    return denied(
      [...inspected.claims, claim("receipt-times", false, "issued_at or expiry unparseable")],
      "ambiguous",
      "ambiguous receipt timestamps — deny on ambiguity",
      { args_hash: inspected.args_hash, policy_version: policy.version },
    );
  }
  if (issuedMs > now + 1000) {
    inspected.claims.push(claim("issued-at", false, "receipt issued_at is in the future"));
    return denied(inspected.claims, "ambiguous", "receipt issued_at is in the future", {
      args_hash: inspected.args_hash,
      policy_version: policy.version,
    });
  }
  if (now >= expiryMs) {
    replay.consume({
      nonce: receipt.nonce,
      consumed_at: new Date(now).toISOString(),
      args_hash: receipt.args_hash,
      tool: receipt.tool,
      resource: receipt.resource,
    });
    inspected.claims.push(claim("expiry", false, `now ${new Date(now).toISOString()} >= ${receipt.expiry}`));
    return denied(inspected.claims, "expired_receipt", "expired receipt", {
      args_hash: inspected.args_hash,
      receipt,
      receipt_hash: receiptContentHash(receipt),
      policy_version: policy.version,
    });
  }
  inspected.claims.push(claim("expiry", true, `valid until ${receipt.expiry}`));

  if (receipt.decision === "deny") {
    replay.consume({
      nonce: receipt.nonce,
      consumed_at: new Date(now).toISOString(),
      args_hash: receipt.args_hash,
      tool: receipt.tool,
      resource: receipt.resource,
    });
    inspected.claims.push(claim("human-decision", false, `denied by ${receipt.actor}`));
    return denied(inspected.claims, "human_denied", `human-denied by ${receipt.actor}`, {
      args_hash: inspected.args_hash,
      receipt,
      receipt_hash: receiptContentHash(receipt),
      policy_version: policy.version,
    });
  }

  if (receipt.policy_version !== policy.version) {
    inspected.claims.push(
      claim("policy-binding", false, `receipt ${receipt.policy_version} != policy ${policy.version}`),
    );
    return denied(inspected.claims, "policy_version_mismatch", "receipt policy version does not match current policy", {
      args_hash: inspected.args_hash,
      receipt,
      policy_version: policy.version,
    });
  }

  if (receipt.tool !== options.call.tool || receipt.resource !== options.call.resource) {
    inspected.claims.push(
      claim(
        "binding",
        false,
        `receipt ${receipt.tool}/${receipt.resource} != call ${options.call.tool}/${options.call.resource}`,
      ),
    );
    return denied(inspected.claims, "binding_mismatch", "receipt is not bound to this tool/resource", {
      args_hash: inspected.args_hash,
      receipt,
      policy_version: policy.version,
    });
  }

  if (receipt.args_hash !== inspected.args_hash) {
    inspected.claims.push(
      claim("args-binding", false, `receipt ${receipt.args_hash} != call ${inspected.args_hash}`),
    );
    return denied(inspected.claims, "changed_arguments", "changed arguments after approval", {
      args_hash: inspected.args_hash,
      receipt,
      policy_version: policy.version,
    });
  }
  inspected.claims.push(claim("args-binding", true, "normalized args hash matches receipt"));

  const expectedRisk = inspected.risk ?? policyRiskFor(policy, options.call.tool);
  if (receipt.risk !== expectedRisk) {
    inspected.claims.push(claim("risk-binding", false, `receipt ${receipt.risk} != policy ${expectedRisk}`));
    return denied(inspected.claims, "risk_mismatch", "receipt risk does not match current policy risk", {
      args_hash: inspected.args_hash,
      receipt,
      policy_version: policy.version,
    });
  }

  replay.consume({
    nonce: receipt.nonce,
    consumed_at: new Date(now).toISOString(),
    args_hash: receipt.args_hash,
    tool: receipt.tool,
    resource: receipt.resource,
  });

  return {
    state: "AUTHORIZED",
    allowed: true,
    requires_receipt: false,
    reason: `authorized by receipt from ${receipt.actor}`,
    args_hash: inspected.args_hash,
    risk: expectedRisk,
    policy_version: policy.version,
    claims: [...inspected.claims, claim("authorized", true, `nonce ${receipt.nonce} consumed`)],
    receipt,
    receipt_hash: receiptContentHash(receipt),
  };
}
