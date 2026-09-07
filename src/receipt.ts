/**
 * Tool-call approval receipts (CHP Profile B signing primitives).
 *
 * A managed MCP allowlist only answers "is this tool name installed?".
 * Authorization binds the human decision to:
 *   actor + tool + tenant/resource + normalized args hash + policy version
 *   + risk + expiry + nonce
 * and authenticates that tuple with HMAC-SHA256 over CHP canonical JSON
 * (same payload discipline as the audit-ledger `sig` /
 * {@link import("@cubiczan/chp").contentHash} family).
 *
 * `args_hash` covers host-injected ∪ model arguments when the host binds
 * fields via `host_bound` or `_meta.cubiczan.host_bound`.
 *
 * Fail-closed: missing, wildcard, or unparseable fields are ambiguous and
 * must never produce a usable allow receipt.
 */

import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { CHP_VERSION, canonicalJson, contentHash } from "@cubiczan/chp";

export const RECEIPT_KIND = "chp.tool_approval_receipt";
export const RECEIPT_SCHEMA_VERSION = "1";

/** Dev-only fallback; override with $CHP_RECEIPT_KEY (or $AUDIT_LEDGER_KEY). */
export const DEFAULT_RECEIPT_KEY = "cubiczan-chp-mcp-insecure-default-key";
export const RECEIPT_KEY_ENV = "CHP_RECEIPT_KEY";
export const AUDIT_LEDGER_KEY_ENV = "AUDIT_LEDGER_KEY";

export type ReceiptDecision = "allow" | "deny";
export type ReceiptRisk = "low" | "medium" | "high" | "critical";

export const RECEIPT_RISKS: readonly ReceiptRisk[] = [
  "low",
  "medium",
  "high",
  "critical",
];

/**
 * Unsigned body. Every field below is covered by {@link ApprovalReceipt.signature}.
 * Extra keys are rejected at parse time so they cannot silently fall out of the MAC.
 */
export interface ApprovalReceiptBody {
  kind: typeof RECEIPT_KIND;
  schema_version: typeof RECEIPT_SCHEMA_VERSION;
  chp_version: string;
  actor: string;
  tool: string;
  resource: string;
  args_hash: string;
  policy_version: string;
  risk: ReceiptRisk;
  issued_at: string;
  expiry: string;
  decision: ReceiptDecision;
  nonce: string;
}

export interface ApprovalReceipt extends ApprovalReceiptBody {
  /** HMAC-SHA256 hex over CHP canonical JSON of the body (signature omitted). */
  signature: string;
}

export function resolveReceiptKey(explicit?: string): string {
  return (
    explicit ||
    process.env[RECEIPT_KEY_ENV] ||
    process.env[AUDIT_LEDGER_KEY_ENV] ||
    DEFAULT_RECEIPT_KEY
  );
}

/** SHA-256 of float-aware canonical JSON — same digest family as Profile B gates. */
export function hashToolArgs(args: unknown): string {
  return contentHash(args, { floatAware: true });
}

export function isReceiptRisk(value: unknown): value is ReceiptRisk {
  return typeof value === "string" && (RECEIPT_RISKS as readonly string[]).includes(value);
}

const AMBIGUOUS_TOKENS = new Set(["", "*", "any", "all", "unknown", "undefined", "null"]);

/**
 * Identity / binding slots must be a concrete string. Globs and reserved
 * tokens are treated as ambiguous — deny, do not guess.
 */
export function isAmbiguousBinding(value: unknown): boolean {
  if (typeof value !== "string") return true;
  const trimmed = value.trim();
  if (AMBIGUOUS_TOKENS.has(trimmed.toLowerCase())) return true;
  if (/[*?[\]{}]/.test(trimmed)) return true;
  return false;
}

export function parseIsoTime(value: unknown): number | undefined {
  if (typeof value !== "string" || value.trim() === "") return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : undefined;
}

export function signingPayload(body: ApprovalReceiptBody): ApprovalReceiptBody {
  return {
    kind: RECEIPT_KIND,
    schema_version: RECEIPT_SCHEMA_VERSION,
    chp_version: body.chp_version,
    actor: body.actor,
    tool: body.tool,
    resource: body.resource,
    args_hash: body.args_hash,
    policy_version: body.policy_version,
    risk: body.risk,
    issued_at: body.issued_at,
    expiry: body.expiry,
    decision: body.decision,
    nonce: body.nonce,
  };
}

export function signReceipt(body: ApprovalReceiptBody, key: string): string {
  const canonical = canonicalJson(signingPayload(body));
  return createHmac("sha256", key).update(canonical, "utf8").digest("hex");
}

export function receiptContentHash(body: ApprovalReceiptBody): string {
  return contentHash(signingPayload(body), { floatAware: true });
}

function safeEqualHex(a: string, b: string): boolean {
  try {
    const left = Buffer.from(a, "hex");
    const right = Buffer.from(b, "hex");
    if (left.length === 0 || left.length !== right.length) return false;
    return timingSafeEqual(left, right);
  } catch {
    return false;
  }
}

export function verifyReceiptSignature(receipt: ApprovalReceipt, key: string): boolean {
  if (typeof receipt.signature !== "string" || receipt.signature.length !== 64) {
    return false;
  }
  const expected = signReceipt(signingPayload(receipt), key);
  return safeEqualHex(receipt.signature, expected);
}

export interface IssueReceiptInput {
  actor: string;
  tool: string;
  resource: string;
  args_hash: string;
  policy_version: string;
  risk: ReceiptRisk;
  decision: ReceiptDecision;
  issued_at: string;
  expiry: string;
  nonce?: string;
  chp_version?: string;
}

export function issueSignedReceipt(input: IssueReceiptInput, key: string): ApprovalReceipt {
  const body: ApprovalReceiptBody = signingPayload({
    kind: RECEIPT_KIND,
    schema_version: RECEIPT_SCHEMA_VERSION,
    chp_version: input.chp_version ?? CHP_VERSION,
    actor: input.actor,
    tool: input.tool,
    resource: input.resource,
    args_hash: input.args_hash,
    policy_version: input.policy_version,
    risk: input.risk,
    issued_at: input.issued_at,
    expiry: input.expiry,
    decision: input.decision,
    nonce: input.nonce ?? randomUUID(),
  });
  return { ...body, signature: signReceipt(body, key) };
}

export function parseApprovalReceipt(value: unknown): ApprovalReceipt | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const rec = value as Record<string, unknown>;
  if (rec.kind !== RECEIPT_KIND) return undefined;
  if (rec.schema_version !== RECEIPT_SCHEMA_VERSION) return undefined;
  if (typeof rec.chp_version !== "string" || rec.chp_version.trim() === "") return undefined;
  if (isAmbiguousBinding(rec.actor)) return undefined;
  if (isAmbiguousBinding(rec.tool)) return undefined;
  if (isAmbiguousBinding(rec.resource)) return undefined;
  if (typeof rec.args_hash !== "string" || !/^[0-9a-f]{64}$/.test(rec.args_hash)) return undefined;
  if (isAmbiguousBinding(rec.policy_version)) return undefined;
  if (!isReceiptRisk(rec.risk)) return undefined;
  if (parseIsoTime(rec.issued_at) === undefined) return undefined;
  if (parseIsoTime(rec.expiry) === undefined) return undefined;
  if (rec.decision !== "allow" && rec.decision !== "deny") return undefined;
  if (typeof rec.nonce !== "string" || rec.nonce.trim() === "") return undefined;
  if (typeof rec.signature !== "string") return undefined;

  const allowed = new Set([
    "kind",
    "schema_version",
    "chp_version",
    "actor",
    "tool",
    "resource",
    "args_hash",
    "policy_version",
    "risk",
    "issued_at",
    "expiry",
    "decision",
    "nonce",
    "signature",
  ]);
  if (Object.keys(rec).some((key) => !allowed.has(key))) return undefined;

  return {
    kind: RECEIPT_KIND,
    schema_version: RECEIPT_SCHEMA_VERSION,
    chp_version: rec.chp_version as string,
    actor: rec.actor as string,
    tool: rec.tool as string,
    resource: rec.resource as string,
    args_hash: rec.args_hash as string,
    policy_version: rec.policy_version as string,
    risk: rec.risk,
    issued_at: rec.issued_at as string,
    expiry: rec.expiry as string,
    decision: rec.decision,
    nonce: rec.nonce as string,
    signature: rec.signature as string,
  };
}
