/**
 * Structured deny / authorization receipts and a CHP-signed audit ledger.
 *
 * Signing is exclusively @cubiczan/chp contentHash + chainHash (spec §3.1).
 * A deny object is never returned unless the ledger append succeeded.
 */

import { chainHash, contentHash } from "@cubiczan/chp";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

export const DENY_REASON_CODES = [
  "policy_deny",
  "expired",
  "replay",
  "args_changed",
  "missing_receipt",
  "ambiguous_policy",
] as const;

export type DenyReasonCode = (typeof DENY_REASON_CODES)[number];

export const GENESIS_SIG = "0".repeat(64);

export type LedgerEvent = "deny" | "authorize" | "execute";

export interface AuthorizationReceipt {
  kind: "authorization";
  receipt_id: string;
  tool: string;
  scope: string;
  args_hash: string;
  issued_at: string;
  expires_at: string;
  approver: string;
  nonce: string;
  content_hash: string;
}

export interface DenyReceipt {
  kind: "deny";
  receipt_id: string;
  tool: string;
  scope: string | null;
  reason_code: DenyReasonCode;
  detail: string;
  args_hash: string;
  issued_at: string;
  content_hash: string;
}

export interface LedgerPayload {
  event: LedgerEvent;
  reason_code: DenyReasonCode | null;
  tool: string;
  scope: string | null;
  receipt_id: string | null;
  args_hash: string;
  body: unknown;
}

export interface LedgerEntry {
  seq: number;
  ts: string;
  event: LedgerEvent;
  reason_code: DenyReasonCode | null;
  tool: string;
  scope: string | null;
  receipt_id: string | null;
  args_hash: string;
  payload: LedgerPayload;
  content_hash: string;
  prev_sig: string;
  sig: string;
}

export interface LedgerAppendInput {
  event: LedgerEvent;
  ts?: string;
  reason_code?: DenyReasonCode | null;
  tool: string;
  scope?: string | null;
  receipt_id?: string | null;
  args_hash: string;
  body: unknown;
}

export interface AuditLedger {
  append(input: LedgerAppendInput): LedgerEntry;
  entries(): readonly LedgerEntry[];
}

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

export function isDenyReasonCode(value: string): value is DenyReasonCode {
  return (DENY_REASON_CODES as readonly string[]).includes(value);
}

function authorizationCanonical(
  receipt: Omit<AuthorizationReceipt, "content_hash">,
): Record<string, unknown> {
  return {
    kind: receipt.kind,
    receipt_id: receipt.receipt_id,
    tool: receipt.tool,
    scope: receipt.scope,
    args_hash: receipt.args_hash,
    issued_at: receipt.issued_at,
    expires_at: receipt.expires_at,
    approver: receipt.approver,
    nonce: receipt.nonce,
  };
}

function denyCanonical(receipt: Omit<DenyReceipt, "content_hash">): Record<string, unknown> {
  return {
    kind: receipt.kind,
    receipt_id: receipt.receipt_id,
    tool: receipt.tool,
    scope: receipt.scope,
    reason_code: receipt.reason_code,
    detail: receipt.detail,
    args_hash: receipt.args_hash,
    issued_at: receipt.issued_at,
  };
}

export function issueAuthorizationReceipt(input: {
  tool: string;
  scope: string;
  args_hash: string;
  approver: string;
  issued_at: string;
  expires_at: string;
  receipt_id?: string;
  nonce?: string;
}): AuthorizationReceipt {
  const unsigned: Omit<AuthorizationReceipt, "content_hash"> = {
    kind: "authorization",
    receipt_id: input.receipt_id ?? crypto.randomUUID(),
    tool: input.tool,
    scope: input.scope,
    args_hash: input.args_hash,
    issued_at: input.issued_at,
    expires_at: input.expires_at,
    approver: input.approver,
    nonce: input.nonce ?? crypto.randomUUID(),
  };
  return {
    ...unsigned,
    content_hash: contentHash(authorizationCanonical(unsigned)),
  };
}

export function verifyAuthorizationReceipt(receipt: AuthorizationReceipt): boolean {
  if (receipt.kind !== "authorization") return false;
  const expected = contentHash(authorizationCanonical(receipt));
  return expected === receipt.content_hash;
}

export function issueDenyReceipt(input: {
  tool: string;
  scope?: string | null;
  reason_code: DenyReasonCode;
  detail: string;
  args_hash: string;
  issued_at: string;
  receipt_id?: string;
}): DenyReceipt {
  const unsigned: Omit<DenyReceipt, "content_hash"> = {
    kind: "deny",
    receipt_id: input.receipt_id ?? crypto.randomUUID(),
    tool: input.tool,
    scope: input.scope ?? null,
    reason_code: input.reason_code,
    detail: input.detail,
    args_hash: input.args_hash,
    issued_at: input.issued_at,
  };
  return {
    ...unsigned,
    content_hash: contentHash(denyCanonical(unsigned)),
  };
}

export function buildLedgerEntry(
  prev: LedgerEntry | undefined,
  input: LedgerAppendInput,
): LedgerEntry {
  const seq = (prev?.seq ?? 0) + 1;
  const ts = input.ts ?? new Date().toISOString();
  const payload: LedgerPayload = {
    event: input.event,
    reason_code: input.reason_code ?? null,
    tool: input.tool,
    scope: input.scope ?? null,
    receipt_id: input.receipt_id ?? null,
    args_hash: input.args_hash,
    body: input.body,
  };
  const content_hash = contentHash(payload);
  const prev_sig = prev?.sig ?? GENESIS_SIG;
  const sig = chainHash(prev_sig, { seq, ts, event: input.event, content_hash });
  return {
    seq,
    ts,
    event: input.event,
    reason_code: payload.reason_code,
    tool: payload.tool,
    scope: payload.scope,
    receipt_id: payload.receipt_id,
    args_hash: payload.args_hash,
    payload,
    content_hash,
    prev_sig,
    sig,
  };
}

/**
 * Persist a structured deny, then return it. If append throws, nothing is
 * returned — an unlogged deny is impossible by construction.
 */
export function recordDeny(
  ledger: AuditLedger,
  input: {
    tool: string;
    scope?: string | null;
    reason_code: DenyReasonCode;
    detail: string;
    args_hash: string;
    issued_at: string;
  },
): DenyReceipt {
  const receipt = issueDenyReceipt(input);
  ledger.append({
    event: "deny",
    ts: input.issued_at,
    reason_code: receipt.reason_code,
    tool: receipt.tool,
    scope: receipt.scope,
    receipt_id: receipt.receipt_id,
    args_hash: receipt.args_hash,
    body: receipt,
  });
  return receipt;
}

export function verifyLedgerChain(
  entries: readonly LedgerEntry[],
): { ok: true } | { ok: false; at: number; reason: string } {
  let prev: LedgerEntry | undefined;
  for (const entry of entries) {
    const rebuilt = buildLedgerEntry(prev, {
      event: entry.event,
      ts: entry.ts,
      reason_code: entry.reason_code,
      tool: entry.tool,
      scope: entry.scope,
      receipt_id: entry.receipt_id,
      args_hash: entry.args_hash,
      body: entry.payload.body,
    });
    if (rebuilt.content_hash !== entry.content_hash) {
      return { ok: false, at: entry.seq, reason: "content_hash mismatch" };
    }
    if (rebuilt.prev_sig !== entry.prev_sig) {
      return { ok: false, at: entry.seq, reason: "prev_sig mismatch" };
    }
    if (rebuilt.sig !== entry.sig) {
      return { ok: false, at: entry.seq, reason: "sig mismatch" };
    }
    prev = entry;
  }
  return { ok: true };
}

export class MemoryLedger implements AuditLedger {
  private readonly log: LedgerEntry[] = [];

  append(input: LedgerAppendInput): LedgerEntry {
    const entry = buildLedgerEntry(this.log.at(-1), input);
    this.log.push(entry);
    return entry;
  }

  entries(): readonly LedgerEntry[] {
    return this.log;
  }
}

export class FileLedger implements AuditLedger {
  private readonly log: LedgerEntry[] = [];

  constructor(private readonly filePath: string) {
    this.log = loadJsonl(filePath);
  }

  append(input: LedgerAppendInput): LedgerEntry {
    const entry = buildLedgerEntry(this.log.at(-1), input);
    mkdirSync(dirname(this.filePath), { recursive: true });
    appendFileSync(this.filePath, `${JSON.stringify(entry)}\n`, "utf8");
    this.log.push(entry);
    return entry;
  }

  entries(): readonly LedgerEntry[] {
    return this.log;
  }
}

function loadJsonl(filePath: string): LedgerEntry[] {
  if (!existsSync(filePath)) return [];
  const text = readFileSync(filePath, "utf8").trim();
  if (!text) return [];
  return text.split("\n").map((line) => JSON.parse(line) as LedgerEntry);
}

export class ReceiptStore {
  private readonly consumed = new Set<string>();

  markConsumed(receiptId: string): void {
    this.consumed.add(receiptId);
  }

  isConsumed(receiptId: string): boolean {
    return this.consumed.has(receiptId);
  }

  consume(receiptId: string): boolean {
    if (this.consumed.has(receiptId)) return false;
    this.consumed.add(receiptId);
    return true;
  }

  hydrateFromLedger(entries: readonly LedgerEntry[]): void {
    for (const entry of entries) {
      if (entry.event === "execute" && entry.receipt_id) {
        this.consumed.add(entry.receipt_id);
      }
    }
  }
}

export function defaultLedgerPath(): string {
  return process.env.CHP_AUDIT_LEDGER ?? `${process.cwd()}/data/chp-audit.jsonl`;
}

export function openLedger(path = defaultLedgerPath()): AuditLedger {
  if (path === ":memory:") return new MemoryLedger();
  return new FileLedger(path);
}
