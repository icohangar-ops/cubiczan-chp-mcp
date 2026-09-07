/**
 * Host-injected argument binding.
 *
 * Semantic Kernel / MCP hosts inject index, tenant, and similar
 * identifiers so the model does not choose them. A managed allowlist
 * still is not a grant — those host values MUST enter the receipt
 * `args_hash` (host ∪ model). If the model supplies a different value
 * for a host-bound field, deny.
 *
 * Wire contract (no dependency on @cubiczan/governed-mcp-gateway):
 *   params._meta.cubiczan.principal   — gateway-injected identity
 *   params._meta.cubiczan.host_bound  — host-injected bound args
 *   call.host_bound                   — explicit overlay (wins on key clash)
 */

import { canonicalJson } from "@cubiczan/chp";
import type { Claim } from "@cubiczan/chp";
import { isAmbiguousBinding } from "./receipt.js";

export const CUBICZAN_META_NS = "cubiczan";

export type HostBindDenyCode = "ambiguous" | "host_bound_override";

export interface ProposedCallForBind {
  tool: string;
  arguments?: unknown;
  host_bound?: unknown;
  _meta?: unknown;
}

export interface HostBoundPolicySlice {
  host_bound_fields?: Record<string, string[]>;
}

export interface HostBindOk {
  ok: true;
  merged: unknown;
  host_bound: Record<string, unknown>;
  host_bound_keys: string[];
  claims: Claim[];
}

export interface HostBindDeny {
  ok: false;
  deny_code: HostBindDenyCode;
  reason: string;
  claims: Claim[];
  host_bound: Record<string, unknown>;
}

export type HostBindResult = HostBindOk | HostBindDeny;

function claim(rule: string, passed: boolean, detail: string): Claim {
  return { rule, passed, detail };
}

export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function canonicalEqual(left: unknown, right: unknown): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

export interface CubiczanMeta {
  principal?: Record<string, unknown>;
  host_bound?: Record<string, unknown>;
}

/** Read the governed-mcp-gateway `_meta.cubiczan` envelope. */
export function readCubiczanMeta(meta: unknown): CubiczanMeta {
  if (!isPlainRecord(meta)) return {};
  const cubiczan = meta[CUBICZAN_META_NS];
  if (!isPlainRecord(cubiczan)) return {};
  return {
    principal: isPlainRecord(cubiczan.principal) ? cubiczan.principal : undefined,
    host_bound: isPlainRecord(cubiczan.host_bound) ? cubiczan.host_bound : undefined,
  };
}

function concreteHostValue(value: unknown): boolean {
  if (typeof value === "string") return !isAmbiguousBinding(value);
  if (value === null || value === undefined) return false;
  return true;
}

function tenantFromPrincipal(principal: Record<string, unknown> | undefined): string | undefined {
  if (!principal) return undefined;
  for (const key of ["orgId", "tenant", "tenant_id"] as const) {
    const value = principal[key];
    if (typeof value === "string" && !isAmbiguousBinding(value)) return value;
  }
  return undefined;
}

export function extractHostBound(
  call: ProposedCallForBind,
  declaredFields: readonly string[],
): { host_bound: Record<string, unknown>; sources: string[] } {
  const meta = readCubiczanMeta(call._meta);
  const fromMeta = meta.host_bound ?? {};
  const fromCall = isPlainRecord(call.host_bound) ? call.host_bound : {};
  const host_bound: Record<string, unknown> = { ...fromMeta, ...fromCall };
  const sources: string[] = [];
  if (Object.keys(fromMeta).length > 0) sources.push("_meta.cubiczan.host_bound");
  if (Object.keys(fromCall).length > 0) sources.push("host_bound");

  if (declaredFields.includes("tenant_id") && host_bound.tenant_id === undefined) {
    const derived = tenantFromPrincipal(meta.principal);
    if (derived !== undefined) {
      host_bound.tenant_id = derived;
      sources.push("_meta.cubiczan.principal.orgId");
    }
  }

  return { host_bound, sources };
}

/**
 * Merge host-injected fields over model arguments.
 * Host keys win only after an override check — a differing model value denies.
 */
export function bindHostInjectedArgs(
  call: ProposedCallForBind,
  policy: HostBoundPolicySlice,
): HostBindResult {
  const declared = policy.host_bound_fields?.[call.tool] ?? [];
  const { host_bound, sources } = extractHostBound(call, declared);
  const hostKeys = new Set<string>([...declared, ...Object.keys(host_bound)]);
  const claims: Claim[] = [];

  if (hostKeys.size === 0) {
    claims.push(claim("host-injected-args", true, "no host-bound fields"));
    return { ok: true, merged: call.arguments, host_bound: {}, host_bound_keys: [], claims };
  }

  if (call.arguments !== undefined && !isPlainRecord(call.arguments)) {
    claims.push(claim("host-injected-args", false, "cannot merge host-bound fields into non-object arguments"));
    return {
      ok: false,
      deny_code: "ambiguous",
      reason: "ambiguous arguments — host-bound fields require an object",
      claims,
      host_bound,
    };
  }

  const modelArgs = isPlainRecord(call.arguments) ? call.arguments : {};

  for (const field of declared) {
    if (!Object.prototype.hasOwnProperty.call(host_bound, field) || !concreteHostValue(host_bound[field])) {
      claims.push(
        claim(
          "host-bound-fields",
          false,
          `host must inject concrete ${field} for ${call.tool}`,
        ),
      );
      return {
        ok: false,
        deny_code: "ambiguous",
        reason: `host-bound field ${field} missing or ambiguous for ${call.tool}`,
        claims,
        host_bound,
      };
    }
  }

  for (const field of hostKeys) {
    if (!Object.prototype.hasOwnProperty.call(modelArgs, field)) continue;
    if (canonicalEqual(modelArgs[field], host_bound[field])) continue;
    claims.push(
      claim(
        "host-bound-override",
        false,
        `model must not override host-bound field ${field}`,
      ),
    );
    return {
      ok: false,
      deny_code: "host_bound_override",
      reason: `model changed host-bound field ${field}`,
      claims,
      host_bound,
    };
  }

  const merged: Record<string, unknown> = { ...modelArgs, ...host_bound };
  const applied = [...hostKeys].sort();
  claims.push(
    claim(
      "host-injected-args",
      true,
      `host-bound ${applied.join(", ")}${sources.length ? ` via ${sources.join(" + ")}` : ""}`,
    ),
  );

  return {
    ok: true,
    merged,
    host_bound,
    host_bound_keys: applied,
    claims,
  };
}
