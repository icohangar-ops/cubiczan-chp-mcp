import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DENY_REASON_CODES,
  MemoryLedger,
  type AuditLedger,
  type LedgerAppendInput,
  type LedgerEntry,
  recordDeny,
  verifyLedgerChain,
} from "../src/audit.js";
import { argsHash } from "../src/permissions.js";
import { ChpRuntime, createRuntime } from "../src/runtime.js";

const EQUITY = {
  symbol: "AAPL",
  side: "BUY",
  quantity: 10,
  notional: 300,
  confidence: 0.9,
};

function denials(ledger: AuditLedger) {
  return ledger.entries().filter((e) => e.event === "deny");
}

function lastDeny(ledger: AuditLedger): LedgerEntry {
  const entry = denials(ledger).at(-1);
  assert.ok(entry, "expected a deny ledger entry");
  return entry;
}

test("unlogged deny is impossible: every reason code is ledgered before return", () => {
  const ledger = new MemoryLedger();
  const clock = { now: () => new Date("2026-09-06T12:00:00.000Z") };
  const runtime = new ChpRuntime({ ledger, clock, defaultTtlSeconds: 60 });

  const paths: Array<{ code: (typeof DENY_REASON_CODES)[number]; run: () => { reason_code: string } }> = [
    {
      code: "ambiguous_policy",
      run: () => {
        const r = runtime.requestAuthorization({ tool: "get_weather", args: { city: "x" } });
        assert.equal(r.ok, false);
        assert.ok(!r.ok && r.deny);
        return r.deny;
      },
    },
    {
      code: "missing_receipt",
      run: () => {
        const r = runtime.executeGated("place_equity_order", { ...EQUITY, notional: 100 });
        assert.equal(r.ok, false);
        assert.ok(!r.ok && r.deny);
        return r.deny;
      },
    },
    {
      code: "policy_deny",
      run: () => {
        const r = runtime.requestAuthorization({
          tool: "place_equity_order",
          args: { ...EQUITY, notional: 9_999 },
        });
        assert.equal(r.ok, false);
        assert.ok(!r.ok && r.deny);
        return r.deny;
      },
    },
    {
      code: "args_changed",
      run: () => {
        const issued = runtime.requestAuthorization({
          tool: "place_equity_order",
          args: EQUITY,
          approver: "cfo@example.com",
        });
        assert.equal(issued.ok, true);
        assert.ok(issued.ok);
        const r = runtime.executeGated("place_equity_order", { ...EQUITY, notional: 3000 }, issued.authorization);
        assert.equal(r.ok, false);
        assert.ok(!r.ok && r.deny);
        return r.deny;
      },
    },
    {
      code: "expired",
      run: () => {
        const issued = runtime.requestAuthorization({
          tool: "place_equity_order",
          args: { ...EQUITY, notional: 100 },
          ttlSeconds: 1,
        });
        assert.equal(issued.ok, true);
        assert.ok(issued.ok);
        clock.now = () => new Date("2026-09-06T12:00:05.000Z");
        const r = runtime.executeGated(
          "place_equity_order",
          { ...EQUITY, notional: 100 },
          issued.authorization,
        );
        clock.now = () => new Date("2026-09-06T12:00:00.000Z");
        assert.equal(r.ok, false);
        assert.ok(!r.ok && r.deny);
        return r.deny;
      },
    },
    {
      code: "replay",
      run: () => {
        const args = { ...EQUITY, notional: 100 };
        const issued = runtime.requestAuthorization({ tool: "place_equity_order", args });
        assert.equal(issued.ok, true);
        assert.ok(issued.ok);
        const first = runtime.executeGated("place_equity_order", args, issued.authorization);
        assert.equal(first.ok, true);
        const r = runtime.executeGated("place_equity_order", args, issued.authorization);
        assert.equal(r.ok, false);
        assert.ok(!r.ok && r.deny);
        return r.deny;
      },
    },
  ];

  const seen = new Set<string>();
  for (const path of paths) {
    const deny = path.run();
    assert.equal(deny.reason_code, path.code);
    const logged = lastDeny(ledger);
    assert.equal(logged.reason_code, path.code);
    assert.equal(logged.event, "deny");
    assert.ok(logged.sig.length === 64);
    assert.ok(logged.content_hash.length === 64);
    seen.add(path.code);
  }

  assert.deepEqual([...seen].sort(), [...DENY_REASON_CODES].sort());
  const chain = verifyLedgerChain(ledger.entries());
  assert.equal(chain.ok, true);
});

test("ledger write failure cannot produce an unlogged deny", () => {
  const broken: AuditLedger = {
    append(_input: LedgerAppendInput): LedgerEntry {
      throw new Error("disk full");
    },
    entries: () => [],
  };
  const runtime = new ChpRuntime({ ledger: broken });
  assert.throws(
    () => runtime.executeGated("place_equity_order", { ...EQUITY, notional: 100 }),
    /disk full/,
  );
});

test("recordDeny appends before returning; throw on append yields no receipt", () => {
  let calls = 0;
  const broken: AuditLedger = {
    append() {
      calls += 1;
      throw new Error("fsync failed");
    },
    entries: () => [],
  };
  assert.throws(
    () =>
      recordDeny(broken, {
        tool: "place_equity_order",
        reason_code: "missing_receipt",
        detail: "x",
        args_hash: "00",
        issued_at: "2026-09-06T12:00:00.000Z",
      }),
    /fsync failed/,
  );
  assert.equal(calls, 1);
});

test("changed args after approve denies with args_changed and a ledger row", () => {
  const runtime = createRuntime();
  const approved = runtime.requestAuthorization({
    tool: "place_equity_order",
    args: EQUITY,
    approver: "cfo@example.com",
  });
  assert.equal(approved.ok, true);
  assert.ok(approved.ok);
  assert.equal(approved.authorization.args_hash, argsHash("place_equity_order", EQUITY));

  const mutated = runtime.executeGated(
    "place_equity_order",
    { ...EQUITY, quantity: 10_000, notional: 3000 },
    approved.authorization,
  );
  assert.equal(mutated.ok, false);
  assert.ok(!mutated.ok);
  assert.equal(mutated.deny.reason_code, "args_changed");
  assert.equal(lastDeny(runtime.ledger).reason_code, "args_changed");
});

test("gated tools require a receipt", () => {
  const runtime = createRuntime();
  const result = runtime.executeGated("wire_treasury_transfer", {
    from_account: "ops-1",
    to_account: "prime-broker",
    amount: 500,
    currency: "USD",
  });
  assert.equal(result.ok, false);
  assert.ok(!result.ok);
  assert.equal(result.deny.reason_code, "missing_receipt");
  assert.equal(lastDeny(runtime.ledger).reason_code, "missing_receipt");
});

test("treasury wire default policy is HITL and never auto-issues a receipt", () => {
  const runtime = createRuntime();
  const pending = runtime.requestAuthorization({
    tool: "wire_treasury_transfer",
    args: {
      from_account: "ops-1",
      to_account: "prime-broker",
      amount: 500,
      currency: "USD",
    },
  });
  assert.equal(pending.ok, false);
  assert.ok(!pending.ok && pending.pending);
  assert.equal(pending.state, "HITL_REQUIRED");
  assert.equal(
    runtime.ledger.entries().some((e) => e.event === "authorize"),
    false,
  );

  const approved = runtime.requestAuthorization({
    tool: "wire_treasury_transfer",
    args: {
      from_account: "ops-1",
      to_account: "prime-broker",
      amount: 500,
      currency: "USD",
    },
    approver: "treasurer@example.com",
  });
  assert.equal(approved.ok, true);
  assert.ok(approved.ok);
  const executed = runtime.executeGated(
    "wire_treasury_transfer",
    {
      from_account: "ops-1",
      to_account: "prime-broker",
      amount: 500,
      currency: "USD",
    },
    approved.authorization,
  );
  assert.equal(executed.ok, true);
  assert.ok(executed.ok);
  assert.equal(executed.result.synthetic, true);
  assert.equal(executed.result.rail, "SIM-WIRE");
});

test("auto-lock under HITL threshold mints a receipt and executes once", () => {
  const runtime = createRuntime();
  const args = { ...EQUITY, notional: 100 };
  const issued = runtime.requestAuthorization({ tool: "place_equity_order", args });
  assert.equal(issued.ok, true);
  assert.ok(issued.ok);
  const first = runtime.executeGated("place_equity_order", args, issued.authorization);
  assert.equal(first.ok, true);
  assert.ok(first.ok);
  assert.equal(first.result.venue, "SIM-EQUITY");
  const replay = runtime.executeGated("place_equity_order", args, issued.authorization);
  assert.equal(replay.ok, false);
  assert.ok(!replay.ok);
  assert.equal(replay.deny.reason_code, "replay");
});

test("scope mismatch is ambiguous_policy", () => {
  const runtime = createRuntime();
  const result = runtime.requestAuthorization({
    tool: "place_equity_order",
    scope: "treasury:wire",
    args: EQUITY,
  });
  assert.equal(result.ok, false);
  assert.ok(!result.ok && result.deny);
  assert.equal(result.deny.reason_code, "ambiguous_policy");
});

test("evaluate_spend_gate BLOCKED is a logged policy_deny", () => {
  const runtime = createRuntime();
  const gate = runtime.evaluateSpend(
    { action: "LONG", asset: "ETH", notional: 9_999, confidence: 0.9 },
    {
      max_notional: 500,
      daily_cap: 2500,
      hitl_threshold: 250,
      min_confidence: 0.55,
      allowed_actions: ["LONG", "SHORT"],
    },
  );
  assert.equal(gate.state, "BLOCKED");
  assert.equal(gate.deny?.reason_code, "policy_deny");
  assert.equal(lastDeny(runtime.ledger).reason_code, "policy_deny");
});

test("inspect_audit_ledger reports a valid chain and finance scopes — not toys", () => {
  const runtime = createRuntime();
  runtime.executeGated("place_equity_order", { ...EQUITY, notional: 100 });
  const view = runtime.inspectLedger();
  assert.equal(view.chain.ok, true);
  const names = view.tools.map((t) => t.tool);
  assert.deepEqual(names, ["place_equity_order", "wire_treasury_transfer", "rebalance_portfolio"]);
  assert.ok(view.tools.every((t) => t.synthetic));
  assert.ok(!JSON.stringify(view.tools).toLowerCase().includes("weather"));
  assert.ok(!JSON.stringify(view.tools).toLowerCase().includes("todo"));
});

test("tampered ledger fails chain verify", () => {
  const ledger = new MemoryLedger();
  const runtime = new ChpRuntime({ ledger });
  runtime.executeGated("place_equity_order", { ...EQUITY, notional: 100 });
  const copy = { ...ledger.entries()[0], sig: "a".repeat(64) };
  (ledger.entries() as LedgerEntry[])[0] = copy;
  const chain = verifyLedgerChain(ledger.entries());
  assert.equal(chain.ok, false);
});
