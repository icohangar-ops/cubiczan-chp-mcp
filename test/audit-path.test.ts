import assert from "node:assert/strict";
import { mkdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { test } from "node:test";

import {
  FileLedger,
  MemoryLedger,
  defaultLedgerPath,
  openLedger,
  resolveConfinedPath,
} from "../src/audit.js";

const cwd = process.cwd();

test("resolveConfinedPath keeps legitimate in-tree paths", () => {
  const expected = resolve(cwd, "data", "chp-audit.jsonl");
  assert.equal(resolveConfinedPath("data/chp-audit.jsonl"), expected);
  assert.equal(resolveConfinedPath("./data/chp-audit.jsonl"), expected);
  assert.equal(resolveConfinedPath(join(cwd, "data", "chp-audit.jsonl")), expected);
  assert.equal(resolveConfinedPath("data/nested/../chp-audit.jsonl"), expected);
});

test("resolveConfinedPath rejects traversal and out-of-base paths", () => {
  assert.throws(() => resolveConfinedPath("../etc/passwd"), /escapes the allowed directory/);
  assert.throws(() => resolveConfinedPath("../../etc/passwd"), /escapes the allowed directory/);
  assert.throws(() => resolveConfinedPath("/etc/passwd"), /escapes the allowed directory/);
  assert.throws(() => resolveConfinedPath(join(cwd, "..", "outside.jsonl")), /escapes the allowed directory/);
  assert.throws(() => resolveConfinedPath(""), /must not be empty/);
});

test("FileLedger reads and appends only after confinement", () => {
  const rel = join("data", `audit-path-${process.pid}-${Date.now()}.jsonl`);
  mkdirSync(join(cwd, "data"), { recursive: true });
  try {
    const ledger = new FileLedger(rel);
    assert.equal(ledger.entries().length, 0);
    ledger.append({
      event: "deny",
      tool: "place_equity_order",
      args_hash: "00",
      body: { ok: false },
    });
    const reopened = new FileLedger(rel);
    assert.equal(reopened.entries().length, 1);
    assert.equal(reopened.entries()[0]?.event, "deny");
  } finally {
    rmSync(resolve(cwd, rel), { force: true });
  }
});

test("FileLedger refuses to open a path that escapes cwd", () => {
  assert.throws(() => new FileLedger("/etc/passwd"), /escapes the allowed directory/);
  assert.throws(() => new FileLedger("../package.json"), /escapes the allowed directory/);
});

test("openLedger(:memory:) is unchanged; default path is confined under cwd", () => {
  assert.ok(openLedger(":memory:") instanceof MemoryLedger);
  const previous = process.env.CHP_AUDIT_LEDGER;
  delete process.env.CHP_AUDIT_LEDGER;
  try {
    assert.equal(defaultLedgerPath(), resolve(cwd, "data", "chp-audit.jsonl"));
    process.env.CHP_AUDIT_LEDGER = "../etc/passwd";
    assert.throws(() => defaultLedgerPath(), /escapes the allowed directory/);
    process.env.CHP_AUDIT_LEDGER = ":memory:";
    assert.equal(defaultLedgerPath(), ":memory:");
  } finally {
    if (previous === undefined) delete process.env.CHP_AUDIT_LEDGER;
    else process.env.CHP_AUDIT_LEDGER = previous;
  }
});
