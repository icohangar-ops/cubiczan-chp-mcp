# Design: Deny telemetry + signed receipts

## Context

`@cubiczan/chp` already exposes Profile B evaluation (`evaluateGate`,
`approveHuman`) and the signing primitives we need:

- `contentHash(payload)` — SHA-256 over spec §3.1 canonical JSON
- `chainHash(prevSig, entry)` — `contentHash({ prev_sig, entry })`

This package remains a thin MCP transport. Receipts and the ledger live
here so denials cannot evaporate as MCP `isError` text.

## Goals / Non-Goals

**Goals**

- Fail closed: a deny object is never returned unless the ledger append
  succeeded. If the ledger throws, the caller sees a write failure, not
  a silent deny.
- Bind each authorization receipt to `tool + scope + args_hash`.
- Demonstrate the model on synthetic capital-moving tools.

**Non-Goals**

- Live brokerage, bank, or custody integrations
- A new HMAC/JWT scheme or a CHP protocol revision
- GitHub Actions on this Cubiczan mirror

## Decisions

1. **Reason codes are a closed enum.** Unknown codes are not emitted.
   Invalid or unsigned receipts map to `missing_receipt` (no valid
   receipt), not a new code.
2. **Check order on execute:** ambiguous policy → missing/invalid
   receipt → replay → expired → args changed → hard policy. First match
   wins so tests are deterministic.
3. **Ledger is JSONL**, path from `CHP_AUDIT_LEDGER` (default
   `./data/chp-audit.jsonl`). Tests inject an in-memory ledger.
4. **Receipts are JSON objects** the client echoes back. Integrity is
   the CHP `content_hash` of the canonical fields, not a bearer secret.
5. **HITL at execute time is allowed** when a valid receipt is present.
   The receipt *is* the authorization. Hard `BLOCKED` rules still deny.
6. **Existing tools stay.** `evaluate_spend_gate` records `policy_deny`
   on `BLOCKED`. `approve_spend` can mint a bound receipt when `tool` +
   `bound_args` are supplied. New `request_authorization` is the explicit
   receipt API.

## Ledger entry

```text
payload  = { event, reason_code|null, tool, scope|null, receipt_id|null, args_hash, body }
content_hash = contentHash(payload)
sig          = chainHash(prev_sig, { seq, ts, event, content_hash })
```

Genesis `prev_sig` is 64 zero hex digits.

## Risks / Trade-offs

- File ledger is process-local; multi-instance deployments need a shared
  store. Documented; the interface is swappable.
- Content-hash receipts are integrity, not secrecy. Anyone who sees a
  receipt can present it until it is consumed, expires, or args diverge.
  Replay tracking is the control.

## Migration

Additive. Clients that ignore new fields keep working. Gated reference
tools are new names.
