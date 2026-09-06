# Tool-approval receipts

A managed MCP allowlist MUST NOT be treated as authorization for a tool
call. Authorization requires a signed receipt whose bindings still match
the call that is about to run.

## Requirements

### Requirement: Receipt schema

The system SHALL issue receipts containing actor, tool, resource,
args_hash, policy_version, risk, issued_at, expiry, decision
(allow|deny), nonce, and an HMAC-SHA256 signature over CHP canonical
JSON of those fields. Args SHALL be hashed with Profile B float-aware
`contentHash`.

### Requirement: Allowlist is not a grant

WHEN a tool is listed in `allowed_tools` and no valid receipt is
presented, THE system SHALL deny (evaluate → `RECEIPT_REQUIRED`;
authorize → `allowlist_is_not_authorization`).

### Requirement: Changed arguments deny

WHEN a receipt is presented with arguments whose canonical hash differs
from `args_hash`, THE system SHALL deny with `changed_arguments`.

### Requirement: Expired receipts deny

WHEN `now >= expiry`, THE system SHALL deny with `expired_receipt` and
consume the nonce.

### Requirement: Replayed receipts deny

WHEN a nonce has already been consumed, THE system SHALL deny with
`replayed_receipt`.

### Requirement: Human deny is logged

WHEN a human issues `decision=deny`, THE system SHALL append a decision
log entry and SHALL deny any later authorize of that receipt
(`human_denied`).

### Requirement: Deny on ambiguity

WHEN tool, resource, actor, arguments, policy version, or receipt fields
are missing, wildcarded, or unparseable, THE system SHALL deny with
`ambiguous`. Extra keys on a receipt SHALL be rejected.

### Requirement: Humans cannot override a missing allowlist entry

WHEN a human issues `decision=allow` for a tool not in `allowed_tools`,
THE system SHALL deny and SHALL NOT return a receipt.
