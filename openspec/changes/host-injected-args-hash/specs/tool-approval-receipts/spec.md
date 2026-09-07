# Tool-approval receipts (delta)

## MODIFIED Requirements

### Requirement: Receipt schema

The system SHALL issue receipts containing actor, tool, resource,
args_hash, policy_version, risk, issued_at, expiry, decision
(allow|deny), nonce, and an HMAC-SHA256 signature over CHP canonical
JSON of those fields. Args SHALL be hashed with Profile B float-aware
`contentHash`. WHEN host-injected fields are present, THE hashed
payload SHALL be the merged host ∪ model arguments, not model args
alone.

### Requirement: Changed arguments deny

WHEN a receipt is presented with arguments whose canonical hash differs
from `args_hash`, THE system SHALL deny with `changed_arguments`. Host-bound
identifier changes (tenant, index) after approval are included.

## ADDED Requirements

### Requirement: Host-bound override deny

WHEN the model changes a host-injected field, THE system SHALL deny with
`host_bound_override` before treating the call as a mere args-hash
mismatch.
