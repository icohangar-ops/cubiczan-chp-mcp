# Authorization receipts (delta)

## ADDED Requirements

### Requirement: Signed authorization receipts

When an action is auto-locked or human-approved, the system SHALL issue
an authorization receipt whose `content_hash` is the CHP content hash of
its canonical fields, bound to `tool`, `scope`, and `args_hash`.

#### Scenario: Approve mints a bound receipt

- GIVEN a HITL_REQUIRED equity order
- WHEN a human approves with `tool` and `bound_args`
- THEN an authorization receipt is returned
- AND its `args_hash` matches the CHP hash of those bound args

### Requirement: Receipt required to execute gated tools

A gated reference tool SHALL refuse execution unless a valid
authorization receipt is presented.

#### Scenario: Missing receipt

- GIVEN a gated tool call with no receipt
- WHEN the tool is invoked
- THEN the deny `reason_code` is `missing_receipt`
- AND a matching ledger deny exists

### Requirement: Args are bound after approval

If the executed args (or tool/scope) differ from the receipt binding,
the system SHALL deny with `args_changed`.

#### Scenario: Quantity changed after approve

- GIVEN an authorization receipt for a 300 notional BUY
- WHEN the same receipt is used with notional 3000
- THEN the deny `reason_code` is `args_changed`
- AND a matching ledger deny exists

### Requirement: Replay and expiry

A consumed receipt SHALL deny with `replay`. An expired receipt SHALL
deny with `expired`.

#### Scenario: Second execute is replay

- GIVEN a receipt already used for a successful execute
- WHEN it is presented again
- THEN the deny `reason_code` is `replay`

#### Scenario: Clock past expires_at

- GIVEN a receipt whose `expires_at` is in the past
- WHEN it is presented
- THEN the deny `reason_code` is `expired`
