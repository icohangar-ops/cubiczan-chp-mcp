# Deny telemetry (delta)

## ADDED Requirements

### Requirement: Structured deny reason codes

The system SHALL emit denials using only these reason codes:
`policy_deny`, `expired`, `replay`, `args_changed`, `missing_receipt`,
`ambiguous_policy`.

#### Scenario: Policy violation is policy_deny

- GIVEN a gated action that fails a hard CHP rule
- WHEN the action is evaluated or executed
- THEN the deny `reason_code` is `policy_deny`

#### Scenario: Closed code set

- GIVEN any deny path in the runtime
- WHEN a deny receipt is produced
- THEN `reason_code` is one of the six published codes

### Requirement: Denies are durable before the caller sees them

The system SHALL append a CHP-signed ledger entry for a deny before
returning that deny. If the ledger write fails, the system MUST NOT
return a deny object.

#### Scenario: Logged policy deny

- GIVEN a functioning ledger
- WHEN a gated tool is denied
- THEN the ledger contains an `event=deny` entry whose `reason_code`
  matches the returned receipt

#### Scenario: Ledger failure is not an unlogged deny

- GIVEN a ledger that throws on append
- WHEN a gated tool would be denied
- THEN the call throws
- AND no deny receipt is returned to the caller
