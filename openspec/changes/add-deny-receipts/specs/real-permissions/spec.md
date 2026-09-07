# Real permissions reference (delta)

## ADDED Requirements

### Requirement: Scoped high-consequence reference tools

The server SHALL expose synthetic finance/trading tools with explicit
scopes and approval gates. The reference MUST NOT be a weather, todo, or
other low-consequence toy API.

#### Scenario: Catalog scopes

- GIVEN the published reference catalog
- WHEN a client lists gated tools
- THEN the tools include an equity order (`trading:equities:place`), a
  treasury wire (`treasury:wire`), and a portfolio rebalance
  (`portfolio:rebalance`)
- AND each tool is marked synthetic (no live rails)

#### Scenario: Treasury wire always needs a human

- GIVEN the default `treasury:wire` policy (`hitl_threshold` 0)
- WHEN authorization is requested without an approver
- THEN the result is HITL_REQUIRED and no authorization receipt is issued

### Requirement: Ambiguous policy is a deny

If the tool is unknown, the requested scope does not match the tool, or
the policy is incomplete, the system SHALL deny with `ambiguous_policy`.

#### Scenario: Unknown tool

- GIVEN a request_authorization for a tool not in the catalog
- WHEN it is evaluated
- THEN the deny `reason_code` is `ambiguous_policy`
