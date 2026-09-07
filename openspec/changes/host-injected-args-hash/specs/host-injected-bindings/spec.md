# Host-injected bindings

Hosts inject tenant, index, and similar identifiers so the model does
not choose them. Those values are part of the authorization binding.

## ADDED Requirements

### Requirement: Host ∪ model args are hashed together

WHEN a proposed call includes host-injected fields (`host_bound` and/or
`_meta.cubiczan.host_bound`), THE system SHALL compute `args_hash` as
the CHP float-aware `contentHash` of the merged host ∪ model arguments.

#### Scenario: Host index is covered by the receipt hash

- GIVEN a host-injected `index_name` and model-chosen `query`
- WHEN a receipt is issued
- THEN `args_hash` equals `contentHash` of the merged object
- AND hashing model args alone SHALL NOT match that receipt

### Requirement: Model cannot override host-bound fields

WHEN the model supplies a host-bound field whose canonical value differs
from the host-injected value, THE system SHALL deny with
`host_bound_override`.

#### Scenario: Model swaps the search index

- GIVEN host `_meta.cubiczan.host_bound.index_name` is `prod-docs`
- WHEN the model arguments include `index_name` of `other-index`
- THEN evaluate, issue-allow, and authorize SHALL deny
- AND `deny_code` SHALL be `host_bound_override`

### Requirement: Declared host-bound fields must be injected

WHEN `policy.host_bound_fields` lists fields for the tool, THE system
SHALL deny with `ambiguous` unless every listed field is present and
concrete after host extraction.

#### Scenario: Policy requires index_name but host omitted it

- GIVEN `host_bound_fields.search.azure_ai` includes `index_name`
- WHEN the call has no `host_bound` and no `_meta.cubiczan.host_bound.index_name`
- THEN the system SHALL deny with `ambiguous`

### Requirement: Allowlist remains a pre-filter

WHEN a tool is allowlisted and host-bound fields match, THE system SHALL
NOT treat that as authorization. Evaluate SHALL return
`RECEIPT_REQUIRED` / `allowlist_is_not_authorization` until a matching
receipt is consumed.

#### Scenario: Allowlisted search with correct host tenant

- GIVEN `search.azure_ai` is on `allowed_tools` and host `tenant_id` matches policy
- WHEN no receipt is presented
- THEN evaluate SHALL be `RECEIPT_REQUIRED`
- AND authorize SHALL deny with `allowlist_is_not_authorization`
