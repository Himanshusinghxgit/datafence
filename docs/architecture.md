# DataFence architecture

DataFence is an authorization and capability layer, not a database layer.

## Ownership

DataFence owns the authenticated-principal and typed-intent boundary, the
immutable resource registry, policy evaluation, lossless authorization
predicates, and signed `AuthorizedExecution` capabilities.

The customer application owns authentication, database/API credentials,
connector/backend implementation, translation to its data platform, execution,
and result handling.

## Canonical flow

```text
AI agent → Intent + authenticated Principal
                       ↓
              DataFenceBoundary.authorize()
                       ↓
                 AuthorizedExecution
                       ↓
       customer's existing connector/backend
                       ↓
                    enterprise data
```

DataFence never constructs or invokes that connector. A customer connector
must call `CapabilityVerifier.verify()` before interpreting the capability.

## Registry and policy

The registry describes resources, fields, data types, classifications, tenant
keys, and supported operations. Policy describes who may perform which
operations, fields, predicates, and limits. Both are required and must refer
to the same frozen registry.

The registry is descriptive; policy is authoritative. The agent cannot add
fields, change the principal, remove policy predicates, or submit raw SQL.

## Non-goals

DataFence is not a universal SQL firewall, ORM, database driver, query runner,
credential store, or domain-specific policy package. Reference connectors may
exist for examples and tests, but they are not part of the core ownership
model.
