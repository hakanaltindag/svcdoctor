# ADR 0007: Layer order places protocol before authentication

## Decision

The authoritative diagnostic layer order is:

```text
L0  Input / config normalization
L1  DNS
L2  TCP
L3  TLS
L4  Protocol / capability discovery
L5  Authentication / authorization
L6  Topology discovery
```

Protocol/capability discovery precedes authentication.

## Context

Earlier documentation placed authentication at L4 and protocol handshake at L5. That
ordering does not match the wire behaviour of either v0.1 service.

Kafka exchanges `ApiVersions` before SASL negotiation. PostgreSQL performs `SSLRequest` and
startup/protocol negotiation before the authentication request. Ordering authentication
first would misrepresent both.

## Consequences

- Short-circuiting follows the corrected order: a protocol-layer failure skips authentication.
- First-broken-layer reporting reflects the real order in which a connection breaks down.
- Capability discovery results are available as evidence before any authentication attempt,
  which allows authentication claims to be qualified by what the peer actually supports.
- `docs/SCOPE.md`, `docs/ARCHITECTURE.md`, `README.md`, and agent instructions use this order.
