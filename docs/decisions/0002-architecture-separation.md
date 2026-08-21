# ADR 0002: Architecture separation

## Decision

> Probes collect facts. Adapters understand protocols. Diagnosis correlates evidence. Renderers explain results.

Service-specific branching must not spread into the generic core. Service extensibility is provided through registration/factory boundaries and service-specific packages.
