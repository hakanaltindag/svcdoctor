# ADR 0001: Modular monolith

## Decision

svcdoctor v0.x is developed as a single-process, modular-monolith Go application targeting `CGO_ENABLED=0`.

## Consequences

- Minimal deployment surface.
- Package boundaries are architectural boundaries.
- No internal microservices or backend are introduced without a validated need.
- Rust is considered only if a future isolated low-level requirement justifies it.
