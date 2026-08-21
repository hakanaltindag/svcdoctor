# ADR 0006: Project license is Apache-2.0

## Status

Accepted.

Supersedes the earlier open state, in which Apache-2.0 and MIT were both candidates.

## Decision

svcdoctor is licensed under the Apache License 2.0.

## Rationale

- Suitable for an infrastructure/DevOps open-source tool.
- Provides an explicit patent grant, which MIT does not.
- Widely accepted in enterprise and cloud-native ecosystems.
- Permissive redistribution and modification.
- Compatible with the intended binary distribution model.

## Consequences

- The physical `LICENSE` file is added during repository bootstrap, not by this decision.
- Release artefacts, SBOM, and provenance metadata reference Apache-2.0.
- Third-party dependency licenses are reviewed for Apache-2.0 compatibility before adoption,
  including the Kafka wire library selected under ADR 0008.
