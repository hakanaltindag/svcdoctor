# ADR 0003: Evidence is a DAG

## Decision

Topology discovery can create new endpoints, so diagnostic output is modeled as an evidence graph rather than a flat probe list. Graph states are `PASS`, `FAIL`, `DEGRADED`, `UNKNOWN`, and `SKIPPED`.

Short-circuiting is part of false-positive control.
