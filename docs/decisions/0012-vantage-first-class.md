# ADR 0012: Vantage is a first-class concept

## Status

Accepted.

## Decision

A **vantage** identifies where probes were executed from. It is a first-class domain and
report concept, not run metadata.

For v0.1 local execution, a vantage must at minimum distinguish the local host.

Future extensions may include:

- Kubernetes pod / namespace / cluster
- remote execution context

Those are not implemented now, and Kubernetes vantage detail is deliberately under-specified.

Final Go fields are not defined by this decision.

## Rationale

svcdoctor's core value is client-vantage diagnosis. Its flagship finding,
`KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`, is not a claim about a cluster; it is a claim about
the relationship between a cluster and one network position.

If the vantage is not recorded and carried, that distinction disappears the moment a report
is shared. A reader sees "broker-2 is unreachable" and concludes the cluster is broken, when
the actual finding was that this client cannot reach it. That misreading is worse than no
report, because it redirects an investigation.

Treating vantage as ordinary metadata makes it easy to drop during rendering or aggregation.
Treating it as first-class makes the connection between finding and location structural.

## Consequences

- Every topology and connectivity finding retains its vantage context and is marked
  `vantageDependent` where applicable.
- Renderers surface the vantage prominently rather than burying it in run metadata.
- The report model carries a dedicated `vantage` section (see `docs/REPORT_SCHEMA.md`).
- Vantage collection belongs to the platform/orchestration boundary, not to diagnosis
  (see `docs/ARCHITECTURE.md` section 15).
