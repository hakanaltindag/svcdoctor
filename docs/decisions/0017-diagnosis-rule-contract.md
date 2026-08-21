# ADR 0017: The diagnosis rule contract

## Status

Accepted.

## Decision

The rule contract lives in `internal/diagnosis`, the package that owns rule
evaluation. No separate contracts, common or shared package is created for it.

A rule is a function, not an interface:

```go
type Rule func(g domain.Graph) []domain.Finding
```

The frozen graph is the only argument, and there is no error result.

`Engine` holds a fixed set of rules, evaluates them, and returns their findings in
the canonical order defined by `domain.SortFindings`. It does nothing else: no
filtering, no ranking, no merging, no suppression, no service dispatch.

## A function, not an interface

A rule is a pure function from evidence to findings, and nothing about it needs to
be more than that. A rule that needs configuration is a closure over it:

```go
func certExpiringSoon(within time.Duration) Rule {
    return func(g domain.Graph) []domain.Finding { ... }
}
```

An interface would add a method set for a single method and invite it to grow.
This is the project's first place where an abstraction was genuinely warranted by
multiple implementations, and a function type is the narrowest form that provides
it. The repository has added no interfaces so far, deliberately.

Reconsider if rules ever need identity or metadata of their own — a stable rule
identifier, a description, or a declared set of codes for cataloguing. At that
point a named interface earns the ceremony. Nothing needs it now.

## Why the graph is the only argument

Each alternative argument was considered and rejected on its own grounds:

- **`RunMetadata` and `Vantage`** describe the run, not the evidence. A rule that
  marks a finding vantage-dependent is stating that its own kind of claim depends
  on network position; it does not need to see the vantage to know that.
- **`ServiceID`** would hand the engine a service name to branch on, which is the
  coupling `docs/ARCHITECTURE.md` section 8 exists to prevent. A service rule is a
  rule that is only wired in for that service.
- **`Report`** would be circular: a report contains the findings a rule produces.
- **A context value** has nothing to cancel. Evaluation is in-memory and bounded by
  the size of the graph.

Adding an argument later is a contract change, so the contract starts at what the
first real rules actually need.

## No error result

A rule reads a frozen in-memory graph. It has no connection to lose, no file to
miss and no deadline to exceed, so an error result would exist only to be always
nil.

The one thing that can go wrong is a rule building a `Finding` that
`domain.NewFinding` rejects, and that is a defect in the rule rather than a
diagnostic outcome. A rule must not respond by quietly returning fewer findings:
silently omitting a conclusion is the failure mode the project's claim discipline
exists to prevent. Rules are responsible for constructing valid findings, and
their own tests are where that is established.

## Ordering

`domain.SortFindings` was exported so that the engine and the report share one
implementation of canonical order. Two implementations of the same order could
disagree, and the report's JSON contract depends on it.

Rules are evaluated in wiring order, but that order does not reach the output.
Reordering the rule set produces the same findings in the same sequence, so how an
engine was assembled cannot change what a report looks like.

## Duplicates are preserved

The engine does not deduplicate findings.

Discarding one of two similar findings requires deciding when two findings are the
same conclusion, and no document defines that. Two rules may legitimately reach the
same code for different reasons, with different details or different evidence, and
dropping one would remove a real finding. A duplicate is a statement about the rule
set, which is better surfaced than hidden.

Reconsider when a real rule set produces duplicates in practice; at that point
finding identity can be defined from evidence rather than guessed at.

## Concrete rules are deferred

This phase implements the contract and the engine and ships no rules.

`docs/FINDINGS.md` names `DNS_RESOLUTION_FAILED`, `TCP_CONNECTION_REFUSED` and
`TLS_CERTIFICATE_EXPIRED`, but only as examples of the naming convention. It
defines no severity, confidence or kind for them.

Kind and confidence could be derived. Evidence in state `FAIL` is a positively
evidenced failure, which is what `CONFIRMED` means, and an exact `FailureClass` on
that node is the direct matching evidence `HIGH` confidence describes.

Severity cannot. Severity is impact, and whether a failed lookup or a refused
connection prevents correct use depends on whether the endpoint was the one the
user asked about or one discovered from it. That distinction is `Origin`, which
ADR 0013 defers until topology orchestration exists. Choosing a severity today
would either hardcode one answer for both cases or invent a policy no document
states.

A second gap points the same way. `docs/FINDINGS.md` section 5 forbids
manufacturing downstream failure findings, but nothing yet says how a generic
transport rule and a service rule avoid both reporting the same failed endpoint —
`KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` and a generic `TCP_CONNECTION_REFUSED`
would otherwise describe one fact twice.

Both are recorded in `docs/BACKLOG.md`. Writing rules before answering them would
put invented diagnostic policy into the layer whose entire purpose is not to
invent.

## Consequences

- Diagnosis is a pure function of a frozen graph, testable without a network.
- The engine cannot branch on a service because it holds no service name.
- The rule set is chosen by explicit wiring, the same mechanism ADR 0009 chose for
  services.
- Findings reach the report in the order the report already uses.
- Adding the first concrete rules requires a severity policy first, not more
  machinery.
