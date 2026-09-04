# ADR 0079 — The failure boundary is a derived diagnostic property

**Status:** Accepted
**Date:** 2026-09-02
**Phase:** 10.0
**Refines:** ADR 0003 and 0013 (the evidence DAG and its boundary), `docs/FINDINGS.md` §5
(first-broken-layer behaviour), which it generalizes rather than replaces.

---

## 1. Context

`docs/FINDINGS.md` §5 already forbids the worst failure-reporting mistake: a DNS failure
followed by three fabricated downstream failures. One evidenced failure plus explicit skips is
correct; four failures is noise.

What it does not yet give an operator is the *positive* statement, which is the one that
actually narrows an investigation:

```text
DNS              PASS
TCP bootstrap    PASS
TLS bootstrap    PASS
auth bootstrap   PASS
metadata         PASS
broker discovery PASS
TCP broker-3     FAIL
```

"broker-3 TCP failed" is a line item. **"Everything up to and including cluster discovery
worked, and the failure is specific to one discovered endpoint"** is a diagnosis. It rules out
DNS, the bootstrap path, TLS, credentials and metadata in one sentence, and it does so without
claiming a cause.

That statement is derivable from the frozen graph. The question this record answers is *who
derives it, and where it lives*.

## 2. Decision

### 2.1 The failure boundary is a derived diagnostic property, computed in the diagnosis layer

It is **not** a new domain field, **not** a graph API contract, and **not** something a renderer
works out for itself.

Four candidates were considered and three rejected:

| Candidate | Verdict |
|---|---|
| A field on `domain.Report` | Rejected. It is a conclusion, and the report assembles and validates rather than concludes (ADR 0015) |
| A `Graph` query the renderer calls | Rejected. A renderer that computes a boundary is reasoning, which ADR 0077 §2.7 forbids |
| A new domain type | Rejected. It would carry exactly what a finding carries |
| **A generic rule producing a finding** | **Selected** |

### 2.2 Definition

For a given **subject** — one endpoint, one target — the failure boundary is the pair:

- **last confirmed-good**: the deepest layer whose evidence for that subject is `PASS`, with
  no `FAIL` at a shallower layer for the same subject;
- **first evidenced failure**: the shallowest layer whose evidence for that subject is `FAIL`
  or `DEGRADED`.

Both are read from the graph. Neither is inferred.

Three properties make it honest:

1. **`SKIPPED` and `UNKNOWN` are neither.** A step that did not run is not a confirmed-good
   boundary and is not a failure. It is recorded as *not measured* and terminates the walk in
   the direction of "we stopped knowing here".
2. **The boundary is per subject.** A run with a healthy bootstrap and one unreachable
   discovered broker has two boundaries, not one, and merging them would produce the false
   summary "Kafka is unreachable".
3. **A boundary is not a cause.** It states where observation stopped succeeding. What that
   implies is a hypothesis, and hypotheses are ADR 0081's.

### 2.3 It is expressed as one generic finding

A single new **generic** finding code, produced by a service-agnostic rule:

```text
DIAG_FAILURE_BOUNDARY
```

- `kind`: `CONFIRMED` — it restates measured states and infers nothing.
- `severity`: `INFO`. The boundary describes *where*, not *how bad*; the impact belongs to the
  finding that reports the failure itself. Severity is never a proxy for anything else
  (`docs/FINDINGS.md` §3.1 rule 5).
- `layer`: the layer of the first evidenced failure.
- `subject`: the subject the boundary is about — always set.
- `evidenceRefs`: the last confirmed-good node and the first failing node. Both halves of a
  contrast are part of the proof (§3.1 rule 10); neither alone establishes a boundary.
- `vantageDependent`: true whenever the failing layer is DNS, TCP or TLS, because reachability
  claims are vantage claims (ADR 0012).

The finding-code count therefore moves **60 → 61** in Phase 10.1. It is a `DIAG_` code rather
than a service code because it is produced by generic machinery over any service's graph — the
first member of a generic namespace, alongside the existing `DNS_`, `TCP_` and `TLS_` ones.

### 2.4 "What this rules out" is presentation, not a second finding

Given a boundary at auth, "DNS, TCP and TLS are ruled out" is *already in the report*: those
nodes are `PASS`. A renderer stating it is printing states it was given, which is presentation.
A rule emitting a `DNS_NOT_THE_PROBLEM` finding for every layer above every boundary is the
negative-hypothesis explosion that makes diagnostic tools unreadable.

**Decision: ruled-out explanations are rendered from the boundary and the graph, and no
"ruled out" finding, field or hypothesis is created.** The renderer may say "DNS, TCP and TLS
succeeded" because it can read that; it may not say "therefore the cause is X", because that is
reasoning.

### 2.5 Boundary shapes the design must express

These are the shapes the Phase 10.1 rule must handle; they are requirements, not an exhaustive
taxonomy.

| Shape | Meaning | Example |
|---|---|---|
| linear boundary | one subject, failure at layer *n*, everything above `PASS` | PG-A: TCP/TLS pass, auth fails |
| blocked downstream | failure at *n*, everything below `SKIPPED`/`UNKNOWN` | DNS fails, TCP never attempted |
| branch-specific | the parent subject is wholly good; one child subject fails | KAFKA-A: one discovered broker |
| divergent siblings | several child subjects, mixed outcomes | KAFKA-C: one broker of three |
| uniform siblings | every child subject fails the same way | every discovered broker unreachable |
| unmeasured tail | budget expired before some subjects were attempted | "not measured", never "not reached" |

The last is the RAB18 lesson in structural form: **less evidence must never produce a stronger
statement.** A subject that was never attempted has no boundary, and the absence is reported as
absence.

### 2.6 Sibling comparison is generic, and stays generic

"One of three brokers is unreachable" versus "all three are" is a materially different
diagnosis, and Phase 10.1 must express the difference **without the generic engine knowing what
a broker is**.

The generic notion is: *sibling subjects sharing a parent subject and a step*. The graph already
carries that — discovered endpoints are children of the discovery node. A generic helper answers
"of the subjects reached from this parent by this step, how many pass, fail, and were not
measured", and a service rule decides what that means for its protocol. Kafka semantics stay in
`internal/diagnosis/kafka`; the counting does not.

## 3. Consequences

**An operator gets the sentence that narrows the search**, and it is a finding — so it is in
JSON, in the terminal, in the shareable projection, and traceable to two evidence nodes.

**The renderer gets something to print instead of something to compute.** This is the difference
between the boundary being a contract and being a coincidence of two implementations agreeing.

**One generic finding code is added in 10.1**, and `docs/FINDINGS.md` §5 grows a section rather
than changing: first-broken-layer behaviour is what the boundary reports.

**Per-subject boundaries mean a report can carry several.** That is correct and is the whole
point of the branch-specific shape; a renderer showing only the deepest or the first would
recreate the false summary this record exists to prevent.

## 4. Alternatives considered

**A `failureBoundary` object on the report.** Rejected: ADR 0015 (the report derives its summary
and does not conclude), and it would need per-subject cardinality anyway — at which point it is
a list of findings with extra steps.

**A `Graph.FailureBoundary()` API.** Rejected as the *primary* mechanism, because whoever calls
it decides what it means, and the obvious caller is the renderer. A helper of this shape may
exist inside the diagnosis layer; it must not be exported to renderers.

**Compute it in the renderer.** Rejected. Two renderers would then hold two implementations of
the same reasoning, and a shareable report would be reasoned about after redaction.

**One boundary per run.** Rejected. It is wrong the moment topology discovery succeeds and a
discovered endpoint fails, which is the flagship Kafka scenario.

## 5. Security implications

None beyond the existing finding contract. The boundary cites two evidence identifiers and sets
a subject, all of which redaction already transforms (ADR 0018). It introduces no new prose
derived from peer-controlled text.

## 6. Compatibility implications

Additive. One new finding code in 10.1; `SchemaVersion` unchanged. A consumer that does not know
`DIAG_FAILURE_BOUNDARY` sees one more `INFO` finding, which `docs/CI.md`'s exit contract already
tolerates: `INFO` findings never affect an exit code.

## 7. Validation requirements

- Unit: each of the six shapes in §2.5, from a synthetic graph, asserting both evidence
  references and the absence of a boundary where nothing was measured.
- Property: a `SKIPPED` or `UNKNOWN` node is never cited as either half of a boundary.
- Property: adding a subject that was never attempted does not change any existing boundary.
- Mutation: treating `SKIPPED` as confirmed-good; treating `UNKNOWN` as failing; merging
  per-subject boundaries into one; citing only the failing half.
- Renderer guard: the terminal and JSON renderers must not compute a boundary — the string
  "ruled out" and any layer arithmetic must not appear in renderer code paths that lack a
  `DIAG_FAILURE_BOUNDARY` finding to read.
