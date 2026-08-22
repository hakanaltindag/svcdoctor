# ADR 0042: A run records the target it was asked about, and a sweep declares its cause

## Status

**Accepted, and implemented in Phase 4.9a-pre.**

`internal/vocabulary` holds the four canonical step names; `internal/app` mints
the anchor in one authorized function and declares the sweep's cause through
`transport.Params.Parent`. Measured against real servers: one anchor, subject
`127.0.0.1:55432`, the requested `dns.lookup` parented directly to it, and every
Phase 4.8b invariant intact — broad discovery, one authentication, every
continuation closed.

The dependency set stays one, `security.Reveal` **two**, `FailureClass` 39,
`FindingCode` **14** and `schemaVersion` **1**. No CLI, no renderer, no Kafka
composition, and `internal/diagnosis/transport` still holds no production rule.

This record decides the one missing structural fact that Phase 4.9a stopped on. It
authorizes an L0 requested-target anchor node, a narrow evidence-authority
exception for `internal/app`, and a direct-parent ownership rule for transport
sweeps.

**It authorizes no finding.** Generic DNS/TCP/TLS finding semantics — codes,
severity, confidence, vantage, partial-success and incomplete-measurement policy
— remain undecided and return to Phase 4.9a. The CLI release gate stays open.

It narrows ADR 0041's evidence-authority boundary, closes half of ADR 0017's
deferral, and tightens `transport.Params.Parent` at one position. It rewrites
nothing.

### Implementation note (Phase 4.9a-pre)

Three things the record did not anticipate, none of which changes it.

**The vocabulary leaf needed a name, and none of the existing conventions fit.**
§11 required a service-neutral leaf and left the name open. `internal/transport`
would have collided with `internal/probe/transport`, and `internal/service/…`
would have implied a service. It is `internal/vocabulary`: a leaf importing
`internal/domain` only, holding four step names and no behaviour, guarded by a
module-wide scan proving each string appears in exactly one production file.

**`internal/app` needed one more import than expected.** Minting an identifier
means escaping it, and ADR 0019 put that encoding in `internal/probe` precisely so
two producers cannot disagree. The run borrows the rule rather than copying it, so
`internal/probe` joined the composition root's allow-list — the encoding only, no
probe.

**The `internal/diagnosis/transport` phase guard had to be split.** It was written
to scan the module for smuggled transport finding codes, and depguard denied the
package `os`. That denial is correct — diagnosis reads a frozen graph — so the
local "no production file here" half stayed, using `go/build`, and the
module-wide half moved to `internal/vocabulary`. The mutation that motivated it
is still caught, verified after the move rather than assumed.

## Problem

Phase 4.9a set out to decide who owns DNS/TCP/TLS diagnosis for the endpoint an
operator asked about, and stopped. Two gaps, both verified from the tree at
`e20c904`:

**A. Ownership.** Diagnosis cannot prove that a transport sweep belongs to the
operator-requested target rather than to a service-discovered one. The only
structural candidates were rootness — forbidden provenance inference
(`REPORT_SCHEMA.md`, ADR 0034 §2), and not type-enforced because
`transport.Params.Parent` is optional — and `SweepScope`, which reaches the
identifier and nothing else (ADR 0032 §5) and would require parsing an
`EvidenceID`.

**B. Subject.** The requested logical `host:port` is the subject of no node.
`dns.lookup` carries the hostname alone; `tcp.connect` and `tls.handshake` carry
the resolved `ip:port`, with `internal/probe/tcp/connect.go` stating outright that
"the endpoint … is not part of the subject: the dial never used a name." The pair
exists in the graph only inside identifiers.

Gap B is the one that makes the flagship failure unfixable. On an NXDOMAIN run the
graph holds exactly one node — a FAIL `dns.lookup` — and there is no TCP child to
recover a port from and no `postgres.*` node to anchor at. `findings: []` is the
composition working as specified.

Both gaps have one cause: **nothing in the graph records why the run happened.**

## Decision

### 1. One node, at L0

A run records one evidence node describing the target it was asked about.

```text
step         a service-neutral requested-target step name
layer        LayerInput (L0)
subject      SubjectKindTarget, ref = the logical endpoint, e.g. db.example.com:5432
state        StatePass
failureClass FailureNone
attributes   none
```

`LayerInput` is L0 — *"input and configuration normalization"* (ADR 0007) — and it
has had no producer since it was declared. `SubjectKindTarget` has had none
either. Neither is being invented; both were reserved and are now being used for
the thing they were reserved for.

The node means exactly one thing:

> **L0 input normalization of the operator's requested target completed, and this
> is the target.**

It does not mean DNS succeeded, TCP succeeded, the endpoint exists, a peer was
reached, the service is healthy, the target is trusted, or that any credential is
authorized anywhere. It is an input fact, and it is the *first* fact of a run
rather than a verdict about one.

#### Why PASS, and why PASS is not a health claim

`StatePass` is *"the step succeeded from this vantage"*, and the temptation is to
say input is not a step. It is: L0 is a layer precisely because normalizing input
is work that can succeed. `params.validate()` in `internal/app/postgres.go` is that
work, and by the time any evidence exists it has succeeded.

The alternatives were considered and are worse. `UNKNOWN` is *"the result could
not be determined"*, which is false and reads as a failed measurement. `SKIPPED` is
*"intentionally not executed"*, which is false. `DEGRADED` claims a defect nobody
observed. **No new `State` is added**, and none is needed.

**The L0 node can never be FAIL, by construction.** Unusable input returns
`ErrInvalidInput` and produces no report at all (ADR 0041; `internal/app/postgres.go`
returns before a builder is touched). So the node cannot perturb
`summary.firstBrokenLayer`, which is the lowest layer holding a FAIL node — the L0
node is never one. A run whose DNS fails still reports `firstBrokenLayer: L1`,
unchanged.

If input validation ever becomes evidence rather than an error, that is a separate
decision and this record does not pre-empt it.

### 2. `internal/app` mints it, and that is the narrowest correct authority

| Model | Verdict |
|---|---|
| **A. `internal/app` mints it** | **Chosen.** Application orchestration is the only layer that receives the operator's logical target. It already holds it as `PostgresParams.Host/Port` and already renders it for `Report.Target` |
| B. `transport.Run` mints it | **Rejected.** Transport would have to be *told* the sweep is user-requested, which is the same declaration in a worse place: a probe that can mint a run-intent node is a probe that knows about runs. It also mints the node for every sweep or needs a flag saying which sweeps are real, and a flag is model A with the authority in the wrong package |
| C. The CLI mints it | **Rejected.** No CLI exists, and when one does its job is parsing and exit codes. A CLI that constructs evidence would make the run boundary bypassable — a caller of `DiagnosePostgres` that is not the CLI would produce a graph with no anchor |
| D. Report construction mints it | **Rejected.** The report is assembled from a frozen graph (ADR 0016). A node that appears at report time is not in the graph diagnosis ran on, which is the entire point |

Model A follows from the architecture rule directly: **probes collect
measurements, not intent.** The operator's request is not an observation of the
network; it is the reason observations were made.

### 3. The evidence-authority exception, stated as narrowly as it can be

Phase 4.8b pinned that `internal/app` creates no evidence
(`TestTheRunCreatesNoSelectionEvidence`). That guard is **not deleted**. It is
narrowed to exactly one hole:

> **`internal/app` may construct exactly one kind of evidence: the L0
> requested-target anchor for a run it owns. It may construct no other node, no
> finding, no `blockedBy` edge and no attribute.**

The mechanical form: the existing AST guard keeps its ban on `NewFinding`,
`AddBlockedBy` and every attribute constructor across all production files, and
permits `NewEvidence`/`AddEvidence` **only inside one named function in one named
file**. Every other production file in the package remains under the original
ban. A second call site anywhere — including a second one in the permitted file's
package — fails the build.

The anchor's descendants are **not** attached by `internal/app`. The run passes
the anchor's `EvidenceID` as `transport.Params.Parent` and the chain records the
edge, exactly as `internal/adapter/kafka` already does for an advertisement. The
run therefore gains no `AddParent` authority either: it declares a cause and the
producer records it.

### 4. Cardinality: exactly one, and the rule must not assume it

v0.1 commands take one logical endpoint, so **one run contains exactly one
anchor** — not one per resolved address, not one per path, not one per retry, and
not a second one on cancellation. The node is minted once, before the sweep.

**A rule must still iterate anchors rather than expect one.** Writing
`theAnchor(g)` would make multi-target support a rule rewrite; writing
`for each anchor` makes it a composition change. The cost is one loop.

**Reopen when** a command accepts several independent logical targets in one run.
Cardinality then becomes one anchor per explicitly requested target and generic
diagnosis operates per anchor independently. No API is generalized for that now.

### 5. Subject: the existing endpoint formatting, and no second parser

The subject ref is the logical endpoint as the run already renders it —
`net.JoinHostPort(host, port)`, which is the function `internal/app` uses today to
build `Report.Target`. IPv6 bracketing therefore comes for free and matches what
redaction's `endpointParts` already expects.

- **No scheme.** svcdoctor does not speak URLs and a scheme would be a second
  encoding of the service.
- **No service name.** The service is in `run.service` (`domain.RunMetadata`). Putting
  it in the subject would make the anchor non-generic, which is mutation S.
- **No alias resolution, no case folding, no canonicalization beyond what the
  endpoint formatter already does.** The anchor records what was asked for. A
  hostname the operator spelled one way and DNS answered another is a fact worth
  preserving, not normalizing away, and `Target.Normalized()` already exists for
  the other half.

### 6. No attributes

The subject carries the endpoint. Nothing else is added:
`target.host`, `target.port`, `target.service`, `requested=true` and `origin=user`
are all refused. Each is either a second copy of a fact the node already states or
a fact another part of the report already owns — ADR 0013's anti-duplication rule
in its plainest form. `requested=true` is the worst of them: it is a boolean that
is true on every instance of a node type that exists only when it is true.

A consumer that cannot obtain a fact structurally is the reopen condition, and
none exists.

### 7. Direct parentage, not descendant reachability — and this is load-bearing

This is the adversarial check the model had to survive, and the naive reading
fails it.

The Kafka parent chain, read from source (`apiversions.go` parents to the
transport node, `metadata.go` parents the exchange to the authentication node and
each advertisement to the exchange, `reachability.go:248` parents the advertised
sweep to the advertisement), is:

```text
target.requested                         L0   <- this record
 └── dns.lookup                          L1
      └── tcp.connect                    L2
           └── tls.handshake             L3
                └── kafka.api_versions   L4
                     └── kafka.authentication      L5
                          └── kafka.metadata       L6
                               └── kafka.broker_advertised   L6
                                    └── dns.lookup  [scoped]  L1
                                         └── tcp.connect      L2
                                              └── tls.handshake L3
```

> **The advertised sweep is a transitive descendant of the requested-target
> anchor.**

So "generic diagnosis owns everything below the anchor" would walk straight into
`KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`'s evidence and reintroduce the exact
duplication ADR 0034 §3 resolved. The model is only safe with a bound:

> **Generic requested-target transport diagnosis owns exactly the transport sweep
> whose root `dns.lookup` node is a *direct* child of a requested-target anchor,
> and within that sweep only the chain-shaped nodes beneath it.**

The traversal is bounded in depth and typed by step:

```text
anchor
  -> direct children with step dns.lookup      (a requested sweep root)
       -> direct children with step tcp.connect
            -> direct children with step tls.handshake
  stop
```

Nothing deeper is generic. This is not a heuristic: it is the exact shape
`transport.Run` emits and nothing else emits, and ADR 0034 §4 already pinned its
one non-obvious property — a TCP node has a TLS child if and only if the sweep's
plan required TLS — with a test in both directions
(`internal/probe/transport/terminallayer_test.go`).

**Layer-bounding was tried and does not work.** `postgres.ssl_request` is L3
(ADR 0040), so an L0→L1→L2→L3 walk by layer would swallow it. Step-typing is
required, which has a consequence recorded in §11.

#### The two cases this decides, verified rather than argued

**Kafka advertised stays disjoint.** The advertised `dns.lookup`'s direct parent
is `kafka.broker_advertised`. It is not a direct child of the anchor, so it is
outside the generic sweep at depth 1. The Kafka rule keeps it whole, and no
suppression is involved.

Better than that: `internal/adapter/kafka` **cannot** mis-parent it. Its
reachability API takes advertisements and derives the parent from the
advertisement node it is iterating; it is never handed the anchor's identifier and
has no way to obtain one. The disjointness is structural, not conventional.

**PostgreSQL's in-band TLS stays service-owned.** `internal/adapter/postgres`
parents the `tls.handshake` node to `postgres.ssl_request`, not to `tcp.connect`,
deliberately — *"parenting it to TCP would lose the fact that PostgreSQL asked for
the upgrade."* So the `tcp.connect` node's only child is `postgres.ssl_request`,
whose step is not `tls.handshake`, and the bounded walk stops at L2. The same step
name under two ownership contexts — the case that made a blanket
"all `tls.handshake` nodes" rule wrong — is resolved by the parent edge the
adapter already records for its own reasons.

### 8. Graph shapes

PostgreSQL, dual-stack, TLS in band:

```text
target.requested  L0 PASS   subject=db.example.com:5432
 └── dns.lookup   L1 PASS   subject=db.example.com
      ├── tcp.connect L2 PASS  subject=10.0.0.1:5432
      │    └── postgres.ssl_request L3 PASS
      │         └── tls.handshake   L3 PASS
      │              └── postgres.startup L4 ...
      └── tcp.connect L2 PASS  subject=[2001:db8::1]:5432
           └── postgres.ssl_request L3 ...
```

Generic ownership: the anchor, the lookup, and both TCP nodes. Nothing below.

NXDOMAIN — the case Phase 4.9a could not fix:

```text
target.requested  L0 PASS   subject=db.example.com:5432
 └── dns.lookup   L1 FAIL   DNS_NXDOMAIN   subject=db.example.com
```

A future rule now has both missing things: ownership, because the lookup is a
direct child of an anchor; and a subject, because the anchor carries
`db.example.com:5432`. Gap A and gap B are closed by one node.

This matches what `transport.Params.Parent` can already express. No new edge kind,
no new API and no reshaping of any existing chain.

### 9. `transport.Params.Parent` gains a contract at the sweep root

`Parent` is documented today as optional derivation that *"does not mean the
subject was discovered, user-supplied, or trusted."* That sentence stays true of
parent edges in general. This record adds an obligation at one position only:

> **A transport sweep declares its cause. A sweep the operator asked for is
> parented to the run's requested-target anchor; a sweep a service caused is
> parented to the service evidence that caused it. A production sweep with no
> parent is a producer defect.**

This is a strengthening of a caller obligation, not a change to what an edge
means. `Parent` still records derivation; what changes is that a sweep root may no
longer decline to say what derived it.

ADR 0032's optional framing was correct when written — every sweep was a root and
there was nothing to declare. That is no longer true and the record is amended
narrowly rather than rewritten (§13).

### 10. This is not `Origin`, and the difference is mechanical

The proposal has to survive the obvious accusation: that "look at the parent to
learn where the endpoint came from" is the rejected `Origin` inference wearing a
node.

**`Origin` asks a question about a subject:** how did *this endpoint* enter the
run? `ARCHITECTURE.md` §5.3 kills it with a case that is routine rather than
exotic — a cluster advertising its bootstrap endpoint back. One `host:port` then
has a discovery-derived node *and* a lookup-derived transport path, both true and
neither ranked, so origin is not a function of the subject and cannot be read off
graph shape.

**The anchor asks a question about an execution:** which sweep did this run
perform because the operator named a target? Run that same counterexample through
it. The bootstrap endpoint advertised back produces two sweeps: one directly
parented to the anchor, one directly parented to `kafka.broker_advertised`, kept
distinct by the `SweepScope` ADR 0032 built for exactly this. The generic rule
owns the first and not the second, and both statements are true simultaneously.
The case that destroys `Origin` leaves the anchor untouched, because the anchor
never claims anything about the endpoint — only about the execution.

Two further mechanical differences:

- **Direction.** The rule enumerates anchors and walks *down*. It never starts at
  a transport node and walks up asking what it is about. That is the asymmetry
  `ARCHITECTURE.md` §5.5 already established for the Kafka rule, and the reason
  the prohibition is unreachable rather than merely obeyed.
- **Recorded, not inferred.** `Origin` would be a per-node field asserting
  provenance for every node retrospectively — a second record of how subjects
  entered the run, competing with graph structure, which is `REPORT_SCHEMA.md`'s
  stated objection. The anchor is one node recorded once, by the only layer that
  holds the fact, at the moment it holds it.

**`Origin` remains deferred, unchanged.** Nothing here lets any layer ask how an
arbitrary subject entered a run, and `REPORT_SCHEMA.md`'s prohibition is not
weakened.

### 11. A generic step vocabulary is required, and it is a real cost

§7's traversal names `dns.lookup`, `tcp.connect` and `tls.handshake`, and depguard
denies `internal/diagnosis/**` the `internal/probe` import. `internal/domain`
deliberately holds no step constants — `names.go` explains that a closed set would
have to enumerate every operation of every service in the core.

So the anchor phase must also create a **generic, service-neutral vocabulary
leaf**: the anchor's own step name, plus the three transport step names a rule
walks. It is the exact counterpart of `internal/service/kafka` and
`internal/service/postgres` — a leaf importing only `internal/domain`, holding no
behaviour — created on the same terms ADR 0040 §22 used, for the same reason.

This is not a new dependency and not a schema change, but it is a new package and
should not arrive as a surprise during implementation. It also closes the generic
half of `BACKLOG.md`'s long-open *"where generic transport vocabulary lives"* item,
whose reopen condition was "the first transport rule needs a key". A rule now
needs step names, which is the same question one noun over.

The package name is left to implementation. It must not be named for a service.

### 12. `Report.Target` is not duplicated, because neither copy is the authority

The hardest question this record answers. `Report.Target.Requested()` is built from
`PostgresParams.Host/Port`; the anchor's subject would be built from the same pair
by the same formatter. Both serialize. Is that two records of one fact?

| Option | Verdict |
|---|---|
| **1. One typed value in the run projects into both; a test pins equality** | **Chosen** |
| 2. `Report.Target` derives from the anchor node | **Rejected.** `domain.NewReport` would have to find a node by step name, putting service-shaped vocabulary into the package that refuses to hold any (`names.go`). It would also make the report unbuildable from a graph with no anchor, which is every graph a test constructs by hand |
| 3. The anchor derives from `domain.Target` | **Rejected.** Backwards: the graph is frozen before the report is assembled (ADR 0016), so the anchor would depend on something that does not exist yet |
| 4. A shared typed value feeds both | This is option 1, stated as its implementation |

> **The single authority for the requested logical target is the run's own typed
> input.** `Report.Target` and the anchor's subject are two projections of it into
> two canonical contracts — report metadata and graph evidence — not two
> authorities that could each be right.

This does not violate ADR 0013. What ADR 0013 forbids is a second *record* of a
relationship the graph already holds, arbitrating between two sources of truth.
Here there is one source and two renderings of it, and the arbitration question
never arises.

**They can drift only through a coding error, and one test closes it:**
`report.Target().Requested()` must equal the anchor node's `Subject().Ref()` in
every run the composition produces. That test is guard 11 in §15.

**Should `Report.Target` derive from the anchor later?** Recommended no —
permanently, for the reason in option 2. Recorded as a reopen condition rather
than a plan.

### 13. No schema change

`schemaVersion` stays **1**.

The anchor is graph content. `domain.Report` already serializes every evidence
node with its subject, layer, step, state and parents, and `LayerInput` and
`SubjectKindTarget` already marshal — both have `String()` and `MarshalJSON` and
both are in their names tables. A report gains one node and one edge. The *shape*
of the document is unchanged.

Nothing is added to the report envelope: no `report.runIntent`, no
`report.requestedTargetEvidence`, no `report.origin`. Every one of them would be
the second authority §12 refuses.

Existing tests that assert exact graph contents for a run will need updating. That
is implementation work, not a contract change.

### 14. Redaction already handles it, and produces the same pseudonym

Verified from `internal/security/redaction`, not assumed:

- `collect` feeds `report.Target().Requested()` and every node's `Subject().Ref()`
  into the **same** `classify` call and the same host/IP pools.
- `redactTarget` and `redactSubject` both rewrite through the **same**
  `table.endpointRef`, which splits a trailing port, pseudonymizes the host and
  keeps the port.
- `redactSubject` already switches on `SubjectKindTarget` explicitly and rebuilds
  it with `NewTargetSubject`.

So the invariant the anchor needs already holds:

```text
LOCAL_FULL          report.target.requested = db.prod.internal:5432
                    anchor subject          = db.prod.internal:5432

SHAREABLE_REDACTED  report.target.requested = host-001:5432
                    anchor subject          = host-001:5432
```

And the numbering cannot shift: `collect` is deliberately separated from
assignment *"so that pseudonym numbering depends on the set of values, not on the
order they were found"*, and the anchor contributes a value the set already
contains.

**No new redaction rule, no new `AttrKind`, no heuristic.** The residual scan
already runs over the whole output. A future canary test must prove this
non-vacuously — that both raw copies existed in the local report and neither
survives the shareable one — because a test that would pass on an empty graph
proves nothing.

### 15. Acceptance matrix for the implementing phase

Defined before code, per the project's habit.

| # | Must hold |
|---|---|
| 1 | `internal/app` creates exactly one kind of evidence: the anchor, in one named function |
| 2 | `internal/app` creates no other evidence step |
| 3 | `internal/app` creates no finding, no `blockedBy`, no attribute |
| 4 | The anchor is `LayerInput` |
| 5 | The anchor's subject is `SubjectKindTarget` |
| 6 | The anchor's subject ref equals the run's logical requested endpoint |
| 7 | The anchor carries no attributes and no service name |
| 8 | The requested sweep's `dns.lookup` node is a **direct** child of the anchor |
| 9 | No discovered sweep's `dns.lookup` node is a direct child of any anchor |
| 10 | A prototype rule identifies the requested sweep without parsing an `EvidenceID` |
| 11 | `Report.Target.Requested()` equals the anchor's subject ref |
| 12 | Redaction yields the same pseudonym in both representations, proven non-vacuously |
| 13 | A run with zero continuations still contains the anchor plus its transport failure evidence |
| 14 | A multi-path run contains one anchor, not one per address |
| 15 | Anchor identity is deterministic: no clock, no random source, no address-family or input-order dependence |
| 16 | A cancelled or partial run contains the same single anchor |
| 17 | The anchor step mints a fixed component arity (ADR 0032 §3's injectivity caveat) |
| 18 | `schemaVersion` is still 1; `FailureClass`, `FindingCode` and `Reveal` counts unchanged |

### 16. Mutation matrix

Each must be caught by a guard, not by review.

| | Mutation | Caught by |
|---|---|---|
| A | The run omits the anchor | 8, 13 |
| B | One anchor per resolved address | 14 |
| C | Anchor uses `SubjectKindEndpoint` | 5 |
| D | Anchor is L1 | 4 |
| E | Requested sweep has no parent | 8 |
| F | Requested sweep is parented to a service node | 8 |
| G | Advertised sweep is parented to the anchor | 9 |
| H | Anchor carries `target.host` / `target.port` attributes | 7 |
| I | The run creates another evidence step | 2 |
| J | The run creates a finding | 3 |
| K | A rule parses an `EvidenceID` | 10, plus the existing AST guard |
| L | `Report.Target` differs from the anchor subject | 11 |
| M | Redaction yields different pseudonyms | 12 |
| N | The anchor leaks a hostname into a shareable report | 12, residual scan |
| O | Transport mints the anchor without an explicit declaration | 1 |
| P | Rootness used instead of explicit parent equality | 9 — a rooted discovered sweep must not qualify |
| Q | Arbitrary descendants treated as requested-target transport | a fixture with a full Kafka chain under one anchor, asserting the advertised sweep is outside the walk |
| R | Anchor duplicated on retry or cancellation | 14, 16 |
| S | Anchor identity includes the service name | 7 |
| T | `schemaVersion` incremented | 18 |

Mutation Q is the one this record exists to prevent, and it needs the full-depth
Kafka fixture from §7 rather than a PostgreSQL graph, because a PostgreSQL graph
is too shallow to distinguish direct-child ownership from descendant ownership.

### 17. The rule stays pure

`diagnosis.Rule` remains `func(domain.Graph) []domain.Finding`. No run context
parameter, no target parameter, no `ServiceID`, no app import, no global, no
registry. A future rule needs only:

```text
for each node with the anchor step, LayerInput and SubjectKindTarget
    subject := node.Subject()                     // gap B closed
    for each direct child with step dns.lookup    // gap A closed
        walk tcp.connect children and tls.handshake grandchildren
```

`Graph` already exposes `Node`, `Nodes`, `Children`, `Parents` and `BlockedBy` —
everything that traversal needs. No app state, no `Origin`, no identifier parsing,
no service branch, no engine suppression. **Preserving this signature is the whole
reason the anchor is a node rather than a parameter.**

### 18. Renderer implications

A renderer seeing `target.requested L0 PASS` above `dns.lookup L1 FAIL` must not
render "target healthy". Three existing mechanisms already prevent it: report
status derives from findings (ADR 0015), `firstBrokenLayer` derives from FAIL
nodes and would read L1, and no renderer exists to get it wrong yet.

The residual risk is a machine consumer reading node states directly and treating
an L0 PASS as a health signal. That is real but small, and the mitigation belongs
in `REPORT_SCHEMA.md`: **an L0 node states that input was accepted and nothing
else.** It is the only node in a graph that is not a measurement, and that
property is worth being explicit about rather than leaving to inference.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| No anchor; infer requested-ness from rootness | Forbidden provenance inference, and not type-enforced — `Parent` is optional, so a discovered sweep without one silently becomes "requested" | Never |
| No anchor; read the scope out of the identifier | `EvidenceID` parsing, already guarded; and a scope is not provenance (ADR 0032 §5) | Never |
| Add `Origin` as a node field | A second record of provenance competing with graph structure, killed by the advertised-back counterexample | An execution or topology planner has a real consumer (ADR 0031 §6) |
| Generic diagnosis owns every descendant of the anchor | Walks into the Kafka advertised sweep and reintroduces the duplication ADR 0034 resolved (§7) | Never |
| Bound the walk by layer instead of step | `postgres.ssl_request` is L3 and would be swallowed | Never |
| Service-namespaced transport findings (`POSTGRES_DNS_*`) | Needs a `postgres.*` anchor that does not exist when DNS fails, and mints one copy of one algorithm per service | Never |
| `internal/app` emits the findings itself | Orchestration would be diagnosing; already banned by the Phase 4.8b guard | Never |
| `Report.Target` derived from the anchor | Puts step vocabulary into `internal/domain`, which refuses to hold any | `internal/domain` acquires a legitimate step vocabulary for another reason |
| An `origin=user` or `requested=true` attribute | A boolean that is true on every instance of a node type that only exists when it is true | Never |

## Consequences

- The two gaps Phase 4.9a stopped on are closed by one node: a requested transport
  sweep is identifiable, and the requested logical endpoint is a real subject.
- `internal/app` gains one narrowly-guarded evidence authority; every other
  restriction Phase 4.8b pinned survives intact.
- Transport sweeps declare their cause. Ownership between generic and service
  diagnosis is resolved by parentage at the sweep root — not by suppression, not
  by `Origin`, and not by a service switch.
- Kafka advertised-endpoint ownership is unchanged and is now structurally
  unreachable from generic diagnosis rather than merely undisturbed.
- PostgreSQL's in-band TLS handshake stays service-owned, decided by an edge the
  adapter already records.
- A new service inherits the anchor unchanged: it declares its requested sweep's
  parent and gets generic transport diagnosis for free, with no edit to generic
  code.
- `schemaVersion`, `FailureClass`, `FindingCode`, `Reveal` and the dependency set
  are all unchanged.
- A generic vocabulary leaf package must be created, which is new surface and is
  recorded rather than discovered.
- ADR 0017's severity deferral is **half closed**: an anchored generic rule now
  has the requested-versus-discovered context that deferral needed. What severity
  such a finding carries is still unwritten, and remains Phase 4.9a's work.

## Reopen conditions

- **A command accepting several logical targets** — cardinality becomes one anchor
  per requested target (§4).
- **A consumer that cannot obtain a target fact structurally** — the first
  candidate attribute (§6).
- **Input validation becoming evidence rather than an error** — the L0 node's
  PASS-only property would need revisiting (§1).
- **`internal/domain` acquiring a legitimate step vocabulary** — option 2 in §12
  becomes available.
- **A second evidence kind wanting to be minted by `internal/app`** — the
  exception in §3 was written to be reopened deliberately, never widened quietly.
