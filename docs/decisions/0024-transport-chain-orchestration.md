# ADR 0024: The transport chain inspects every address and chooses no continuation

## Status

Accepted.

## Decision

`internal/probe/transport` runs the generic transport chain for one endpoint:

```text
DNS -> TCP for every resolved address -> TLS where the caller asked for it
```

It owns transport orchestration. It does not own diagnosis: no overall status, no
severity, no confidence, no finding.

### 1. Every resolved address is attempted

A production client stops at the first address that works. svcdoctor does not,
because the addresses it does not try are exactly the ones that hide the problem:
a broken address family, a host behind a different firewall rule, a down member of
a load-balanced set.

Stopping early would also make the report depend on which address happened to be
listed first, which a tool that collects evidence cannot accept. `docs/SCOPE.md`
already lists "reachability verification of every advertised broker endpoint" as a
target capability, and the flagship finding in `docs/FINDINGS.md` section 6 is
built on it.

One TCP node per address; one TLS node per address where TLS was requested.
Partial success stays visible as partial success.

### 2. Execution is sequential

Addresses are attempted one at a time, in the canonical order the DNS probe
produced.

Concurrency would buy latency, which is not what a diagnostic tool optimizes, and
it would make the evidence — and the order of the returned continuations — depend
on which handshake finished first.

### 3. The chain keeps every completed path and chooses none

Sweeping every address can produce several usable connections. The chain returns
all of them and picks no favourite.

This is the part of the design that changed during Phase 2.4, and the reason is
worth recording. The first implementation retained "the first successful path in
canonical address order" and closed the rest. That looked like a neutral
mechanism. It was not: `netip.Addr.Compare` orders every IPv4 address before every
IPv6 one, so whenever both families worked the continuation was always IPv4.
Nobody chose that policy, nothing documented it, and no test would have caught it
changing.

Two concerns had been coupled that have nothing to do with each other:

| Concern | Why it exists | Whose decision |
|---|---|---|
| Canonical evidence ordering | A report must be byte-stable for the same facts | The domain's, since Phase 1 |
| Runtime connection selection | A protocol has to be spoken over exactly one path | The layer that knows what it is about to say |

There is no transport-level reason to prefer one working path over another. The
chain therefore expresses no preference, and the layer that has a reason — an
adapter that knows what protocol it is about to speak, or the orchestration that
knows what the user asked — makes the choice where it can be recorded and
justified.

`Result.Continuations()` returns the completed paths in canonical address order.
**That order is evidence ordering, not a ranking**, and the documentation says so:
a caller that takes the first entry is making its own choice, not following one
made here.

### 4. The evidence graph belongs to the caller

The chain writes into a `domain.GraphBuilder` the caller supplies and never
freezes it. One endpoint is not one report: a topology sweep will record many
endpoints into one graph, and only the caller knows when the run is over.

A parent edge means **derivation**: the TCP attempt exists because the lookup
produced that address. It is not provenance, and nothing may read `Origin` out of
the shape of this graph (ADR 0013).

### 5. A skipped node requires a subject that can be named honestly

- **TCP failed and TLS was requested.** The address is a known, concrete thing, so
  a TLS node is recorded: `SKIPPED`, classified
  `EXEC_SKIPPED_PREREQUISITE_FAILED`, and `BlockedBy` the TCP node. The report can
  answer "why was TLS never checked?".
- **The lookup produced no address.** No TCP or TLS node is recorded. There is no
  address to name, and inventing one to hang a skipped node on would be a
  synthetic fact and would break the rule that a subject names what its layer
  touched (ADR 0020). The failed DNS node is the record.

The second case appeared to contradict `docs/ARCHITECTURE.md` section 12, which
reads "DNS FAIL -> TCP/TLS ... are SKIPPED". The ambiguity was whether that
sentence describes *layers* or mandates *nodes*. ADR 0020's subject rule is the
more specific and later contract, so it wins at the node level, and section 12 has
been amended to say so explicitly.

### 6. Budget

The caller's context is passed to every probe, and an optional `StepTimeout`
bounds each step. The per-step bound exists because a single black-holed address
would otherwise consume the whole budget and leave every later address unmeasured:
the report would say less the slower the target is.

When the budget is gone the remaining addresses are recorded as **not attempted**:
`SKIPPED` with `EXEC_CANCELLED` or `EXEC_LOCAL_TIMEOUT`. A local budget expiring is
never a claim about the target.

### 7. TLS is optional and never inferred from a port

The presence of `Params.TLS` is the request; nil stops the chain after TCP. A port
number is a convention rather than evidence: ADR 0011 already refuses to infer a
service from one, and inferring a protocol would be the same mistake one layer
down.

## Context

Phases 2.1 to 2.3 produced three generic probes. None knows about the others and
none knows about the graph. Phase 2.4 is the first layer that combines them, so it
is the first time all of these questions become real at once: which addresses are
attempted, which connection survives, what shape the evidence takes, who owns the
budget.

Getting it wrong is silent. The code compiles, the tests pass, and the report is
either incomplete (an early-stopping sweep) or the protocol layer speaks over a
connection nobody measured.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Stop at the first working address | Hides the broken one and makes the report depend on DNS ordering. That is a production client's goal, not a diagnostic tool's | Never; it contradicts why the tool exists |
| Retain one connection by canonical-first order | Reuses evidence ordering as selection policy. Because canonical order puts IPv4 first, the observable behaviour is an IPv4 preference nobody chose — the worst kind of policy, because it is invisible | Never in this layer; a caller that wants a rule states it in its own layer |
| Retain one connection by lowest latency | Timing-dependent: identical environments would continue over different paths | Never |
| Retain one connection by address family | Explicit client policy, and this layer has no basis for it | A caller genuinely needs family control — and then it is the caller's parameter |
| Sweep first, then establish the continuation separately | The second establishment is a redial: the protocol would run over a connection whose transport was never measured, and no test would catch it. It also needs a second node for the same `(step, endpoint, address)`, which is the identifier-scoping case ADR 0019 defers | Never |
| Return no connection and let orchestration ask for one later | Same redial, same objection | Never |
| Concurrent address sweeping | The evidence and the continuation order would depend on completion timing | A real performance requirement appears; selection must then be decoupled from completion order |
| Happy Eyeballs | Designed to establish a connection quickly; collecting evidence is a different goal, and racing means some addresses are never attempted | Never in this layer |
| Synthetic TCP/TLS nodes when a lookup produced no address | Naming an address that does not exist is a fabricated fact | A rule or renderer genuinely needs an explicit "not attempted" node; a node whose subject is the *endpoint* could then be discussed |
| The chain freezing and returning the graph | One endpoint is not one report, and a topology sweep cannot add to a frozen graph | Never |
| An overall status or health field on the result | "Two addresses worked and one did not" is the whole result; what it means is severity policy this layer does not have | Never in this layer |
| Retries | The chain does not need them to be correct, and each retry wants a second node for the same `(step, endpoint, address)` — the scoping question ADR 0019 defers | A retry policy is genuinely required |

## Consequences

- Every transport path of an endpoint has independent evidence; partial failure
  stays visible.
- The same facts produce the same graph: resolver order, map iteration and network
  timing cannot change the output.
- Every live connection has exactly one owner at every moment, and whichever path
  the caller continues over is the one its evidence describes. Nothing is redialed.
- A caller that wants only the evidence closes the `Result` and every connection
  goes with it. A caller that wants one takes it and closes the rest.
- The chain holds one socket per completed path for the duration of the sweep.
  That is bounded by the address count, and it is the price of not making a choice
  the layer has no basis to make. A caller worried about it closes the Result
  promptly.
- A protocol layer receives the address it reached and the identifier of the
  deepest node on that path, so it can parent its own evidence to the transport
  that was measured.
- `GraphBuilder` did not become an execution engine: the chain only tells it what
  happened (ADR 0013).
