# ADR 0019: Evidence identifiers are derived from the step and the subject

## Status

Accepted.

## Decision

The producer of a piece of evidence mints its identifier, and the identifier is
**derived from what the node is about**:

```text
<step>/<subject reference>
```

For the DNS probe that is `dns.lookup/kafka.internal`. For a later transport probe
it will be `tcp.connect/10.0.0.1:9092`.

The scheme has three properties, and each one is load-bearing:

- **Derived, not generated.** The same step against the same subject produces the
  same identifier on every run. Nothing about it depends on a clock, a counter, a
  random source or the order in which probes executed.
- **Readable.** A local report can be read, diffed and grepped without a lookup
  table, and an identifier says what its node is.
- **Producer-owned.** `internal/domain` deliberately generates no identifiers; it
  has no clock and no random source and could not produce anything stable. The
  code that knows the shape of the run is the only code that can.

`/` is the separator. No resolvable name contains one, so the DNS probe rejects a
host containing it rather than emitting an identifier that cannot be read back
unambiguously.

> **A delimiter choice must never decide what input a layer accepts.** The DNS
> rejection is acceptable only because nothing legitimate is refused by it. A
> probe whose input can legitimately contain the separator must change how the
> identifier encodes the subject — escaping it, or choosing a different
> encoding — and must not reject input the layer would otherwise accept. An
> identifier is a bookkeeping detail; what svcdoctor is willing to diagnose is
> not, and letting the first constrain the second would narrow the product to
> suit its own record-keeping.

## Context

ADR 0013 and `internal/domain/evidenceid.go` left the scheme open on purpose: the
grammar is permissive about structure and strict about determinism, because the
first real producer had not been written. Phase 2.1 is that producer, so the
scheme has to exist.

Identifiers are not an internal detail. They appear in the canonical JSON, they
are what findings reference (ADR 0014), and structural redaction rewrites them
(ADR 0018). Choosing badly is expensive to undo.

## Scoping and encoding stay open, deliberately

The scheme above is Phase 2.1's and is **not** being redesigned before a second
probe exists. Two questions are left open and belong to Phase 2.2, when the TCP
probe and the transport chain make them concrete:

- **Scoping.** What distinguishes two legitimate nodes for the same step and
  subject in one run — see the section below.
- **Encoding.** How the subject reference is embedded, including which separator
  is used and what happens when a subject can contain it. The delimiter rule above
  binds whatever answer Phase 2.2 reaches.

Deciding either now would mean designing for a caller that does not exist. The
DNS probe's scheme is a working instance of the convention, not the final grammar,
and a Phase 2.2 change to the encoding is expected rather than a reversal.

## Uniqueness, and what it deliberately does not solve

One identifier means one node per `(step, subject)` per run. `GraphBuilder`
rejects a duplicate identifier outright rather than merging, so a second lookup of
the same name in one run is refused.

That is the correct behaviour today and it is not a complete answer. Topology
discovery may legitimately probe one endpoint twice — once as a bootstrap target
and once as an advertised broker — and those are two facts, not one. Resolving it
needs a scope or provenance component in the identifier, which is the same
question as `Origin`, deferred by ADR 0013 until topology orchestration exists.

Adding a scope now would be inventing a shape for a caller that does not exist.
The gap is recorded in `docs/BACKLOG.md`, and it should be reopened by the phase
that first probes one endpoint twice.

## Redaction

The identifier grammar admits hostnames, and this scheme puts one in every
identifier. That is not a leak, because ADR 0018 rewrites every identifier to
`evidence-NNN` and remaps every reference to it. The readable form is a local
convenience; a shareable report keeps only the correlation.

The interaction is worth stating explicitly because it runs the other way to
intuition: a *less* readable identifier would not make a shareable report safer,
and would make a local one harder to work with.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| UUIDs | Nondeterministic. Two runs of the same checks would produce different reports, so nothing could be diffed, and the domain has no random source by design | Never for this purpose; a genuinely opaque identity requirement would be a different problem |
| A hash of the step and subject | Costs readability and buys nothing. It hides an identifier that redaction already removes, and a local report is where the readable form earns its keep | A subject can be too long or too structured to embed directly |
| A sequence counter | Depends on execution order, which becomes nondeterministic as soon as endpoints are probed concurrently. The canonical report must be byte-stable for the same facts | Never; ordering must not reach identity |
| Subject alone, without the step | Collides immediately: DNS, TCP and TLS all describe the same endpoint | — |
| Caller-supplied identifiers | Every caller would invent its own grammar, and no two probes would agree. The producer knows the step and the subject; that is the whole input | A caller has scope information the probe cannot know — which is the deferred topology case above |

## Consequences

- Two runs against an unchanged environment produce byte-identical identifiers,
  so reports diff cleanly.
- A probe needs no identifier service, no counter and no injected generator.
- The same `(step, subject)` cannot be recorded twice in one graph, which surfaces
  the topology scoping question as a loud failure rather than a silent overwrite.
- Every later probe follows the same scheme, so identifiers stay predictable
  across layers without a shared registry.
