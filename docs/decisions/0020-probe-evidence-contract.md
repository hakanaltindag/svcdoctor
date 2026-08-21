# ADR 0020: Generic transport probes normalize at their own boundary

## Status

Accepted.

## Decision

A generic transport probe collects facts through a producer-local observation and
hands out `domain.Evidence` and nothing else. Phase 2.1 establishes the contract
with the DNS probe; TCP and TLS follow it.

```text
observe (the only I/O)  ->  observation (producer-local)  ->  evidence (pure)
```

### The observation stays inside the probe

The observation type is unexported and holds exactly what the producer saw,
including the raw resolver error and the raw address values. Normalization happens
inside the package, and only `domain.Evidence` crosses the boundary. That is what
makes ADR 0010 structural here rather than a rule to remember: there is no
exported path a raw runtime object could take.

There is still no `domain.Observation` and there should never be one. An
observation is producer-shaped by definition.

### One function performs I/O; the rest is pure

`observe` is the only place that touches the network or reads a clock. Every
decision after it — canonical answers, state, failure class — is a pure function
of the observation, so classification is tested without any resolver at all.

This is also the first legitimate use of `time.Now` in the repository. Diagnosis
and the domain have no clock on purpose; an execution producer must have one,
because latency is a fact it is there to measure.

### The subject names what the layer actually observed

DNS evidence carries a `SubjectKindEndpoint` subject whose reference is the
queried name **with no port**. At L1 no port has been chosen, and adding one would
record something the lookup did not observe. A layer that does know a port uses
`host:port`.

`SubjectKindTarget` is wrong here: the lookup is about one host the run is trying
to reach, not about the diagnostic request as a whole.

TCP evidence follows the same rule to a different answer: its subject is the
**concrete `ip:port` that was dialed**, because that is what the attempt observed.
A TCP connection never uses a name. Which endpoint the attempt belonged to is
scope, and it lives in the identifier (ADR 0019), not in a claim on the node.

Stated generally, and this is the part later probes should copy:

> **A subject names what its layer actually touched — not what the run is
> ultimately about, and not what a neighbouring layer touched.**

The consequence is that one endpoint produces subjects that differ by layer: a
name at L1, an address at L2. That is correct rather than inconsistent. They are
connected by the graph, which is where relationships belong (ADR 0013).

`security.Endpoint` is not reused as the subject. It exists to bind a credential
to a place and requires a port; a subject is a label on a fact. Keeping them
separate also keeps `internal/domain` a leaf.

### Attributes carry facts, not derivations

The DNS probe records one attribute, `dns.answers`, and deliberately not
`dns.answer_count`, `dns.family_count` or an rcode. A count is derivable from the
list, and a derived attribute is a second copy of a fact that can disagree with
the first. An rcode is not available from the standard library, and recording an
invented one would be worse than recording nothing.

The attribute is absent, not empty, when nothing resolved, so an absent answer set
and an empty one are distinguishable.

**Identity-bearing values must be declared, and must hold one identity each.** A
producer records them with `domain.HostAttr` or `domain.HostListAttr`, which is
what lets structural redaction replace them without guessing at shapes
(ADR 0022). One identity per value or per list entry, never embedded in prose:
redaction replaces whole values, so two names in one string would survive
together. This is a security requirement on every future probe and adapter, not a
style preference.

Phase 2.1 and 2.2 stated this as a *shape* rule — an address or a `host:port`
reference — because both probes happened to record only values redaction could
recognize structurally. Phase 2.3 showed that shape alone cannot carry the rule,
since a certificate name is a bare hostname indistinguishable from any other
dotted string. The shape guidance still holds where it applies; the declaration is
what makes it enforceable.

Phase 2.2 tested the rule from the other direction: the TCP probe records **no
attributes at all**. Its subject, state, failure class and duration say everything
it observed, and a peer-address attribute would restate the subject while a family
attribute would restate the address. The discipline is not "add the obvious
attributes" — it is that an attribute must carry a fact nothing else carries.

### Classification is conservative, and the order of the checks is the contract

1. **A lookup that returned without error is a completed measurement.** Its
   outcome is decided by what came back. A context that expires immediately
   afterwards does not unmake it, or a run near its budget would randomly report
   `UNKNOWN` for facts it actually collected.
2. **Otherwise the caller's context is consulted first.** svcdoctor's own deadline
   expiring means nothing was learned about the target: `UNKNOWN` with
   `EXEC_LOCAL_TIMEOUT`, never a remote failure. Cancellation is `UNKNOWN` with
   `EXEC_CANCELLED`.
3. **Only then is the resolver's own error classified.**

Step 2 is not theoretical. The standard library reports a caller deadline as a
`*net.DNSError` with `IsTimeout` set, and it does **not** wrap
`context.DeadlineExceeded`, so a probe that trusted the error alone would report
svcdoctor's own budget expiring as a remote DNS timeout. The observation therefore
records `ctx.Err()` alongside the resolver error, because the resolver error alone
cannot say whose deadline expired.

### A failure is evidence; only unusable input is an error

Every DNS outcome, including every failure, comes back as evidence. A Go error is
returned only for input the probe cannot use or for a failure to construct valid
evidence — defects in the caller or in the probe, not statements about the target.

Raw error text never reaches evidence. A resolver error can name the resolver's
own address, a search domain or the queried host, in prose redaction cannot
recognize.

### One interface, for one reason

`Resolver` exists because no test may depend on an uncontrolled public service.
Hermetic testing is a real second implementation, which is the bar this project
sets before an interface is justified.

There is deliberately **no generic `Probe` interface**. DNS, TCP and TLS take
different inputs and produce different facts; a shared shape imposed before the
transport chain exists would be a guess. Concrete functions first.

### Classification uses structured errors, never text

Phase 2.1 read `*net.DNSError` fields; Phase 2.2 reads error numbers through
`errors.Is`. Neither matches on error text, and no probe may. Error strings differ
by platform and by Go release, so a probe that matched them would make confident
claims that quietly stop being true — the exact failure mode svcdoctor exists to
avoid producing in others.

Where a platform reports a condition in a form the mapping does not recognize, the
probe records a conservative class rather than guessing a precise one.

## Context

Phase 1 built the whole evidence model with no producer, so every question about
*how* a fact becomes evidence was open. Phase 2.1 is the first producer, and the
answers it gives will be copied by every probe and adapter after it. Writing them
down now is cheaper than discovering in Phase 3 that two probes disagree about
what a subject means.

Phase 2.2 was the first test of that. The TCP probe adopted the contract without
changing it, and the two places it had to extend rather than follow — a subject
that is an address rather than a name, and a produced resource — are recorded here
and in ADR 0021. Nothing in the contract had to be walked back, which is the
strongest evidence available that it was not overfitted to DNS.

Phase 2.3 was the third test and the first to change something. The TLS probe
follows the contract — producer-local observation, one I/O function, typed-error
classification, conservative timeout attribution, subject naming what the layer
touched — and it records nine attributes where TCP recorded none, because a
handshake genuinely observes that many independent facts. That volume exposed a
gap this record had understated: the attribute *shape* rule was not enough,
because a certificate name is a bare hostname that redaction cannot recognize by
shape at all. The rule is now that a producer **declares** identity through the
value's type; see ADR 0022. The shape guidance below still holds for the values
it covers.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| An exported observation type | Nothing outside the package needs it, and exporting it creates a second public representation of the same facts that could drift from the evidence | A caller needs the raw facts for something evidence cannot express |
| A generic `Probe` interface | One method set for three probes with different inputs and outputs, invented before the transport chain that would use it | The chain exists and reveals a shape all three genuinely share |
| Recording `dns.answer_count` and family counts | Derivable from `dns.answers`; a derived attribute is a second copy of a fact | A consumer needs a figure the list cannot yield |
| Recording an rcode | The standard library does not expose one. Inventing it would fabricate protocol detail | A resolver that reports rcodes is adopted |
| Classifying not-found as `DNS_NXDOMAIN` | The standard library sets `IsNotFound` for both NXDOMAIN and NODATA, so NXDOMAIN would assert a non-existence never evidenced. `DNS_NO_ADDRESS` claims only that no usable address came back, which is true in both cases | A resolver positively evidences NXDOMAIN |
| A third failure class for "no answer, existence unknown" | Splits one diagnostic outcome across two classes for a distinction no available resolver reports. Widening the weaker class covers every case instead | A resolver distinguishes the two *and* the difference changes what an operator should do |
| Mapping `context.DeadlineExceeded` to `DNS_TIMEOUT` | Collapses "svcdoctor ran out of time" into "the target failed", which is the false positive the claim discipline exists to prevent | Never |
| A `Clock` interface | Nothing needs deterministic time. Duration assertions are broad and startedAt is checked for validity, not for an exact value | A test genuinely requires a fixed instant |
| Normalizing the queried name (lowercasing, trailing dot, IDNA) | Changes the question that was asked. Evidence must record the question actually asked | A layer needs a normalized form *in addition to* the queried one |
| Reusing `security.Endpoint` as the subject | Credential scope and evidence subject are different concepts, and it would require a port L1 does not have | Never; they are separate concepts |

## Open question this phase surfaced, and how it was settled

Phase 2.1 first shipped with a tension recorded here rather than resolved:
`DNS_NO_ADDRESS` was documented in `internal/domain/failureclass.go` as "the name
exists but yielded no usable address", while the probe also used it for the
undistinguished not-found case, where existence is unknown. The class was the
weaker and safer of the two available claims, but its own documentation asserted
slightly more than the probe could evidence.

**Resolved by widening the class contract**, in the same phase:

```text
FailureDNSNoAddress    the lookup yielded no usable address
```

It now says nothing about whether the name exists, which is what makes it true in
all three cases it has to cover: a name that exists with no address record, a name
that does not exist, and the common case of a resolver that does not distinguish
them. Widening the weaker claim was preferred to adding a third class, which would
have split one diagnostic outcome across two classes for a distinction no
available resolver reports.

`FailureDNSNXDomain` keeps its meaning and is now explicitly the stronger claim:
it requires a resolver that positively evidences non-existence, and a producer
must not upgrade a not-found answer to it without that evidence. No resolver in
the repository qualifies, so nothing produces it today — enforced by
`TestNXDomainStaysReserved` rather than left to discipline.

The alternative of *narrowing the probe* — reporting `UNKNOWN` for a not-found
answer — was rejected. The resolver answered definitively, so the failure is
evidenced; `UNKNOWN` would discard a real first-broken-layer signal.

## Consequences

- Every later probe has a worked example to follow, and a difference from it is a
  decision someone has to justify.
- Classification is unit-testable without a network, because it is a pure function
  of a value.
- A local budget expiring can never be reported as a target failure by a probe
  built this way.
- A shareable report stays safe as probes are added, provided each one keeps
  identity in a shape redaction recognizes. `test/security` holds the contract
  test that proves it for DNS.
