# Architecture

## 1. Style

svcdoctor v0.x is a **modular monolith**: one process, one Go codebase, and one cgo-free binary.

The architectural flow is:

```text
Input / CLI
    |
    v
Application orchestration
    |
    +--> Generic probes ---------> Observations
    |
    +--> Service adapter --------> Protocol/topology observations
                                  |
                                  v
                            Evidence graph
                                  |
                                  v
                              Diagnosis
                                  |
                                  v
                               Report
                                  |
              +---------+---------+---------+
              |         |         |         |
           Terminal   JSON    Markdown    HTML
```

The invariant is:

> **Probes collect facts. Adapters understand protocols. Diagnosis correlates evidence. Renderers explain results.**

A second principle governs how this architecture grows:

> **Extensibility comes from stable boundaries, not from maximizing abstractions.**

Concrete structs first. Interfaces only at real boundaries.

## 2. Layer order

The authoritative layer order is:

```text
L0  Input / config normalization
L1  DNS
L2  TCP
L3  TLS
L4  Protocol / capability discovery
L5  Authentication / authorization
L6  Topology discovery
```

Protocol/capability discovery precedes authentication because that is the real wire
order of the services in scope.

Kafka:

```text
DNS -> TCP -> TLS -> ApiVersions -> SASL mechanism discovery / authentication
    -> Metadata topology discovery
    -> Metadata -> topology verification
```

PostgreSQL:

```text
DNS -> TCP -> TLS / SSLRequest -> Startup / protocol negotiation
    -> AuthenticationRequest / authentication -> multi-host / role discovery
```

Short-circuiting and first-broken-layer reporting follow this order. See ADR 0007.

## 3. Probes

Generic probes collect transport facts such as DNS, TCP, and TLS. They do not understand Kafka, PostgreSQL, Redis, or any other service semantics.

A probe returns observations. A probe does not diagnose a problem.

Examples:

- DNS resolution result and latency
- TCP connect result and latency
- TLS handshake, chain validation, SAN validation, expiry, negotiated protocol/cipher

Generic does not mean parameterless. A TLS probe may accept SNI, ALPN, protocol version
bounds, trust source, and client certificate material, because those are generic TLS
concepts. The caller supplies them; the probe does not know which service asked.

### 3.1 How a probe produces evidence

Every generic probe follows the same shape, established by the DNS probe in
`internal/probe/dns` and fixed by ADR 0020:

```text
observe (the only I/O)  ->  observation (producer-local)  ->  domain.Evidence
```

- **The observation stays inside the probe.** It holds the raw error and the raw
  runtime values; nothing but `domain.Evidence` crosses the package boundary. That
  is what makes ADR 0010 structural rather than a rule to remember.
- **One function performs I/O and reads the clock.** Everything after it is pure,
  so classification is testable without a network. This is the first layer where
  clock access is legitimate: latency is a fact a probe exists to measure.
- **The subject names what the layer observed**, and nothing more. L1 evidence
  carries a host with no port, because no port has been chosen yet; L2 evidence
  carries the concrete `ip:port` that was dialed, because a TCP connection never
  uses a name. One endpoint therefore has different subjects at different layers,
  connected by the graph rather than by repeating a value.
- **Identifiers are derived** as `<step>[/<component>...]`, escaped so that no
  input has to be refused to keep them unambiguous (ADR 0019).
- **Attributes carry facts, not derivations**, and identity-bearing values are
  **declared**: `domain.HostAttr` / `domain.HostListAttr` for a network peer, one
  identity per value or list entry (ADR 0022), and `domain.IdentityAttr` for a
  principal or named resource that is not a peer (ADR 0037). Never embedded in
  prose. The kind carries privacy semantics; the attribute key carries the
  semantic role and survives redaction.
- **Classification is conservative.** A completed measurement is a fact; otherwise
  the caller's context is consulted before the I/O error, so svcdoctor's own
  deadline expiring is `UNKNOWN`, never a remote failure.
- **A failure is evidence.** A Go error means the probe was called with unusable
  input, not that the target is broken.

A probe introduces a test seam only when a hermetic test genuinely needs one.
`Resolver` and `Dialer` exist because DNS and TCP reach the network; the TLS probe
has **no seam**, because a real `crypto/tls` server on a loopback listener the
test controls reproduces every case, and an interface with no test consumer is the
speculative abstraction the architecture forbids. There is likewise no generic
`Probe` interface: DNS, TCP and TLS take different inputs and produce different
facts.

A probe that establishes or wraps a connection returns it under the ownership
contract of section 4.1. TLS is both a consumer and a producer of that contract:
it takes ownership of the connection it is handed, and hands on the TLS connection
wrapping the same socket (ADR 0023).

### 3.2 Transport orchestration is not application orchestration

A generic transport chain sequences DNS, TCP and TLS for one endpoint and decides that a
failed lookup blocks the connection attempt that would have followed. That sequencing is
part of the probe boundary.

> **Generic transport orchestration is not application orchestration.**

Both run steps in order, which is what makes them easy to conflate. They are on opposite
sides of an architecture boundary:

| | Generic transport orchestration | Application orchestration |
|---|---|---|
| Lives in | `internal/probe` | `internal/app`, `cmd/svcdoctor` |
| Knows | how to run DNS → TCP → TLS for one endpoint, and when a failure blocks the next layer | which service was selected, which adapter to wire, which rules to evaluate, which renderer to use, which exit code to return |
| Produces | evidence and, on success, a live connection | a report, rendered output, and a process exit code |
| Depends on | `internal/domain` and the standard library | every layer |

Anything that chooses a *service*, assembles a *report*, or decides what the *process* does
is application orchestration and does not belong in a probe.

**Application orchestration is decided and built for PostgreSQL**, and Phase 5.1 added the
product boundary above it. `internal/app` holds the composition root; `cmd/svcdoctor` is
process bootstrap; `internal/cli` owns dispatch, input, output selection and the exit code;
`internal/render/json` writes the canonical artifact; `internal/platform/local` produces the
vantage fact. `test/integration/postgres` guards the boundaries between them. **ADR 0041**
defines the run boundary
it implements: one command is one run; the run owns the root context, one
`GraphBuilder`, every continuation, the selection of at most one credential-bearing path,
closure of the rest, the freeze, diagnosis and the `LOCAL_FULL` report — and owns no
rendering, no output format and no redaction-mode choice.

Its principle is **discover broadly, authenticate narrowly**: every resolved path is measured
as far as credential-free discovery permits, and exactly one eligible path receives the one
authentication attempt a run is allowed. The CLI tree is action-first —
`svcdoctor diagnose <service>` — which partially supersedes ADR 0011's shape while preserving
its rationale that each service owns its own flags, help and validation.

The composition root is deliberately concrete: one PostgreSQL run, no service registry and no
generic adapter interface. ADR 0009 declines that abstraction until two services prove a
shared contract rather than merely existing, and Kafka's bootstrap, topology discovery and
advertised-endpoint sweeps are not PostgreSQL's single credentialed continuation. Phase 4.8a validated the whole
PostgreSQL slice end to end — real socket through diagnosis, report and redaction — from a
**test** composition boundary, which is what ADR 0028 §1 contemplates when it says *"Today the
only caller is a test."* The decisions a production root needs are collected in ADR 0041.

The same split governs timeouts. A per-probe or per-chain deadline is transport-local. The
whole-run execution budget, cancellation propagation, and the partial-run exit code in
section 13 belong to the application boundary.

**Below the application root, the output boundary is fixed by ADR 0048.** It is one chain, and
each arrow crosses exactly once:

```text
cmd/svcdoctor    root signal context, os.Exit
    ↓
internal/cli     parse, validate, build params, derive the run deadline
    ↓
internal/app     one diagnosis
    ↓
app.Result       Report + Incomplete
    ↓
internal/cli     select the output security mode
                 (LOCAL_FULL, or SHAREABLE_REDACTED via internal/security/redaction)
                 and the exit code
    ↓
internal/render  the artifact on stdout
```

Implemented across Phases 5.1 to 5.3. The command builds a `render.Input` — the chosen
report projection plus whether execution completed — and dispatches to `internal/render/json`
or `internal/render/terminal`. Both forms describe the same run and neither chooses an exit
code.

`internal/render` imports `internal/domain`, `internal/vocabulary` and
`internal/service/postgres` for step labels, and nothing else. A
`render-is-presentation-only` depguard rule keeps it that way — denying
`internal/security/redaction`, because the projection is chosen *before* a renderer runs, and
denying `os`, because output that varied with where it was written would stop being the
artifact a test and a pipeline both read.

The credential travels the other direction and stops well short of the report:

```text
--password-file / --password-stdin   read once, bounded, at the command boundary
    ↓
security.Secret                      masked in every formatting verb
    ↓
security.Credential                  bound to the logical endpoint, never an address
    ↓
internal/app → internal/adapter/postgres
    ↓
wire, and only there, security.Reveal
```

`internal/cli` may construct a `Secret` and may not open one: depguard denies it the wire
packages and forbidigo denies the call. No secret reaches a renderer, a report, an evidence
node or an error string.

The command layer owns process outcome; the renderer owns presentation and owns nothing else.
A renderer chooses no exit code, performs no diagnosis, applies no redaction and imports no
adapter, probe, app or diagnosis package. Diagnosis always runs on the truthful `LOCAL_FULL`
report, so redaction can never change what was concluded — only what a shared copy reveals.

Two consequences of that chain are load-bearing rather than incidental, and ADR 0048 states
them normatively. `SummaryStatus` and `Result.Incomplete()` are orthogonal, so a renderer must
present the target-side status, whether a session was established, and whether execution
completed as three separate facts. And `Result.Incomplete()` is not part of the report: a
report cannot observe its own partiality (`docs/REPORT_SCHEMA.md` §8), so machine consumers
learn it from the process exit code.

This distinction is a boundary clarification, not a new decision: it follows from section 14
and from the invariant that probes collect facts. `docs/BACKLOG.md` applies it to the phase
plan.

### 3.3 The transport chain

`internal/probe/transport` is the first orchestration in the repository. It runs one endpoint
through DNS, then TCP for **every** resolved address, then TLS where the caller asked for it,
and records the relationships the probes know nothing about (**ADR 0024**).

- **Every address is attempted.** A production client stops at the first that works; a
  diagnostic tool must not, because the untried address is the one that hides the problem.
- **Execution is sequential**, in the canonical order the DNS probe produced, so the graph and
  the retained connection do not depend on timing.
- **Every completed path is handed back, and the chain chooses none.** There is no
  transport-level reason to prefer one working path over another, and any rule the chain
  applied would be client policy in disguise: canonical address ordering, for instance, would
  make IPv4 the continuation whenever both families work. Choosing belongs to the layer that
  knows which protocol it is about to speak. `Continuations()` is ordered for byte-stability,
  not as a ranking.
- **The graph belongs to the caller.** The chain writes into a `GraphBuilder` and never
  freezes it, because one endpoint is not one report.
- **No aggregate judgement.** "Two addresses worked and one did not" is the whole result;
  what it means needs a severity policy this layer does not have.

Parent edges here mean derivation — the TCP attempt exists because the lookup produced that
address — and never provenance (ADR 0013).

## 4. Connection ownership

Generic transport owns DNS, TCP, and TLS. A protocol adapter must not reimplement that logic.

Protocol handshakes require the established connection to stay open, so:

> **Generic transport must be able to transfer ownership of a successfully established live connection to the protocol adapter when required.**

Guardrail: a service adapter calling `net.Dial` directly, or performing its own TLS
handshake, is an architecture violation. If the adapter needs a live connection, the
transport layer hands one over; the adapter does not open a second one.

Opening a second connection is not only a layering violation. It also breaks measurement
fidelity, because the protocol step would then be attributed to a connection that was
never the one measured.

### 4.1 The ownership contract

As of Phase 2.2 this is an API rather than a principle. A probe that establishes a
connection returns it alongside the evidence, in a value that owns it until somebody
takes it (**ADR 0021**):

```go
r, err := tcp.Connect(ctx, dialer, endpoint, addr)
if err != nil { return err }
defer r.Close()                  // safe in every path, including after a transfer

if conn, ok := r.TakeConn(); ok {
    defer conn.Close()           // the caller owns it now
}
```

- The probe never closes a successful connection; it hands it over.
- `TakeConn` transfers ownership exactly once.
- `Close` releases the connection only while the result still owns it, so it is safe
  to defer unconditionally and safe to call twice.
- A failed attempt owns nothing.
- A probe that *consumes* a connection takes ownership unconditionally, in every
  outcome including a returned error, so a caller never has to work out which
  branch left it responsible. Closing a wrapper closes what it wraps, so one
  socket always has exactly one owner (ADR 0023).

**Evidence never owns a connection.** `domain.Evidence` has no field one could occupy,
and the graph and the report hold evidence, so no live resource can reach anything that
is serialized. The two have different lifetimes on purpose: closing the connection does
not make the attempt stop having succeeded.

There is no registry, no map keyed by evidence identifier and no package-level state
holding sockets. The connection is reachable only through the value the caller was handed.

## 5. Adapters

Adapters understand service protocol semantics. Kafka and PostgreSQL adapters may orchestrate generic probes, perform protocol-specific handshakes, discover authentication mechanisms, normalize protocol errors, and discover topology.

Adapters do not render output and should not contain human-oriented root-cause narratives.

Adapters own normalization: raw protocol responses and error codes become normalized
observations at the adapter boundary. Diagnosis never receives a raw protocol object.

### 5.1 The Kafka adapter boundary

`internal/adapter/kafka` is the first adapter, and it fixes the shape the next one
should follow (**ADR 0025**):

- **It never opens a connection.** The transport chain establishes and measures the
  paths; the adapter speaks over those exact connections and hands them on.
- **It asks every path and chooses none.** ApiVersions describes the broker at the
  other end of one connection, so a bootstrap name with several backends produces
  several facts. Choosing one would hide an inconsistent broker behind a working
  one.
- **A completed exchange keeps its connection**, so the next protocol step
  continues on the measured socket. A broken exchange closes it: only the adapter
  can tell an unknown socket state from a broker that merely answered with an
  error code.
- **The protocol library lives in one subpackage.** `internal/adapter/kafka/wire`
  is the only place that imports kmsg, and nothing above it sees a library type.
- **Protocol evidence parents the transport node whose connection it used**, so a
  reader can follow one address from L1 to L4.

Service-specific error codes are attributes, never `FailureClass` values:
`internal/domain` stays service neutral. A code is normalized into the generic
vocabulary only when the protocol response proves that generic fact by itself —
Kafka's `UNSUPPORTED_VERSION` is `PROTOCOL_UNSUPPORTED_VERSION`, and everything
else stays conservative, because reading a cause out of a number is diagnosis.

A transport path that failed never reaches the adapter, so it carries no
`SKIPPED` protocol node. That follows from the input contract rather than from
section 12, whose subject rule such a node would satisfy; the question is
deferred with a reopen condition in ADR 0025 §9.

### 5.2 Credential-free discovery comes before credential use

Phase 3.2 added L5 mechanism discovery — `kafka.sasl_handshake` — and Phase 3.2c
added the step that follows it, `kafka.sasl_authenticate`. The boundary between
them generalizes past Kafka (**ADR 0026**, **ADR 0030**):

- **A step that sends no credential may run on every measured path**, because it
  costs the target nothing. ApiVersions and SaslHandshake both qualify: a
  handshake request carries a mechanism name and no identity or secret.
- **A step that sends a credential may not run anywhere until a layer can say
  where.** An authentication attempt is logged, counted and lockout-relevant, so
  "every path" and "the first path" are policy, not defaults — and *the first*
  would silently mean IPv4, the artifact ADR 0024 removed from the transport
  chain. The two discovery steps therefore take a slice of sessions; the
  authentication step takes one.
- **Path selection for credentials therefore belongs to the layer that can record
  why it chose**, which is the orchestration boundary that does not exist yet.
  **ADR 0028 makes that structural**: the authentication API takes exactly one
  session rather than a list, so no ordering and no index inside the adapter can
  become a selection. Authenticating several brokers stays possible, as a loop
  the caller writes deliberately.
- **Mechanism, policy and diagnosis stay separate.** That the protocol permits
  PLAIN on an unverified channel, that svcdoctor should refuse it, and that using
  it is worth reporting are three statements owned by three layers. An adapter
  that silently refused would invent policy; one that silently sent would break a
  documented one. **ADR 0028 resolves this without merging the three**: the
  adapter *obeys* a fail-closed policy value it is handed — as it would obey
  `ForwardingPolicy` — and records a refusal as `SKIPPED` with
  `EXEC_SKIPPED_BY_POLICY`. Obeying a declared policy is not owning one, and a
  recorded refusal is neither silence nor a finding.
- **A layer cannot enforce a policy about a fact it cannot see.** The fact must
  be **declared by the component that observed it**, not inferred by
  type-asserting a connection — the same declaration-over-inference rule ADR 0022
  fixed for identity-bearing attributes. Phase 3.2b built it (**ADR 0029**):
  `security.Channel` travels with the connection from `tls.Result.Channel()`
  through `transport.Continuation`, `kafka.Session` and `kafka.HandshakeSession`,
  and `security.CredentialTransportPolicy` reads it. Both zero values fail closed,
  and an adapter has no way to strengthen the claim.
- **PostgreSQL negotiates TLS from inside its own protocol flow, and the adapter
  sequences it without reimplementing it.** `internal/adapter/postgres` writes an
  `SSLRequest`, reads exactly one byte, and — when the server accepts — hands the
  *same* socket to `internal/probe/tls`. It has no dialer, no resolver, and
  `depguard` denies it `crypto/tls`, so it cannot open a connection or inspect
  one. The graph records the causation:
  `tcp.connect → postgres.ssl_request → tls.handshake → postgres.startup`,
  and the TLS node's parent is the negotiation rather than the TCP node because
  that is why the handshake happened. **No generic STARTTLS abstraction was
  created**: one protocol needs this, and a service-neutral hook shaped like
  PostgreSQL's negotiation would be a guess about a second caller that does not
  exist (ADR 0036).
- **Channel authority follows the observation boundary, not the call path.**
  Phase 4.2 narrowed ADR 0029's wording after Phase 4.0 established that a
  protocol can negotiate TLS from inside its own flow rather than inside the
  transport chain. The probe that performs a handshake owns the two TLS facts;
  the component that decides to leave a connection in the clear owns plaintext;
  everything else propagates. The transport chain consequently lost the ability to
  name a TLS constant, which is a narrowing rather than a widening, and `depguard`
  denies adapters `crypto/tls` so no layer can interrogate a socket to re-derive
  one. A failed handshake reports `unknown`: `Channel` governs writes to a live
  connection, and a rejected certificate produced none.
- **A refusal names the fact that caused it, or names nothing.** The identifier of
  the node that classified a channel travels the same way the channel does
  (`ChannelEvidence`), so an unverified-TLS refusal points at the L3 node carrying
  `tls.verified=false`. On a plaintext path it points at nothing, because no node
  in the graph states that TLS is absent and the TCP node proves nothing about
  encryption. **The smallest honest representation of "nothing proves this" is
  nothing** — a synthetic blocker would make a report read as though something had
  been established (**ADR 0030 §9**).

**A runtime ownership fact is not a diagnostic observation.** The channel is the
first fact this project carries beside a connection without also recording it as
evidence, and the distinction is deliberate: `tls.verified` already states what a
handshake proved, on the node that observed it, so a second copy would be one fact
with two representations that can disagree (ADR 0013, ADR 0016). What eventually
reaches a report is not the channel but its consequence — a `SKIPPED` node with
`EXEC_SKIPPED_BY_POLICY` when policy refused an attempt.

### 5.2b One run may measure one subject more than once

A run can legitimately measure the same thing twice: a bootstrap sweep resolves a
hostname, and a later topology sweep resolves it again because a service
advertised it. Two executions, at two moments, for two reasons, of one subject —
and both are true.

Evidence identifiers are derived from what a node is about, so those two lookups
mint one identifier and the graph rejects the second. That rejection is correct;
what was missing was a way to say the measurements differ. A **sweep scope**
(**ADR 0032**) supplies it: an opaque caller-owned label, carried unchanged
through DNS, TCP and TLS, contributing one optional component to the identifier
and touching nothing else.

Three properties make it safe to rely on:

- **It never reaches a subject or an attribute.** What was observed is unchanged
  by who asked. If a scope could reach a subject, two measurements of one host
  would begin describing two hosts.
- **It is not `Origin`.** A scope says which execution produced a measurement,
  never how a subject entered the run. The same distinction section 5.3 draws for
  parent edges.
- **Unscoped is the default and reproduces Phase 2 byte for byte**, so a caller
  that never needs a second sweep never sees it.

The chain also accepts an optional derivation parent, so a sweep caused by an
earlier observation can say so. That edge means derivation and not provenance,
exactly as elsewhere.

### 5.3 Topology discovery records endpoints and probes none of them

Phase 3.3 is where svcdoctor first learns of endpoints the operator never named.
The boundary it draws generalizes past Kafka (**ADR 0031**):

- **Discovery and reachability are separate phases.** A Metadata response is
  recorded as evidence; nothing it advertises is resolved, dialled or spoken to.
  Probing discovered endpoints in the same phase would force credential
  forwarding, execution deduplication, a recursion bound and a severity view
  about unreachable brokers into the step that was supposed to produce their
  input.
- **Derivation is structural; provenance is not.** A discovered endpoint's node
  parents to the exact exchange that carried it, and that edge records
  *derivation* — this fact came from that response. It does **not** record how the
  endpoint entered the run, and section 12's rule stands unchanged: nothing may
  read `Origin` out of graph shape. The two come apart whenever a cluster
  advertises the bootstrap endpoint back, which is routine: one `host:port` then
  has a discovery-derived node *and* a lookup-derived transport path, both true
  and neither ranked. `Origin` therefore stays deferred until an execution or
  topology planner has a real consumer for it (**ADR 0031 §6**).
- **A service identity is not a network target.** A broker has an identity the
  service reports and an advertised address it can be reached at, and they are
  different fields answering different questions. They are recorded separately,
  and an evidence identifier carries both, so one identity at two addresses and
  two identities at one address both stay two facts. Neither is assumed unique or
  stable: preserving those conflicts is the point.
- **Contradictions are preserved; only identical facts collapse.** A diagnostic
  tool that merged conflicting topology would be hiding the finding somebody ran
  it to get. The one collapse performed — a byte-identical repetition — is
  reported as a count so it is visible rather than silent.
- **Discovery is not credential authority.** "Same cluster" does not authorize a
  credential. The discovery API has no parameter a credential could occupy, and
  a discovered endpoint is deliberately not the type that binds one.

**Connection lifetime follows the protocol, not the evidence state.** ApiVersions
keeps a connection whose broker answered with an error code, because any request
may still follow it; a rejected SaslHandshake closes one, because the broker will
accept only the agreed mechanism's continuation and there is nothing left to send;
a refused or rejected authentication closes one for the same reason, since that
continuation is exactly what was declined or refused. A successful authentication
is the first step whose result is a connection *more* usable than the one it
consumed, which is why it produces a distinct type. The criterion throughout is
whether the protocol defines a next message on that socket.

### 5.4 A discovered endpoint is measured by generic transport, once per advertisement

Phase 3.4 is the consumer section 5.3 was built to feed. It takes the
advertisements a Metadata exchange recorded and measures their network endpoints
with the generic transport chain — DNS, TCP and TLS — and nothing else
(**ADR 0033**).

- **It stops at L3, and the stop is the phase.** No protocol request, no
  authentication and no second Metadata reaches a discovered broker. Nothing
  re-enters, so there is no recursion, no depth limit to tune and no visited set:
  the bound arrives with the traversal.
- **The transport plan is supplied by the caller, never inferred.** A Metadata
  response carries a host and a port and says nothing about whether that listener
  is plaintext or TLS. The port is a convention, and the bootstrap connection
  describes one listener on one broker — copying either would turn "this run was
  encrypted" into "this cluster is encrypted". The plan reuses the transport
  chain's own TLS type rather than an adapter-shaped copy, and it is execution
  *intent*: `security.Channel` remains something only the layer that performed a
  handshake may state.
- **One advertisement, one sweep.** Two advertisements naming one endpoint produce
  two measurements. That redundancy is deliberate: a deduplicated sweep would have
  two causes and one effect, and with a singular derivation parent it could only be
  recorded by choosing one advertisement as *the* cause — a semantic ownership
  decision made by a tiebreak, with the loser's measurement silently unattributed.
  **Redundant but truthful execution was chosen over deduplicated execution**, and
  the reopen condition is a graph representation that can hold many causes for one
  execution.
- **Fact normalization belongs to the layer above.** Discovery decides what counts
  as one advertisement; reachability executes once per resulting fact and adds no
  second dedup layer.
- **Measurement identity is not subject identity.** A bootstrap endpoint advertised
  back is measured again under its own sweep scope, reusing no bootstrap evidence;
  the two nodes share a subject and differ only in which execution they belong to.
- **It judges nothing.** The evidence is generic transport evidence with generic
  failure classes. No service-specific transport failure class, no aggregate
  reachability verdict, no finding and no severity — this phase produces exactly
  the data a future rule needs and deliberately does not use it.
- **It is measurement-only, so it owns nothing afterwards.** Every connection a
  sweep establishes is closed before the call returns; no continuation and no
  socket reaches the caller. Per-layer latency is preserved, and no aggregate
  replaces it.

### 5.5 A service rule anchored at a service fact needs no provenance

Phase 3.5 decided what may be concluded from advertised-endpoint reachability
evidence, before any rule was written (**ADR 0034**); Phase 3.6 implemented that
decision as `internal/diagnosis/kafka.AdvertisedEndpointUnreachable`, svcdoctor's
first rule, and Phase 3.7 added `UnusableAdvertisement` beside it (**ADR 0035**).
One idea in them generalizes past Kafka and belongs here rather than in a service
record:

> **A diagnosis rule that starts at a service fact and walks derivation edges
> downward has its context by construction. A rule that starts at a transport
> node and asks what that node is about does not, and cannot get it without
> provenance.**

The direction of traversal is the whole difference. A rule anchored at
`kafka.broker_advertised` is looking at a discovered endpoint because it walked
there from the advertisement; it never asks how any endpoint entered the run, so
`REPORT_SCHEMA.md`'s prohibition on reading provenance out of graph shape is not
merely obeyed but unreachable. A generic rule meeting a failed `dns.lookup` node
has no such anchor, and the question it must ask first — *was this endpoint asked
for, or discovered?* — is exactly `Origin`.

That is why ADR 0017's severity blocker dissolves for the Kafka rule and stands
unchanged for a generic transport rule, and why svcdoctor authorizes the first
and declines the second. The same asymmetry will apply to PostgreSQL: a rule
anchored at a discovered replica endpoint can state its impact; an unanchored
transport rule still cannot.

**Two anchored rules partition their input rather than competing for it.** The
second Kafka rule needed no arbitration with the first, and that is a property of
the anchor rather than of good manners: both start at the same kind of node and
branch on one field of it that the producer already commits to, so their trigger
conditions are complementary by construction. A third rule over the same node
should establish the same thing about itself, on the graph where the mechanisms
that enforce it come apart — the ordinary cases hide which one is doing the work.

Two consequences worth keeping visible:

- **Ownership is resolved by anchoring, not by suppression.** Where a service
  rule owns a piece of evidence, no generic rule is written for it. The engine
  does not deduplicate findings and must not learn to: suppression keyed on
  identity no document defines is how a report starts hiding things.
- **Severity is the impact of a finding's claim about its own subject**, never a
  count-derived verdict about the whole target. "Two of three brokers are
  reachable, so this is fine" is an availability model, and svcdoctor observes no
  replication topology to justify one.

### Adapter contract sizing

The registration boundary may be defined early. The adapter contract itself must stay minimal.

- Define the registration boundary before the first service lands.
- Keep the shared contract as small as the Kafka implementation actually requires.
- Phase 3.1 needed **no** generic adapter interface and **no** registry: one
  implementation, no CLI and no second service, so any method set would encode
  guesses about PostgreSQL. See ADR 0025.
- Let the real Kafka implementation reveal what belongs in the contract.
- Treat PostgreSQL as the second real implementation that validates any shared abstraction.
- Do not create speculative generic interfaces for a single implementation.

See ADR 0009.

### 5.6 A run records what it was asked about, and a sweep declares its cause

Section 5.5 established that a rule anchored at a service fact needs no provenance,
and closed with the asymmetry that followed: *a generic rule meeting a failed
`dns.lookup` node has no such anchor, and the question it must ask first — was this
endpoint asked for, or discovered? — is exactly `Origin`.*

**ADR 0042 gives the generic rule an anchor of its own**, and it is not `Origin`.

A run records one L0 evidence node describing the target the operator asked about:
`LayerInput`, `SubjectKindTarget`, subject `host:port`, PASS. The requested transport
sweep is parented to it, through the derivation parent the chain already accepts. The
composition root mints it, because probes collect measurements and the operator's
request is not a measurement — it is the reason measurements were made.

Three properties make it safe, and each is the counterpart of a property in 5.2b:

- **It answers a question about an execution, not a subject.** `Origin` asks how *an
  endpoint* entered the run and dies on a cluster advertising its bootstrap endpoint
  back — one `host:port` with a discovery-derived node and a lookup-derived path, both
  true, neither rankable. The anchor asks which *sweep* the operator caused, and that
  same case leaves it untouched: there are two sweeps, kept distinct by the scope 5.2b
  describes, and the generic rule owns one of them.
- **It is recorded, not inferred.** Nothing reads provenance off graph shape. One layer
  records one fact it holds, and a rule enumerates anchors and walks *down* — the same
  direction 5.5 identified as the whole difference.
- **It is one projection of one authority, not a second record.** The run's typed input
  produces both `report.target.requested` and the anchor's subject. Neither is
  authoritative over the other; a test pins that they agree.

**Ownership is direct parentage, and descendant reachability would be a bug.** A Kafka
advertised sweep is a *transitive* descendant of the bootstrap target — the chain runs
`tls.handshake → api_versions → authentication → metadata → broker_advertised → dns.lookup`
— so a rule owning "everything below the anchor" would diagnose a discovered broker and
duplicate the finding 5.5's Kafka rule exists to make. The boundary is therefore:

> **Generic transport diagnosis owns the sweep whose root `dns.lookup` node is a direct
> child of a requested-target anchor, and within it only the chain-shaped nodes beneath
> that root.**

The traversal is bounded in depth and typed by step, which is exactly the shape the
transport chain emits and nothing else emits. Bounding it by *layer* instead does not
work: PostgreSQL's `postgres.ssl_request` is at L3 and would be swallowed. That same
step-typing is what leaves PostgreSQL's in-band handshake service-owned, since its
`tls.handshake` node parents to the negotiation rather than to TCP.

**Implemented in Phase 4.9a-pre.** `internal/vocabulary` is the leaf that gives the four
step names one spelling — the anchor's plus the three transport steps a rule walks —
because diagnosis may not import a probe and `internal/domain` deliberately holds no step
constants. `internal/app` mints the anchor in one authorized function and passes its
identifier as the sweep's `Parent`; the Phase 4.8b ban on evidence construction there is
narrowed to that one site rather than removed, and the call count is asserted.

Two properties were verified by measurement rather than argument. Against a real Kafka
graph, the naive descendant walk is shown to capture the advertised sweep and the
authorized walk is shown not to — so the hazard above is a fact about this repository, not
a hypothetical. And against a real PostgreSQL run, both renderings of the requested
endpoint pseudonymize to the same value, with the raw hostname proven present locally and
absent from the shareable document.

**What the anchor authorized, and what it did not.** ADR 0043 then decided the policy for
**DNS and TCP**, and Phase 4.9b implemented it as `internal/diagnosis/transport`: two rules,
three findings, subjected to the anchor's logical endpoint, withheld when any path succeeded
and when measurement was incomplete. That closes ADR 0017's deferral for those two layers.

The package is the first whose subject is not a service fact, which makes it the only place
where "scan the graph for failed transport nodes" is even expressible — so its guards are
structural rather than behavioural: no `Parents` call, no self-recursive traversal, no service
name in a predicate or a literal, and imports limited to the evidence model and the
vocabulary. A prose guard checks the sentences too, because a rule can reach the right
conclusion and then explain it wrongly, and a reader acts on the sentence.

**It stays open for generic TLS, for a reason rather than an opinion.** No production run
yields a `tls.handshake` node whose direct parent is a requested `tcp.connect` — PostgreSQL
negotiates in band, and Kafka has no composition root — so a TLS policy would govern evidence
that cannot occur. That is recorded in `docs/BACKLOG.md` as a release-gate item rather than
closed by widening the walk, which would reintroduce the Kafka hazard above.

**The gap beside it is closed, and it generalizes.** PostgreSQL's in-band handshake was owned
by neither layer: its parent is a service node, so the generic walk cannot reach it, and no
PostgreSQL rule anchored at a generic step. ADR 0044 gave it to PostgreSQL and stated the
principle in one sentence — **a generic probe's evidence belongs to the layer that caused the
probe to run, read from the parent edge that layer already recorded, never from the step name
of the node itself.** Redis and MySQL inherit it unchanged if they ever negotiate in band.

That is not the provenance inference section 5.5 forbids, and the difference is who wrote the
edge: the adapter parented the handshake to its negotiation deliberately, to record why the
execution happened, so a rule reads a stated fact rather than guessing from shape. The two
ownership rules also differ in scope, deliberately — a generic transport finding claims
something about *the requested target*, so one working path withholds it; a PostgreSQL finding
claims something about *this endpoint*, so a second address working withholds nothing.

And `Origin` remains deferred: nothing here lets any layer ask how an arbitrary subject
entered a run.

### 5.7 A step that cannot run says so, at the step

Most evidence records what a peer did. One kind records what *svcdoctor* could not
do, and it exists because absence turned out to be unreadable.

A run that reaches PostgreSQL's authentication step without a credential used to
record nothing, and so did a run cancelled at that exact point. The two graphs
were byte-identical, so no rule could tell them apart — and the first of them
reported `status: OK` with every node passing and no session established
(**ADR 0046**).

The fix generalizes, and it is the same shape §5.6 uses for ownership:

> **A fact about why a step did not run belongs to the step, recorded by its
> producer at the moment it is discovered. Diagnosis reads nodes; it never infers
> from a node that is not there.**

Three properties keep it honest:

- **SKIPPED, not FAIL or UNKNOWN.** Nothing failed — no byte was sent and the peer
  was never asked — and nothing was indeterminate. The step was intentionally not
  executed, which is what SKIPPED means.
- **The class is generic.** `EXEC_REQUIRED_INPUT_MISSING` names no service, no
  protocol and no kind of input, and is distinct from the policy skip, the
  capability gap and the privilege gap that sit beside it. A future step needing a
  certificate or a token it was never given reaches the same condition.
- **Ordering is part of the contract.** The check sits after the capability gap —
  an endpoint demanding a mechanism svcdoctor cannot perform is answered with that,
  not with "configure a credential" — and before the channel policy, the endpoint
  binding and every layer that could derive or reveal a secret.

The claim it supports is `WARN`, not `ERROR`: the endpoint did nothing wrong, and
severity is the impact of a claim about its own subject rather than a lever for
forcing a process exit code. Whether a run that never reached a session should
*look* clean in a terminal is a renderer question, and the record says so instead
of answering it with severity.

### 5.7a A mechanism svcdoctor cannot perform is decided before a credential is opened

**Implemented for Kafka in Phase 6.1a; the same ordering has held in
`internal/adapter/postgres` since Phase 4.4b.**

An adapter decides whether it can perform the negotiated authentication mechanism
**before** anything reasons about a credential:

```text
negotiated mechanism supported?
  -> credential present?
  -> channel policy permits a credential?
  -> endpoint authorizes this credential?   (SecretFor)
  -> Reveal
  -> credential-bearing wire output
```

Each step is a precondition for the next, and the first one is not negotiable. Kafka's
SASL mechanisms differ in message *framing*, not only in cryptography, so handing a
session that agreed to SCRAM to a PLAIN exchange writes the identity and password as
RFC 4616's three NUL-separated fields to a peer that never agreed to receive them. The
secret is on the wire whether or not the peer can parse it. Phase 6.1a reproduced exactly
that before closing it.

**The mechanism gap outranks the channel-policy refusal.** Both decline to send a
credential, and they read differently: a policy refusal says *establish verified TLS and
this will work*, which is false when the mechanism cannot be performed at all. Reporting
the channel would send an operator to fix TLS and change nothing.

The outcome is `UNKNOWN` + a capability class — `AUTH_MECHANISM_UNSUPPORTED` — never
`FAIL`, and never `AUTH_MECHANISM_NOT_OFFERED`, which is the opposite direction and
belongs to the handshake step. §12 states the general rule: an unsupported capability is a
gap in svcdoctor, not a defect in the target. The node carries no blocker edge, because
nothing in the graph obstructed the step.

### 5.7b Generic requested-target TLS belongs to the transport that caused it

**Decided in ADR 0053, implemented in Phase 6.1b.**

A `tls.handshake` that is a **direct child** of a `tcp.connect` in a requested-target sweep is
generic transport evidence, and `internal/diagnosis/transport` owns it:

```text
target.requested -> dns.lookup -> tcp.connect -> tls.handshake     generic (ADR 0053)
tcp.connect -> postgres.ssl_request -> tls.handshake               PostgreSQL (ADR 0044)
kafka.broker_advertised -> dns.lookup -> tcp.connect -> tls.handshake   Kafka (ADR 0034)
```

The three are **structurally disjoint** and need no suppression, precedence or service-name
check. PostgreSQL's handshake is a grandchild of its connection; a Kafka advertised sweep's
lookup hangs off an advertisement rather than an anchor — even though it sits transitively
below a bootstrap target and is otherwise the identical shape, which is why the walk takes
direct children only and never recurses.

**Endpoint-scoped, and deliberately unlike DNS and TCP beside it.** Those aggregate at the
anchor and withhold on partial success, because a reachability claim is about the address set
and one working path falsifies the negative. A certificate is presented by *one* endpoint, so
a sibling succeeding cannot falsify what this one presented — and a client selecting the
failing address gets the failure. Each failing endpoint therefore carries its own finding.
This matches ADR 0044, which keeps scope from becoming a property of whether a service
negotiates TLS in band.

**Five codes over six produced classes**, none of them mirroring a `FailureClass` spelling:
generic codes carry no service prefix, so a code repeating its class would make
`failureClass` and `code` indistinguishable to a consumer matching on strings. The three
declared classes with no producer gain no code, and an unrecognized class produces nothing —
a default branch folding the unknown into the floor would grant a new producer a claim nobody
reviewed.

### 5.7c Four ways an authentication does not happen, and none of them is the others

**Implemented for Kafka in Phase 6.1c-P1; the PostgreSQL half has held since Phase 4.11b
(ADR 0046).**

An authentication step that presents nothing has four distinct reasons for it, and each
sends an operator somewhere different:

| Condition | State | Class | What the operator does |
| --- | --- | --- | --- |
| svcdoctor cannot perform the negotiated mechanism | `UNKNOWN` | `AUTH_MECHANISM_UNSUPPORTED` | nothing — the gap is svcdoctor's |
| the run configured no credential | `SKIPPED` | `EXEC_REQUIRED_INPUT_MISSING` | supply a credential |
| a credential existed and the policy withheld it | `SKIPPED` | `EXEC_SKIPPED_BY_POLICY` | fix the channel, then retry |
| the broker evaluated a credential and refused it | `FAIL` | `AUTH_CREDENTIALS_REJECTED` | fix the credential |

They must never be collapsed into one class. The two `SKIPPED` rows are the pair most at
risk, because both end with nothing sent, and they are the pair that matters most:
`EXEC_SKIPPED_BY_POLICY` reads as *establish verified TLS and this will work*, which is
false when the run holds nothing to present. Over a perfect channel it would still have
nothing to offer.

The ordering in the adapter is what keeps them apart, and it is the security contract:

```text
negotiated mechanism supported?          -> AUTH_MECHANISM_UNSUPPORTED
  -> credential present?                 -> EXEC_REQUIRED_INPUT_MISSING
  -> channel policy permits a credential? -> EXEC_SKIPPED_BY_POLICY
  -> endpoint authorizes this credential? (SecretFor)
  -> Reveal
  -> credential-bearing wire output      -> AUTH_CREDENTIALS_REJECTED
```

**The mechanism guard outranks the missing credential**, because supplying one would change
nothing for an exchange svcdoctor cannot frame; reporting a missing credential would send an
operator to configure one for a mechanism that can never run. **The missing credential
outranks the channel policy**, because with nothing to present the policy has no question to
answer and there is no endpoint binding to check.

Each of the first three records a node and returns normally. They are diagnostic outcomes,
not invocation failures. A missing credential was an invocation error in Kafka until Phase
6.1c-P1, which is precisely how a real diagnostic outcome stayed outside the report.

None of the three carries credential-derived attributes — not a length, not an identity, not
an "empty password" string. Each describes a secret that was never supplied, and a length is
a genuine disclosure.

### 5.7d Kafka protocol ownership: every outcome a producer emits has a claim

**Implemented in Phase 6.1c-P2** as `internal/diagnosis/kafka.Protocol`.

The owner-before-producer invariant of ADR 0054 is what this section records being satisfied
for Kafka. The matrix below is the whole production surface of the four protocol steps:

| Step | State | FailureClass | Owner |
|---|---|---|---|
| `kafka.api_versions` | FAIL | `PROTOCOL_UNSUPPORTED_VERSION` | `KAFKA_API_VERSIONS_VERSION_REJECTED` |
| `kafka.api_versions` | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE`, `PROTOCOL_MALFORMED_RESPONSE`, `PROTOCOL_PEER_CLOSED` | `KAFKA_API_VERSIONS_NOT_COMPLETED` |
| `kafka.sasl_handshake` | FAIL | `AUTH_MECHANISM_NOT_OFFERED` | `KAFKA_AUTH_MECHANISM_NOT_OFFERED` |
| `kafka.sasl_handshake` | FAIL | the four protocol classes | `KAFKA_SASL_HANDSHAKE_NOT_COMPLETED` |
| `kafka.sasl_authenticate` | FAIL | `AUTH_CREDENTIALS_REJECTED` | `KAFKA_CREDENTIALS_REJECTED` |
| `kafka.sasl_authenticate` | FAIL | `AUTH_MECHANISM_NOT_OFFERED` | `KAFKA_AUTH_MECHANISM_NOT_OFFERED` |
| `kafka.sasl_authenticate` | FAIL | the four protocol classes | `KAFKA_AUTHENTICATION_NOT_COMPLETED` |
| `kafka.sasl_authenticate` | UNKNOWN | `AUTH_MECHANISM_UNSUPPORTED` | `KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` |
| `kafka.sasl_authenticate` | SKIPPED | `EXEC_SKIPPED_BY_POLICY` | `KAFKA_CREDENTIAL_WITHHELD` |
| `kafka.sasl_authenticate` | SKIPPED | `EXEC_REQUIRED_INPUT_MISSING` | `KAFKA_CREDENTIAL_NOT_CONFIGURED` |
| `kafka.metadata` | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE`, `PROTOCOL_MALFORMED_RESPONSE`, `PROTOCOL_PEER_CLOSED` | `KAFKA_METADATA_NOT_COMPLETED` |
| any of the four | UNKNOWN | `EXEC_LOCAL_TIMEOUT`, `EXEC_CANCELLED` | `Result.Incomplete()`, deliberately not a finding |
| any of the four | PASS | — | the renderer's outcome line (ADR 0052), deliberately not a finding |

Two rows were found by re-deriving the surface from source rather than trusting the earlier
audit, and both matter. `AUTH_MECHANISM_NOT_OFFERED` reaches `kafka.sasl_authenticate` because
`authenticationFailure` falls through to `handshakeFailure`; it keeps the specific code rather
than falling into the floor. And `PROTOCOL_UNSUPPORTED_VERSION` is *unreachable* at
`kafka.metadata`, because that step consults no broker error code — so no mapping exists for
it, since a dead mapping authorizes a claim for evidence that cannot occur.

**The table is closed and has no default branch.** A triple absent from it produces nothing,
including a `FailureClass` a later phase adds. Folding the unrecognized into a floor would
grant a new producer the floor's claim — "svcdoctor could not attribute why" — which may be
false for a class that is perfectly attributable.

**No anchor walk, and that is not an oversight.** The generic transport rules descend from
`target.requested` because a `tls.handshake` node is service-neutral and only provenance
distinguishes a bootstrap sweep from an advertised one. A `kafka.sasl_authenticate` node has no
such ambiguity: the step name *is* the anchor, which is the case §5.5 describes. So the rule
walks no edges, needs no `Origin` and parses no identifier — with one exception, the policy
refusal, which reads its `blockedBy` edge because its claim is *why nothing was attempted* and
that answer lives on another node.

**One node, at most one finding.** Disjointness is structural: the table is keyed on the node's
own step, state and class, so nothing needs precedence, suppression or a second pass. The
advertised-broker rules cannot compete, because they anchor at `kafka.broker_advertised` and
require a *passing* `kafka.metadata`.

### 5.8 Kafka BASIC: decided in Phase 6.0, not implemented

Five records fix Kafka's prerequisites. Each is **Accepted**, and as of Phase 6.1c three
of them describe shipped code: ADR 0050 and ADR 0051 are implemented by the composition
root in §5.9, and ADR 0053 was implemented a phase earlier by design. ADR 0052 remains
renderer vocabulary and waits for Phase 6.4; the SCRAM constraints below wait for the
Phase 6.2a security review.

**`internal/adapter/kafka` now has exactly one production importer, `internal/app`, so
every Kafka stage is product-reachable.** That sentence used to read "no production
importer", and the guard that enforced it was transformed rather than deleted — see
§12.1.

**Discovery does not widen secret authority (ADR 0050).**

> Discovery may create evidence; discovery must not create secret authority.

A Metadata response is evidence obtained from the authenticated bootstrap peer, never
authorization to send a credential elsewhere. A credential is presented on exactly one
connection — the selected bootstrap path — and advertised broker measurement stays
credential-free DNS, TCP and TLS, as ADR 0033 already had it. Verified TLS to the
bootstrap endpoint proves endpoint identity, not transferable cluster-wide authority;
Kafka has no cluster-identity assertion a client can verify. Authenticating a discovered
broker requires a new explicit authority decision, not a side effect of another phase.

**Run completeness is asymmetric (ADR 0051).** PASS is existential — one working address
resolves a logical advertisement. FAIL is universal — the negative claim *this endpoint
was not reachable* holds only when no selectable path was left unmeasured. A refused
address beside an address that timed out locally therefore leaves the run **incomplete**,
while a passing address beside one that timed out does not. `Result.Incomplete()` is
reused; no schema change.

**The product outcome is what was obtained (ADR 0052).** Kafka has no session, so the
renderer's terminal line becomes a per-service `outcome`, and Kafka's is
`Kafka metadata obtained` — narrower than *cluster* metadata, because the request is
Metadata v1 with `Topics = []` and returns no topic, partition, replica or ISR state.
Topology is a separate count of advertised broker endpoints **reached**, past tense, with
`not measured` never collapsed into `not reached`, and never `usable` — nothing
authenticates a discovered broker.

**Generic requested-target TLS is endpoint-scoped (ADR 0053).** DNS and TCP claims concern
a logical address set and withhold on partial success; a certificate is presented by one
endpoint, so a sibling succeeding cannot falsify what this one presented. Five codes,
carrying no service prefix and none mirroring a `FailureClass`. Kafka bootstrap composition
is its first production producer, which is why it is sequenced before that composition
(§12.1).

**SCRAM's shared core never receives plaintext (ADR 0055).** The RFC 5802 derivation is
already implemented for PostgreSQL in `internal/adapter/postgres/wire/scram.go` using the
standard library only, so completing Kafka SCRAM adds **no module dependency**. The security
review this section previously deferred to is complete — it is Phase 6.2a — and it
**rejected** the model stated here before it: a shared core taking plaintext as a short-lived
argument.

The adopted model is ADR 0055's Model D. The core exposes **no API that accepts a password in
any type**. It parses and validates everything the peer chose — nonce extension, salt,
attribute grammar, the iteration ceiling — and *then* invokes a derivation callback the wire
package supplied, which closes over the plaintext and calls `crypto/pbkdf2` inside the wire
package. What crosses the package boundary is the SaltedPassword: credential-derived and
sensitive, but scoped to one principal on one target rather than being the operator's reusable
password.

This keeps the property ADR 0038 §16 calls "the whole point" — no PBKDF2 runs before the peer's
demand has been bounded — while making a plaintext leak from the shared package structurally
impossible rather than lint-enforced. The core still must not import `internal/security` or
`net`, call `security.Reveal`, perform I/O, log, use `fmt`, put peer bytes in errors, know an
endpoint, know service framing or retain connection state. It owns its own size and iteration
bounds, because the two wire packages bound peer payloads eight times apart. `Reveal` stays in
wire packages and its production call-site count remains **exactly two**.

Extraction is not purely extraction: Kafka reads the username from the SCRAM `n=` field, so
RFC 5802 §5.1 `saslname` escaping is new, unvectored code.

**Phase 6.2a-R2 made that contract exact (ADR 0056), and Phase 6.2 is authorized.** The core is
`internal/sasl/scram`, a leaf importing nothing internal and exactly six standard-library
packages. It exposes `Begin(Username) (*State, clientFirstBare, error)`,
`(*State).Continue(serverFirst, Derive) (clientFinal, error)` and `(*State).Verify(serverFinal)
error`. It generates the nonce itself — a caller-supplied nonce would put entropy authority in
two wire packages. The derivation callback is called **exactly once**, after ten validation
steps including the iteration ceiling and an encoded-salt bound checked *before* the base64
decode, and never on any rejection path. State is minimized at each step: after `Continue` it
holds a 32-byte expected server signature and nothing else.

**SASLprep is refused for a correctness reason, not a convenience one.** PostgreSQL applies it
on both sides; Apache Kafka does not (`KAFKA-6272`). The two services require **opposite**
behaviour for non-ASCII credentials, so no shared implementation is correct for both. Over
printable ASCII SASLprep is provably the identity, so svcdoctor restricts usernames and SCRAM
passwords to U+0020–U+007E and is correct against both, with no Unicode dependency. SASLname
escaping is core-owned, because it is pure RFC grammar.

The gate transition is atomic: `TestNoSharedSCRAMPackageExists` is deleted in the *same* commit
that introduces the package, the depguard allowlist and the positive guards — never before.

**Phase 6.2 implemented all of it.** `internal/sasl/scram` is a leaf importing six standard
library packages and nothing else, enforced by a depguard allowlist and by the package's own
AST guards. PostgreSQL was migrated onto it with no semantic change — three sentinels became
aliases so `errors.Is` identity and every `FailureClass` survived untouched, and the two
framing sentinels were deliberately translated rather than aliased so that "this postgres
frame could not be decoded" and "this SCRAM attribute list could not be decoded" stay distinct.
Kafka SASL/SCRAM-SHA-256 followed, validated against the real three-broker cluster including a
principal whose name requires `=2C`/`=3D` escaping.

**`security.Reveal` still has exactly two production call sites**, and keeping it there took a
correction: giving PLAIN and SCRAM an exported exchange each — the obvious structure — gave
each its own reveal and silently made three. `kafka/wire.Authenticate` reveals once and
dispatches on the plaintext, and a repository-wide AST guard now pins the count rather than
leaving it to lint plus memory.

Adding SCRAM made two outcomes newly reachable at `kafka.sasl_authenticate`, and ADR 0054
required their owners in the same change-set: `AUTH_PEER_VERIFICATION_FAILED`, because SCRAM
authenticates **both** parties and "the broker did not prove it knows the credential" is the
opposite claim from "the broker refused what svcdoctor presented", and `UNKNOWN` +
`EXEC_UNSUPPORTED_BY_SVCDOCTOR` for credentials outside the printable-ASCII range.

### 5.9 Kafka application composition: one journey, one credential, one selected socket

**Implemented in Phase 6.1c.** `internal/app.DiagnoseKafka` is the second composition
root and the first production importer of `internal/adapter/kafka`, which makes every
Kafka stage product-reachable in one commit. It was allowed to land because the owners
landed first (§12.1): the mechanism guard in 6.1a, generic requested-target TLS in 6.1b,
the required-input producer in 6.1c-P1 and the protocol claim table in 6.1c-P2.

```text
target.requested                                   L0, the only node app creates
  └── dns.lookup                                   L1
        ├── tcp.connect [addr A] ── tls.handshake  L2/L3, every resolved address
        └── tcp.connect [addr B] ── tls.handshake
                 ├── kafka.api_versions            L4, every completed path
                 └── kafka.sasl_handshake          L5, every completed path
  ------------------------ credential boundary ------------------------
                       └── kafka.sasl_authenticate L5, at most ONE path
                             └── kafka.metadata    L6
                                   └── kafka.broker_advertised × N
                                         └── dns.lookup    credential-free
                                               └── tcp.connect
                                                     └── tls.handshake
```

**Discover broadly, authenticate narrowly.** Everything above the credential boundary is
credential-free, and the SASL handshake is credential-free as a property of the Kafka
protocol rather than as a promise: a `SaslHandshake` request carries a mechanism name and
nothing else. Measuring a second path therefore costs the broker a connection and not an
authentication attempt, which is what makes per-path divergence observable before any
secret is in play.

**Bootstrap-only credential authority.** ADR 0050 is enforced in four independent ways,
none of which relies on review:

- `KafkaParams.validate` refuses a credential bound to anything but the logical target, so
  a rebind costs the target zero connections and comes back as `ErrInvalidInput` rather
  than as evidence.
- The composition calls `security.NewCredential`, `security.NewSecret`, `security.Reveal`
  and `Credential.SecretFor` **nowhere**; a static guard in `test/security` fails on any
  of them.
- `kafka.MeasureAdvertised` takes a builder, a list of advertisements and a transport
  plan. No parameter can hold credential material, and a reflection guard fails if
  `TransportPlan` ever grows a field that could.
- A behavioural test drives a hostile broker that advertises an attacker endpoint holding
  a **valid certificate signed by the CA the run trusts**, and counts zero application
  bytes at the attacker above its TLS layer.

**At most one credential-bearing attempt per run.** One `kafka.Authenticate` call site,
outside any loop, both asserted statically. There is no retry against a sibling address,
no mechanism fallback and no channel downgrade: a credential-bearing retry is not an L2 or
L3 transport retry, because it spends an attempt against whatever counts them.

**Path selection.** Candidates are the paths whose broker accepted the mechanism, and the
canonically smallest address wins. Unlike PostgreSQL's selector there is no class
partition, because a `HandshakeSession` exists only where the broker agreed to
authenticate — the other class is unreachable. Canonical order is a tie-break among paths
that were **all** already measured through TLS, ApiVersions and the handshake, not a
preference for an address family.

**A path that is not usable is not selectable, structurally.** `transport.Run` records a
`Continuation` only when the handshake produced a connection, so TCP PASS + TLS FAIL and
TCP PASS + TLS UNKNOWN never reach the Kafka adapter at all. The composition filters
nothing; there is nothing to filter.

**Continuation ownership.** Each stage consumes what it is given and hands on only what
the protocol leaves usable. The composition closes unselected candidates explicitly at the
moment of selection, and every stage result is closed on every path out through a
deferred, idempotent `Close`. The two are deliberately redundant: either alone keeps the
ledger balanced, and a test that counts opens against closes on real sockets is what makes
that a fact rather than an inspection of `defer` statements.

**Advertised measurement stops at transport.** No ApiVersions, no SaslHandshake, no
SaslAuthenticate and no second Metadata is sent to a discovered endpoint, and the sweep is
gated on the Metadata exchange having completed.

#### 5.9.1 A TLS identity override is authority for one endpoint, and discovery cannot widen it

**This is a trust-authority decision, not a plumbing detail**, and it is the second thing
in this phase that a Metadata response must not be allowed to widen. ADR 0050 says a
*credential* authorized for the endpoint the operator named does not travel to an endpoint
a peer named. `TLSOptions.ServerName` is the same kind of value — **an assertion about who
one endpoint must prove itself to be** — and it gets the same rule:

> A bootstrap-only `ServerName` override **must not** be inherited by Metadata-discovered
> brokers. Every advertised broker is verified against **its own advertised hostname**.

The advertised plan therefore inherits exactly the run-wide trust configuration and nothing
endpoint-specific:

| Field | Inherited | Why |
|---|---|---|
| `RootCAs` | **yes** | which authorities this run trusts is a property of the run |
| `MinVersion` / `MaxVersion` | **yes** | a protocol-version floor is a run-wide policy |
| `InsecureSkipVerify` | **yes** | an explicit per-run opt-in, recorded once on the report |
| `ServerName` | **no** | it names *one* endpoint's identity |

Inheriting it would be wrong in both directions, which is why neither is acceptable. It
would **manufacture false failures**: every advertised broker's certificate would be checked
against the bootstrap's name, and managed Kafka routinely serves a distinct certificate per
broker endpoint, so a healthy cluster would report identity mismatches no real client would
ever see. And it would **weaken a real check**: whenever a discovered broker happened to
present a certificate for the bootstrap name, it would verify — so an attacker who could
obtain, or already holds, a certificate for the bootstrap name would be trusted at an
address the operator never named.

Clearing it restores the transport chain's default, which is to verify against the host the
sweep was asked to reach. The advertised sweep therefore verifies **more** strictly, not
less: each endpoint against its own identity rather than all of them against one.

`TestASuccessfulMetadataExchangeSweepsAdvertisedEndpoints` fails if the override travels.

**Completeness is Kafka's own predicate.** `incompleteKafkaRun` implements ADR 0051:
`kafka.metadata` PASS does **not** short-circuit, because advertised reachability is half
of what the command promised to measure. One working path resolves an advertisement
outright; a failure resolves it only when no selectable sibling was left unmeasured. An
unrecognized sweep shape reads as unresolved, never as a verdict.

**What Phase 6.1c does not do.** No CLI route and no renderer: `svcdoctor diagnose kafka`
does not exist, and ADR 0052's `outcome` and `topology` lines are Phase 6.4. No SCRAM —
see §5.8 and the Phase 6.2a gate. No new `FindingCode`, no new `FailureClass`, no schema
change, no dependency, and `Reveal` stays at two production call sites.

## 6. Diagnosis

Diagnosis consumes normalized evidence only.

> **Diagnosis consumes normalized evidence. Diagnosis does not perform network or protocol I/O.**

Diagnosis does not:

- call probes
- call adapters
- resolve DNS
- open sockets
- perform TLS handshakes
- send protocol requests such as Kafka requests

Diagnosis runs on a frozen, complete evidence set. When evidence is missing or
inconclusive, diagnosis reports `UNKNOWN`, `SKIPPED`, or an explicit insufficient-evidence
result. It never performs I/O to fill the gap.

Cross-service correlation logic and service-specific correlation rules remain separate.
Cross-service transport correlation lives in `internal/diagnosis/transport/`; service rules
live in `internal/diagnosis/<service>/`.

`internal/diagnosis/kafka/` and `internal/diagnosis/postgres/` exist and hold rules;
`internal/diagnosis/transport/` is empty and is **not** a gap waiting to be filled — whether
generic transport findings should exist at all needs run intent, which `diagnosis.Rule`
cannot see. A run that fails at DNS, TCP or TLS therefore produces complete evidence, a
correct `firstBrokenLayer`, and no finding. See ADR 0017 and ADR 0040 section 26.1; it is
tracked as a product release gate in `docs/BACKLOG.md`.

Each service rule package imports `internal/domain` and its own
`internal/service/<service>/` vocabulary leaf, and nothing else. The leaf exists because
depguard denies diagnosis the adapter import while the two layers still share step names and
a few attribute keys; it holds constants and no behaviour. This allows service-specific knowledge without
contaminating the shared engine.

### 6.1 Rule contract

```text
immutable domain.Graph -> rules -> []domain.Finding
```

A rule is a function, `func(domain.Graph) []domain.Finding`, owned by
`internal/diagnosis`. The frozen graph is its only argument and it returns no error: it
reads in-memory evidence and has nothing operational to fail at. See ADR 0017.

- The engine holds rules, evaluates them, and orders the result. It does not filter, rank,
  merge or suppress findings, and it holds no service name to branch on. A service rule is
  simply a rule that is only wired in for that service.
- Findings come back in the canonical order of `domain.SortFindings`, the same order the
  report uses. Wiring order does not reach the output.
- The engine does not deduplicate. Deciding when two findings are one conclusion is not
  defined anywhere, and dropping one could remove a real finding.
- Diagnosis stops at findings. It assembles no report, derives no summary (ADR 0015), and
  maps nothing to an exit code.
- A rule must not knowingly emit a dangling evidence reference, but the authoritative
  membership check stays at report construction, where both sides are owned (ADR 0014).

Purity is enforced by `depguard` in `.golangci.yml` rather than left to discipline:
`internal/diagnosis` may not import probes, adapters, renderers, platform collectors, `net`,
`net/http`, `crypto/tls`, `os`, `os/exec`, or a random source.

### 6.2 Redaction boundary

```text
LOCAL_FULL Report -> Redact -> SHAREABLE_REDACTED Report
```

> **Redaction transforms an already-valid canonical report into another valid canonical
> report. It does not diagnose.**

It lives in `internal/security/redaction`, a subpackage so that `internal/security` stays a
leaf and the `domain -> security` direction remains available. It creates no findings,
changes no severity, confidence, kind, state, failure class or graph relationship, performs
no I/O, and never mutates its input.

- Identity is removed, correlation is preserved: each distinct value maps to one stable
  pseudonym everywhere it appears. Ports survive; they say which protocol was expected.
- Evidence identifiers are rewritten, because the identifier grammar admits hostnames.
  Every reference is remapped with them and the result passes the ADR 0014 check.
- Assignment is deterministic: values are collected, sorted, then numbered. Pseudonyms are
  per-report, so two shared reports cannot be correlated.
- The output is rebuilt through the ordinary domain constructors, so its summary is
  re-derived (ADR 0015) rather than copied.
- Redaction fails closed. There is no partial result, and errors never name the value they
  were protecting.

Enforced by `depguard`: the package may not import probes, adapters, diagnosis, renderers,
`net`, `net/http`, `os`, `os/exec`, a random source, or `regexp` — redaction is structural,
and pattern matching is only a safety net over already-known values. See ADR 0018.

## 7. Renderers

Renderers transform the canonical report model into output formats.

v0.1 target outputs:

- Terminal
- JSON
- Markdown
- HTML

JSON is the canonical representation. Terminal, Markdown, and HTML are derived from the
same canonical report model.

Renderers do not:

- diagnose
- create findings
- compute severity
- discover secrets
- interpret protocol semantics

## 8. Service extensibility

New services are registered explicitly at a single composition root. There is no central
service switch.

Forbidden:

```text
if kafka { ... } else if postgres { ... } else if redis { ... }
```

Accepted, and not considered sprawl:

```text
registry.Register(kafka)
registry.Register(postgres)
registry.Register(redis)
```

Adding a service may change that one wiring point. It must not require edits across
unrelated adapters, probes, diagnosis rules, or renderers.

Not wanted:

- magic `init()` auto-registration
- reflection-based plugin discovery
- a generic plugin framework

Desired extension shape:

```text
internal/adapter/redis/
internal/diagnosis/redis/
internal/service/redis/          (only when both of the above name the same constant)
internal/adapter/redis/testdata/
```

`internal/service/<service>` is a **leaf vocabulary package**: constants, no behaviour, and
`internal/domain` as its only import. It exists because diagnosis may not import an adapter,
and a rule anchored at a service fact must still name the step it anchors at.

It is created on demand and only for what a second package genuinely reads. It is not a
shared service layer: no interface, no registry, no dispatcher, no protocol logic, and no
second copy of a value the evidence already carries. Phase 3.6 created the first one for
exactly three Kafka constants and left the rest in the adapter. See ADR 0034 §19, and the
`service-vocabulary-is-a-leaf` depguard rule that keeps it a leaf.

See ADR 0009.

## 9. Finding codes

Finding codes carry a service namespace, for example:

```text
KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE
POSTGRES_TLS_DECLINED
REDIS_ANNOUNCED_NODE_UNREACHABLE
```

The core knows only the generic code contract. It must not hold a central enumeration of
every service's codes. Code ownership stays in the service-specific package.

A central enum listing every service is the same coupling as central service branching,
in a different shape.

## 10. Evidence boundary

The chain is:

```text
raw protocol/network result -> Observation -> normalized Evidence -> Diagnosis -> Finding
```

Canonical evidence must preserve:

- a stable schema
- deterministic serialization
- redaction safety
- no raw protocol-library or runtime objects crossing the boundary

Raw objects such as protocol-library response structs, `tls.ConnectionState`, or transport
error values must not enter canonical evidence. Uncontrolled `map[string]any` payloads are
also excluded, because they defeat schema stability, deterministic output, and structural
redaction at the same time.

When a service needs complex data, prefer:

- a normalized scalar or list representation, or
- separate evidence nodes

Do not introduce speculative machinery around this boundary. Constructs such as
`EvidenceProvider`, `ObservationFactory`, `EvidenceProcessor`, `ProbeResultFactory`, or
`GenericEvidenceNormalizer` should not exist without a demonstrated need.

See ADR 0010.

## 11. Evidence DAG

The evidence structure is not a linear pipeline. Topology discovery reveals new endpoints,
each of which opens its own probe chain.

```text
TARGET
  |
  v
DNS -> TCP -> TLS -> PROTOCOL -> AUTH -> TOPOLOGY
                                            |
                                            +--> broker-1 -> DNS -> TCP -> TLS -> protocol
                                            +--> broker-2 -> DNS -> TCP -> TLS -> protocol
                                            +--> broker-3 -> DNS -> TCP -> TLS -> protocol
```

Each node carries one of:

```text
PASS | FAIL | DEGRADED | UNKNOWN | SKIPPED
```

Kafka example:

```text
bootstrap.kafka:9092
  -> DNS PASS
  -> TCP PASS
  -> TLS PASS
  -> ApiVersions PASS
  -> Metadata PASS
       |
       +-> broker-1:9092 -> DNS PASS -> TCP PASS -> TLS PASS
       +-> broker-2:9092 -> DNS FAIL
       +-> broker-3:9092 -> DNS PASS -> TCP FAIL
```

A resulting finding may be `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`, explicitly qualified as
being true **from the current vantage point**, and linked to the evidence that demonstrates
both bootstrap success and discovered-endpoint failure.

### 11.1 Evidence graph boundary

```text
Evidence     = one canonical normalized fact
Graph        = the relationships between facts
GraphBuilder = mutable construction
Freeze       = the immutable boundary diagnosis consumes
```

> **The graph stores structure. It does not decide execution semantics.**

- **Relationships are graph-owned.** Parent references live in the graph, not on
  `Evidence`. A fact does not carry a claim about the shape of the run.
- **Multiple parents are allowed**, which is what makes the structure a DAG. Cycles and
  self edges are rejected.
- **`BlockedBy` is distinct from a parent.** A parent is structure or derivation; a
  blocked-by reference is the explicit causal explanation for why a `SKIPPED` check did
  not run, and only `SKIPPED` evidence may carry one. The graph never infers it — the
  orchestration layer records it.
- **Ordering is lexical `EvidenceID` order**, never insertion order, so a report is
  byte-stable for the same content regardless of probe concurrency.
- **`Freeze` produces an immutable `Graph`.** Diagnosis consumes only that, never the
  builder, which is what allows diagnosis to be a pure function.

Explicitly outside the graph's responsibility: endpoint semantic equality and
deduplication, topology recursion, visited sets, depth limits, retries, concurrency,
scheduling, timeouts, authentication, credential forwarding, short-circuit decisions,
and any service-specific semantics. The graph validates only its own structural
integrity.

Cycle detection and a visited set look alike and are not the same thing. Cycle detection
is graph integrity; "do not probe this endpoint again" is execution policy. See ADR 0013.

## 12. Short-circuiting and claim discipline

Dependent layers must not generate false positives when an earlier layer fails.

- DNS FAIL -> TCP/TLS/protocol/auth are SKIPPED for that endpoint and no downstream claim is made.
- TCP FAIL -> TLS/protocol/auth are SKIPPED.

**A SKIPPED node requires a subject that can be named honestly.** The rule above is about
claims, not about manufacturing nodes: a subject names what its layer would have touched
(ADR 0020), so a skipped node exists only when that thing is known.

- TCP failed for a known address, so the TLS node exists: `SKIPPED`, classified
  `EXEC_SKIPPED_PREREQUISITE_FAILED`, and `BlockedBy` the TCP node.
- A lookup that produced no address leaves **no** TCP or TLS nodes, because there is no
  address to name. Inventing one to hang a skipped node on would be a synthetic fact. The
  failed DNS node is the record, and the summary's first broken layer is L1.

See ADR 0024.
- TLS FAIL on a TLS-required path -> protocol/auth are SKIPPED unless a safe diagnostic probe explicitly justifies otherwise.

Additional claim rules:

- An unsupported capability is not a FAIL. svcdoctor not supporting a mechanism is a gap in
  svcdoctor, not a defect in the target. Use `UNKNOWN`.

- **A normalized failure class is scoped to the protocol step that proved it.** As of Phase
  4.5b the PostgreSQL adapter has three SQLSTATE classifiers, one per step, and merging them
  into a shared dictionary is a rejected alternative rather than an open refactor. The same
  `3D000` means *the requested database does not exist* at session establishment and means
  nothing at startup or authentication, because neither of those steps has named a database
  for a lookup to fail on. A code arriving where its meaning is not established gets the
  honest weak class. See ADR 0039 section 7.1.

  This rule has teeth as of Phase 4.4b, which is the first phase with several ways to be
  unable to do something. A PostgreSQL server demanding md5, a server offering only
  `SCRAM-SHA-256-PLUS`, a password outside the range svcdoctor can prepare, and an iteration
  count above svcdoctor's ceiling are all `UNKNOWN` + a capability class — never `FAIL`, and
  never `AUTH_CREDENTIALS_REJECTED`. Each says *"svcdoctor could not determine whether this
  credential authenticates"*, and none of them is a claim about the target. A peer that
  positively does **not** offer what svcdoctor speaks is the other case, and it stays `FAIL`
  with `AUTH_MECHANISM_NOT_OFFERED`, because that is a fact the peer evidenced.
- Missing privilege is not healthy and not a FAIL. Use `SKIPPED` and record the privilege required.
- A local timeout is not a remote failure. Distinguish an exceeded local budget from an
  observed remote timeout; the former means nothing was learned about the target.
- Unknown version blocks version-dependent claims.

Short-circuiting is part of correctness, not merely an optimization.

### 12.1 Evidence that can fail does not ship before something can explain it

**Decided in ADR 0054. Accepted as policy; mechanical enforcement is deferred.**

> A production-reachable FAIL-producing evidence stage must not be introduced unless
> every reachable FAIL outcome has a diagnosis owner, or an Accepted ADR explicitly
> records evidence-only behaviour as intentional and explains why it is safe.

> UNKNOWN and SKIPPED outcomes must have an explicit visibility policy whenever their
> absence from the findings list could make a report appear complete or healthy when it
> is neither. The policy may be a finding, run-level visibility such as
> `Result.Incomplete()`, or a recorded decision that the evidence node alone suffices —
> but not silence by default.

The invariant exists because the opposite failed repeatedly during PostgreSQL closure:
`findings: 0` beside `status: OK` and a broken L3 (closed by ADR 0044), requested-target
transport failures with no owner (ADR 0043), a missing credential producing a graph in
which every step passed (ADR 0046), and a local timeout visible as nothing at all
(ADR 0047). Each was found late, by audit rather than by the phase that added the
producer, because a missing finding fails no test and looks exactly like a healthy target.

Two consequences bind planning:

- **Owner before producer.** When a phase would introduce a producer whose failures have
  no owner, the owner lands first, in its own phase. This is why generic requested-target
  TLS diagnosis is sequenced before `DiagnoseKafka` composition.
- **The escape hatch is a record, not an omission.** Evidence-only is legitimate — ADR 0033's
  advertised sweep was deliberately evidence-only for two phases — provided an Accepted ADR
  argues it and states a reopen condition.

Enforcement is a **per-service closure test**, specified in ADR 0054 §5. A static lint
cannot substitute, because reachability of a `FailureClass` from a composition root is not
decidable from the import graph.

**Kafka has one as of Phase 6.1c; PostgreSQL does not yet.** For Kafka it is two files that
together satisfy §5, and the first of them is the old negative gate turned around rather
than retired:

- `internal/diagnosis/kafka`'s `TestTheAuthorizedTableIsExactlyTheProducedOutcomes`
  enumerates every outcome the four protocol producers emit and fails in **both**
  directions — a produced outcome with no owner, and an owner for an outcome no producer
  emits.
- `test/security/kafka_production_reachability_test.go` asserts the positive closure now
  that composition exists: **exactly one** production importer of the adapter and it is
  `internal/app`, **exactly one** `DiagnoseKafka`, the exact set of six rules the
  composition wires, no credential minting or secret resolution in the composition root,
  one authentication call site outside any loop, and no credential-bearing field on the
  advertised transport plan.

The two guard files assert each other's key contents, because a guard cannot protect
itself and the failure this boundary exists to prevent is a guard deleted to make a commit
pass.

## 13. Execution budget, cancellation, and concurrency

These are architectural semantics. Exact timeout values and worker counts are implementation
decisions and are not fixed here.

- Every run has a local execution budget.
- Individual probes may have narrower timeouts than the run budget.
- A local deadline expiring is **not** proof that the remote target failed. An exhausted local
  budget means nothing was learned about that step; it is `UNKNOWN`, not `FAIL`.
- Cancellation preserves already collected evidence. Evidence gathered before cancellation
  remains valid and is reported.
- A partial run may still produce a report. Incompleteness is surfaced in the summary and in
  the exit code (see `docs/SCOPE.md`).
- Concurrency may be used later to probe independent endpoints in parallel.
- Output ordering must remain deterministic regardless of execution concurrency. Concurrent
  execution is an implementation detail; the canonical report is ordered canonically.

The last two points together are the constraint that matters: parallelism may change how fast
a run completes, never what the report says or in what order it says it.

## 14. Dependency direction

Preferred direction:

```text
cmd -> app -> adapter/probe -> domain
             diagnosis -----> domain
             render --------> domain
             platform ------> domain
             security ------> shared safe primitives

             adapter/<svc>  -> service/<svc> -> domain
             diagnosis/<svc> ---^
```

`service/<service>` sits below both an adapter and a service's rules, which is what lets the
two share a constant without diagnosis importing the adapter. It imports `domain` and nothing
else.

Forbidden dependencies include:

- probe -> adapter
- probe -> diagnosis
- adapter -> render
- diagnosis -> probe
- diagnosis -> adapter/network client
- render -> adapter/probe/diagnosis execution
- platform -> adapter/probe/diagnosis

## 15. Platform boundary and vantage

`internal/platform/` provides environment context, not diagnosis.

Platform collectors and context providers:

- collect facts and context
- do not produce diagnosis
- do not contain adapter logic
- do not contain protocol semantics

The application/orchestration layer collects platform context when required. Diagnosis
consumes only normalized platform evidence/context, exactly as it consumes any other
evidence, and performs no platform I/O itself.

Kubernetes integration stays Phase 5 work, with the rest of platform and productization. No
Kubernetes client library selection is made at this stage. See `docs/BACKLOG.md` for the
authoritative phase numbering.

### Vantage

A **vantage** identifies where probes were executed from, and it is a first-class concept
rather than run metadata. Vantage collection belongs to this platform/orchestration boundary.

For v0.1 local execution the vantage must at minimum distinguish the local host. Kubernetes
and remote execution contexts are future extensions and are deliberately under-specified.

> A connectivity finding is only valid from the recorded vantage point, unless the evidence
> explicitly proves otherwise.

Every topology and connectivity finding retains its vantage context. See ADR 0012 and
`docs/REPORT_SCHEMA.md`.

## 16. Rules

v0.1 uses typed Go rules. Do not add an external DSL. Rules must be deterministic and unit-testable. Expr/CEL may be considered later only for validated user-defined predicate requirements.

## 17. Test data convention

- Unit and package-level fixtures live in a package-adjacent `testdata/` directory,
  for example `internal/adapter/kafka/testdata/` and `internal/diagnosis/kafka/testdata/`.
- Cross-package and environment-dependent tests live under `test/integration/` and `test/security/`.
- `test/integration/kafka/` runs the Kafka vertical against a real three-broker cluster behind
  the `integration` build tag, so `go test ./...` never needs Docker. It is the Phase 3
  acceptance gate; results are recorded in `docs/validation/KAFKA_PHASE3_VALIDATION.md`.

## 18. Open implementation decisions

These are deliberately left open. Implementation should reveal the minimum natural boundary
rather than a boundary chosen in advance.

**Attribute-key ownership.** Adapters and diagnosis rules for the same service will need a
shared normalized attribute vocabulary. Where those key definitions live is not decided. Any
chosen location must not create a forbidden dependency direction (section 14). Kafka
demonstrates the real boundary first; PostgreSQL later validates whether the pattern is stable.

**Contract-package placement.** Final package ownership for the Adapter contract, the
registry, the probe chain contract, the diagnosis `Rule` contract, and CLI orchestration is
not decided beyond the architecture principles already locked. Concrete structs first;
interfaces only at real boundaries.

## 19. MCP and other frontends

MCP is not part of the core. Once the canonical JSON schema and reusable application service are stable, MCP can become another frontend/adapter:

```text
             +-> CLI
Diag engine -+-> MCP (later)
             +-> API (later, only if justified)
```

Do not couple core domain types to MCP types today.
