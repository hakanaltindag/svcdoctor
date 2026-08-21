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
  **declared** with `domain.HostAttr` / `domain.HostListAttr`, one identity per
  value or list entry, never embedded in prose (ADR 0022).
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

The same split governs timeouts. A per-probe or per-chain deadline is transport-local. The
whole-run execution budget, cancellation propagation, and the partial-run exit code in
section 13 belong to the application boundary.

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

Phase 3.2 added L5 mechanism discovery — `kafka.sasl_handshake` — and stopped
there. The boundary it draws generalizes past Kafka (**ADR 0026**):

- **A step that sends no credential may run on every measured path**, because it
  costs the target nothing. ApiVersions and SaslHandshake both qualify: a
  handshake request carries a mechanism name and no identity or secret.
- **A step that sends a credential may not run anywhere until a layer can say
  where.** An authentication attempt is logged, counted and lockout-relevant, so
  "every path" and "the first path" are policy, not defaults — and *the first*
  would silently mean IPv4, the artifact ADR 0024 removed from the transport
  chain.
- **Path selection for credentials therefore belongs to the layer that can record
  why it chose**, which is the orchestration boundary that does not exist yet.
- **Mechanism, policy and diagnosis stay separate.** That the protocol permits
  PLAIN on an unverified channel, that svcdoctor should refuse it, and that using
  it is worth reporting are three statements owned by three layers. An adapter
  that silently refused would invent policy; one that silently sent would break a
  documented one. Both are deferred rather than guessed.

**Connection lifetime follows the protocol, not the evidence state.** ApiVersions
keeps a connection whose broker answered with an error code, because any request
may still follow it; a rejected SaslHandshake closes one, because the broker will
accept only the agreed mechanism's continuation and there is nothing left to send.
The criterion is whether the protocol defines a next message on that socket.

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
live in `internal/diagnosis/<service>/`. This allows service-specific knowledge without
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
internal/adapter/redis/testdata/
```

See ADR 0009.

## 9. Finding codes

Finding codes carry a service namespace, for example:

```text
KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE
POSTGRES_TLS_POLICY_MISMATCH
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
- Missing privilege is not healthy and not a FAIL. Use `SKIPPED` and record the privilege required.
- A local timeout is not a remote failure. Distinguish an exceeded local budget from an
  observed remote timeout; the former means nothing was learned about the target.
- Unknown version blocks version-dependent claims.

Short-circuiting is part of correctness, not merely an optimization.

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
```

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
