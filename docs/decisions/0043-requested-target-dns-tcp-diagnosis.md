# ADR 0043: svcdoctor says what it could not reach, and no more than that

## Status

**Accepted, and implemented in Phase 4.9b.**

`internal/diagnosis/transport` holds two rules and three codes, wired into
`internal/app.DiagnosePostgres` beside the four PostgreSQL rules. A run that
cannot resolve its target now reports `DNS_NAME_NOT_RESOLVED` and
`PROBLEMS_FOUND` where it previously reported nothing and `OK`; a run whose every
address refuses reports `TCP_CONNECTION_NOT_ESTABLISHED`.

`FindingCode` went from 14 to **17**. `FailureClass` stays 39, `schemaVersion`
**1**, `security.Reveal` **two**, the dependency set one. No CLI, no renderer, no
Kafka composition, and no TLS claim of any kind.

Two things the record did not anticipate are noted at the end of the decision.

This record decides what svcdoctor may conclude from the generic transport
evidence of an operator-requested target, so that the next phase can implement
three rules without inventing anything. It adds no production diagnosis code, no
finding code in Go, no `FailureClass`, no schema field and no engine behaviour.

**Scope is DNS and TCP.** Generic TLS is deferred with a reason rather than an
opinion (§14), and PostgreSQL's in-band TLS gap is recorded and left to its own
record (§15).

It closes ADR 0017's generic transport deferral **for DNS and TCP only**, and
consumes ADR 0042 as its structural prerequisite. ADR 0034, ADR 0040 and ADR 0041
are unchanged.

### Implementation note (Phase 4.9b)

Two things, neither of which changes the policy.

**The prose guard caught the record's own draft detail text.** ADR 0043 section 8
forbids naming a firewall, route or network policy as a cause. The first
implementation of the TCP detail named them in order to *deny* them — "svcdoctor
did not observe a listener, a route, a firewall or a network policy" — and the
mechanical guard rejected it, correctly. Denying a cause plants it: a reader who
meets the word in a diagnosis reaches for it. The detail now says what is known
and what is not, and names nothing it did not observe. The guard was kept blunt
rather than taught about negation.

**One mutation turned out to be structurally impossible.** The plan required
proving that non-deterministic evidence-reference order is caught. It cannot be:
`domain.NewFinding` deduplicates and sorts references, so a rule that collected
them through a map produces byte-identical output. That is recorded as a property
of the domain rather than counted as a test.

## Problem

A run whose endpoint fails at DNS or TCP produces complete evidence, a correct
`summary.firstBrokenLayer`, and **zero findings**. Measured, not argued:

```text
tls.handshake  FAIL  TLS_PEER_NOT_TLS
findings: 0        status: OK        firstBrokenLayer: L3
```

That is a real run of the production composition. `status: OK` beside a broken
layer is the report a first-time user meets, and it is the reason the CLI release
gate exists.

Until ADR 0042 this could not be fixed. A rule meeting a failed `dns.lookup` node
had to ask "was this endpoint asked for, or discovered?" before it could say
anything about impact, and that question is `Origin`. ADR 0042 answered it
structurally: a run records the target it was asked about, and the sweep it caused
is parented to that node.

So the question is no longer *whether* a generic rule can exist. It is what it may
say.

## Decision

### 1. Ownership is the ADR 0042 walk, and nothing else

> **A generic transport rule enumerates requested-target anchors and descends by
> typed step. It never starts at a transport node and asks what that node is
> about.**

```text
anchors  = nodes where Step == target.requested ∧ Layer == L0 ∧ Subject.Kind == TARGET
lookups  = Children(anchor)  where Step == dns.lookup
connects = Children(lookup)  where Step == tcp.connect
```

Direct children at every level. No transitive descent, no graph rootness, no
`SweepScope`, no identifier parsing, no `Origin`, no service name, no engine
suppression. `diagnosis.Rule` stays `func(domain.Graph) []domain.Finding`.

The descent stops at `tcp.connect` in this record, because §14 defers TLS. When
TLS is decided the third level is `Children(connect) where Step == tls.handshake`
and nothing else changes.

**Why direct and not transitive**, restated because it is the invariant most
likely to be "simplified" later: a Kafka advertised sweep is a *transitive*
descendant of the bootstrap target, through
`tls.handshake → api_versions → sasl → metadata → broker_advertised`. A rule
owning every `dns.lookup` below an anchor would diagnose a discovered broker and
duplicate `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`. That is measured in
`internal/adapter/kafka/anchorboundary_test.go`, which asserts both that the naive
walk reaches it and that the authorized walk does not.

### 2. One decision per anchor, not per address

The aggregation unit is the requested-target anchor. One anchor yields at most one
DNS finding and at most one TCP finding, whatever the address count.

The subject is the anchor's own subject — the logical endpoint, `db.example.com:5432`
— taken from the node and never rebuilt from a hostname plus a port found
elsewhere. This is the thing ADR 0042 was built to provide, and using a resolved
address instead would throw it away.

**No finding per concrete address.** Twenty failed addresses are twenty pieces of
evidence for one claim, not twenty claims. A report that emits twenty findings for
one endpoint has stopped being a diagnosis and become a log.

### 3. What the evidence can actually be

Re-read from the probes rather than from the class list, because three declared
classes have no producer and policy for them would be policy for nothing.

**`dns.lookup`** — exactly one node per sweep:

| State | Class | The measured fact |
|---|---|---|
| PASS | `NONE` | at least one usable address |
| FAIL | `DNS_NO_ADDRESS` | the resolver answered, and the answer contained no usable address |
| FAIL | `DNS_TIMEOUT` | the resolver did not answer within its own limit |
| FAIL | `DNS_RESOLVER_FAILURE` | the resolver reported a failure svcdoctor cannot classify further |
| UNKNOWN | `EXEC_CANCELLED` | the run was cancelled |
| UNKNOWN | `EXEC_LOCAL_TIMEOUT` | svcdoctor's own budget expired |

**`DNS_NXDOMAIN` has no producer and this record designs nothing for it.** The
probe deliberately emits the weaker `DNS_NO_ADDRESS` because Go's resolver sets
`IsNotFound` both for a name that does not exist and for a name with no address
record. That restraint is upstream of this policy and this policy must not undo it
(§5).

**`tcp.connect`** — one node per resolved address:

| State | Class | The measured fact |
|---|---|---|
| PASS | `NONE` | a connection was established |
| FAIL | `TCP_CONNECTION_REFUSED` | `ECONNREFUSED` — a host answered and declined |
| FAIL | `TCP_CONNECTION_RESET` | `ECONNRESET` |
| FAIL | `TCP_NETWORK_UNREACHABLE` | `ENETUNREACH` |
| FAIL | `TCP_HOST_UNREACHABLE` | `EHOSTUNREACH` |
| FAIL | `TCP_CONNECTION_TIMEOUT` | `ETIMEDOUT` — the kernel's unanswered SYN |
| FAIL | `TCP_CONNECTION_FAILED` | the attempt failed and was not classifiable |
| UNKNOWN | `EXEC_CANCELLED` / `EXEC_LOCAL_TIMEOUT` | not attributable to the peer |
| UNKNOWN | `NONE` | the dialer returned neither a connection nor an error |
| SKIPPED | `EXEC_CANCELLED` / `EXEC_LOCAL_TIMEOUT` | the address was never tried |

**The probes already separate local from remote, and that is load-bearing.**
Cancellation and budget exhaustion become `UNKNOWN` at every layer; a bare timeout
carrying no error number becomes `UNKNOWN` + `EXEC_LOCAL_TIMEOUT` rather than
`TCP_CONNECTION_TIMEOUT`, because *"calling it TCP_CONNECTION_TIMEOUT would turn
our own budget into a claim about the peer"*. Only `ETIMEDOUT` — the kernel
reporting an unanswered SYN — is a target fact.

> **A rule that fires only on `StateFail` cannot turn a cancelled measurement into
> a target failure.** The invariant is structural, not a policy the rule has to
> remember.

### 4. Two DNS findings, because they send a reader to two different places

The claims are genuinely distinct, and FINDINGS.md §11 forbids merging when the
remediation differs materially.

#### `DNS_NAME_NOT_RESOLVED`

| | |
|---|---|
| **Trigger** | the requested sweep's `dns.lookup` node is FAIL with `DNS_NO_ADDRESS` |
| **Claim** | *The requested hostname did not resolve to a usable address from this vantage point.* |
| **Must not claim** | that the name does not exist, anywhere or at all; that the zone is misconfigured; that no record was ever created; that the service is down or absent. The producer refused to assert non-existence and the finding inherits that refusal |
| **Kind** | `CONFIRMED` — the resolver answered and the answer is the evidence |
| **Severity** | `ERROR` |
| **Confidence** | `HIGH` — the claim is exactly what was measured, with no inferential step |
| **`vantageDependent`** | `true` |
| **Layer** | `L1` |
| **Subject** | the anchor's subject |
| **Evidence** | the `dns.lookup` node alone |

#### `DNS_RESOLUTION_FAILED`

| | |
|---|---|
| **Trigger** | the `dns.lookup` node is FAIL with `DNS_TIMEOUT` or `DNS_RESOLVER_FAILURE` |
| **Claim** | *Name resolution for the requested hostname did not complete from this vantage point.* |
| **Must not claim** | that the name is invalid; that the authoritative zone is broken; that a firewall is responsible; that the service is unavailable |
| **Kind** | `CONFIRMED` — that resolution did not complete is directly evidenced. The claim is about completion, not about cause, which is why it is not a hypothesis |
| **Severity** | `ERROR` |
| **Confidence** | `HIGH` |
| **`vantageDependent`** | `true` |
| **Layer** | `L1` |
| **Subject** | the anchor's subject |
| **Evidence** | the `dns.lookup` node alone |

The two are **mutually exclusive by construction**: one lookup node, one failure
class, disjoint trigger sets. No arbitration, no suppression.

#### Why both are ERROR, and the tension that decision carries

`SeverityError` is *"something that prevents correct use"*, and severity is the
impact of the finding's claim about its own subject (ADR 0034 §13). Either failure
leaves the target unusable from this position and leaves the run unable to measure
anything about it. That is ERROR on the per-subject reading.

**The tension is recorded rather than smoothed away.** `docs/SCOPE.md` says exit
code 1 means *"svcdoctor itself worked and found a target-side problem"*, and a
resolver that times out may be a defect on this side rather than the target's. The
alternative — WARN, and therefore exit 0 — is worse: exit 0 means "no problem
found", and a run that learned nothing about the target would report itself clean.
That is precisely the failure this record exists to fix.

Three things keep ERROR honest: the claim says *from this vantage point* and never
blames the target's DNS; `vantageDependent: true` is the field that tells a reader
to re-check from elsewhere; and the two codes are separate, so a consumer that
cares can branch. **Reopen if** field use shows resolver-side failures dominating
and exit 1 misleading operators.

#### Why `vantageDependent: true` for both

Resolution is a function of which resolver this vantage uses. Split-horizon DNS is
routine, and the same name legitimately resolves differently inside and outside a
network. A `false` here would invite a reader to conclude the name is broken
everywhere.

### 5. One TCP finding, and it is truthful for every reachable class

#### `TCP_CONNECTION_NOT_ESTABLISHED`

| | |
|---|---|
| **Trigger** | §6 |
| **Claim** | *No measured TCP connection to the requested endpoint completed from this vantage point.* |
| **Must not claim** | that the service is down; that no listener exists; that a firewall, route, security group or network policy is responsible; that the host is unreachable |
| **Kind** | `CONFIRMED` |
| **Severity** | `ERROR` — no client at this position can reach the endpoint |
| **Confidence** | `HIGH` — the claim is the conjunction of the measurements, with no inferential step |
| **`vantageDependent`** | `true` — source address, routing and filtering all change the answer |
| **Layer** | `L2` |
| **Subject** | the anchor's subject |
| **Evidence** | the anchor's `dns.lookup` node and every FAIL `tcp.connect` node of the sweep |

**One code, tested against every reachable class rather than assumed.** The claim
is "no connection completed", and that is true for refused, reset, timeout,
network-unreachable, host-unreachable and the unclassifiable floor alike. It is
also true for every mixture of them.

**`TCP_ENDPOINT_UNREACHABLE` was rejected as a name for exactly this reason.** A
refused connection proves the *opposite* of unreachable: a host answered. A code
whose name contradicts one of its own triggers is a code that will be misread in
an incident.

**The reason distribution stays in the evidence.** A consumer that needs to
distinguish refused from timed-out reads `FailureClass` on the cited nodes, which
is the vocabulary that exists to carry exactly that. Splitting the public code by
errno would make the stable machine contract vary with platform error
classification — the thing the TCP probe's own comments refuse to do.

#### Why not split refused from no-answer

It was the closest call in this record. Refused and timed-out do send an operator
to different places, and FINDINGS.md §11 says not to merge when remediation
differs materially.

It was rejected because **the split is not stable across the aggregation unit.**
One endpoint routinely produces `ECONNREFUSED` on one family and `ETIMEDOUT` on
another — an IPv4 address with nothing listening and an IPv6 address that is
filtered. Under a split vocabulary that endpoint has no single code, and every
resolution is bad: two findings for one endpoint is the per-address noise §2
rejects; picking one by priority makes the public contract depend on which family
sorted first; and a third "mixed" code adds a machine-visible state whose only
meaning is "the tool could not decide".

The stable claim shared by every failed path is the one all of them support. The
recommendation carries the distinction (§8) and the evidence carries the detail.

### 6. Aggregation: four cases, pinned

Let `P` be the requested sweep's `tcp.connect` nodes.

| Case | Condition | Result |
|---|---|---|
| **A** | any node in `P` is PASS | **no finding** |
| **B** | `P` is non-empty, every node is FAIL | **`TCP_CONNECTION_NOT_ESTABLISHED`** |
| **C** | at least one FAIL, at least one UNKNOWN or SKIPPED, none PASS | **no finding** |
| **D** | `P` is empty, or no node is FAIL | **no finding** |

**Case A — partial success withholds, and this is not a new idea.** FINDINGS.md
§3.1 item 4: *"Partial success never becomes total failure, and withholding a
finding is not withholding information — the evidence stays in the report either
way."* ADR 0034 §6 applied it to advertised endpoints. A client that selects the
working path succeeds, so a finding saying the endpoint could not be reached would
be false.

One address usable out of twenty is still Case A. The claim is about the endpoint,
and the endpoint was reached.

**Case C — incompleteness is not failure.** The run did not establish that every
path fails, so the finding's claim is unproven. It is withheld rather than
downgraded to `HYPOTHESIS`: `Result.Incomplete()`, exit code 4 and
`summary.unknownEvidenceCount` already say the run was cut short, and a HYPOTHESIS
here would add a second, weaker representation of the same fact while nudging a
reader toward a conclusion the evidence does not support. **Reopen if** a real
report shows a reader missing a genuine outage because of it.

**Case D covers the DNS-failed shape.** When the lookup produced no address the
chain mints no `tcp.connect` node, so `P` is empty and no TCP claim is made —
correctly, since nothing at L2 was measured. The DNS finding is the whole answer.

### 7. Evidence references: minimal sufficient proof

FINDINGS.md §10 requires enough to establish the claim and nothing that decorates
it.

- **DNS findings cite the `dns.lookup` node alone.** The anchor is not cited: it
  proves the run's input, not the failure, and it is already the finding's
  subject.
- **The TCP finding cites the `dns.lookup` node and every FAIL `tcp.connect`
  node.** The lookup is part of the proof rather than decoration — it establishes
  which addresses existed to be tried, and without it "every path failed" has no
  denominator. Each FAIL node is a conjunct of the claim.
- **No PASS node is ever cited**, because in the authorized cases none exists.
- **No SKIPPED or UNKNOWN node is cited**, because Case C withholds and a blocked
  step is never a cause (FINDINGS.md §11).

Order is deterministic: `NewFinding` sorts and de-duplicates references.

### 8. Recommendations follow the evidence and name no cause

One recommendation per finding, and none of them guesses.

| Finding | Recommendation |
|---|---|
| `DNS_NAME_NOT_RESOLVED` | Verify the hostname is spelled as intended and that it has an address record visible to the resolver this host uses. |
| `DNS_RESOLUTION_FAILED` | Verify that the resolver this host is configured to use is reachable and answering. |
| `TCP_CONNECTION_NOT_ESTABLISHED` | Verify that the endpoint accepts connections on this port from this network position, and inspect the per-address outcomes recorded on the cited evidence. |

The TCP recommendation is deliberately broad, and pointing at the evidence is the
part that makes it useful: the classes distinguish "a host declined" from "nothing
answered", and the reader is sent to them rather than being handed a guess.

Forbidden, per FINDINGS.md §17 and §20 of the phase brief: naming a firewall,
route, security group or network policy as the cause when the evidence
distinguishes none of them; telling anyone to open a port or start a service; any
executable command; any service-specific configuration name. A generic transport
finding must never mention `advertised.listeners`, `pg_hba.conf` or `ssl=`.

**Detail may summarize the class distribution** — "every measured address refused
the connection", "two addresses refused, one timed out" — because that is a
restatement of cited evidence, not a new claim, and it does not vary the code.
FINDINGS.md §13 still applies: a consumer that needs the distribution reads the
evidence, never the sentence.

### 9. Duplicate prevention is structural

| Case | Generic | Service |
|---|---|---|
| PostgreSQL requested DNS failure | **YES** | no |
| PostgreSQL requested TCP failure | **YES** | no |
| PostgreSQL `SSLRequest` failure | no | PostgreSQL |
| PostgreSQL in-band TLS failure | no | **unowned — §15** |
| PostgreSQL startup / auth / session | no | PostgreSQL |
| Kafka bootstrap DNS / TCP | **YES**, once composition mints an anchor | no |
| Kafka advertised DNS / TCP / TLS | no | Kafka (ADR 0034, ADR 0035) |
| Cancellation or budget during a requested sweep | **no finding** | none |

No pair can fire on one failure, and no engine suppression exists or is needed.
The proof is by anchor, not by name: every `POSTGRES_*` rule requires a
`postgres.*` node and every `KAFKA_*` rule requires a `kafka.broker_advertised`
node, and the §1 walk reaches neither. Conversely no service rule anchors at
`dns.lookup` or `tcp.connect` —
`internal/diagnosis/postgres/doc.go` says so in as many words, and a repository-wide
search finds no rule anchored at a transport step.

### 10. Effect on the report, and why two fields can disagree

| Run | Today | After implementation |
|---|---|---|
| No usable address | FAIL evidence, `firstBrokenLayer: L1`, **findings []**, **status OK** | one `DNS_NAME_NOT_RESOLVED` ERROR, `firstBrokenLayer: L1`, **status PROBLEMS_FOUND** |
| Every address fails | FAIL evidence, `firstBrokenLayer: L2`, **findings []**, **status OK** | one `TCP_CONNECTION_NOT_ESTABLISHED` ERROR, `firstBrokenLayer: L2`, **status PROBLEMS_FOUND** |
| One address works, others fail | `firstBrokenLayer: L2`, findings from service diagnosis | **unchanged** — no generic finding |

`summary` implementation does not change. Status is already derived from findings
and `firstBrokenLayer` from FAIL evidence.

**The third row is the one to understand rather than to fix.**
`firstBrokenLayer: L2` with no TCP finding is not a contradiction: the field
reports the earliest layer holding positively evidenced failure, and a failed IPv6
path is exactly that. The finding reports a conclusion about the target, and the
target was reached. `REPORT_SCHEMA.md` §7.5 already records that the two answer
different questions; this record adds the first case where they routinely differ
in a *healthy* run, and that is worth a renderer knowing.

### 11. Claim discipline, restated as the test these findings must pass

> **"I could not measure it" and "it is broken" are different claims.**

Every sentence in §4 and §5 is a statement about what svcdoctor observed from one
position. None asserts that a service is down, that a name does not exist, that
infrastructure is misconfigured, or that a cause is known. Where the evidence
cannot distinguish causes, the finding says what it measured and points at the
evidence.

### 12. Final code set

Three codes, following the convention `docs/FINDINGS.md` §1 already fixed:
generic transport findings use the **layer** as the namespace, and *"no extra
generic prefix is introduced"*.

```text
DNS_NAME_NOT_RESOLVED
DNS_RESOLUTION_FAILED
TCP_CONNECTION_NOT_ESTABLISHED
```

**`TARGET_*` was rejected**: the brief proposed it, and it contradicts a written
convention. `FindingCode.Namespace()` exists so a renderer can group by owner, and
`TARGET` names no owner.

**No code may collide with a `FailureClass` name.** `TCP_CONNECTION_FAILED` and
`DNS_NO_ADDRESS` are failure classes; a finding code spelled identically would
make a claim indistinguishable from an observation in any consumer that matches on
strings, and would be the one-to-one mirroring that turns a diagnosis vocabulary
into a second copy of the evidence vocabulary. The chosen three collide with
nothing.

Total after implementation: **17** codes — 12 PostgreSQL, 2 Kafka, 3 generic.

### 13. `FailureClass` disposition — every reachable class, no silent default

| Step | State | Class | Disposition |
|---|---|---|---|
| `dns.lookup` | PASS | `NONE` | no finding |
| `dns.lookup` | FAIL | `DNS_NO_ADDRESS` | **`DNS_NAME_NOT_RESOLVED`** |
| `dns.lookup` | FAIL | `DNS_TIMEOUT` | **`DNS_RESOLUTION_FAILED`** |
| `dns.lookup` | FAIL | `DNS_RESOLVER_FAILURE` | **`DNS_RESOLUTION_FAILED`** |
| `dns.lookup` | UNKNOWN | `EXEC_CANCELLED` | INCOMPLETE — withheld |
| `dns.lookup` | UNKNOWN | `EXEC_LOCAL_TIMEOUT` | INCOMPLETE — withheld |
| `dns.lookup` | — | `DNS_NXDOMAIN` | NOT REACHABLE — no producer |
| `tcp.connect` | PASS | `NONE` | no finding; suppresses Case B |
| `tcp.connect` | FAIL | `TCP_CONNECTION_REFUSED` | **`TCP_CONNECTION_NOT_ESTABLISHED`** (Case B) |
| `tcp.connect` | FAIL | `TCP_CONNECTION_RESET` | same |
| `tcp.connect` | FAIL | `TCP_CONNECTION_TIMEOUT` | same |
| `tcp.connect` | FAIL | `TCP_NETWORK_UNREACHABLE` | same |
| `tcp.connect` | FAIL | `TCP_HOST_UNREACHABLE` | same |
| `tcp.connect` | FAIL | `TCP_CONNECTION_FAILED` | same |
| `tcp.connect` | UNKNOWN | `EXEC_CANCELLED` / `EXEC_LOCAL_TIMEOUT` | INCOMPLETE — forces Case C |
| `tcp.connect` | UNKNOWN | `NONE` | INCOMPLETE — forces Case C; a dialer defect is not a target fact |
| `tcp.connect` | SKIPPED | `EXEC_CANCELLED` / `EXEC_LOCAL_TIMEOUT` | INCOMPLETE — forces Case C |
| `tls.handshake` | any | any | **DEFERRED — §14** |

### 14. Generic TLS is deferred, and the reason is a fact

**No production run produces a generic requested-target `tls.handshake` node.**
`internal/app` calls `transport.Run` with `TLS` unset, deliberately, because
PostgreSQL negotiates encryption in band; Kafka's only TLS-bearing sweep is the
*advertised* one, which ADR 0034 owns. Verified in source, not assumed.

A TLS policy written now would govern evidence no run can produce, and its rule
would be testable only against hand-built graphs. This repository has consistently
refused that: ADR 0034 §4 checked its terminal-layer invariant against real
fixtures precisely because *"this was the most likely blocker of the phase, so it
was checked rather than assumed"*.

The class-by-class analysis already performed — that TLS mixes target facts
(expired certificate), local-trust facts (unknown authority), client-capability
facts (version mismatch) and protocol facts (peer not TLS), and therefore cannot
honestly share one code, one severity or one `vantageDependent` value — is carried
in `docs/BACKLOG.md` as **research notes, not accepted semantics**.

**Reopen when** a production run produces a `tls.handshake` node whose direct
parent is a requested-target `tcp.connect` node. Kafka bootstrap composition is
the likely first.

**No placeholder TLS finding code is created.**

### 15. PostgreSQL's in-band TLS gap is recorded, not fixed

Measured:

```text
postgres.ssl_request  PASS
  └── tls.handshake   FAIL   TLS_PEER_NOT_TLS
findings: 0        status: OK        firstBrokenLayer: L3
```

That node is owned by nobody. ADR 0040 §2 anchors PostgreSQL rules only at
`postgres.*` steps; ADR 0042 §7 gives generic diagnosis only handshakes whose
direct parent is a requested `tcp.connect`. Both are correct, and the node falls
between them.

**This record does not widen generic ownership to reach it.** Doing so would mean
either transitive descent — which reintroduces the Kafka hazard §1 exists to
prevent — or a service-shaped exception inside a generic rule. It is a service
diagnosis gap and belongs to a PostgreSQL record.

It stays a CLI release-gate item, and it is the reason this policy closes two of
the gate's three named failures rather than all three.

## Acceptance matrix

Defined before implementation, per the project's habit. Every row is one requested
target; `status` and `firstBrokenLayer` are as the report would derive them.

| # | Scenario | Generic finding | Subject | Sev | Status | fBL |
|---|---|---|---|---|---|---|
| 1 | lookup FAIL `DNS_NO_ADDRESS` | `DNS_NAME_NOT_RESOLVED` | anchor | ERROR | PROBLEMS_FOUND | L1 |
| 2 | lookup FAIL `DNS_TIMEOUT` | `DNS_RESOLUTION_FAILED` | anchor | ERROR | PROBLEMS_FOUND | L1 |
| 3 | lookup FAIL `DNS_RESOLVER_FAILURE` | `DNS_RESOLUTION_FAILED` | anchor | ERROR | PROBLEMS_FOUND | L1 |
| 4 | lookup UNKNOWN `EXEC_LOCAL_TIMEOUT` | none | — | — | OK | unset |
| 5 | lookup UNKNOWN `EXEC_CANCELLED` | none | — | — | OK | unset |
| 6 | lookup PASS | none | — | — | per service | per service |
| 7 | one address, refused | `TCP_CONNECTION_NOT_ESTABLISHED` | anchor | ERROR | PROBLEMS_FOUND | L2 |
| 8 | all refused | same | anchor | ERROR | PROBLEMS_FOUND | L2 |
| 9 | all `ETIMEDOUT` | same | anchor | ERROR | PROBLEMS_FOUND | L2 |
| 10 | all network-unreachable | same | anchor | ERROR | PROBLEMS_FOUND | L2 |
| 11 | refused + timeout, all FAIL | same, **one finding** | anchor | ERROR | PROBLEMS_FOUND | L2 |
| 12 | reset + host-unreachable, all FAIL | same, **one finding** | anchor | ERROR | PROBLEMS_FOUND | L2 |
| 13 | v4 FAIL, v6 PASS | **none** | — | — | per service | L2 |
| 14 | v4 PASS, v6 FAIL | **none** | — | — | per service | L2 |
| 15 | FAIL + UNKNOWN, no PASS | **none** (Case C) | — | — | OK | L2 |
| 16 | all UNKNOWN | **none** (Case D) | — | — | OK | unset |
| 17 | no TCP nodes, DNS failed | DNS finding only | anchor | ERROR | PROBLEMS_FOUND | L1 |
| 18 | 20 addresses, all FAIL | one finding, 20 + 1 refs | anchor | ERROR | PROBLEMS_FOUND | L2 |
| 19 | 1 PASS + 19 FAIL | **none** | — | — | per service | L2 |
| 20 | `dns.lookup` root with no anchor | **none** | — | — | — | — |
| 21 | Kafka advertised DNS FAIL | **none** generic; Kafka rule unaffected | — | — | — | — |
| 22 | Kafka advertised TCP FAIL | **none** generic; Kafka rule unaffected | — | — | — | — |
| 23 | PostgreSQL requested DNS FAIL | DNS finding; no `POSTGRES_*` | anchor | ERROR | PROBLEMS_FOUND | L1 |
| 24 | PostgreSQL requested TCP FAIL | TCP finding; no `POSTGRES_*` | anchor | ERROR | PROBLEMS_FOUND | L2 |
| 25 | PostgreSQL in-band TLS FAIL | **none** — §15 gap | — | — | OK | L3 |
| 26 | shareable report of row 1 | subject pseudonymized, correlated with `target.requested` | — | — | — | — |
| 27 | two runs of row 8 | byte-identical findings | — | — | — | — |

Row 20 is the guard that ownership is by anchor and not by step: a `dns.lookup`
with no requested-target parent yields nothing, which is what keeps the rule
inert on graphs built before ADR 0042 and on any future sweep that declares a
different cause.

## Mutation matrix

| | Mutation | Caught by |
|---|---|---|
| A | diagnose a root `dns.lookup` with no anchor | row 20 |
| B | diagnose transitively-reachable Kafka advertised DNS | rows 21–22, on the real Kafka graph |
| C | diagnose Kafka advertised TCP | row 22 |
| D | use a resolved IP as the subject | rows 1, 8 assert subject equality with the anchor |
| E | emit a TCP finding when a path passes | rows 13, 14, 19 |
| F | emit HYPOTHESIS on FAIL + UNKNOWN | row 15 |
| G | treat UNKNOWN or SKIPPED as FAIL | rows 4, 5, 15, 16 |
| H | one finding per failed address | rows 8, 18 assert exactly one |
| I | split mixed TCP classes into separate codes | rows 11, 12 |
| J | name a firewall or a down service in the claim or recommendation | a prose guard over the recommendation and summary text |
| K | parse an `EvidenceID` | an AST guard, mirroring the one in `internal/app` |
| L | name `Origin` or `SweepScope` | an AST guard, mirroring `internal/diagnosis/kafka` |
| M | branch on a service name | depguard already denies diagnosis the adapter import; plus an AST guard |
| N | add engine suppression | the engine has no such path; `internal/diagnosis` tests pin it |
| O,P | generic and service findings on one failure | rows 21–25 |
| Q | change `firstBrokenLayer` | `internal/domain` summary tests |
| R | claim non-existence from `DNS_NO_ADDRESS` | a prose guard: the summary must not contain "does not exist" |
| S | turn cancellation into a target ERROR | rows 4, 5, 15, 16 |
| T | add a TLS finding code | the existing `internal/vocabulary` guard, narrowed to allow exactly the three authorized codes |
| U | widen ownership to PostgreSQL in-band TLS | row 25 |
| V | change the `Rule` signature | it is a compile-time contract |
| W | add a schema field | `internal/domain` JSON tests |
| X | leak the target subject through redaction | a canary test, as ADR 0042 §14 required |
| Y | non-deterministic evidence-ref order | row 27 |

**One existing guard must be narrowed rather than deleted.**
`internal/vocabulary`'s `TestNoGenericTransportFindingCodeExists` currently rejects
every `DNS_`, `TCP_`, `TLS_` and `TARGET_` finding code. Implementation turns it
into an allow-list of exactly the three codes above, still rejecting every other
`DNS_`/`TCP_` code and **every** `TLS_` code, so §14's deferral keeps a mechanical
enforcement rather than becoming a convention.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| One DNS code for all three classes | "no address" and "no answer" send a reader to the zone and to the resolver respectively; FINDINGS.md §11 forbids the merge | Never |
| Separate TCP codes for refused vs no-answer | Not stable across the aggregation unit: one endpoint routinely produces both, and every tiebreak makes the public contract depend on address family | A single endpoint can no longer produce mixed classes |
| A third "mixed" TCP code | Adds a machine-visible state whose only meaning is that the tool could not decide | Never |
| `TARGET_*` namespace | Contradicts the convention `docs/FINDINGS.md` §1 already fixed; `TARGET` names no rule owner | Never |
| `TCP_ENDPOINT_UNREACHABLE` | A refused connection proves a host answered; the name contradicts its own trigger | Never |
| `TCP_CONNECTION_FAILED` as a finding code | Collides exactly with a `FailureClass` name, making a claim indistinguishable from an observation | Never |
| A finding per failed address | Twenty pieces of evidence for one claim are not twenty claims | A per-address claim exists that the endpoint-level one does not entail |
| A degraded / partial-reachability finding | No policy defines what partial reachability means for a client that picks one path; the evidence already carries the divergence | A consumer needs family-level reachability and the evidence cannot serve it |
| HYPOTHESIS for Case C | Duplicates what `Result.Incomplete()` and exit code 4 already state, while nudging toward an unproven conclusion | A report shows a reader missing a real outage |
| Deciding generic TLS now | No producer exists; the rule would be unreachable and testable only against hand-built graphs | A requested-target `tls.handshake` node is produced in production |
| Widening the walk to reach PostgreSQL in-band TLS | Transitive descent reintroduces the Kafka duplication hazard | Never |

## Consequences

- The two most common transport failures stop producing empty reports. A run that
  cannot resolve or cannot connect says so, with a subject an operator recognizes.
- `status: OK` beside a broken L1 or L2 becomes impossible; beside a broken L3 it
  remains possible until §15 is closed.
- Three codes enter the machine contract, none colliding with a `FailureClass`.
- Diagnosis stays a pure function of a frozen graph. No `Origin`, no identifier
  parsing, no service switch, no suppression, no schema change, no dependency.
- Redis, RabbitMQ and MySQL inherit DNS and TCP diagnosis for free: a service that
  declares its requested sweep's parent gets all three findings with no edit to
  generic code.
- A renderer must be prepared for `firstBrokenLayer: L2` in a run with no TCP
  finding, which is correct and is now the routine dual-stack case.

## Reopen conditions

- **A production requested-target generic `tls.handshake` producer** — §14.
- **PostgreSQL in-band TLS acquiring an owner** — §15, its own record.
- **Field evidence that ERROR on `DNS_RESOLUTION_FAILED` misleads through exit
  code 1** — §4.
- **A report where withholding on Case C hid a real outage** — §6.
- **A consumer that genuinely needs family-level reachability** — the degraded
  finding rejected above.
