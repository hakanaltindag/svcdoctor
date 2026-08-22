# ADR 0041: A run discovers broadly and authenticates narrowly

## Status

**Accepted, and implemented in Phase 4.8b.**

`internal/app` holds the PostgreSQL composition root: `DiagnosePostgres`, a pure
`selectPath`, and nothing else. Measured against real servers, including a real
dual-stack name — two transport paths, two startup observations, **one**
authentication, and both sockets closed.

No production code was added by this record itself. `internal/app`, `cmd/svcdoctor` and
`internal/render` remain empty; the `security.Reveal` count stays **two**, the
dependency set one, `schemaVersion` **1**, and no `FailureClass`, `FindingCode`,
`AttrKind`, evidence attribute or redaction rule changes.

This record defines the production run boundary that a future CLI will call. It
closes the selection decision ADR 0028 §1 deferred, and it partially supersedes
ADR 0011 — command-tree shape only, rationale preserved.

**It authorized production composition, which Phase 4.8b then built.** The CLI
and the renderers remain absent and are Phase 5.

### Implementation note (Phase 4.8b)

Two things the policy did not anticipate, neither of which changes it.

**A run may carry no credential.** When the selected path demands authentication
and the run has none, nothing is presented and no authentication node is
recorded — the same absence §13 defines for an unselected path, and the startup
node's `postgres.auth_method` already says what was wanted. §7's limit is
unaffected: zero attempts is at most one. What is missing is a *finding* saying
"no credential was configured", which is diagnosis work and has no rule; it is
recorded as a gap rather than papered over.

**The class preference in §8.1 was added by an adversarial review of the first
implementation, before it was committed.** That implementation selected purely by
canonical order over every startup-successful path, so a `trust` path that sorted
first was continued and a configured credential was never exercised — a run that
reported `OK` without answering the question it was asked. The correction is a
partition before the tie-break; no other invariant moved, and credential attempts
remain ≤ 1.

## Problem

Phase 4.8a drove the PostgreSQL slice end to end against real servers and
measured the thing that forced this record:

```text
localhost
  ├── 127.0.0.1
  └── ::1
```

Both produced usable transport continuations. The integration harness had been
taking `Continuations()[0]` and was therefore silently selecting IPv4 — the exact
invisible preference ADR 0024 §3 removed from the transport chain, sitting
unnoticed in the suite meant to validate it.

That is not a test bug. It is the application-orchestration decision arriving,
and every layer beneath it has deliberately refused to make it:

- **ADR 0024 §3** — the chain measures every address and *ranks none*. Canonical
  order is evidence ordering, not a ranking: *"a caller that takes the first
  entry is making its own choice, not following one made here."*
- **ADR 0028 §1** — authentication takes exactly one connection, by type.
  *"Selection is the caller's… Today the only caller is a test; when application
  orchestration exists it selects and records why."*

So: **how does one user-requested run compose transport discovery, protocol
discovery, authentication, diagnosis, report construction and the output boundary
when a logical endpoint resolves to several usable paths?**

## Decision

### 1. The principle

> **svcdoctor discovers broadly without multiplying credential risk, then
> authenticates narrowly and deterministically.**

Every section below is an application of that sentence. Two symmetric
alternatives were considered and both rejected; see §20.

### 2. One command is one run

One user command invocation is one diagnostic run.

**The run owns:** the root context and the whole-run deadline it carries; one
`domain.GraphBuilder`; transport discovery; every continuation returned for the
logical endpoint; service-specific credential-free discovery; the selection of at
most one path for the credential-bearing step; connection lifecycle and closure;
the graph freeze; diagnosis invocation; and construction of the canonical
`LOCAL_FULL` report.

**The run does not own:** rendering format, terminal presentation, JSON
formatting, shareable-redaction mode selection, or any future `inspect`
serialization policy. Those belong at the output boundary.

Measurement and presentation stay separate. That separation is what lets the same
measurement serve more than one action without either growing a second probe
stack.

### 3. The CLI namespace is action-first

```text
svcdoctor diagnose postgres …
svcdoctor diagnose kafka …
svcdoctor inspect  postgres …
svcdoctor inspect  kafka …
```

Rejected: `svcdoctor postgres …`, `svcdoctor postgres diagnose …`.

The top level is the action; the service is the operand. Further actions may be
added when a product need justifies one — **this record authorizes none beyond
reserving the shape.**

#### 3.1 This supersedes ADR 0011's command tree, and nothing else

ADR 0011 is Accepted and decides a service-first tree (`svcdoctor kafka …`).
**ADR 0041 supersedes that tree shape and only that.**

ADR 0011's rationale is not overridden — it is preserved intact, and action-first
satisfies it one level deeper:

| ADR 0011 requires | Under action-first |
|---|---|
| Each service owns its own flag set | `diagnose postgres --dsn …` vs `diagnose kafka --bootstrap …` |
| Each service owns its own help text | per-service command, one level down |
| Each service owns its own validation | unchanged |
| **The CLI holds no service switch** | unchanged — each action enumerates registered services |
| Service type is never inferred from a port | unchanged |

ADR 0011 keeps its text and gains a status note. Its reasoning about
*"a single flat flag set covering every service"* remains correct and remains the
reason services are subcommands at all.

### 4. `diagnose` and `inspect` share one measurement architecture

There must never be a `diagnose` probe stack and an `inspect` probe stack
evolving separately. Conceptually:

```text
measurement (§7)
   ├── diagnose → diagnosis → LOCAL_FULL report → output boundary
   └── inspect  → (output contract deferred)
```

**`inspect`'s output contract is deferred**, and the namespace is reserved rather
than designed. The reason is a real constraint, not caution:

- `domain.Report` is the only canonical serialized artifact (ADR 0016), and
  `domain.Graph` deliberately has no `MarshalJSON`.
- A `Report` with zero findings reports `SummaryStatusOK`, which means *"no
  finding reached ERROR or CRITICAL"*. From `inspect`, where no rule ever ran,
  that would misstate what happened.
- Giving `Graph` a serialization contradicts ADR 0016; adding a report field is a
  report-schema decision this record does not make.

**`inspect` must never silently run diagnosis to satisfy an API shape.** The
smallest likely future option — a report field recording that diagnosis did not
run — is named here as a reopen direction and is **not** authorized.

### 5. The multi-path model

```text
DNS                                            one lookup
  ↓
TCP                    every resolved address
  ↓
SSLRequest             every completed path
  ↓
TLS                    every path the endpoint agreed to encrypt
  ↓
Startup                every usable path
  ↓
──────────────── credential boundary ────────────────
  ↓
Authentication         at most ONE path
  ↓
Session                only the continued path
  ↓
Freeze → Diagnosis → LOCAL_FULL report → output boundary
```

The credential boundary is the load-bearing line. Above it, measuring another
path costs the target a connection. Below it, measuring another path costs the
target an **authentication attempt** — which ADR 0028 records is *"logged,
counted, and in directory-backed deployments a step towards lockout."*

### 6. Credential-free discovery is not a credential attempt

Normative:

> **Credential-free discovery connections are not credential attempts. The
> per-run authentication-attempt limit begins only when svcdoctor presents
> authentication material or proof.**

This is a fact about the protocol, not a convenience. `postgres.StartupParams` is
`{User, Database}`: startup discloses the role name — the protocol has no
anonymous startup — and presents no secret and no proof.

What that buys is the reason the blanket refusal in §20 was rejected.
`pg_hba.conf` selects behaviour by **source address**, so paths to one logical
endpoint can genuinely differ, and the difference is observable **before any
credential is presented**:

| Divergence | Where it becomes visible | Credential cost |
|---|---|---|
| one family gets `scram-sha-256`, another `md5` | `postgres.auth_method` on each startup node | none |
| one family is `reject`ed | `postgres.startup` FAIL `AUTHZ_NOT_PERMITTED` (`28000`), **no authentication node** | none |
| one family gets `trust` | `postgres.auth_method="ok"` | none |
| the paths reach different servers | differing `postgres.server_version`, `postgres.error_is_native` | none |

Phase 4.8a measured the `reject` row end to end against a real server.

### 7. The authentication-attempt limit

> **At most one credential-bearing authentication attempt per logical endpoint
> per run.**

No automatic second attempt. No retry on another address. No fallback after any
authentication outcome. No "try IPv4 then IPv6". No "try the next healthy
continuation". No user-facing override that multiplies attempts.

The precedent is ADR 0036 §4, which refused to reproduce `sslmode=prefer`
precisely because a fallback swallows the failure a diagnostic exists to find. A
second credential attempt after a refusal would do the same thing to a peer's
clearest assertion, and would spend a second attempt against whatever counts
them.

**Counting rule:** attempts are counted by **authentication execution**, never by
connection count. A run that opens four sockets and presents material once has
made one attempt.

### 8. Selection

After credential-free discovery has run on every path the run budget permitted:

1. **Build the continuation set.** A path belongs to it when its startup
   exchange completed. A path whose startup terminally failed does not; its
   evidence stands and may produce its own finding.
2. **Partition it by what the endpoint demanded**, and prefer the class this run
   can carry furthest (§8.1):
   - a run carrying a credential prefers **auth-required** paths;
   - a run carrying none prefers **trust / no-auth** paths.

   The non-preferred class is used only when the preferred one is empty.
3. **Select exactly one path from the preferred class**, by:
   1. an explicit address selection, if such an override exists (§10); otherwise
   2. **deterministic canonical order within that class.**
4. **Continue only that path** through authentication and session establishment.
5. **Close every other continuation** (§11).

A path that requested no authentication is continued without a credential being
presented; that is the adapter's existing behaviour and it consumes no attempt.
Credentials are never sent to a `trust`-style path to normalize the shape of a
run.

For v0.1 an `--address` override is **not required and not authorized**; the
class preference plus the deterministic tie-break is sufficient.

#### 8.1 Why class comes before canonical order

`pg_hba.conf` selects behaviour by source address, so one family can be admitted
on `trust` while another is asked for SCRAM. Ordering addresses alone would then
continue the `trust` path, and a run that had been given a credential would reach
`ReadyForQuery`, report `OK`, and **never exercise the credential** — answering a
different question from the one the operator asked, and grading it healthy.

> **Neither class is healthier.** A `trust` path is not unhealthy and a SCRAM path
> is not better; an endpoint that admits a connection without asking for anything
> has told the truth about itself, and svcdoctor reports that truthfully. The
> preference is about **product intent**: when an operator supplies a credential,
> svcdoctor should exercise that credential if the measured endpoint offers a
> legitimate path on which it can be exercised.

Symmetrically, a run carrying no credential cannot exercise a path that demands
one, so it prefers the path it can carry to `ReadyForQuery` — and never attempts
credential-required authentication with nothing to present.

**This is candidate selection, before authentication.** It is not a retry and not
a fallback: exactly one path is continued, and **credential attempts remain ≤ 1**
whichever class wins. Nothing is re-attempted after any outcome.

**Known limit.** The partition reads the adapter's normalized `auth_method` and
so distinguishes *demanded* from *not demanded*, not *performable* from *not
performable*. An endpoint demanding `md5` on one family and SCRAM on the other
puts both in the auth-required class, and canonical order may select the `md5`
path — where svcdoctor records its own capability gap rather than exercising the
credential. Resolving that needs either a new adapter surface saying "svcdoctor
can perform this" or a duplicate of the adapter's mechanism policy in
orchestration, and neither is authorized here. Reopen when a measured deployment
shows it.

### 9. Canonical order is a tie-break, and that is materially different

This section exists because the distinction is easy to lose and expensive to lose.

Canonical order here is **not** a claim that IPv4 is preferred, healthier,
faster, or primary; not a routing policy; not Happy Eyeballs; not a resolver
preference; not a latency optimization.

It is **only a deterministic tie-break, applied after every candidate path has
already been measured through credential-free discovery.**

The difference from what ADR 0024 removed is structural:

| | ADR 0024's rejected behaviour | This record |
|---|---|---|
| Which paths are measured beyond TCP | **one** — the first in canonical order | **all** of them |
| What the other paths contribute | nothing; they were closed unmeasured | full `SSLRequest`, TLS and `Startup` evidence |
| Is source-dependent divergence observable | **no** | **yes**, at zero credential cost (§6) |
| What canonical order decides | which path is measured at all | which already-measured eligible path receives the one credential |
| Chosen, documented, tested | none of the three | all three |

ADR 0024's objection was that *"Nobody chose that policy, nothing documented it,
and no test would have caught it changing."* All three conditions are removed
here. The residual IPv4 lean now decides only where the credential goes among
paths that have already been measured and whose divergence is already in the
report.

**Rejected as selection inputs:** resolver order — the DNS probe sorts addresses
canonically (`internal/probe/dns/lookup.go`), so the resolver's ordering is not
recoverable downstream and reconstructing it is not attempted; first-connected,
fastest TLS, lowest latency, Happy Eyeballs, random, map iteration and goroutine
completion order — all make **timing an input**, and selection must be
deterministic under documented inputs (§17).

### 10. A future `--address`, and its safety contract

`--address` is **deferred**, not authorized. If it is ever introduced, this
contract binds it:

> `--address` is **only a filter** over addresses the run's own DNS resolution
> already returned for the logical endpoint.

It must not: dial an address DNS did not return; change the logical credential
endpoint; widen credential authority; replace the logical hostname; become the
TLS `ServerName`; alter certificate identity validation; or bypass DNS evidence.

An address absent from the run's resolution is a **usage/configuration error**,
never a silent extra dial.

The reason is ADR 0028 §2: a credential is authorized by the **logical
endpoint**, never by a resolved address, *"because security.Endpoint compares
normalized names and resolution is a runtime fact that changes, differs per
vantage and can be attacker-influenced. DNS therefore cannot widen credential
authority, and neither can the TLS server name."* A `--address` that leaked into
either would reopen exactly that hole.

### 11. Continuation ownership

The run owns every continuation transport discovery returns, until ownership
transfers into a protocol stage. Every continuation ends in **exactly one**
outcome:

```text
transferred to the next stage          or          closed by the run
```

Unselected continuations are **deliberately closed**. This is application
ownership policy and **not a protocol requirement** — nothing in the PostgreSQL
or Kafka protocol obliges a client to close an idle socket promptly. It follows
ADR 0021, and it matches the precedent in `internal/adapter/kafka/reachability.go`,
which closes a whole sweep because *"a connection kept open would be a socket
with no reader and no owner."*

Closure is never left to garbage collection, and a close error is not a fact
about the target.

### 12. Path divergence

Divergent paths are the case this design exists to surface, not a problem to
normalize away.

| Paths | Behaviour |
|---|---|
| A: startup PASS `auth_method=sasl` · B: startup FAIL `AUTHZ_NOT_PERMITTED` | B's rejection is truthful evidence and may produce its own finding. **A remains eligible and receives the one credential attempt.** |
| A: `auth_method=ok` (trust) · B: `auth_method=sasl` · **credential configured** | **B is selected** (§8.1): the run exercises the credential it was given. Exactly one `Authenticate` execution. No credential ever crosses A. |
| A: `auth_method=ok` (trust) · B: `auth_method=sasl` · **no credential configured** | **A is selected**: the run carries what it has as far as `ReadyForQuery`. **Zero** credential attempts, and B is not attempted with nothing to present. |
| Either of the two rows above, with the addresses in the opposite canonical order | **The same class still wins.** Class is decided before ordering, so reversing which address sorts first does not change which class is continued — only which member of that class is. |
| A and B both `sasl` | Both measured through startup. Exactly one receives the credential, by §8. |

**A failure on one path never suppresses the credential attempt on another
eligible path.** Doing so would recreate the rejected blanket refusal (§20) under
a different name.

**No claim is made about the untested paths at the authentication layer.** They
were measured as far as they were measured, and no further. §16 states the limit
of what may be inferred from that.

### 13. Absence, not a synthetic SKIPPED node

For a path discovered through startup but not selected for authentication:

> **The authentication node is simply absent. No synthetic `SKIPPED`
> authentication node is minted.**

Because the step was never entered. The startup node already records what the
endpoint requested, the path's own `Subject` identifies its address, and graph
structure already distinguishes the paths — so a `SKIPPED` node would duplicate
what is represented and would imply execution reached a boundary it never
reached. ADR 0013 forbids the duplication.

This is deliberately **different** from the existing policy-driven `SKIPPED`
shapes, and ADR 0030 is why the difference matters. There, svcdoctor *does* reach
the step boundary and makes an explicit execution-policy decision at it — the
credential-transport refusal is a decision about a connection that got that far.
Here, orchestration decided earlier that this path would not continue at all.

**Absence is not `PASS` and must never render as one.** A reader distinguishes
the two states structurally: `postgres.auth_method="ok"` with no authentication
node is a server that demanded nothing; `postgres.auth_method="sasl"` with no
authentication node is a path that was not continued.

### 14. No selection evidence

No `selected=true`, `selected_address`, `selection_reason` or equivalent
attribute or node is added.

The authenticated path is already identifiable: the authentication node carries
its own `Subject` — the concrete `ip:port` — and its parent chain links it to the
transport evidence it continued from. ADR 0019's identifier scheme makes
multi-path protocol evidence collision-free, because every PostgreSQL step's
identifier already includes the address as a component.

So a renderer can state *"transport succeeded on A and B; authentication
continued on A"* from structure alone. Adding an attribute would duplicate a fact
the graph represents — ADR 0013.

**This is reading a node's own recorded subject, not inferring provenance from
graph shape.** `Origin` remains deferred, and nothing here reads derivation edges
as provenance (ADR 0034 §4).

Acceptance tests must establish selection through `domain` APIs and `Subject`,
**never by parsing an `EvidenceID` string**.

### 15. Run budget, cancellation and partial execution

The root context carries the whole-run deadline. **No second budget framework is
invented.** Per-step timeouts remain subordinate; the effective bound is
`min(remaining run deadline, step timeout)`.

> **The run deadline always wins.**

With several paths, sequential credential-free discovery may mean the deadline
expires before every path reaches the same layer. When the context ends:

- stop starting new work;
- preserve evidence already recorded;
- **never turn unattempted work into a target failure** — there is no
  "path B failed because the run ended before we tried it";
- close every owned continuation;
- freeze the partial graph;
- diagnose what was truthfully measured;
- construct the report.

A partial graph is a valid graph. **Execution incompleteness is not
report-construction failure**, which `docs/SCOPE.md` already fixes: codes 0, 1 and
4 all mean a report exists.

### 16. What may not be inferred across paths

Explicit, because the reasoning that produced this record could be misread into
an assumption it does not need.

> **This record makes no claim that two paths to one hostname reach equivalent
> backends, and no claim that authenticating one predicts the result of
> authenticating another.**

A hostname may resolve to independent servers, load balancers, replicas, proxies
or differently configured endpoints. Even two paths that both request
`SCRAM-SHA-256` may not be backed by the same catalog.

The policy is safe without that assumption, and this is why:

- every path is measured through credential-free discovery, so divergence is
  observed rather than assumed away;
- divergent evidence is preserved intact;
- exactly one path is authenticated;
- graph structure discloses which one;
- **nothing is claimed about the authentication result on the others.**

They are not claimed healthy at authentication. They are not claimed failed at
authentication. They were not authenticated. That distinction is load-bearing and
must survive into renderer prose.

### 17. Determinism

Selection is a pure function of documented inputs: the set of completed
continuations, each path's startup outcome, and — if it ever exists — an explicit
address selection. **Timing is never an input.** Neither is map iteration order,
goroutine scheduling, resolver ordering, or connection latency.

Two runs against an unchanged target must select the same path.

### 18. Diagnosis, report and redaction

**Diagnosis runs after `Freeze()`**, once, on the graph that actually exists, and
on any terminal outcome including cancellation. No incremental diagnosis: the
contract is `Graph → []Finding` and a rule must not observe a graph still being
mutated (ADR 0017).

Diagnosis receives **truthful, unredacted** evidence. The composition root must
not mutate, suppress, reorder or add findings; must not reinterpret a SQLSTATE;
must not infer a root cause; and must not manufacture retry-derived evidence.

**The run produces a `LOCAL_FULL` report** and never constructs a shareable one —
`domain.NewReportSecurity` refuses `SHAREABLE_REDACTED` outright, and
`redaction.Redact` is its only producer (ADR 0018).

```text
run → LOCAL_FULL report → output boundary
                            ├── local rendering
                            └── Redact(report) → SHAREABLE_REDACTED
```

Redaction is a derivative at the output boundary. There is no second
"redacted diagnosis" path, and diagnosis always precedes redaction.

### 19. Service registration

This record pins the principle only:

- explicit service registration at a single composition root;
- no magic `init()` registration, no reflection discovery, no plugin framework;
- **no speculative generic `Adapter` interface.**

That is ADR 0009 consumed, not replaced. The mechanics belong to the
implementation phase.

Kafka and PostgreSQL share the *principle* — discover broadly, authenticate
narrowly — and Kafka reached it first: `kafka.Run` takes `[]*transport.Continuation`,
asks every path for ApiVersions because discovery costs the target nothing, and
returns sessions plural, while authentication stays singular.

They do **not** share an orchestration contract. Kafka has a bootstrap, topology
discovery, advertised-endpoint measurement and a rule against forwarding
credentials to discovered brokers; PostgreSQL has one logical endpoint and one
credentialed continuation. A shared interface would need `any`, a union of
unrelated options, or a type switch — which ADR 0009 declines. A composition root
can construct each workflow explicitly without one.

### 20. Rejected alternatives

| Alternative | Verdict |
|---|---|
| **`N > 1` ⇒ authenticate none**, report a partial run | **Rejected.** It withholds svcdoctor's primary function on any dual-stack endpoint — the common case — to avoid a risk that credential-free discovery already surfaces at zero credential cost (§6). It also had no honest exit code: `docs/SCOPE.md` reserves 4 for cancellation or budget exhaustion, and a policy refusal is neither |
| **Authenticate every usable path** | **Rejected.** Multiplies credential attempts, audit events, lockout pressure and load by the address count, on every run. ADR 0028 makes that security-relevant |
| **Canonical-first as the whole mechanism** | **Rejected** — that is ADR 0024's failure exactly: only one path is ever measured beyond TCP, so IPv4 becomes the only path meaningfully diagnosed. Retained *only* as a tie-break after every path is measured (§9) |
| **Controlled fallback on selected failure classes** | **Rejected for v0.1.** Every variant needs a policy surface — fallback after TCP timeout? TLS mismatch? credential rejection? peer-verification failure? — and fallback after a credential refusal both duplicates an attempt and obscures the peer's clearest assertion. ADR 0036 §4 is the precedent |
| **Latency, first-connected, Happy Eyeballs, random, resolver order** | **Rejected.** All make timing or an unavailable input decide where a credential goes (§9, §17) |
| **Synthetic `SKIPPED` authentication nodes for unselected paths** | **Rejected.** Fabricates a step that was never entered and duplicates what structure states (§13) |
| **A `selected=…` attribute** | **Rejected.** The node's own `Subject` and parent chain already carry it (§14) |
| **Service-specific selection policy** | **Rejected.** The question is identical for a Kafka bootstrap and a PostgreSQL endpoint; differing would be arbitrary |
| **A generic `Adapter` interface** | **Rejected** (§19) |
| **Giving `Graph` a canonical serialization for `inspect`** | **Rejected.** Contradicts ADR 0016 (§4) |
| **A second run-budget framework** | **Rejected.** The context deadline is sufficient (§15) |

### 21. Edge cases

| Case | Behaviour |
|---|---|
| **A. Zero usable continuations** | Transport evidence stands alone. No protocol stage runs. Freeze, diagnose, report. **No service finding is invented** for transport evidence |
| **B. Exactly one continuation** | The ordinary case. No ambiguity; the tie-break never engages |
| **C. Several paths, one startup-eligible** | Authenticate that one |
| **D. Several paths, several eligible** | Exactly one, by the deterministic tie-break. The others keep their startup evidence and receive no authentication node |
| **E. One path rejected at startup, another proceeds** | Preserve the rejection; continue on the eligible path |
| **F. A trust / no-auth path** | Continued without presenting a credential. Credentials are never sent for uniformity |
| **G. Deadline expires mid-discovery** | Stop new work; preserve evidence; close continuations; freeze; diagnose; report. Unattempted work is **never** a target failure |
| **H. Future `--address` naming an address DNS did not return** | Usage/configuration error. Never an extra dial |
| **I. Several address families** | No family is semantically preferred. Canonical order is a tie-break only (§9) |
| **J. Two paths reach different backends** | Distinct evidence preserved. One authenticated. **No equivalence claim**, and no backend-identity conclusion beyond what evidence supports (§16) |

### 22. Acceptance matrix for the implementation phase

Structural wherever possible; prose assertions only where structure cannot carry
the property.

| # | Must be proven |
|---|---|
| 1 | No implicit `Continuations()[0]` anywhere in production |
| 2 | No IPv4/IPv6 preference outside the documented canonical tie-break |
| 3 | DNS/TCP discovery preserves every completed path |
| 4 | Credential-free discovery runs on every path the run budget permitted |
| 5 | Protocol evidence for multiple addresses does not collide |
| 6 | Credential-bearing attempts ≤ 1 per logical endpoint per run |
| 7 | Attempts counted by **authentication execution**, not connection count |
| 8 | A startup rejection on one path does not prevent discovery on another |
| 9 | Several eligible paths ⇒ exactly one authentication execution |
| 10 | No retry after an authentication failure |
| 11 | No fallback to another address, for any failure class |
| 12 | Every unselected continuation is closed |
| 13 | No socket is left ownerless |
| 14 | Trust / no-auth paths receive no credential |
| 15 | The selected path is observable from the authentication node's own `Subject` |
| 16 | No `EvidenceID` string parsing determines selection |
| 17 | No selection attribute exists |
| 18 | Partial execution still freezes, diagnoses and reports |
| 19 | The run deadline wins over per-path work |
| 20 | Unattempted work is never represented as a target failure |
| 21 | Diagnosis sees unredacted evidence |
| 22 | Redaction occurs only after report construction |
| 23 | `LOCAL_FULL` is the run's artifact |
| 24 | Generic transport ownership is unchanged (§24) |
| 25 | No generic `Adapter` interface appears |
| 26 | The action-first CLI namespace is preserved |
| 27 | `diagnose` and `inspect` share the measurement architecture |
| 28 | `inspect` never silently runs diagnosis |
| 29–31 | A future `--address` cannot alter credential authority, cannot become the TLS `ServerName`, and cannot dial outside DNS results |
| 32 | A dual-stack fixture produces several `Startup` observations and **at most one** credential-bearing authentication |
| 33 | Trust + SCRAM with a credential configured ⇒ the **SCRAM** path is selected, exactly one `Authenticate` execution |
| 34 | Trust + SCRAM with no credential ⇒ the **trust** path is selected, **zero** credential attempts |
| 35 | Rows 33 and 34 with the addresses in the opposite canonical order ⇒ the same class still wins |
| 36 | `Incomplete()` is true whenever the run context ended before the work did, and false for every run that finished — including an authentication failure and ordinary path divergence |

`localhost` is already such a fixture; Phase 4.8a measured it.

### 23. Mutation plan for the implementation phase

Each must apply, compile, be caught, and be restored.

| # | Mutation | Caught by |
|---|---|---|
| A | Select `paths[0]` before running discovery | acceptance 3, 4 |
| B | Authenticate every eligible path | acceptance 6, 9 |
| C | Fall back to path 2 after path 1's authentication failed | acceptance 6, 10, 11 |
| D | Choose the fastest path | determinism test (17) |
| E | Choose from map iteration | determinism test (17) |
| F | Stop discovery after the first startup success | acceptance 4 |
| G | Skip startup on unselected transport paths | acceptance 4, 8 |
| H | Leak `--address` into the TLS `ServerName` | acceptance 30 |
| I | Let `--address` dial an address absent from DNS | acceptance 31 |
| J | Leak `--address` into credential endpoint authority | acceptance 29 |
| K | Leave an unselected continuation open | acceptance 12, 13 |
| L | Mint a synthetic PASS authentication node for an unselected path | acceptance 9, 15 |
| M | Mint a synthetic FAIL authentication node for unattempted work | acceptance 20 |
| N | Add `selected=true` evidence | acceptance 17 |
| O | Diagnose before `Freeze` | purity guard (21) |
| P | Redact before diagnosis or report construction | acceptance 21, 22 |
| Q | Retry authentication automatically | acceptance 10 |
| R | Use exit 4 for ordinary multi-path selection | exit-code contract test (§24) |
| S | Introduce a generic `Adapter` interface | acceptance 25 |
| T | Give `inspect` an independent measurement pipeline | acceptance 27 |
| U | Prefer the trust path despite a configured credential and an available auth-required candidate | acceptance 33 |
| V | Prefer an auth-required path with no credential configured and a trust candidate available | acceptance 34 |
| W | Replace the class preference with plain canonical order over every startup-successful path | acceptance 33, 34 |
| X | Stop deriving `Incomplete()` from the run context | acceptance 36 |

### 24. Exit codes and the generic transport gate are untouched

**Exit codes are unchanged.** `docs/SCOPE.md` stands: 4 remains reserved for a
run that completed only partially because of cancellation or local
execution-budget exhaustion. It must **not** be used for more than one address
existing, for deterministic selection, for an ordinary policy decision, or for an
intentionally unselected path. If implementation meets an outcome that genuinely
cannot map to the existing contract, that is a separate decision.

**The generic transport diagnosis release gate remains OPEN.** ADR 0017 is
unresolved and this record does not resolve it sideways. A run may still produce
DNS/TCP/TLS evidence, a correct `firstBrokenLayer`, and **zero service findings**,
and the composition root must not add service findings over generic transport
evidence to close the gap.

## ADR impact

| ADR | Action | Reason |
|---|---|---|
| **0009** | Kept, consumed | Explicit registration, no speculative interface (§19) |
| **0011** | **Partially superseded** | Command-tree shape only; rationale preserved (§3.1) |
| **0013** | Kept, cited | No duplicate representation (§13, §14) |
| **0016** | Kept, cited | Report is canonical; `inspect` output deferred (§4) |
| **0017** | Kept, **unresolved** | Generic transport ownership stays open (§24) |
| **0019** | Kept, cited | Address-bearing identifiers make multi-path protocol evidence collision-free (§14) |
| **0021** | Kept, cited | Connection ownership justifies closing unselected continuations (§11) |
| **0024** | Kept | Its deliberate absence of transport-layer ranking is consumed, not overturned (§9) |
| **0028** | Kept; **its deferral is closed** | Selection is now decided and recorded; authentication stays singular; credential authority stays bound to the logical endpoint (§7, §10) |
| **0030** | Kept, cited | Its `SKIPPED`-by-policy shape is acknowledged and deliberately not reused (§13) |
| **0036 §4** | Kept, cited | The no-fallback precedent (§7) |
| **0040** | Kept, cited | Source-address-dependent behaviour and vantage reasoning (§6) |

## Consequences

- Production composition is authorized and may begin. Nothing else changes today.
- A dual-stack endpoint is measured on every path through startup, and receives
  exactly one credential attempt.
- Source-dependent `pg_hba` divergence becomes visible without presenting a
  credential on every path.
- The unselected paths carry no authentication node, and no claim is made about
  them at that layer.
- Kafka gains no new obligation. Its bootstrap already discovers broadly; when it
  authenticates, the same limit applies.

## Deferred, with reopen conditions

- **`inspect`'s output contract** — reopen when the renderer phase decides, or if
  `inspect` enters release scope. The smallest option is a report field recording
  that diagnosis did not run; it is not authorized here.
- **`--address` and any `--prefer-*` / `--all-addresses` flag** — reopen on a
  demonstrated user need. §10's safety contract binds any of them in advance.
- **Retry and fallback** — reopen when a measured transient failure demonstrably
  prevents a diagnosis that would otherwise have been possible.
- **Generic transport diagnosis ownership** — ADR 0017, unchanged.
- **Service registration mechanics** — the implementation phase.
- **Concurrent path discovery** — sequential for now. Reopen on a real
  performance requirement, and only if selection stays decoupled from completion
  order (ADR 0024's own reopen condition).

## Amendment (Phase 4.9a-pre): one hole in the evidence-authority ban

This record's implementation pinned that `internal/app` creates no evidence, and
that guard was right about everything it was defending: orchestration must not
record measurements, findings or a second representation of which path was
selected.

ADR 0042 §3 opens exactly one hole in it. The run may construct **one** kind of
evidence — the L0 requested-target anchor describing the endpoint it was asked
about — because it is the only layer that holds that fact, and because without it
a generic transport rule can neither identify the operator's sweep nor name its
subject. The guard is narrowed rather than deleted: `NewFinding`, `AddBlockedBy`
and every attribute constructor stay banned across the whole package, and
`NewEvidence` is permitted in one named function only.

The run still attaches no descendants. It passes the anchor's identifier as
`transport.Params.Parent` and the chain records the edge, so §14's rule — that
orchestration never parses an evidence identifier — is unaffected, as are path
selection, the one-authentication limit and the LOCAL_FULL boundary.
