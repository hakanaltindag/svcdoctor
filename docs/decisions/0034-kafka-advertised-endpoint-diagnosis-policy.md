# ADR 0034: A Kafka rule owns advertised-endpoint reachability, anchored at the advertisement

## Status

Accepted as **policy**. No rule is implemented here.

This record decides what svcdoctor may conclude from the evidence Phase 3.4
produces, so that Phase 3.6 can implement a rule without inventing anything. It
adds no production diagnosis code, no finding, no severity enum and no engine
behaviour.

It deliberately revisits the two questions ADR 0017 deferred — transport severity
policy, and the generic-versus-service finding overlap — and answers them **for
service-anchored rules only**. ADR 0017 is not rewritten; §3 explains why its
blocker dissolves here and still stands everywhere else.

## Problem

Phase 3.4 produces the evidence the flagship Kafka finding was always going to
need, and stops (ADR 0033). Writing the rule next looks like the obvious step and
is a trap: four questions become answerable at the same moment, each is
individually tempting, and answering them by implementation would put invented
diagnostic policy into the layer whose entire purpose is not to invent — the
failure mode ADR 0017 names in as many words.

The four:

- **Ownership.** A generic `TCP_CONNECTION_REFUSED` rule and
  `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` would cite the same evidence
  identifier on the first real run.
- **Severity.** ADR 0017 says severity needs to know whether an endpoint was
  user-supplied or discovered — which is `Origin`, deferred since ADR 0013.
- **Aggregation, twice over.** One advertisement now produces one sweep with
  several addresses, and one run produces several advertisements. Neither
  "reachable" nor "unreachable" is defined for a partial result.
- **Incompleteness.** A local timeout produces UNKNOWN transport evidence, and
  "I could not measure it" must not become "it is broken".

Verified from the tree at `89928b5`, not assumed:

- `internal/diagnosis/kafka`, `internal/diagnosis/transport` and
  `internal/diagnosis/postgres` contain a `.gitkeep` and nothing else. No rule
  of any kind exists.
- `diagnosis.Rule` is `func(domain.Graph) []domain.Finding` — the graph is the
  only argument. No vantage, no `ServiceID`, no run intent.
- `Graph` exposes `Node`, `Nodes`, `Parents`, `Children`, `BlockedBy`, `Len`.
- No `Origin` field or accessor exists anywhere.
- `Severity` is `INFO < WARN < ERROR < CRITICAL`; `Confidence` is `LOW / MEDIUM /
  HIGH`; `FindingKind` is `CONFIRMED / HYPOTHESIS`. A `CONFIRMED` finding may not
  carry a discriminator.
- `Summary` derives `PROBLEMS_FOUND` from the presence of any ERROR or CRITICAL
  finding.
- depguard denies `internal/diagnosis/**` importing `internal/adapter/**`.

The graph shapes below were dumped from the real Phase 3.4 fixtures, not drawn
from the code by eye.

## Decision

### 1. The graph this policy reads

One advertisement, TLS plan, two addresses, one refused:

```text
kafka.metadata                     L6 PASS
  └── kafka.broker_advertised      L6 PASS   subject=broker-1.internal:9093
        └── dns.lookup   [scoped]  L1 PASS   subject=broker-1.internal
              ├── tcp.connect      L2 PASS   subject=10.20.0.1:9093
              │     └── tls.handshake L3 PASS   subject=10.20.0.1:9093
              └── tcp.connect      L2 FAIL   subject=10.20.0.2:9093
                    └── tls.handshake L3 SKIPPED  EXEC_SKIPPED_PREREQUISITE_FAILED
                          blockedBy ──> the L2 FAIL node
```

Three properties of that shape carry the whole policy:

- **The advertisement's subject is the advertised endpoint**, `host:port` as the
  cluster stated it. It is a `SubjectKindEndpoint` and it is not a resolved
  address.
- **The sweep hangs off the advertisement by a derivation edge**, so every node
  of the sweep is reachable from the advertisement by walking `Children`, and
  from nowhere else.
- **A SKIPPED TLS node names its blocker**, so a prerequisite failure has one
  owner and one explanation rather than two causes.

### 2. Anchoring: the rule starts at the advertisement and walks down

This is the mechanism the rest of the record depends on.

> **The rule enumerates `kafka.broker_advertised` nodes and, for each, walks
> `Children` to the sweep that advertisement caused. It never starts from a
> transport node and asks what that node is about.**

The direction is the point. A rule that started at a failed `dns.lookup` node and
asked "is this endpoint one the user named, or one the cluster advertised?" would
be asking for provenance, and would answer it by reading graph shape — which
`docs/REPORT_SCHEMA.md` forbids and ADR 0031 §6 re-affirms. A rule anchored at the
advertisement never asks. It has the context by construction: it is looking at
this advertisement's sweep because it walked there from this advertisement.

Every claim in this policy is therefore local to one advertisement fact, and none
of them is a statement about how any endpoint entered the run.

### 3. Ownership: the Kafka rule owns it, and no generic finding fires here

| Model | Verdict |
|---|---|
| A. Generic transport findings only | **Rejected.** The user is told "connection refused to 10.20.0.2:9093" and is not told that the address came from a broker advertisement, that the bootstrap succeeded, or that this is the classic `advertised.listeners` failure. The single most useful sentence svcdoctor can produce is the one this model deletes |
| **B. One Kafka finding, transport evidence referenced beneath it** | **Chosen for this context** |
| C. Both | **Rejected.** `docs/FINDINGS.md` §5 already forbids the analogous shape — one evidenced failure plus explicit skips is correct, "four failures is noise that hides the real cause". Two findings over one evidence node is the same noise in a different direction |
| D. Generic for user-supplied targets, Kafka for advertised | **Rejected, and it is the trap.** It requires knowing which endpoints were user-supplied, which is exactly `Origin`. It reads as the balanced answer and is the one option that cannot be implemented |
| E. Generic only where no service rule claims the evidence | **Rejected as a mechanism.** Implemented in the engine it is suppression keyed on undocumented identity, which is a stop condition for this phase. Implemented by wiring it is model B with extra steps |

#### When are two findings duplicates?

The overlap question has been open since ADR 0017 because nobody defined the
test. This record defines it:

> **Two findings are duplicates when the same evidence entails both and one makes
> no claim the other does not already make. They are complementary when each
> states something the other does not, and each would remain true and useful if
> the other were removed.**
>
> They are **causal parent and child** when one states a condition and the other
> states a consequence of it that is separately evidenced — in which case
> `docs/FINDINGS.md` §5 applies and only the earliest evidenced failure is
> reported. They are **independent** when they rest on disjoint evidence.

Applying it: `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` entails the transport
observation and adds the broker identity, the advertisement that named the
endpoint, and the contrast with a successful bootstrap. A generic
`TCP_CONNECTION_REFUSED` over the same node adds nothing the evidence node does
not already state. **Duplicate. The generic finding does not fire.**

### 4. The terminal transport layer is observable, and that was the real risk

Reachability is defined against what the run required, and the run's transport
plan is a caller-supplied value (ADR 0033 §2) that is **not stored in the graph**.
If a rule could not tell a plaintext plan from a TLS plan, it would read "TCP
PASS" as success on a sweep where TLS was mandatory and report an endpoint as
reachable that no client can use. This was the most likely blocker of the phase,
so it was checked rather than assumed:

| Plan | TCP not attempted | TCP failed | TCP connected |
|---|---|---|---|
| plaintext | SKIPPED TCP, **no TLS node** | TCP node, **no TLS node** | TCP PASS, **no TLS node** |
| TLS | SKIPPED TCP + **SKIPPED TLS** | TCP node + **SKIPPED TLS** | TCP PASS + **TLS node** |

> **A TCP node has a TLS child if and only if the sweep's plan required TLS.**

The biconditional is total over the chain's branches, and it is now pinned by
`internal/probe/transport/terminallayer_test.go` in both directions — including
the branch that carries it, where a refused connection still records the
handshake that was required and did not happen. The invariant had always held; it
was emergent rather than stated, and something outside transport now depends on
it.

**So the terminal layer is:** TLS when the sweep's TCP nodes have TLS children,
TCP otherwise.

**The one gap, and why it is immaterial.** A sweep whose lookup produced no
address mints no TCP node and therefore no TLS node, so its plan is
unknowable. It does not need to be known: nothing was reachable at L1, and the
verdict is the same whichever layer would have been terminal. The gap sits
exactly where it cannot affect an answer.

**This is not the forbidden inference.** Reading "a handshake was attempted here"
off a node that records a handshake is reading what the graph states about an
execution. Reading "this endpoint was discovered" off the shape around a node is
inventing provenance. The first is evidence; the second is why `Origin` stays
deferred.

### 5. `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`, defined exactly

For one advertisement `A` whose endpoint is usable, let `S(A)` be the sweep
derived from `A` and `T` its terminal layer per §4. The finding is authorized
**iff all of**:

1. the `kafka.metadata` exchange that carried `A` is PASS — the contrast half,
   and the reason the claim is about the cluster's configuration rather than
   about the network in general;
2. no path in `S(A)` reached `T` in state PASS;
3. at least one node in `S(A)` is FAIL — the failure is positively evidenced,
   not merely absent;
4. no path in `S(A)` is unresolved for a reason that belongs to svcdoctor — no
   UNKNOWN node, and no TCP node SKIPPED for budget.

Condition 4 is what keeps the claim honest, and it is the difference between the
three states this policy refuses to collapse:

```text
proven unreachable      every required path failed, positively evidenced   -> CONFIRMED
not proven reachable    some paths failed, others never completed          -> HYPOTHESIS (§8)
measurement incomplete  nothing was positively evidenced                   -> no finding
```

Case by case:

| Situation | Authorized? |
|---|---|
| DNS produced no usable address | **Yes.** Terminal layer irrelevant |
| DNS PASS, every TCP FAIL | **Yes.** The SKIPPED TLS nodes under them are not extra causes (§9) |
| TCP PASS somewhere, every TLS FAIL, TLS required | **Yes** — the required layer was never reached |
| TCP PASS somewhere, TLS not required | **No.** Terminal layer reached |
| Any path reaches `T` | **No** (§6) |
| Any UNKNOWN in the sweep | **No CONFIRMED finding** (§7) |
| Advertisement unusable, no sweep ran | **No.** Out of scope (§14) |

**A TLS-only failure is still "unreachable", and the summary must say where.**
Under a TLS plan an endpoint whose every handshake fails cannot be used by a
client, so the claim is true. But `TLS_HOSTNAME_MISMATCH` is far more actionable
than "unreachable", so the finding's summary names the earliest evidenced failing
layer and its class, per `docs/FINDINGS.md` §5. A dedicated certificate-shaped
Kafka finding may later refine this case; it is a reopen condition, not an
invention for today.

### 6. Multi-address: any path reaching the terminal layer withholds the finding

```text
broker.internal -> 10.0.0.10   TCP FAIL
                -> 2001:db8::10 TCP PASS, TLS PASS
```

**No `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`.** A client that selects the working
address succeeds, so the claim would be false.

**And no partial-reachability finding either**, which is the harder half of the
decision. The tempting `KAFKA_ADVERTISED_ENDPOINT_PARTIALLY_REACHABLE` is
withheld because its actionability depends on a fact svcdoctor does not observe:
**which address a real client would select.** The chain measures every address
precisely because a diagnostic tool must not stop at the first that works (ADR
0024); a production client does the opposite, and may use Happy Eyeballs, an
OS-level policy, or its own ordering. Declaring a problem would assume one client
model; declaring health would assume another.

| Policy | Verdict |
|---|---|
| ANY address succeeding means reachable | **Chosen for the unreachability finding**: it is the condition under which the claim is provably false |
| ALL addresses must succeed | Rejected. Would report a healthy dual-stack endpoint as broken whenever one family is unrouted |
| Reachable but degraded | Rejected **for now**: "degraded" is a claim about client behaviour |
| Per-path facts only, no aggregate | **This is what happens.** The per-address evidence is in the graph and in the report |
| Two findings, reachable + one path failed | Rejected. The second is the degraded claim wearing a different name |

**Withholding a finding is not withholding information.** Both paths and both
failure classes are in the report; what is withheld is a conclusion svcdoctor
cannot justify. **Reopen when** either a client-selection model is documented, or
address-family asymmetry is shown to be actionable independently of selection.

### 7. UNKNOWN never becomes a remote failure

| Sweep | Finding |
|---|---|
| Every path UNKNOWN (local timeout, cancellation) | **None.** `Summary` already reports unknown and skipped counts; a finding would restate it and dress svcdoctor's budget as the cluster's fault |
| Some paths FAIL, others UNKNOWN, none reached `T` | **HYPOTHESIS** (§8) |
| Some path reached `T` | None, per §6 |

`docs/FINDINGS.md` §4 is the governing rule: *"I could not measure it" and "it is
broken" are different claims.* An unfinished measurement is a gap in svcdoctor.

### 8. Kind, and the severity of a hypothesis

**CONFIRMED** when §5's four conditions hold. The evidence directly supports the
stated condition, which is what `FindingKindConfirmed` means — and it does not
claim a root cause: *why* the endpoint is unreachable stays open, which the kind
explicitly permits.

**HYPOTHESIS** for the mixed FAIL/UNKNOWN case, with the discriminator *"re-run
with a larger execution budget so the unmeasured paths are attempted"* — a next
observation, not a remediation.

**A hypothesis here carries a different claim, and therefore a different
severity, and that is not severity tracking confidence.** The two findings state
different things:

```text
CONFIRMED   "no advertised path reaches this endpoint"          prevents correct use  -> ERROR
HYPOTHESIS  "at least one path failed; the rest were unmeasured" real, not proven     -> WARN
```

`SeverityWarn` is defined as *a real problem that is not currently breaking use*,
which is exactly the second claim. Had the claim been held fixed and the severity
lowered because belief was weaker, that would have collapsed impact into
epistemic strength — which the model forbids. The claim changed; the impact
followed.

### 9. `blockedBy` decides who owns a prerequisite failure

A refused connection under a TLS plan produces two nodes: `tcp.connect` FAIL and
`tls.handshake` SKIPPED, the second naming the first as its blocker.

> **The blocker owns the failure. The SKIPPED node is an explanation, never an
> independent cause, and never the primary evidence of a finding.**

This is `docs/FINDINGS.md` §5 applied to the structure the chain actually
produces, and it is why "every TCP failed" is one finding rather than one per
layer. A rule that counted states mechanically would find two failures per
address and report a TLS problem on a port that never accepted a connection.

A prerequisite skip is therefore **never referenced as a cause** (§11): the
blocker is already referenced, and the skip adds no independent proof. §11.2
shows this needs no exclusion rule of its own — selecting each path's earliest
non-PASS node cannot reach a downstream skip, because its blocker is its parent
and is earlier on the same path.

The one skip a finding does reference is a different animal: an address the
budget never attempted is recorded as a SKIPPED TCP node with an `EXEC_` class,
and the hypothesis of §8 cites it as evidence of the incompleteness it asserts,
not as a cause (§11.4).

### 10. Multi-broker: broker-scoped findings, and no aggregate

**One finding per unreachable advertisement.** No cluster-level aggregate.

| Case | Findings |
|---|---|
| 3 advertised, 3 reachable | none |
| 3 advertised, 1 unreachable | 1 |
| 3 advertised, 2 unreachable | 2 |
| 3 advertised, 0 reachable | 3 |
| 3 advertised, 2 reachable, 1 UNKNOWN-only | none from §7 |

An aggregate is rejected because it would state no independent fact: "all three
are unreachable" is the conjunction of three findings that are all present, and
each of them names its own evidence and its own broker. Worse, the obvious
aggregate wording would be false — **the cluster is demonstrably not down**,
because the broker that answered Metadata was reached over a measured path in
this very run. `KAFKA_CLUSTER_UNHEALTHY`, `KAFKA_BROKER_DOWN` and
`KAFKA_NETWORK_BROKEN` are not authorized, now or by this record.

**Reopen when** an aggregate would carry something the conjunction does not — the
candidate is "no advertised broker is usable from here, so this client can do
nothing beyond bootstrap metadata", which needs a model of what a client requires
and does not exist.

### 11. Evidence references: minimal, sufficient, and both halves of the contrast

`docs/FINDINGS.md` §6 requires both halves — the successful bootstrap and
Metadata discovery, and the discovered endpoint failing — because *"the finding's
entire meaning is the contrast between them"*. That is an existing tracked
contract and this record honours it rather than narrowing it.

Every authorized finding references:

1. the `kafka.metadata` exchange node — the successful half;
2. the `kafka.broker_advertised` node — the fact that named the endpoint;
3. **the minimal causal evidence set that proves the claim.**

Nothing else.

#### 11.1 The causal set is each path's earliest non-PASS node

An earlier draft of this record wrote (3) as *"the nodes that positively evidence
the failure at the terminal layer"*. That was written from the case where TLS was
required and every handshake failed, and it does not generalize — in two of the
five shapes the chain produces it names the wrong nodes or none at all:

- **A DNS failure has no terminal-layer node**, because a sweep that resolved
  nothing mints neither a TCP nor a TLS node. The wording would leave the claim
  with no causal evidence.
- **A TLS-required sweep whose every TCP attempt failed has no *failing* TLS
  node.** Its terminal-layer nodes are all SKIPPED, so read literally the wording
  points at exactly the nodes §9 forbids citing as causes.

The general rule, which covers all five:

> **For each measured path, cite the earliest node on that path whose state is not
> PASS. When the lookup itself did not pass, the sweep has no paths and the DNS
> node is the whole causal set.**

#### 11.2 Why this needs no separate SKIPPED exclusion

The rule in §9 — *the blocker owns the failure, never the skip* — is not a second
rule layered on top of this one. **It is a consequence of it**, and the structure
makes it provable rather than conventional:

`recordSkippedTLS` records a SKIPPED handshake whose blocker **is its parent**,
the TCP node on the same path. A TLS node is therefore SKIPPED only when its TCP
node did not pass, and that TCP node is earlier on the path. So:

> **A SKIPPED TLS node can never be a path's earliest non-PASS node.**

Selecting the earliest non-PASS node therefore excludes every downstream skip and
selects its blocker automatically. Two rules collapse into one, and Phase 3.6 has
no exclusion list to maintain.

#### 11.3 No PASS node is referenced in any authorized case

The governing rule stays *"include a PASS node only when the claim cannot be
proved without it"*, and the outcome, stated so Phase 3.6 makes no judgement
call, is that **the condition never fires**:

- failed TCP nodes exist only if the lookup produced addresses, so a DNS PASS
  node proves nothing they do not;
- failed TLS nodes exist only if the connection was established, so a TCP PASS
  node proves nothing they do not.

Each causal node already carries its own precondition. Evidence dumping is not
thoroughness — it buries the two or three nodes that matter.

#### 11.4 The hypothesis cites its unmeasured paths, and they are not causes

The mixed FAIL/UNKNOWN finding (§8) claims *"at least one path failed; the rest
were unmeasured"*. Both halves of that claim need evidence, so its causal set
includes the paths whose earliest non-PASS node is `UNKNOWN`, or `SKIPPED` with
`EXEC_LOCAL_TIMEOUT` or `EXEC_CANCELLED` — the shape `recordUnattempted` produces
for an address the budget never reached.

Citing them is consistent with §9 rather than an exception to it: they are cited
as evidence of the **incompleteness the finding asserts**, not as causes of a
remote failure. A reader who follows them sees what svcdoctor did not finish,
which is precisely what the hypothesis is about.

#### 11.5 The exact table, for Phase 3.6

`M` is the `kafka.metadata` node and `A` the `kafka.broker_advertised` node; both
are present in every row.

| Sweep shape | Path owners | Evidence references |
|---|---|---|
| DNS FAIL (`DNS_NO_ADDRESS`, `DNS_NXDOMAIN`, `DNS_RESOLVER_FAILURE`) | none — no paths exist | `M` + `A` + the DNS FAIL node |
| DNS PASS, every TCP FAIL, **plaintext plan** | each TCP FAIL node | `M` + `A` + every TCP FAIL node |
| DNS PASS, every TCP FAIL, **TLS plan** (SKIPPED TLS children present) | each TCP FAIL node | `M` + `A` + every TCP FAIL node. **The SKIPPED TLS nodes are not referenced** — identical to the plaintext row, because the refs do not depend on the plan |
| DNS PASS, every TCP PASS, every TLS FAIL | each TLS FAIL node | `M` + `A` + every TLS FAIL node. No TCP PASS node |
| DNS PASS, mixed: some paths TCP FAIL, others TCP PASS + TLS FAIL | per path, whichever came first | `M` + `A` + the per-path owners, a mixed TCP/TLS set |
| Mixed FAIL + UNKNOWN / budget-SKIPPED, none reached the terminal layer (**HYPOTHESIS**) | per path, earliest non-PASS — FAIL, UNKNOWN, or SKIPPED with an `EXEC_` class | `M` + `A` + every path owner, **including the unmeasured ones** (§11.4) |
| Any path reached the terminal layer | — | no finding (§6) |
| Every path UNKNOWN | — | no finding (§7) |

Two invariants fall out of the table and are worth stating because they make
review cheap: **no reference is ever a PASS node**, and **no reference is ever a
SKIPPED node carrying `EXEC_SKIPPED_PREREQUISITE_FAILED`.**

### 12. Subject, and why the finding attaches to the advertisement fact

**Subject = the advertised endpoint**, taken from the advertisement node's own
subject (`SubjectKindEndpoint`, `broker-1.internal:9093`). Not a resolved address
— the claim spans every path, and naming one address would make it look like a
claim about one of them. Not the node identifier: `Subject` has no kind for a
service-internal integer, and overloading the endpoint kind to carry one would
misrepresent it. The node identifier travels in the summary and on the referenced
evidence, where it already is.

**The finding is identified by its code plus the advertisement it derives from,
not by `host:port`**, and the difference is load-bearing in the cases Phase 3.3
exists to preserve:

- two node identifiers advertising one endpoint are **two facts**, so two sweeps
  and two findings — with the same subject, distinguished by their evidence;
- one node identifier advertising two endpoints is two facts, two findings;
- the bootstrap endpoint advertised back is one advertisement fact and one
  finding, whose subject happens to equal the run's target — which is correct and
  needs no provenance.

No `FindingID` is introduced. Global finding identity and duplicate semantics stay
open (ADR 0017), and nothing here needs them.

### 13. Severity: per-subject impact, not cluster availability

The question the model forces is what `Severity` measures. `SeverityError` is
*"something that prevents correct use"*, and a `Finding` has a `Subject`. So:

> **Severity is the impact of the finding's own claim about its own subject.**

An advertised broker endpoint that cannot be reached from this vantage prevents
correct use *of that broker*: a client cannot produce to or consume from the
partitions it leads. That is ERROR, and it is ERROR whether one broker or three
are affected.

| Policy | Verdict |
|---|---|
| A. Any unreachable = ERROR | **Chosen**, on the per-subject reading above |
| B. One unreachable = WARN, all = ERROR | **Rejected.** Makes the meaning of the evidence about broker 2 depend on unrelated brokers, and rests on an availability model svcdoctor does not have: replication factor, partition leadership and `min.insync.replicas` are all unobserved. "2 of 3 reachable is fine" is an invention |
| C. Broker-scoped ERROR; cluster availability is a separate question | **This is A, stated with its boundary**, and the boundary is what makes A safe |
| D. Severity cannot be assigned yet | **Rejected, deliberately** — see below |

**Why D no longer applies, without rewriting ADR 0017.** ADR 0017 deferred
severity because it "depends on whether the endpoint was the one the user asked
about or one discovered from it. That distinction is `Origin`." That reasoning is
correct for a rule that meets a transport node with no context. It dissolves for
a rule **anchored** at an advertisement: such a rule only ever runs on discovered
endpoints, so the distinction ADR 0017 needed is supplied by the anchor rather
than by a field. ADR 0017's blocker therefore stands, unchanged, for unanchored
generic transport rules — which is precisely why this record authorizes a Kafka
rule and no generic one.

**CRITICAL is not used.** It is *"an error with severe or broad impact"*, and
breadth here would be a cluster-level claim this record refuses to make (§10).

### 14. What this policy does not own

Boundaries, so the finding does not become a bucket:

- **Partial reachability** (§6) — no finding.
- **TLS verification quality on an otherwise reachable endpoint** — a certificate
  that fails on one path while another succeeds is a real inconsistency and is
  *not* an unreachability finding. It belongs to a future TLS-consistency policy.
- **An unusable advertisement** (empty host, port 0) — Phase 3.3 already records
  it as a FAIL node and Phase 3.4 runs no sweep. A finding for "the cluster
  advertises an endpoint no client can act on" is genuinely independent and
  genuinely useful, and is **not authorized here**: it is a configuration
  finding, not a reachability one, and it deserves its own decision.
- **Bootstrap-path transport failure** — not owned by this policy; see §16.

### 15. Controller identity does not affect severity

Metadata reports a controller node identifier, and the advertisement nodes carry
node identifiers, so a rule *could* compare them. It will not.

The controller is a point-in-time fact: it moves on election, the response
describes the moment it was read, and a client does not need the controller to
produce or consume. Making controller reachability CRITICAL would encode an
availability model the evidence does not support, and would make a run's severity
depend on which broker happened to be controller during the exchange. Recorded
and rejected for v1. **Reopen when** svcdoctor diagnoses admin operations, which
genuinely require the controller.

### 16. Bootstrap success with advertised failure is the canonical case

```text
bootstrap primary.internal:9092  reached, authenticated, Metadata answered
advertised broker-2.internal:9093  unreachable from this vantage
```

This is not contradictory evidence — it is the Kafka advertised-listener failure
mode, and being able to state it is why the project exists. The policy states it
as: **the cluster answered, and then advertised an address this client cannot
reach**, which is exactly the contrast §11's evidence references carry.

No `Origin` is needed to say it. The advertisement's derivation chain supplies the
local context, and the claim is scoped to that advertisement. It must not be
generalized into a statement about how any endpoint entered the run — and the
same endpoint being both bootstrap target and advertised broker, measured twice
in one run under ADR 0032's scopes, is the standing proof that such a
generalization would be false.

**Generic transport findings for the bootstrap path are not decided here.** That
path has no owner: it is produced by whatever orchestrates a run, and application
orchestration does not exist. Deciding it now would require run intent — "is this
a Kafka diagnosis or a bare endpoint check?" — which `Rule` cannot see, because it
receives only a `Graph`. Recorded as the reason, not as an oversight.

### 17. Vantage dependence is always true here

Every finding this policy authorizes carries `vantageDependent: true`,
unconditionally. Reachability of an advertised endpoint is a statement about
network position: the same broker may be reachable from inside the cluster and
unreachable from a laptop, a CI runner or another network zone. ADR 0012 and
`docs/REPORT_SCHEMA.md` §4 already require it, and a reader who mistakes this
finding for a claim about the cluster has been actively misled.

The flag is a flag. The `Vantage` itself stays on the report, recorded once.

### 18. Discriminator and recommendations

**Discriminator:** none on CONFIRMED — the model rejects that combination, and
correctly: there is nothing left to settle. On the HYPOTHESIS, the discriminator
names the observation that would settle it (§8), never an action.

**Recommendations:** the *mapping* is fixed here so Phase 3.6 invents nothing; the
wording is Phase 3.6's. A recommendation is tied to the evidenced failure layer
and to nothing else:

| Evidenced failure | Recommendation is about |
|---|---|
| DNS | whether the advertised name resolves from this vantage, and what `advertised.listeners` publishes |
| TCP | routing, firewalling and security groups between this vantage and that address and port |
| TLS | whether the certificate names the advertised host, and whether its issuer is trusted here |

A single generic recommendation is forbidden: "check networking" obscures the
evidence the finding just proved. No executable remediation, ever.

### 19. Attribute-key ownership: the reopen condition is now met

ADR 0031 §9 kept the Kafka attribute keys in the adapter with the reopen
condition *"a real second consumer"*. Phase 3.6 is that consumer, and depguard
denies `internal/diagnosis/**` importing `internal/adapter/**` — correctly, and
the rule must not be weakened.

**Decision: `internal/service/kafka` is authorized as a leaf vocabulary package,
and this phase does not create it.** The move is mechanical and belongs to the
phase that has the consumer in hand. The exact contents, so Phase 3.6 makes no
judgement calls:

```text
move to internal/service/kafka (re-exported or referenced by the adapter):
    StepMetadata          "kafka.metadata"
    StepBrokerAdvertised  "kafka.broker_advertised"
    AttrBrokerNodeID      "kafka.broker.node_id"
```

That is the whole set the authorized rule needs. Everything else it reads is
already service-neutral domain data: the subject, the state, the failure class,
the layer and the edges. `AttrMetadataControllerID` stays in the adapter until
§15 is reopened, and the advertised host and port stay there too — they are
already on the advertisement's subject, and moving a second copy would create two
sources for one fact.

The package imports `internal/domain` and nothing else. **No Kafka key enters
`internal/domain`**, and no central catalogue of finding codes is created: the
code constant lives with the rule that produces it (`docs/FINDINGS.md` §1).

### 20. Summary and exit-code coupling, stated rather than discovered

`Summary` derives `PROBLEMS_FOUND` from the presence of any ERROR or CRITICAL
finding, and `docs/SCOPE.md` maps that to exit code 1. So §13's choice has
operational consequences before any CLI exists:

> **One unreachable advertised broker will make a Kafka run exit non-zero.**

That is accepted deliberately. Exit 1 means "svcdoctor worked and found a
target-side problem", which is precisely this situation, and an advertised
endpoint no client can reach is the problem the tool was run to find. The
alternative — WARN, exit 0 — would make the flagship finding invisible to
automation, which is the outcome most likely to make the tool worthless in CI.

The HYPOTHESIS at WARN (§8) correctly does **not** trigger it, so an incomplete
measurement never fails a pipeline on svcdoctor's own timeout.

### 21. `Origin` is not required, and is not inferred

**Not required.** Every question this policy had to answer was answered from the
anchor (§2), the derivation edges, and the transport evidence itself. Severity —
the one place ADR 0017 predicted `Origin` would be needed — is per-subject impact
under an anchor that already guarantees the endpoint is a discovered one (§13).

**Not inferred.** No parent chain, sweep scope, subject, evidence identifier, or
root-ness is read as provenance. The policy does not read a `SweepScope` at all:
scopes keep the nodes of two sweeps distinct so the graph can hold both (ADR
0032), and diagnosis walks edges rather than parsing identifiers.

`Origin` stays deferred on exactly ADR 0013's and ADR 0031 §6's terms. **Reopen
when** an execution or topology planner has a real consumer for provenance — a
generic transport rule that must decide whether the endpoint it is looking at was
asked for is the most likely one, and it is precisely the rule this record
declines to authorize.

## Consequences

- Phase 3.6 can implement one rule with no remaining policy decision: the trigger
  conditions, kind, severity, confidence, subject, evidence set, vantage flag,
  discriminator and recommendation mapping are all fixed here.
- The generic-versus-service overlap is resolved **for advertised endpoints** by
  ownership rather than by suppression, so no engine change is needed and none is
  authorized.
- The canonical report schema is unchanged. No domain type, enum or constructor
  is touched.
- `internal/probe/transport` gained tests and no behaviour: the terminal-layer
  invariant the policy rests on is now pinned in both directions.
- One finding code is authorized: `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`. No
  catalogue, no aggregate codes, no generic transport codes.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Emit both a generic and a Kafka finding | Two phrasings of one causal fact; `docs/FINDINGS.md` §5 forbids the analogous noise | Never for one evidence node |
| Generic findings for user-supplied endpoints, Kafka for advertised | Requires `Origin`, the deferred fact — the option that looks balanced and cannot be built | `Origin` exists with a real consumer |
| Engine-level suppression of overlapping findings | Suppression keyed on identity no document defines; also a stop condition for this phase | Never in this shape |
| Severity from reachable/unreachable counts | Encodes an availability model — replication, leadership, `min.insync.replicas` — that svcdoctor never observed | svcdoctor observes replication topology |
| CRITICAL when every advertised broker fails | A breadth claim about a cluster that demonstrably answered Metadata in this run | An aggregate finding is justified on its own evidence |
| An aggregate cluster finding | States no fact the per-broker findings do not; the natural wording would be false | It carries something the conjunction does not |
| `KAFKA_ADVERTISED_ENDPOINT_PARTIALLY_REACHABLE` | Actionability depends on client address selection, which svcdoctor does not observe | A client-selection model is documented, or asymmetry is shown actionable regardless |
| Treat a SKIPPED TLS node as a second failure | Double-counts a prerequisite failure that `blockedBy` already attributes | Never |
| CONFIRMED unreachable from UNKNOWN evidence | Converts svcdoctor's own budget into a remote failure | Never |
| Lower the severity of the hypothesis because belief is weaker | Collapses impact into epistemic strength; the model separates them on purpose | Never — change the claim instead |
| Subject = a resolved address | The claim spans every path; naming one would misrepresent its scope | Never |
| Subject = the node identifier | `Subject` has no kind for a service-internal integer | A subject kind for service identity is justified on its own |
| Reference every node in the sweep | Buries the two or three nodes that prove the claim | Never |
| Put Kafka attribute keys in `internal/domain` | A core registry every new service would edit — the coupling ADR 0009 exists to prevent | Never |
| Weaken depguard so diagnosis may import the adapter | Inverts the dependency direction to avoid a mechanical move | Never |

## Reopen conditions

- **A client address-selection model** — partial multi-address reachability
  becomes decidable (§6).
- **Application orchestration exists** — the bootstrap path acquires an owner and
  the "do generic transport findings exist at all?" question becomes answerable
  with run intent (§16).
- **An aggregate that states an independent fact** — cluster-level reachability
  (§10).
- **svcdoctor diagnoses admin operations** — controller reachability may affect
  severity (§15).
- **A certificate-shaped Kafka finding** — refines the TLS-all-failed case out of
  the unreachability finding (§5, §14).
- **A configuration-shaped finding for unusable advertisements** — the case §14
  places out of scope.
- **`Origin` acquires a real consumer** — unchanged from ADR 0013 and ADR 0031 §6
  (§21).
