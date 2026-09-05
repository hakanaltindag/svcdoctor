# ADR 0084 — Kafka topology-scoped reachability, and the advertised-suitability hypothesis

**Status:** Accepted
**Date:** 2026-09-05
**Phase:** 10.2
**Reopens:** ADR 0034 §10, on the condition that record itself named.
**Refines:** ADR 0078–0083 (the Phase 10 reasoning model), which it changes in nothing.

---

## 1. Context

Phase 10.1B activated generic reasoning and deliberately produced **no service intelligence**:
convergence, the failure boundary and the confidence ladder went live, and no rule used any of
them to say anything about a service. Phase 10.2 is the first service exemplar, and Kafka is
the exemplar because it is the only service in the tree whose runs learn a *topology* — a set
of endpoints a peer named, each of which was then measured.

The archaeology matters more here than usual, because most of what a reader would expect Phase
10.2 to build already exists and has since Phase 3.6:

| Question an operator asks | Already answered by |
|---|---|
| did the bootstrap path work | `DIAG_FAILURE_BOUNDARY` + the three generic transport findings |
| is this a Kafka endpoint at all | `KAFKA_API_VERSIONS_*` |
| was my credential accepted | `KAFKA_CREDENTIALS_REJECTED`, and six neighbours that are *not* it |
| did the cluster describe itself | `KAFKA_METADATA_NOT_COMPLETED` |
| was this discovered broker endpoint reachable | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` |
| did the cluster name an endpoint no client can use | `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` |
| which DNS/TCP/TLS stage did a discovered endpoint fail at | the same finding, in its summary |

Thirteen Kafka finding codes, and between them they cover every *per-endpoint* claim the
evidence supports. Phase 10.2 therefore adds **no per-endpoint rule at all**. Duplicating one
would be the "little over existing findings" case the phase brief explicitly says to discard.

What is missing is one level up.

## 2. The problem, stated exactly

Given three advertised brokers, one of which was refused, a v0.4.0 report carries one
`KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` and one `DIAG_FAILURE_BOUNDARY`. Both are true. Neither
says the thing an operator reads the report to learn:

> The other two were reached, so this client does have a path to the cluster's broker plane,
> and the failure is specific to one endpoint.

Given three advertised brokers, **none** of which was reached, the report carries three
findings that are individually identical to the previous case's one. Nothing distinguishes
"one broker of three" from "the whole advertised set" except counting findings, which a reader
cannot do safely because a fourth broker svcdoctor never attempted produces the *same three
findings*.

So two facts are absent and neither can be recovered from the conjunction of what is present:

1. **completeness** — whether the set the findings describe is the whole set;
2. **contrast** — what became of the endpoints that are *not* in a finding.

ADR 0034 §10 refused an aggregate on the grounds that *"all three are unreachable" is the
conjunction of three findings that are all present*. That was right about the conjunction and
it did not consider these two, because in Phase 3.5 neither was expressible: `RuleContext`
did not exist, so a rule could not see that svcdoctor's own budget had cut a run short, and
the confidence ladder did not exist, so a rule had no principled way to state a set-level
inference at less than full strength. Both arrived in Phase 10.1.

§10's own reopen condition is *"when an aggregate would carry something the conjunction does
not"*. Completeness and contrast are that something.

## 3. Decision: `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY`

A **CONFIRMED observation**, one per Metadata exchange, emitted only when at least one
advertised endpoint positively failed.

| Field | Value |
|---|---|
| `kind` | `CONFIRMED` — every number in it is a count of states the graph already holds |
| `severity` | **`INFO`** |
| `confidence` | `HIGH` — it restates measured states and infers nothing |
| `layer` | `L6` |
| `subject` | the `kafka.metadata` node's own subject: the endpoint the question was asked at |
| `vantageDependent` | `true` |
| `discriminator` | none, and `domain.NewFinding` refuses one on a `CONFIRMED` finding |
| `recommendations` | none, except on a partial set, where one `NEXT_EVIDENCE` asks for the missing measurement |

**Severity is `INFO`, and this is the decision most likely to be argued with.** ADR 0034 §13
fixed the rule that decides it: severity is the impact of *this finding's* claim about *its
own* subject, and never a count-derived cluster verdict. Escalating because three endpoints
failed rather than one is precisely that verdict. The impact of an unreachable broker endpoint
is already reported, at `ERROR`, once per endpoint, by the finding that has carried it since
Phase 3.6. This one adds scope and completeness, which are context rather than impact.

It has the useful consequence that Phase 10.2 cannot change any exit code: `deriveSummary`
promotes only `ERROR` and `CRITICAL`.

### 3.1 Three sentences, and why the third exists

| Condition | Sentence |
|---|---|
| complete, none reached | *None of the N broker endpoints this cluster advertised could be reached from this vantage point* |
| complete, some reached | *K of the N … could not be reached …; the other M were reached* |
| **not complete** | *K of the N … could not be reached …; M were reached and P were not measured* |

The third exists because of the one claim this rule must never make. On a set with anything
unmeasured, both "none of them" and "only that one" assert a total nobody established — they
fail in opposite directions and need the same missing fact. The incomplete form states all
three counts and calls none of them a total, and its detail says in as many words that *an
endpoint that was not measured is not an endpoint that refused*.

This is the RAB18 lesson in this rule's terms: **less evidence must never produce a stronger
claim.**

### 3.2 Nothing is emitted for a healthy run

Every endpoint reached produces no finding. A report that reports what worked as thoroughly as
what did not is a report nobody reads to the end, and the terminal already prints
`topology  3 of 3 advertised broker endpoints reached` for exactly this case.

## 4. Completeness has two halves and needs both

```text
complete  ==  no advertised endpoint is unmeasured   AND   !RuleContext.Incomplete
```

Neither half implies the other, and dropping either is a mutation the suite plants.

The first is a statement about *this exchange's children*: it is false when a sweep produced an
`UNKNOWN` node carrying a local class, when a name resolved and nothing was attempted against
it, or when the sweep is a shape the transport chain does not produce.

The second is svcdoctor's statement about *its own execution* (ADR 0080 §2.1). It matters
because a run cut short may have been cut short before an advertisement was ever recorded, and
a rule reading the graph cannot see what was never written down. A run cancelled after the last
sweep finished has a complete child set and an incomplete run; the claim is withheld anyway,
which is the safe direction.

### 4.1 The classification is ADR 0051's, stated a third time on purpose

`internal/app` holds this predicate for run completeness and `internal/render/terminal` holds
it for the topology count line. depguard denies `internal/diagnosis` both, for reasons that
have nothing to do with this, so a third statement of it is unavoidable.

**The agreement is proven at the output boundary rather than asserted.** One graph goes through
the engine and through the terminal renderer, and the finding's three counts are compared
against the rendered line's, over all 512 three-endpoint shapes. A divergence would produce a
report whose finding and whose summary line contradict each other three lines apart, which is
worse than either being wrong alone.

PASS is existential and FAIL is universal: one working path resolves an endpoint outright,
whatever happened on its siblings, and a negative is complete only when nothing was left
unmeasured.

**An advertisement the cluster stated unusably counts as not reached, not as unmeasured.**
There was no endpoint to sweep and none was promised, so it is a positively observed negative;
`KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` owns what it means. Calling it unmeasured would let one
unusable advertisement silently block every complete claim.

## 5. Decision: `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE`

A **HYPOTHESIS** that the endpoints a cluster advertised may not be usable from this client's
network position.

| Field | Value |
|---|---|
| `kind` | `HYPOTHESIS` |
| `severity` | `WARN` |
| `confidence` | `MEDIUM`, and **`HIGH` is unreachable** |
| `layer` | `L6` |
| `subject` | the exchange's subject — the same as the observation's, and a different code |
| `vantageDependent` | `true` |
| `discriminator` | *whether the advertised addresses are the ones a client on this network is expected to use to reach these brokers* |
| `recommendations` | one `NEXT_EVIDENCE` / `COMPARE`, `SelfCollectable: false` |

### 5.1 Four preconditions, each load-bearing

1. The Metadata exchange passed. Without it there is no advertised set.
2. Every advertised endpoint was measured, and the run was not cut short (§4).
3. At least one advertised endpoint positively failed.
4. **No advertised endpoint was reached.**

### 5.2 Why the ceiling is `MEDIUM` and why that is structural

The rule declares `diagnosis.AuthorityNone`. ADR 0081 §2.3 admits `HIGH` on exactly two grounds
— the peer stated the condition in its own protocol, or every distinguishable alternative was
measured and excluded — and neither is available:

- **No Kafka field says this.** There is no error code meaning "my advertised address is
  unreachable from where you are". A Metadata response is a list of endpoints, not a claim
  about them.
- **Alternatives remain unexcluded**, and they are ordinary rather than exotic: a route that
  does not exist for the broker ports, a packet filter that admits the bootstrap port and not
  the others, a load balancer or NAT in front of the bootstrap endpoint, brokers whose
  listeners are down. svcdoctor measured none of them and can measure none of them.

So `AdmitConfidence` cannot return `HIGH` for this rule whatever the evidence looks like, and
raising the ceiling would mean *declaring an authority the rule does not have* — a source change
a reviewer sees, rather than a threshold that drifts.

**Commonness is not evidence.** The advertised-listener misconfiguration is the best-known
Kafka failure in the field, and that is a fact about the population of incidents rather than
about this one.

### 5.3 What makes it discriminable enough to emit at all

ADR 0083 §2.2 rule 2: if nothing distinguishes a claim from the alternatives, emit no causal
hypothesis.

The bootstrap contrast is what distinguishes it, and it distinguishes exactly one thing: this
client demonstrably reached this cluster one way, and could not reach it the way the cluster
described. That excludes *"this client has no path to the cluster"* and excludes nothing else.
One exclusion is `MEDIUM`.

### 5.4 Why precondition 4 also forbids a per-endpoint version

The tempting rule — *"broker-3 failed and its peers succeeded, so broker-3's advertisement may
be unsuitable"* — is not a weaker version of this hypothesis. It is **contradicted by its own
premise**: two advertised addresses in the same plane were reached from this client, so the
advertised addresses demonstrably work here, and what is left is specific to one broker in a
way no advertisement claim explains better than a broker-side one.

A reachable peer is therefore observed evidence *inconsistent* with the claim (ADR 0081 §2.4),
and a rule holding contradicting evidence emits nothing. This is why the hypothesis is
topology-scoped rather than endpoint-scoped, and why there is no `KAFKA_ADVERTISED_ENDPOINT_
SUSPECT`.

### 5.5 The refusal is a feature and there is a corpus fixture for it

Scenario K14: one advertised endpoint, unreachable, bootstrap reachable. svcdoctor emits the
confirmed unreachability, the boundary, the topology observation and this hypothesis at
`MEDIUM` — and it does **not** choose between *a network path that is unavailable* and *an
advertisement unsuitable for this client*. The fixture forbids "the cause", "therefore",
"this proves" and "the only explanation" for exactly that reason.

## 6. What the prose may and may not say

svcdoctor knows the endpoint a Metadata response reported. It does **not** know any broker's
configuration, and it never will in BASIC.

| Admissible | Inadmissible |
|---|---|
| *cluster metadata advertised this endpoint* | *`advertised.listeners` is set to X* |
| *these endpoints may not be usable from this client's network position* | *`advertised.listeners` is misconfigured* |
| *no measured path reached them* | *a firewall is blocking them* |
| *the bootstrap endpoint was reached* | *the cluster is up but the brokers are down* |

The detail says so explicitly — *"svcdoctor read no broker setting and holds none"* — because
the distinction is the one a reader is most likely to collapse on their own.

**No value a peer chose is interpolated into any of this prose.** The only values that reach
these strings are integers this package counted off the graph's own structure. The advertised
hostname, port and broker node identifier travel on the subject and on the referenced evidence,
where redaction transforms them (ADR 0081 §2.7). A fuzz target asserts the property as byte
equality of the prose across different advertised names, which is stronger than a substring
search and immune to the encoding tricks a substring search misses.

## 7. What stays refused

Everything ADR 0034 §10 refused except the aggregate, plus one more:

- **`KAFKA_CLUSTER_UNHEALTHY`, `KAFKA_BROKER_DOWN`, `KAFKA_NETWORK_BROKEN`** — still
  unauthorized. The observation is a count and the hypothesis is about addresses; neither is a
  verdict about a cluster, a host or a process.
- **The claim §10 named as the candidate aggregate** — *"no advertised broker is usable from
  here, so this client can do nothing beyond bootstrap metadata"*. Its second clause needs a
  model of what a client requires, which still does not exist. The observation states the
  reachability counts and stops before the consequence.
- **A per-endpoint suitability hypothesis** — §5.4.
- **Partial multi-address reachability within one advertisement** — ADR 0034 §6 is untouched.
  This record is about several *advertisements*; that one is about several *addresses under
  one advertisement*, and its blocker — that svcdoctor does not observe which address a real
  client would select — is unchanged.
- **Controller and KRaft inference.** `kafka.metadata.controller_id` is recorded, and
  `internal/adapter/kafka/metadata.go` documents the measurement that makes it useless for
  identity: a stable three-broker Apache Kafka 4.0 cluster returned 1, 1, 2, 1, 1, 3, 2, 3
  across eight exchanges while the quorum leader never moved. No rule reads it.
- **Partition, replication, ISR and consumer-group claims.** BASIC requests none of it. If a
  Kafka DEEP mode ever wants them it is a different diagnostic surface and its own record.
- **Address-shape heuristics.** A reachable loopback, RFC 1918 or `.internal` advertisement
  produces nothing at all. The failure is the evidence; the shape of the address is not, and
  a broker on the same host as the client is a correct deployment.

## 8. Identity, subjects and convergence

Semantic identity is `(Code, Subject)` and merging is gated on `Layer` and `Discriminator`
agreeing (ADR 0081 §2.1 and §2.2a). Two questions follow.

**Do these collide with the per-endpoint findings?** No. The codes differ, and so do the
subjects: these are filed against the endpoint the Metadata question was asked at, and the
per-endpoint findings against the advertised endpoints. Even when a cluster advertises the
bootstrap's own resolved address — which it may — the codes differ and nothing merges.

**Could two of these merge?** Only if one graph held two `kafka.metadata` nodes sharing a
subject, which no producer makes: a Kafka BASIC run performs exactly one Metadata exchange, and
the exchange's evidence identifier carries the address it ran over.

It would nonetheless be **unsafe** rather than merely arbitrary if it happened. `Summary` and
`Detail` are taken from a `RuleID` tie-break (ADR 0081 §2.2), which is safe for every finding
in the tree because once code, subject and layer agree the two routes state one claim in two
wordings. These two codes break that assumption: *"None of the 2"* and *"1 of the 2"* are
different counts, and choosing between them alphabetically would publish a number nobody
measured.

**So the shape is refused rather than reconciled.** When two passing Metadata exchanges share a
subject, both rules return nothing for that subject — the same direction `collectSweep` errs in
for a shape it does not recognize. Convergence is therefore never exercised for these codes,
which is a stronger guarantee than merging them correctly would be, and a fuzz property asserts
that no generated graph produces two findings sharing an identity.

**This is not a defect in the Phase 10.1B merge contract.** That contract's stated safety
condition is that prose which survives a tie-break is one claim in two wordings, and the
condition is met by every rule in the tree because these two rules are structurally prevented
from violating it. What Phase 10.2 adds is the observation that the condition is a *rule
author's obligation* rather than an engine guarantee, and `docs/FINDINGS.md` now says so.

## 9. Recommendation metadata stays off `domain.Recommendation`

ADR 0082 §2.1 puts `kind`, `safety`, `rationale` and `selfCollectable` on
`domain.Recommendation`, additively, and Phase 10.1B declined to move them because nothing
populated them. Phase 10.2 is the first phase with a real `NEXT_EVIDENCE` instance and still
does not move them, for two reasons: it is a generic change touching every service's renderer
and every golden report, and this phase's contract is Kafka reasoning.

**The guardrails run anyway.** Both rules construct their advice through `diagnosis.NewAdvice`
and `diagnosis.AdmitAdvice` and project only the action text onto `domain.Recommendation`, so
the producible-class check, the read-only requirement on next evidence, the confidence gate and
the no-executable-command validator all execute at construction. Advice the classification
would reject yields **no recommendation at all** rather than an unclassified string, because
emitting the string would be the guardrail deleting itself.

The field move remains ADR 0082's and is a candidate for the phase that touches the renderers.

## 10. Consequences

**Finding codes move 61 → 63**, both in the `KAFKA_` namespace (13 → 15). The generic `DIAG_`
namespace stays at **one**: a topology claim belongs to the service whose topology it is.

`SchemaVersion` stays **1** and `RunSchemaVersion` stays **1**. No JSON field is added,
removed, renamed or repurposed. No failure class, state, step, layer or exit code changes. No
renderer changes — both findings render through the existing findings block.

**Two claims about one subject appear in one report**, and that is the intended shape: the
observation is what was measured and the hypothesis is what it might mean, kept apart because
ADR 0078 §2.2 makes a reader's ability to tell a measurement from a piece of reasoning a
property of the model rather than of the wording.

**The corpus grows an `allowed` list.** A service scenario runs eight rules and produces
between zero and eight findings, and the failure this corpus exists to catch is *a rule
speaking in a scenario nobody expected it to speak in*. Naming every code that may appear turns
that from an oversight into a build failure.

## 11. Alternatives considered

**Leave ADR 0034 §10 closed and ship no aggregate.** Rejected, and it was the starting
position. It leaves an operator unable to distinguish one broker from the whole plane without
counting findings, and counting findings is exactly what an unmeasured endpoint makes unsafe.

**One code with `ERROR` for the universal case and `INFO` for the partial one.** Rejected: it
is severity as a function of a count, which ADR 0034 §13 forbids by name.

**Two codes, one per sentence shape.** Rejected. They are one claim — the measured scope of
advertised reachability — at three fill levels, and splitting them would be the permutation
multiplication the phase brief warns against. The shapes are distinguished by counts a consumer
reads structurally from the evidence, not by parsing prose.

**A per-endpoint suitability hypothesis.** Rejected — §5.4. It is contradicted by its own
premise whenever a peer is reachable, and where no peer is reachable the topology-scoped
version already covers it.

**Emitting the suitability hypothesis at `LOW` on an incomplete set.** Rejected. The claim is
about a whole set; on a partial set it is not a weaker claim about the same thing, it is a
claim about something that was not measured. The correct output is the observation with its
three counts and the next-evidence recommendation that asks for the rest.

**Reading `kafka.metadata.controller_id`.** Rejected — §7, on measurement rather than on
principle.

**A generic `SiblingOutcome` call for the broker classification.** Rejected. The generic query
counts child subjects one hop down, and an advertisement's children are DNS lookups and TCP
connections whose subjects are a bare host and a resolved address — per address, not per
broker. Deciding that an advertisement was "reached" requires knowing that a TLS node exists
beneath a TCP node if and only if the plan required one, which is exactly the service-and-
transport knowledge `internal/diagnosis/kafka` already holds for ADR 0034. The generic core
stays unaware, and the `go/ast` guard over `internal/diagnosis` keeps it that way.

## 12. Security implications

None new. Both rules are pure functions of a frozen graph; `diagnosis-is-pure` denies the
package the adapter, the probes, `internal/security`, `net`, `crypto/tls`, `os` and the random
sources, so "a rule cannot read a credential, a file, an environment variable or a socket" stays
a build failure. `Reveal` and `SecretFor` production call sites stay at **4** each.

The live risk is peer-controlled text, and §6 handles it: no advertised value is interpolated
into prose, asserted as byte equality under fuzzing. A credential-withheld state is a distinct
finding from a rejected credential and neither rule reads either, so no Phase 10.2 claim can
turn svcdoctor's own security decision into an accusation against a credential.

Neither rule recommends widening a credential's authority, and neither can: the vocabulary that
would classify such advice is `CONFIG_CHANGE` at best, and the two recommendations these rules
produce are `OBSERVE` and `COMPARE`.

## 13. Validation requirements

- Unit: every sentence shape, the completeness matrix in both halves, the hypothesis's four
  preconditions, the confidence ceiling asserted on the ladder rather than on prose.
- Property: the three verdict categories against all 512 three-endpoint sets, with the counts
  checked against the fixture's own intention.
- Property: no partial set produces a total; no bootstrap failure produces a topology claim;
  a reachable peer removes the hypothesis; degrading any endpoint to unmeasured never
  strengthens anything; rule order and discovery order do not reach the output.
- Property: the finding's counts agree with the terminal's topology line, over all 512 shapes.
- Corpus: K01–K14, each with `expected`, `allowed` and `forbidden`, and a universal refusal
  list applied to every scenario.
- Fuzz: arbitrary advertised sets including shapes no producer makes, asserting no panic,
  bounded runtime, at most one finding per identity, sorted resolving references, no blocked
  node cited, inert prose, and prose byte-identical across advertised names.
- Mutation: `scripts/phase102-mutations.sh`, 24 plants, zero survivors.
- Scaling: 3, 10, 50, 100 and 500 advertised endpoints, with the complexity recorded.
