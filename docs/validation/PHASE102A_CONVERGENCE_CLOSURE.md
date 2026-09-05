# Phase 10.2A — Convergence semantic closure

**Status:** implemented. One production behaviour change, no schema change, no new finding code.

Phase 10.2 reported that two Kafka topology results with one semantic identity could carry
materially different prose — *"None of the 3 …"* against *"1 of the 3 …"* — and prevented that
particular collision by making the two-result shape unreachable. It also said, in as many words,
that rule applicability safety does not prove generic convergence safety.

This phase settled the general question. It did not go the way the phase brief's §5 default
merely permitted; **the audit found three reachable production shapes where the tie-break was
already publishing a claim no rule made.**

---

## 1. Baseline

`b79a9cf`, tree clean, one commit ahead of `origin/main` and deliberately not pushed.
`v0.4.0^{}` = `1182311`, untouched.

## 2. The inventory (§1), produced mechanically

Every production rule was attributed to the finding codes it can construct, by parsing each
diagnosis package and walking intra-package references **including the package-level claim
tables** the services keep their codes in. The first version of the scan walked only function
bodies, attributed 5 of Kafka's 15 codes, and reported the whole tree clean — so the analysis is
now a permanent test with two non-vacuity proofs
(`test/security/convergenceinventory_test.go`).

```text
internal/diagnosis                 1 rules,  1 codes
internal/diagnosis/transport       3 rules,  8 codes
internal/diagnosis/kafka           5 rules, 15 codes
internal/diagnosis/postgres        5 rules, 19 codes
internal/diagnosis/redis           4 rules,  9 codes
internal/diagnosis/rabbitmq        3 rules, 11 codes
attributed 63 of 63 declared finding codes
```

**Cross-package convergence is structurally impossible**: a finding code constant is declared in
exactly one package, service rule packages import only `domain`, `internal/diagnosis` and their
own vocabulary, and the generic packages produce only `DIAG_`, `DNS_`, `TCP_` and `TLS_` codes.
So every candidate is within one package.

### 2.1 Cross-rule: one pair, and it never merges

| Code | Rules | Layer | Kind | Severity | Confidence | Vantage | Discriminator | Prose |
|---|---|---|---|---|---|---|---|---|
| `POSTGRES_CONNECTION_NOT_PERMITTED` | `postgres/startup`, `postgres/authentication` | **L4 vs L5** | CONFIRMED | ERROR | HIGH | true | none | **IDENTICAL** — both call `notPermitted` with shared constants |

Layer has been a merge precondition since Phase 10.1B, so these two never converge. Notably
their prose is already shared through one constant in `internal/diagnosis/postgres/shared.go`,
which is exactly the pattern §2.2b now prescribes.

### 2.2 Intra-rule: three unsafe, one safe

Static analysis cannot see a single rule producing two findings with one identity — it depends
on how many evidence nodes a run produces — so this half was found by reasoning over each rule's
iteration and then **measured** by driving the real production rules.

| Producer | Code | How two arise | Prose relationship |
|---|---|---|---|
| `kafka/protocol` | `KAFKA_AUTH_MECHANISM_NOT_OFFERED` | the claim table maps it from **two steps**, `kafka.sasl_handshake` and `kafka.sasl_authenticate`, at one address | **IDENTICAL** — summary, detail and recommendation byte-equal |
| `kafka/advertised-endpoint` | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` | **two brokers advertised at one endpoint** | **SEMANTICALLY_CONFLICTING** |
| `kafka/unusable-advertisement` | `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` | the same shape | **SEMANTICALLY_CONFLICTING** |
| `kafka/advertised-endpoint` | same code, CONFIRMED + HYPOTHESIS | one endpoint, one broker proven unreachable and one only suspected | **SEMANTICALLY_CONFLICTING** |
| `kafka/advertised-topology`, `-suitability` | their codes | two Metadata exchanges sharing a subject | **CURRENTLY_MUTUALLY_EXCLUSIVE** — the shape is refused by the rule |
| every other rule | — | one node per (code, subject) | — |

The other multi-site codes were checked and are safe for a structural reason rather than a
prose one: `KAFKA_SASL_HANDSHAKE_NOT_COMPLETED`, `KAFKA_AUTHENTICATION_NOT_COMPLETED`,
`KAFKA_METADATA_NOT_COMPLETED`, `KAFKA_API_VERSIONS_NOT_COMPLETED`,
`KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` and `POSTGRES_TLS_CERTIFICATE_NOT_VALID_NOW`
each reach one code from several failure classes **on a single step**, and a run mints one node
per step per address.

### 2.3 Prose relationship vocabulary (§2)

| Class | Definition | Merge |
|---|---|---|
| `IDENTICAL` | byte-equal summary and detail | yes |
| `SEMANTICALLY_EQUIVALENT` | different wording, same claim content | **not representable without fuzzy matching, and therefore not a class the engine acts on.** Two rules that mean one claim share the constant that states it |
| `SEMANTICALLY_COMPLEMENTARY` | each carries distinct valid information | no — both are kept, and merging would discard one |
| `SEMANTICALLY_CONFLICTING` | choosing one changes the diagnostic claim | no — this is the class the closure exists for |
| `CURRENTLY_MUTUALLY_EXCLUSIVE` | rule applicability proves they cannot coexist in one evaluation | not exercised; and since 10.2A nothing depends on the proof |

`SEMANTICALLY_EQUIVALENT` is deliberately collapsed into `IDENTICAL` at the contract boundary.
The phase brief anticipated this: *"if semantic equivalence itself requires fuzzy/string
reasoning, that is a sign the contract should instead use a single canonical prose owner or
typed payload"*. It does, so it does not.

## 3. The three defects, measured

All three were reachable, all three published a claim no rule made, and all three had been live
since Phase 10.1B activated convergence.

**Two brokers at one endpoint.** A Kafka cluster may advertise two brokers at one host and port.
ADR 0031 keeps them as two evidence nodes precisely so that *"two nodes at one address"* stays
visible, and ADR 0034 §10 decided that they are *"two facts and produce two findings; nothing
deduplicates by endpoint or by node identifier"*. Convergence deduplicated by endpoint anyway,
because the subject is the endpoint and the broker number lives only in the prose:

```text
before:  "…for broker node 2 could not be reached…"   refs=[ad/2 metadata tcp/10.20.0.2]
         "…for broker node 7 could not be reached…"   refs=[ad/7 metadata tcp/10.20.0.7]
after:   "…for broker node 2 could not be reached…"   refs=[ad/2 ad/7 metadata tcp/…2 tcp/…7]
```

Node 7's claim was gone and its evidence was retained under node 2's sentence. **A merge
silently overrode an Accepted decision.**

**The same shape for `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE`.**

**A confirmed claim absorbing a hypothesis.** The worst of the three:

```text
before:  CONFIRMED  HIGH  "…for broker node 2 could not be reached…"
         HYPOTHESIS LOW   "…for broker node 7 may be unreachable; at least one path failed
                           and the remaining paths were not measured"
                           discriminator: re-run with a larger execution budget
after:   CONFIRMED  HIGH  "…for broker node 2 could not be reached…"   (discriminator dropped)
```

The unset discriminator folded into the set one, `CONFIRMED` absorbed `HYPOTHESIS`, and the
report stated flatly that an endpoint whose paths were never finished measuring *could not be
reached*. **Less evidence produced a stronger claim** — the failure this project names by name.

None is a defect in a rule. Each rule said something true; the engine chose between two true
sentences and published one over both sets of evidence.

## 4. Why `RuleID`-winner prose is not epistemically valid (§3)

The original argument was that once `Code`, `Subject` and `Layer` match, two routes state one
claim at one layer and only the wording differs, so which wording survives changes nothing a
consumer parses.

**Its hidden premise is that a finding's prose says nothing its structured fields do not.** That
premise held for every rule in the tree until Phase 10.2, and Kafka's advertised-endpoint rules
break it deliberately: the broker node identifier is in the summary and not in the subject,
because `docs/REPORT_SCHEMA.md` has no subject kind for a service-internal integer (ADR 0034
§12). Two findings then share an identity while describing different things.

Determinism was never the question. A deterministic choice between two true sentences is still a
choice svcdoctor is not entitled to make, and the sentence it discards is the one a reader would
have acted on. **The model is architectural debt and it has been removed**, not justified.

## 5. The models weighed (§4)

Recorded in full in ADR 0081 §4. In summary: **B — prose MUST_EQUAL for merge eligibility** was
selected. It is mechanical, byte-comparable, needs no schema change, and is a **strict
narrowing**: a group that used to merge either still merges byte for byte, or becomes two
findings that each state exactly what their rule stated. Convergence can now produce *more*
findings than before and never a *different* one, which is why no golden output moved.

A (keep the winner) was rejected on the evidence above. C and E (typed semantic payload
generating canonical prose) are the right answer *if* B ever forces a rule author to duplicate a
constant across packages; nothing does today, and adopting them now would move every sentence
out of the package that owns the claim for one motivating case. D (a primary prose owner)
re-creates the arbitrary choice as a wiring decision. F (similarity matching) is refused
outright.

## 6. What changed in the implementation

| | Before | After |
|---|---|---|
| merge key | layer, discriminator | layer, **summary, detail**, discriminator |
| `Summary` / `Detail` | the tie-break winner's | **preconditions; no winner exists** |
| representative selection | `MinFunc` by `(RuleID, Summary, Detail)` | `group[0]`, and which member it is cannot matter |
| recommendation union order | winner first, then by `RuleID` | **content order** — evidence, then reconciled fields, then advice |
| discriminator folding | matched on layer | matches on the whole non-discriminator key |

`AttributedFinding.Rule` is still validated — a finding attributed to a non-identity is a caller
defect — and is now read by nothing.

**One belt-and-braces addition:** `mergeGroup` re-checks that every member agrees on layer and
prose and returns `ErrCannotConverge` if not. A partitioning defect becomes a refusal the engine
reports as its own failure (exit 4) rather than a published value nobody measured.

## 7. The `RuleID` rename property (§10)

> Renaming a `RuleID`, while preserving rule semantics and the registration set, must not change
> the canonical diagnostic meaning.

**It did not hold before this phase, in two places.** Prose came from the winner, so a rename
could change the published sentence. And the recommendation union was ordered "winner first,
then by `RuleID`", so a rename could reorder a user-visible array.

Both are gone, and the property is now **structural rather than tested-and-hoped-for**: no merged
field is derived from a rule's name, so there is nothing for a rename to reach.
`TestC06ARuleIDRenameCannotChangeAnything` rewrites every identity through five namings —
including ones that reverse the original alphabetical order and one that gives every rule the
same name — and requires byte-identical output. ADR 0081 §2.6a records the property; §2.6's
tie-break by `RuleID` no longer has a subject.

## 8. Kafka mutual exclusivity (§6), and the distinction that matters

**Rule applicability safety.** *"None of the N"* and *"K of the N … the other M were reached"*
come from two branches of one `if` in `reachabilityProse`, evaluated once per advertised
topology, and `topologies` returns at most one entry per exchange subject. One exchange yields
one sentence. `TestC07TheTopologySentencesAreMutuallyExclusive` drives all 512 shapes at both
completeness settings and asserts it.

**Generic convergence safety.** It is no longer *why the report is safe*. The same test then
constructs the two sentences directly and requires convergence to keep both. Phase 10.2 relied
on the invariant because the engine would otherwise have picked one; the invariant is now kept
because it is true, not because anything depends on it.

## 9. PostgreSQL pressure preview (§7), analysis only

No rule was implemented and none is proposed.

**PostgreSQL has no prose-conflict pressure today.** Every PostgreSQL summary and detail is a
compile-time constant — the package contains no `fmt.Sprintf` at all — so two findings sharing a
code, subject and layer would necessarily share prose and merge correctly. The one convergent
pair already shares its constants through `shared.go`.

Four places where Phase 10.3 could create pressure:

1. **A third producer of `POSTGRES_CONNECTION_NOT_PERMITTED` at L5.** Layer is what separates the
   existing pair; a new authentication-stage anchor would remove that separation and leave prose
   as the only distinguisher. Since both existing producers share one constant, they would then
   merge — correctly.
2. **Quantitative prose over multiple hosts.** The design document's PG-C scenario is
   *"multi-host: A primary, B standby"*. A rule that says *"N of M endpoints are read-only"*
   under a subject that is the target rather than an endpoint is the Kafka topology shape with a
   different name, and the counts would conflict exactly as *"None of the 3"* and *"1 of the 3"*
   would have.
3. **A per-host claim filed against the target.** Two hosts' claims sharing one subject is the
   duplicate-advertisement shape. Filing per endpoint avoids it entirely.
4. **Interpolating a SQLSTATE into prose.** `POSTGRES_CONNECTION_NOT_PERMITTED` maps several
   SQLSTATEs onto one code and keeps its prose constant, deliberately. A rule that named the
   SQLSTATE in the sentence would make two refusals at one endpoint two claims.

In all four the closure now produces two honest findings rather than one invented one. The
guidance for Phase 10.3 is the positive form: **keep prose constant, or put in the subject what
the prose names.**

Redis carries the one other interpolating rule — `REDIS_ENDPOINT_NOT_SERVING` names the
normalized error prefix in its detail — and it is protected by the same change. A run mints one
`redis.ping` node, so it is not reachable today.

## 10. Validation

| | |
|---|---|
| C01 identical prose converges | pass |
| C02 differing layer does not | pass |
| C03 materially different summary does not | pass |
| C04 materially different detail does not | pass |
| C03/C04 kind absorption cannot smuggle a weaker claim in | pass |
| C05 registration order cannot choose prose | pass |
| C06 a rename cannot change anything, including advice order | pass |
| C07 Kafka mutual exclusivity, and the net beneath it | pass |
| C08 the one production convergence still merges | pass |
| C09 the evidence union is deterministic and complete | pass |
| C10 confidence reconciliation unchanged | pass |
| the three Kafka defects, through the real rules | pass |
| the inventory guard, with two non-vacuity proofs | pass |
| **`scripts/phase102a-mutations.sh`** | **8 planted, 8 caught, 0 survivors** |

### 10.1 Existing tests that changed, and why

Five unit tests failed on the new contract. **None was asserting a property that is still true**;
each was constructed to demonstrate the tie-break, with deliberately differing prose so that a
winner could be observed.

| Test | Change |
|---|---|
| `TestDIAG025TheMergeTable` | routes now share prose; every reconciled-field assertion is unchanged; the two "the winner's" assertions became the MUST_EQUAL statement; the recommendation order assertion follows content order |
| `TestDIAG026ConfidenceDoesNotAccumulate` | five routes share one sentence and carry distinct evidence |
| `TestARunLevelClaimHasOneIdentity` | identity assertions unchanged; the merge half uses one sentence |
| `TestMC04RegistrationOrderCannotReachAnyCanonicalField` | the two L2 routes share prose so the non-vacuity check still proves a merge happened |
| `TestPerformanceStaysLinear` | the `stateRule` fixture's summary named the evidence identifier, making every finding's prose unique. It now states what the finding claims. **The old fixture was itself an instance of the anti-pattern** |
| `TestS08TwoRulesOneConclusionConverge` | one shared sentence, plus a new `TestS08b…` asserting the differing-prose half through the full pipeline |

### 10.2 Integration

All eight suites were run against real servers. Convergence runs in every one of them, so this
is where a narrowing that changed a report would show up as a count.

| Suite | Result |
|---|---|
| Apache Kafka 4.0.0, three-broker KRaft | green |
| PostgreSQL 18 | `TestTheTLSKeyIsOwnedByTheDatabaseUser` only — the known macOS virtiofs failure |
| Redis 8.2.1 · Valkey | green |
| RabbitMQ | `TestRAB24And25AddressLiterals/RAB-25 IPv6 literal` only — the known colima failure |
| LavinMQ · Redpanda v25.1.9 · multi-target | green |

The two failures are the environmental baseline recorded in Phase 10.1B, failing at the fixture
or transport level before any rule runs. **No integration assertion moved.**

One observation recorded rather than smoothed over: the first `make integration-redis` run, third
in a back-to-back chain behind PostgreSQL, failed six tests. Run on its own the same suite passed
in full, twice, and the failures were connection-level rather than diagnostic. It is fixture
readiness under a rapid teardown-then-start sequence, not a product regression — but it is the
kind of thing that reads as one, so it is written down.

## 11. Public output

**No golden byte moved.** The change is a strict narrowing and no current production run
produces two findings with one identity and differing prose — the three shapes that do require a
duplicate Kafka advertisement.

Verified mechanically:

| | Expected | Measured |
|---|---|---|
| finding codes | 63 | **63** |
| `SchemaVersion` | 1 | **1** |
| `RunSchemaVersion` | 1 | **1** |
| failure classes | 42 | **42** |
| `Reveal` call sites | 4 | **4** |
| `SecretFor` call sites | 4 | **4** |
| external modules | 2 | **2** |
| exit codes | 5 | **5** |

**One production behaviour change**, and it is the point of the phase: a report that would have
carried one merged finding over two conflicting claims now carries both. It needs a duplicate
Kafka advertisement to reach, which no fixture in the tree produces and a real cluster can.

## 12. Schema

`SchemaVersion` stays **1**. The convergence model is entirely internal — `SemanticIdentity`,
`mergeKey` and `AttributedFinding` are unexported or `internal/`-only, and none is serialized —
so making prose a precondition needed no public structure at all. Models C and E would have,
which is part of why they were not selected now.

**Phase 10.2A required no schema change.**
