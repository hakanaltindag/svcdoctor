# Phase 10.2 — Kafka diagnostic intelligence

**Status:** implemented. Two Kafka finding codes; `SchemaVersion` unchanged.

Phase 10.1B activated generic reasoning and deliberately produced no service
intelligence. Phase 10.2 is the first service exemplar, and it is deliberately
small: **two rules, two codes, and a long list of claims that stay refused.**

Everything here is frozen by **ADR 0084**, which reopens ADR 0034 §10 on the
condition that record named for itself and upholds everything else it refused.

---

## 1. Baseline

| | |
|---|---|
| start `HEAD` | `be134d8` — Phase 10.1B |
| `origin/main` at start | `74f87b4` — **one commit behind**; 10.1B was local-only |
| `v0.4.0^{}` | `1182311`, unchanged, tag object `0b7418e` untouched |

The phase was **stopped at its own gate** on the first pass and returned
`BASELINE_BLOCKED`: §0 requires `HEAD == origin/main` and the 10.1B commit had
never been pushed. The user then authorized a normal fast-forward push,
`74f87b4..be134d8` was pushed, `git ls-remote` confirmed `refs/heads/main` at
`be134d8`, and the phase began.

Frozen counts at the baseline: `SchemaVersion` 1, `RunSchemaVersion` 1, **61**
finding codes, **42** failure classes, **4** `Reveal` and **4** `SecretFor`
production call sites, **2** external modules, **5** exit codes.

## 2. The archaeology, which decided the size of the phase

Kafka already had thirteen finding codes, and between them they cover every
**per-endpoint** claim the evidence supports.

| Question | Already answered by |
|---|---|
| did the bootstrap path work | `DIAG_FAILURE_BOUNDARY` + three generic transport findings |
| is this a Kafka endpoint | `KAFKA_API_VERSIONS_*` |
| was the credential accepted | `KAFKA_CREDENTIALS_REJECTED`, and six neighbours that are *not* it |
| did the cluster describe itself | `KAFKA_METADATA_NOT_COMPLETED` |
| was this discovered endpoint reachable | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` |
| did the cluster name an unusable endpoint | `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` |
| which stage did a discovered endpoint fail at | the same finding, in its summary |

So the phase brief's candidate list mostly resolved to *already built*. Five of
its nine candidate categories were discarded on the evidence:

| Candidate | Verdict |
|---|---|
| `BOOTSTRAP_PATH_FAILURE` | discarded — the boundary and the transport findings |
| `BOOTSTRAP_PROTOCOL_FAILURE` | discarded — `KAFKA_API_VERSIONS_*` |
| `METADATA_DISCOVERY_FAILURE` | discarded — `KAFKA_METADATA_NOT_COMPLETED` |
| `DISCOVERED_BROKER_REACHABILITY_FAILURE` | discarded — exists since Phase 3.6, CONFIRMED at HIGH |
| `DISCOVERED_ENDPOINT_TLS_FAILURE` | discarded — the existing rule names the TLS class in its summary; ADR 0034 §3 already gives it ownership of the transport evidence beneath an advertisement |
| `DISCOVERED_ENDPOINT_NAME_RESOLUTION_FAILURE` | discarded — same rule, DNS branch |
| `PARTIAL_BROKER_REACHABILITY` | **built** |
| `ALL_MEASURED_BROKERS_UNREACHABLE` | **built**, as one code with the above |
| `ADVERTISED_ENDPOINT_SUSPECT` | **built**, topology-scoped rather than endpoint-scoped |

**No per-endpoint rule was added.** Duplicating one would be the "adds little
over existing findings" case the brief says to discard, and it would have
collided with ADR 0034 §3's ownership rule.

## 3. The Kafka evidence capability matrix

What a Kafka BASIC run can prove, read off the producers rather than off
documentation.

### Directly knowable

| Fact | Node | Authority |
|---|---|---|
| bootstrap DNS outcome | `dns.lookup` under the requested-target anchor | direct |
| bootstrap TCP outcome | `tcp.connect`, per resolved address | direct |
| bootstrap TLS outcome | `tls.handshake`, per address, **iff the plan required TLS** | direct |
| ApiVersions outcome | `kafka.api_versions` + `kafka.request_api_version` | peer |
| SASL mechanism offered | `kafka.sasl_handshake` + `kafka.sasl.mechanism` | peer |
| authentication outcome | `kafka.sasl_authenticate`, five distinguishable states | peer |
| credential **withheld by policy** | same step, `SKIPPED` + `EXEC_SKIPPED_BY_POLICY` | svcdoctor's own |
| credential **absent** | same step, `SKIPPED` + `EXEC_REQUIRED_INPUT_MISSING` | svcdoctor's own |
| Metadata outcome | `kafka.metadata` | peer |
| broker node id | `kafka.broker.node_id` on each advertisement | peer |
| advertised host and port | `kafka.broker.advertised_host` / `_port` | peer |
| advertisement usability | advertisement node state: PASS or FAIL | derived, deterministic |
| broker count | `kafka.metadata.broker_count`, and the child nodes | peer |
| per-advertisement DNS / TCP / TLS | the sweep beneath each advertisement | direct |
| run completeness | `RuleContext.Incomplete`, from `incompleteKafkaRun` | svcdoctor's own |

### Derived, and used

- **advertised-endpoint reachability** — existential PASS, universal FAIL, over
  the sweep, with "not measured" kept as a third category (ADR 0051).
- **the transport plan** — read structurally: a TCP node has a TLS child if and
  only if the plan required TLS. Pinned in both directions by
  `internal/probe/transport/terminallayer_test.go`.

### Recorded and deliberately unused

- **`kafka.metadata.controller_id`.** `internal/adapter/kafka/metadata.go`
  records the measurement that makes it useless for identity: a stable
  three-broker Apache Kafka 4.0 KRaft cluster returned 1, 1, 2, 1, 1, 3, 2, 3
  across eight exchanges while the quorum leader never moved. No rule reads it.
- **`kafka.metadata.advertised_entry_count` / `unrepresentable_entry_count`.**
  An entry that cannot be a subject reference produces no node at all, so no
  finding can reference it (ADR 0035 §1).

### NOT CURRENTLY KNOWABLE

No rule may depend on any of these, and none does.

- broker liveness, process state, host state
- any broker configuration value, including `advertised.listeners`
- routing, packet filters, security groups, Kubernetes NetworkPolicy
- partition, replica, ISR, leader, consumer-group or lag state
- controller identity or KRaft quorum health
- cluster health in any sense
- which address a real client would select from a multi-address endpoint
- whether an advertised endpoint is reachable from anywhere other than here
- the implementation serving the Kafka protocol
- the operator's intent — there is no `expect:` block (ADR 0083 §2.6)

## 4. Rule inventory

Two rules. Both live in `internal/diagnosis/kafka/topology.go` and are wired at
`internal/app/kafka.go`.

### `kafka/advertised-topology` → `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY`

| | |
|---|---|
| kind / severity / confidence | `CONFIRMED` / **`INFO`** / `HIGH` |
| layer / subject | `L6` / the `kafka.metadata` node's own subject |
| vantage-dependent | true |
| required evidence | Metadata PASS, ≥1 advertisement, ≥1 **positively** failed endpoint |
| supporting evidence | the exchange, every advertisement, one reaching node per reached endpoint, the causal failure node of each unreached one |
| contradiction | none possible: it restates counts |
| discriminator | none — `CONFIRMED` findings carry none |
| next evidence | one `OBSERVE`, and only on a partial set |
| forbidden claims | any cause; "all/every broker"; a cluster verdict; a total on a partial set |

`INFO` is the load-bearing choice. ADR 0034 §13: severity is the impact of this
finding's own claim about its own subject, never a count-derived cluster verdict
— and escalating because three endpoints failed rather than one *is* that
verdict. The impact is already reported at `ERROR`, once per endpoint. A useful
consequence: Phase 10.2 cannot move any exit code.

### `kafka/advertised-suitability` → `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE`

| | |
|---|---|
| kind / severity / confidence | `HYPOTHESIS` / `WARN` / **`MEDIUM`; `HIGH` unreachable** |
| layer / subject | `L6` / the same exchange subject, different code |
| vantage-dependent | true |
| required evidence | Metadata PASS; a **complete** set; ≥1 positively failed; **none reached** |
| supporting evidence | the exchange, every unreached advertisement, each causal failure node |
| contradiction | a reached advertised endpoint — which suppresses the rule entirely |
| discriminator | *whether the advertised addresses are the ones a client on this network is expected to use to reach these brokers* |
| next evidence | one `NEXT_EVIDENCE` / `COMPARE`, `SelfCollectable: false` |
| forbidden claims | `advertised.listeners` anything; "misconfigured"; firewall; cluster down; any causal connective |

**The ceiling is structural.** The rule declares `diagnosis.AuthorityNone`, and
`AdmitConfidence` admits `HIGH` only on `AuthorityDirect` or on
`AuthorityCompleteContrast` for a `CONFIRMED` finding. Raising it means
declaring an authority the rule does not have — a source change a reviewer sees.
`TestTheSuitabilityHypothesisCanNeverBeHigh` asserts it on the ladder itself,
not on a rendered string, and `K-M16` plants the false declaration.

## 5. Bootstrap versus topology: the exact boundary

```text
bootstrap DNS/TCP/TLS  →  ApiVersions  →  SASL  →  Metadata  ┃  advertised sweeps
                                                             ┃
        no topology claim is possible left of this line ─────┛
```

The gate is one condition: a `kafka.metadata` node in state `PASS`. Left of it
there is no advertised set, so there is nothing for a topology claim to be
about, and both rules return nothing.

`TestKP01` drives all six places a bootstrap journey can stop — DNS, TCP, TLS,
ApiVersions, SASL handshake, authentication — at both completeness settings, and
requires zero topology findings from each. `TestKP02` drives four Metadata
failure classes. `K-M01` and `K-M02` plant the removal of the gate.

**Authentication is the sharpest case and it is §17 of the brief verbatim.** A
rejected credential blocks topology discovery, so the useful conclusion stays
local to bootstrap. Corpus fixture K03 forbids "advertised", "unreachable",
"the password" and "the account" — the last two because Kafka answers with one
error code for a wrong secret, an unknown principal, a disabled account and a
failing backend alike.

## 6. Partial reachability, and the three categories

| Advertised set | Observation | Hypothesis |
|---|---|---|
| PASS PASS PASS | none | none |
| PASS PASS FAIL, complete | *1 of the 3 … could not be reached …; the other 2 were reached* | none — contradicted |
| FAIL FAIL FAIL, complete | *None of the 3 … could be reached …* | **yes, MEDIUM** |
| PASS UNKNOWN FAIL | *1 of the 3 … could not be reached …; 1 was reached and 1 was not measured* | none |
| UNKNOWN UNKNOWN FAIL | *1 of the 3 …; 0 were reached and 2 were not measured* | none |
| FAIL FAIL UNKNOWN | *2 of the 3 …; 0 were reached and 1 was not measured* | none |

The third sentence exists because on a partial set both *"none of them"* and
*"only that one"* assert a total nobody established — they fail in opposite
directions and need the same missing fact.

**Completeness has two halves and needs both:** no advertised endpoint
unmeasured, **and** `RuleContext.Incomplete` false. Neither implies the other. A
run cancelled after the last sweep finished has a complete child set and an
incomplete run, and the claim is withheld anyway. `K-M05` plants dropping the
second half.

**Sibling contrast.** The generic `SiblingOutcome` query was evaluated and not
used, and ADR 0084 §11 records why: it counts child subjects one hop down, and
an advertisement's children are DNS lookups and TCP connections whose subjects
are a bare host and a resolved address — per address, not per broker. Deciding
that an advertisement was *reached* needs the terminal-layer biconditional,
which is the service-and-transport knowledge `internal/diagnosis/kafka` already
holds. **The generic core stays Kafka-unaware**, and the existing `go/ast` guard
over `internal/diagnosis` proves it.

## 7. The advertised endpoint: what may and may not be claimed

CONFIRMED and HYPOTHESIS are separate findings with separate codes, and the
separation is the point (brief §25).

| Claim | Kind | Confidence |
|---|---|---|
| this advertised endpoint was unreachable from this vantage point | `CONFIRMED` | `HIGH` — the pre-existing per-endpoint finding |
| K of N were not reached and M were, over a complete set | `CONFIRMED` | `HIGH` — a count of measured states |
| the advertised endpoints may not be usable from this client's network | `HYPOTHESIS` | `MEDIUM` |
| `advertised.listeners` is misconfigured | **never** | — |

**Why the hypothesis is topology-scoped.** The endpoint-scoped version —
*"broker-3 failed and its peers succeeded, so broker-3's advertisement may be
unsuitable"* — is contradicted by its own premise: two advertised addresses in
the same plane were reached from this client, so the advertised addresses
demonstrably work here. A reachable peer is observed evidence inconsistent with
the claim, and a rule holding contradicting evidence emits nothing.

**What makes it discriminable at all** is the bootstrap contrast, and it
discriminates exactly one thing: this client reached this cluster one way and
could not reach it the way the cluster described. That excludes *"this client
has no path to the cluster"* and excludes nothing else. One exclusion is
`MEDIUM`.

## 8. The address-shape trap

A reachable loopback, RFC 1918 or `.internal` advertisement produces **nothing
at all**. A broker on the same host as the client is a correct deployment, and
an RFC 1918 address reached from inside that network is correct too.

The mirror property is the stronger one and is also tested: when an endpoint
really is unreachable, the claim is **byte-identical** whatever the address
looks like — `127.0.0.1`, `10.30.0.1`, `192.168.44.7` and `broker.example` all
produce the same two sentences. A rule that said more about one of them would be
reasoning from a shape. `K-M12` and `K-M13` plant the heuristic in both forms.

## 9. TLS and DNS after discovery

Neither got a new rule, and ADR 0034 §3 is why: the existing per-endpoint
finding already **owns** the transport evidence beneath an advertisement, names
the earliest evidenced failing layer and every distinct failure class at it, and
no generic transport finding fires on the same nodes. A Kafka rule adding a
competing TLS interpretation would be the duplication brief §16 forbids.

The distinctions the generic TLS evidence already draws are preserved because
nothing in Phase 10.2 touches them: an identity mismatch is
`TLS_HOSTNAME_MISMATCH`, an untrusted chain is `TLS_UNKNOWN_AUTHORITY`, an
expiry is `TLS_CERTIFICATE_EXPIRED`. Corpus fixture K07 forbids "expired", "not
trusted" and "self-signed" on a hostname-mismatch scenario; `K-M10` plants the
expiry claim on the TLS recommendation.

## 10. Authentication and credential binding

Untouched, and guarded. `TestKP05` drives both non-attempt states and requires:

- the withheld state produces `KAFKA_CREDENTIAL_WITHHELD` and the absent one
  `KAFKA_CREDENTIAL_NOT_CONFIGURED`;
- **neither produces `KAFKA_CREDENTIALS_REJECTED`** — a credential nobody
  presented was not refused by anyone;
- neither produces `KAFKA_AUTHENTICATION_NOT_COMPLETED` — a deliberate refusal
  is not a negotiation that broke down;
- no topology claim, because no topology was learned;
- the prose contains no "rejected", no "invalid", no "broadening" and no
  "reuse the".

`TestNoTopologyClaimSpeaksAboutACredential` sweeps every topology claim the
package can build, at both completeness settings, for authentication vocabulary.
It exists because `K-M11` survived the first mutation run by putting
`KAFKA_CREDENTIALS_REJECTED`'s own sentence onto the suitability hypothesis.

Neither rule recommends widening a credential's authority, and neither can: the
two recommendations they produce are `OBSERVE` and `COMPARE`.

## 11. Convergence, and the Summary/Detail re-validation

Brief §32 and §33 asked whether the Phase 10.1B merge contract survives real
service convergence. **It does, and Phase 10.2 found the first pair of codes for
which it would not have.**

Phase 10.1B fixed `Summary` and `Detail` as the `RuleID` tie-break winner, safe
because once `Code`, `Subject` and `Layer` all agree the two routes state one
claim in two wordings. These two codes break that assumption: two topology
counts over one exchange would be *"None of the 3"* and *"1 of the 3"* — two
different numbers, and a tie-break would publish one of them alphabetically.

**The resolution is to make the shape unreachable rather than to merge it
correctly.** `topologies` refuses to produce anything for a subject carried by
two passing `kafka.metadata` nodes, which is a graph no producer makes. So
convergence is never exercised for these codes, which is a stronger guarantee
than merging them correctly would be.

**This is not `DESIGN_BLOCKED`.** No Accepted Phase 10 contract changes. What
changed is that the safety condition is now written down as a rule author's
obligation — `docs/FINDINGS.md` §3.1 gains rule 19 — rather than left as an
observation about the rules that happened to exist. `K-M19` plants the removal
of the refusal.

Order independence is proven three ways: rule-set rotation produces byte-
identical findings (`TestKP12`), advertisement order does not change the
sentence or the references (`TestKP13`), and a fuzz property requires at most
one finding per `(code, subject)` on any generated graph.

## 12. Epistemic safety

**False positives.** The corpus's fourteen fixtures each carry `expected`,
`allowed` and `forbidden`, and `allowed` is new: a Kafka scenario runs eight
rules, and the failure this corpus exists to catch is *a rule speaking in a
scenario nobody expected it to speak in*. Anything neither expected nor allowed
fails the scenario. A universal refusal list of twenty-one phrases is applied to
every fixture on top of its own.

**"firewall" is deliberately not a bare forbidden word.** The production
recommendation for an evidenced TCP failure says *"Check routing, firewall rules
and security group policy between this vantage point and the advertised address
and port"*, which is a place to look and not a claim about a cause. The
forbidden entries are the assertions — "a firewall is", "firewall is blocking",
"blocked by a firewall".

**Monotonicity.** Degrading any endpoint from a positively observed outcome to
an unmeasured one removes the hypothesis and removes the universal negative
(`TestKP11`). Removing the Metadata success removes the whole topology surface.
Adding a reachable peer removes the hypothesis rather than weakening it
(`TestKP10`), because contradicting evidence suppresses rather than qualifies.

**The refusal that is a feature.** Corpus K14: one advertised endpoint,
unreachable, after a reachable bootstrap. svcdoctor emits the confirmed
unreachability, the boundary, the topology observation and the hypothesis at
`MEDIUM`, and it does **not** choose between a network path that is unavailable
and an advertisement unsuitable for this client. The fixture forbids "the
cause", "therefore", "this proves" and "the only explanation".

## 13. Validation

| Level | What ran | Result |
|---|---|---|
| L1 | `internal/diagnosis/kafka/topology_test.go` — sentence shapes, the completeness matrix, the four preconditions, the confidence ceiling, subject discipline, reference sufficiency | pass |
| L2 | K-P01 … K-P15 in `test/diagnosis/kafkaproperties_test.go`, most stated over all 512 three-endpoint sets | pass |
| L3 | `scripts/phase102-mutations.sh` | **25 planted, 25 caught, 0 survivors** |
| L4 | `FuzzAdvertisedTopology`, 2.6 M executions over 120 s | pass |
| L5 | the eight service integration suites | §16 |
| L6 | the golden incident corpus K01–K14, with `expected`, `allowed` and `forbidden` | pass |
| — | the renderer-agreement check, over 448 scenarios that produce an observation | pass |
| — | historical mutation suites 9.1A/B/C, 9.2B, 9.3A, 10.1A, 10.1B | 0 survivors each |

Non-vacuity is measured rather than assumed: 448 of 512 generated sets produce
an observation, 154 findings are built across the shape matrix, and each guard
that could pass on an empty input fails loudly instead.

### 13.1 What the validation found

**A latent defect in every mutation harness in the repository.** The pre-check
that makes a wrong `-run` regex loud was written as
`printf '%s' "$selected" | grep -q '^=== RUN'` under `set -o pipefail`. `grep -q`
exits at its first match, which closes the pipe under `printf`, whose SIGPIPE
becomes the pipeline's status — so a **large** selection was reported as *no
selection at all*. Small outputs fit the pipe buffer and never showed it.

It was measured directly: a regex that matched 1026 tests and 200 KB of verbose
output was reported as "no matching test", and the same regex run by hand
matched. All eight scripts are fixed to use a here-string.

**The 20 "pre-existing survivors" recorded in `CLAUDE.md` were this artefact.**
With the fix, `phase91a` is 20 caught / 0 survivors and `phase91b` is 31 caught
/ 0 survivors. The claim was verified by re-running `phase91a` with the old
check restored: every reported survivor is a `no matching test` line naming a
regex that does match. One honest discrepancy is recorded rather than smoothed
over — the old check produced **14** survivors in `phase91a` on this machine
today against the **8** the note records, and a count that varies with how much
output a selection happens to produce is exactly what a SIGPIPE-timing artefact
looks like.

**A false positive in a Phase 10.2 test assertion, found by the fuzzer in under
a second.** The prose-safety check was a substring search for the advertised
hostname, and `Brok` is a case-insensitive substring of "broker", which every one
of these sentences contains and none copied. A substring search over English is a
search for coincidences. It was replaced by the property that was meant: rebuild
the identical graph shape under a fixed benign name and require the prose to be
**byte-identical**. That holds against any encoding, homoglyph or escaping a
substring check would miss. A second fuzz finding refined it further — the empty
string is a legal `":9092"` endpoint and an illegal bare hostname, so it changed
the graph's *shape* rather than its names, and the comparison had to normalize
both positions.

**Four of the ten first-run mutation survivors were the suite's fault rather
than the product's**, and fixing them added four guards that had not existed:
the unrecognized-sweep classification, the credential-vocabulary boundary, the
exact reference set, and the merge-safety refusal. A twenty-fifth plant was added
for the reference set, because a mutation suite that only confirms the tests you
already wrote has measured the tests.

## 14. Public output

| | Before | After |
|---|---|---|
| `SchemaVersion` | 1 | **1** |
| `RunSchemaVersion` | 1 | **1** |
| finding codes | 61 | **63** |
| `KAFKA_` codes | 13 | **15** |
| generic `DIAG_` codes | 1 | **1** |
| failure classes | 42 | **42** |
| `Reveal` call sites | 4 | **4** |
| `SecretFor` call sites | 4 | **4** |
| external modules | 2 | **2** |
| exit codes | 5 | **5** |
| renderer files changed | — | **0** |

**No JSON field was added, removed, renamed or repurposed.** Both codes are
additive; a consumer that does not know them sees one more `INFO` finding and,
on a total failure, one more `WARN` hypothesis.

**Exit semantics are unchanged and proven so.** `deriveSummary` promotes only
`ERROR` and `CRITICAL`. The observation is `INFO` and the hypothesis is `WARN`,
so neither can move an exit code in either direction — and the scenarios that
produce them already exit 1 on the per-endpoint `ERROR`.

**Terminal.** Both render through the existing findings block; no renderer
changes.

```text
  · INFO  KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY  ip-001:<port>
    None of the 3 broker endpoints this cluster advertised could be reached from this vantage point
```

**Shareable.** Subjects pseudonymize through the existing redaction contract,
the counts survive because they carry no identity, and the two claims still name
**one** subject between them so a reader can tell they concern the same
exchange. No advertised hostname, bootstrap hostname or resolved address
survives into the shareable projection.

## 15. Schema

`SchemaVersion` 1, `RunSchemaVersion` 1. Two pressures were felt and neither was
acted on.

- **Recommendation kind and safety class.** ADR 0082 §2.1 puts them on
  `domain.Recommendation` additively, and Phase 10.2 is the first phase with a
  real `NEXT_EVIDENCE` instance. They still did not move: it is a generic change
  touching every renderer and every golden report, and this phase's contract is
  Kafka reasoning. **The guardrails run anyway** — both rules construct advice
  through `diagnosis.NewAdvice` and `AdmitAdvice` and project only the action
  text, so the producible-class check, the read-only requirement, the confidence
  gate and the no-executable-command validator all execute. Advice the
  classification would reject yields **no recommendation at all**, because
  emitting the string would be the guardrail deleting itself.
- **Structured contradiction.** Unchanged from Phase 10.1B: contradiction is
  rule-internal and reaches no report field. Here it manifests as a rule that
  does not fire, which is what ADR 0081 §2.4 prescribes.

Neither was forced into an existing string field. **Phase 10.2 required no
schema change.**

## 16. Performance

Both rules walk each advertisement's own sweep once and never compare a pair of
them, so the cost is linear in nodes and edges. Measured, twenty iterations each:

| advertised endpoints | graph nodes | per evaluation |
|---|---|---|
| 3 | 17 | 4.6 µs |
| 10 | 38 | 19 µs |
| 50 | 158 | 58 µs |
| 100 | 308 | 123 µs |
| 500 | 1508 | 657 µs |

5× the endpoints costs 5.4× the time. No `O(N²)` behaviour, no per-pair
allocation, and a 500-endpoint set still produces exactly one observation and
one hypothesis.

## 17. The principal review

1. Kafka diagnosis runs with **no network I/O** — `diagnosis-is-pure` makes it a
   build failure.
2. Rules **cannot** access credentials — `internal/security` is denied.
3. Bootstrap failure **cannot** produce topology diagnosis — gated on Metadata
   `PASS`; `TestKP01`, `K-M01`.
4. Metadata failure **cannot** produce discovered-broker diagnosis — `TestKP02`,
   `K-M02`.
5. `UNKNOWN` **cannot** count as a broker failure — `TestKP03`, `K-M03`.
6. `SKIPPED` **cannot** count as a broker failure — same, via ADR 0051's
   predicate.
7. Incomplete measurement **cannot** produce "all brokers failed" — `TestKP06`,
   `K-M17`.
8. Incomplete measurement **cannot** produce "only broker X failed" — same.
9. A loopback address alone **cannot** produce a configuration finding —
   `TestKP08`, `K-M12`.
10. A private address alone **cannot** either — `K-M13`.
11. Broker TCP failure **cannot** imply a firewall — universal refusals, `K-M08`.
12. Nor a broker process being down — `K-M22`, and the pre-existing overclaim
    guard bans "is down".
13. Nor prove `advertised.listeners` wrong — `K-M07`.
14. Auth failure **cannot** imply a bad password — `K-M09`, corpus K03.
15. Hostname mismatch **cannot** imply expiry — `K-M10`, corpus K07.
16. One failed broker **cannot** imply a cluster outage — `K-M22`, corpus K08.
17. Successful siblings **do** provide useful contrast — the observation's second
    sentence.
18. Sibling contrast **cannot** become `HIGH` by voting — `AuthorityNone` admits
    `MEDIUM` at most, and no count reaches the ladder.
19. Evidence deletion **cannot** strengthen a Kafka hypothesis — `TestKP11`.
20. Contradictory evidence **cannot** increase confidence — `TestKP10`, `K-M14`.
21. Raw metadata **cannot** enter trusted prose — byte-equality fuzz property,
    `K-M21`.
22. Broker subjects **cannot** incorrectly converge — different codes and
    different subjects; the one hazardous shape is refused, `K-M19`.
23. `RuleID` winner **cannot** change semantic Kafka meaning — §11.
24. Summary/Detail winner semantics are **still safe**, and the condition is now
    written down as rule 19 of the quality bar.
25. Redpanda **cannot** trigger Apache-Kafka-only conclusions — `TestKP15` sweeps
    every claim for implementation vocabulary; `K-M23`.
26. Discovered-endpoint diagnoses **are** vantage-qualified — `vantageDependent`
    true on both, asserted in the fuzz target.
27. Credential-withheld states **are** distinct from auth failure — `TestKP05`,
    `K-M11`.
28. The generic core **remains** Kafka-unaware — the `go/ast` guard, unchanged
    and still passing.
29. Renderers **remain** reasoning-free — zero renderer files changed.
30. The canonical report **is** still the source of truth.
31. Schema v1 **is** still semantically honest — §15.
32. Fleet **still** avoids cross-target causal reasoning — untouched.
33. The architecture still satisfies *probes collect facts, adapters understand
    protocols, diagnosis correlates evidence, renderers explain results.*
