# Phase 11.0 — Diagnostic planning / next-best-evidence opportunity audit

- **Phase:** 11.0 — principal-level architecture and epistemic-safety audit. **No production Go
  code, no test change, no fixture, no harness.**
- **Baseline:** `22633f29303076f92810fc1f184f065fd6aec8af`, `HEAD == origin/main`, working tree
  clean at start
- **Record:** ADR 0092
- **Outcome:** **DEFER DIAGNOSTIC PLANNING.** Twenty-nine candidates weighed across five service
  families and three generic layers; **zero admitted**. Real competing explanation pairs exist —
  and the two strongest are **already fully served by structured `NEXT_EVIDENCE` advice that
  shipped in Phase 10.4B**.

---

## 1. Baseline, as measured

Nothing below is taken from a historical document. Every figure was re-measured against the tree
at `22633f2`, and where a figure is test-proven the guard that proved it is named.

| Fact | Value | How |
|---|---|---|
| `HEAD` | `22633f2` | `git rev-parse HEAD` |
| `origin/main` | `22633f2` | `git rev-parse origin/main` — identical |
| working tree at start | clean | `git status --short` empty |
| Phase 10.8B committed | yes, `22633f2` *"feat(rabbitmq): preserve capacity-scope explanation"* | `git show --stat HEAD` |
| ADR 0091 committed | yes, `5bd6589` | `git log` |
| `make check` before editing | **exit 0** — fmt-check, `go test ./...`, `go vet ./...`, `golangci-lint run ./...` *0 issues*, `CGO_ENABLED=0 go build ./...` | run |

### 1.1 Frozen counts

| Measurement | Value | How |
|---|---|---|
| `domain.SchemaVersion` | **1** | `internal/domain/report.go:21` |
| `domain.RunSchemaVersion` | **1** | `internal/domain/runreport.go:26` |
| declared `FindingCode`s | **65** | `TestMTG05TheFindingCodeCountIsUnchanged` |
| **attributed** `FindingCode`s | **65 of 65** | `TestTheConvergenceInventoryIsComplete` |
| production diagnostic rules | **22** | same scan |
| `FailureClass` values | **42** | `grep -oE 'Failure[A-Za-z0-9]+:' internal/domain/failureclass.go \| sort -u` |
| `RuleContext` fields | **3** (`Graph`, `Vantage`, `Incomplete`) | `TestDIAG017RuleContextCarriesExactlyThreeFields` |
| external modules | **2** | `TestTheDependencyCountIsExact` |
| `security.Reveal` production sites | **4** (one per service) | `TestRevealHasOneProductionCallSitePerService` |
| `SecretFor` production sites | **4** | same suite |
| exit codes | **5** (`0`–`4`) | `docs/SCOPE.md` §exit codes |
| service adapters | **4** — Kafka, PostgreSQL, Redis/Valkey, RabbitMQ/LavinMQ | `internal/adapter/*` |
| composition roots | **4** leaf + 1 fleet | `internal/app/{kafka,postgres,redis,rabbitmq}.go`, `internal/fleet/run` |

### 1.2 Rules and codes per package — the scan's own output

```
internal/diagnosis                1 rules,  1 codes
internal/diagnosis/transport      3 rules,  8 codes
internal/diagnosis/kafka          5 rules, 15 codes
internal/diagnosis/postgres       6 rules, 21 codes
internal/diagnosis/redis          4 rules,  9 codes
internal/diagnosis/rabbitmq       3 rules, 11 codes
attributed 65 of 65 declared finding codes
```

Codes by namespace: `POSTGRES_` 21 · `KAFKA_` 15 · `RABBITMQ_` 11 · `REDIS_` 9 · `TLS_` 5 ·
`DNS_` 2 · `TCP_` 1 · `DIAG_` 1.

### 1.3 Reasoning-primitive producers — re-measured, not inherited

Phase 10.5A published this table at `105e43b`. Phases 10.6A, 10.7A/B, 10.8A/A.1 and 10.8B have
landed since. **Every row reproduces unchanged.**

| Primitive | Production producers | Where |
|---|---|---|
| `FindingKindHypothesis` | **2 codes** | `kafka/advertisedendpoint.go:266` (incomplete branch), `kafka/topology.go:655` |
| `Finding.Discriminator` set by a rule | **2 sites** | `advertisedendpoint.go:269`, `topology.go:668` (`converge.go:480` is the merge, not a rule) |
| `diagnosis.NewBasis` | **1 site** | `kafka/topology.go:700` |
| `BasisBuilder.Support` | **1 site**, three calls | `topology.go:700,702,704` |
| `BasisBuilder.Contradict` | **0** | — |
| `BasisBuilder.Miss` | **0** | — |
| `BasisBuilder.Block` | **0** | — |
| `AdmitConfidence` | **1 site** | `topology.go:647` |
| `AuthorityNone` passed as a value | **1** | `topology.go:648` |
| `AuthorityDirect` passed as a value | **0** | named in PostgreSQL comments; the rule sets `ConfidenceHigh` as a literal |
| `AuthorityCompleteContrast` passed as a value | **0** | — |
| `AdviceKindNextEvidence` producers | **5 sites** | `postgres/session.go:306`, `postgres/admission.go:416,428`, `kafka/topology.go:624,670` |
| `AdviceKindRemediation` producers | **0** | the constant is referenced only by the guardrails |
| `SelfCollectable: true` | **2** | `topology.go:628`, `admission.go:432` |
| `SelfCollectable: false` | **3** | `topology.go:677`, `admission.go:423`, `session.go:314` |
| `GraphBuilder.AddBlockedBy` | **6** adapter/probe sites | read by 3 rules, by `domain.Report`'s projection and by redaction |

**`RecommendationKind` vocabulary:** `UNSPECIFIED`, `NEXT_EVIDENCE`, `REMEDIATION` — 3 values,
2 producible.
**`SafetyClass` vocabulary:** `UNSPECIFIED`, `OBSERVE`, `VERIFY`, `COMPARE`, `CONFIG_CHANGE`,
`RESTART`, `DISRUPTIVE`, `SECURITY_WEAKENING` — 8 values; `RESTART`, `DISRUPTIVE` and
`SECURITY_WEAKENING` are **unreachable by construction** (`NewAdvice` refuses a non-`Producible`
class, and `domain.NewClassifiedRecommendation` re-checks at the report boundary).
**`Authority` vocabulary:** `NONE`, `DIRECT`, `COMPLETE_CONTRAST` — 3 values, 1 with a producer.

### 1.4 Recorded evidence attributes — re-measured

ADR 0090 §3's inventory reproduces exactly at this commit. **70 recorded**, and the derivation is
mechanical:

| Origin | Count |
|---|---|
| `internal/vocabulary` (`tls.verified`) | 1 |
| `internal/probe/tls` | 9 |
| `internal/probe/dns` (`dns.answers`) | 1 |
| `internal/probe/tcp` | **0** |
| Kafka — `internal/service/kafka` 4 + `internal/adapter/kafka` 10 | 14 |
| PostgreSQL — `internal/service/postgres` 7 + `internal/adapter/postgres` 10 | 17 |
| Redis — `internal/service/redis` | 7 |
| RabbitMQ — `internal/service/rabbitmq` | 21 |
| **total** | **70** |

Consumption is unchanged from ADR 0090 §3: **10** read by a rule, **24** by a renderer, **2** by
both, **38** by neither. This audit re-derives no consumption figure of its own, because ADR 0090
§7 already froze the principle that **unconsumed is not debt**, and Phase 11.0's question is a
different one.

**One structural fact is worth stating because it decides several candidates below: the TCP probe
records no evidence attribute at all.** Everything a connection attempt establishes travels as
`State` + `FailureClass` on the node. There is nothing latent in a TCP node to consume.

---

## 2. Records read

Read in full or in the sections that constrain this audit:

**ADRs.** 0008 (no hidden client behaviour), 0009 (composition-root registration), 0010
(canonical evidence excludes raw objects), 0012 (vantage), 0014 (a finding cites evidence;
severity is data), 0017 (the rule contract), 0028 / 0030 (credential authority is the logical
endpoint), 0034 §10, §12, §13, §17, §18 (Kafka claim policy), 0039 §17 (no SQL), 0040 §5, §18,
§20, §22 (PostgreSQL rule surface), 0041 (discover broadly, authenticate narrowly), 0043 §14–15
(generic transport claims), 0050 (discovery creates no secret authority), 0054 (owner before
producer), 0058 (trust versus identity), 0059 (an address is not a name), 0063 §10–11 and 0065,
0066 (Redis command allowlist, prefix-only classification, no expectation), 0067, 0068 §4.1,
0069 §6, §8, §9.4 and 0070 (RabbitMQ bounded AMQP policy), 0071–0074 (multi-target configuration,
credentials, execution, aggregate report), 0077 §2.1, §2.7, **0078** (the reasoning model; §2.6
purity and the iterative deferral), **0079** (the failure boundary; §2.4 no negative explosion),
**0080** (rule architecture; `RuleContext`), **0081** (identity, the confidence ladder, the four
evidence relations, §2.2b prose as precondition, §2.6a the rename property, §2.7 peer text),
**0082** (recommendation safety and next-best evidence), **0083** (§2.1 additive evolution, §2.2
the false-positive policy, §2.3 defective rules, **§2.6 declared intent**, §2.7 non-causal
aggregates), 0084 §4, §7, §9, 0085 §3.2, §4, §5, **0086** (next-best evidence and
indistinguishable hypotheses, in full), **0087** (evidence-relation semantics, OUTCOME C),
**0088** (Redis/RabbitMQ selection), **0089** (observation expansion), **0090** (existing
evidence consumption), **0091** (canonical explanation semantics).

**Documents.** `docs/FINDINGS.md`, `docs/OUTPUT.md`, `docs/BACKLOG.md`, `docs/SCOPE.md`,
`docs/design/DIAGNOSTIC_INTELLIGENCE.md` (§E competing hypotheses, §G next-best evidence, §I
service exemplars, §P phasing).

**Validation records.** `PHASE100_DIAGNOSTIC_TRACEABILITY.md`,
`PHASE101A_DIAGNOSTIC_CORE_VALIDATION.md`, `PHASE101B_DIAGNOSTIC_ACTIVATION_VALIDATION.md`,
`PHASE102_KAFKA_DIAGNOSTIC_VALIDATION.md`, `PHASE102A_CONVERGENCE_CLOSURE.md`,
`PHASE103_POSTGRES_DIAGNOSTIC_VALIDATION.md`, `PHASE104A_NEXT_BEST_EVIDENCE_CONTRACT.md`,
`PHASE105A_EVIDENCE_RELATION_AUDIT.md`, `PHASE106A_DIAGNOSTIC_OPPORTUNITY_AUDIT.md`,
`PHASE107A_DIAGNOSTIC_OBSERVATION_EXPANSION_AUDIT.md`,
`PHASE107B_POSTGRES_SESSION_READ_ONLY_OBSERVATION.md`,
`PHASE108A_EXISTING_EVIDENCE_CONSUMPTION_AUDIT.md`,
`PHASE108A1_CANONICAL_FINDING_EXPLANATION_CORRECTION.md`,
`PHASE108B_RABBITMQ_CAPACITY_CANONICAL_EXPLANATION.md`.

**Phase 10.4B has no validation record of its own.** Its contract is
`PHASE104A_NEXT_BEST_EVIDENCE_CONTRACT.md` and its implementation is commit `105e43b`
*"feat(diagnosis): preserve structured next-evidence advice"*; the phase is traced through
`test/diagnosis/nextevidenceinvariant_test.go` (NBE-021) and the `docs/OUTPUT.md` §next-evidence
section rather than through a separate document. That is recorded here because the brief asked
for the record and looking for one is otherwise a dead end.

---

## 3. What "diagnostic planning" means, frozen for this audit

A **planning opportunity** exists only when all seven hold:

1. svcdoctor has reached an **epistemic boundary** — a point where its current evidence supports
   no further true claim about the subject;
2. at least **two genuinely distinct explanations** remain compatible with that evidence;
3. the explanations **matter operationally** — they send the operator to different places;
4. a **concrete observation O** exists whose possible outcomes would materially distinguish them;
5. O has a **defined authority boundary** — it is known what O's result would and would not prove;
6. O has **bounded cost and side effects**;
7. O's result would **change what svcdoctor can responsibly say**.

**Explicitly not planning**, and each exclusion killed at least one candidate below: another
recommendation; generic troubleshooting advice; *"check the firewall / the logs / with your
DBA"*; arbitrary remediation; documentation links; **retrying the same probe**; collecting data
because it happens to be available; a hard-coded troubleshooting sequence; an LLM-generated
investigation plan.

Full text of the definition, the competing-explanation test and the observation taxonomy is
frozen in **ADR 0092 §2**. This section is the summary the case files are scored against.

---

## 4. The complete diagnostic frontier — DPF-001 … DPF-067

Complete over all **65** finding codes plus the non-finding states (`UNKNOWN`, `SKIPPED`,
blocked, budget-cut, cancelled, and every observation that is deliberately not a finding).
Nothing is sampled.

`CLOSED_FRONTIER` means the finding leaves **no unresolved operator-relevant question** — either
because the claim is already exactly as wide as the evidence, or because the residual question is
about svcdoctor's own capability or the operator's own input rather than about the target.

### 4.1 Generic DNS

| ID | State | Frontier | Candidate |
|---|---|---|---|
| DPF-001 | `DNS_NAME_NOT_RESOLVED` | *Does the name exist, or does this host's resolver not see it?* | **C-05** |
| DPF-002 | `DNS_RESOLUTION_FAILED` | *Is the resolver unreachable, or the upstream slow?* | **C-05** |
| DPF-003 | `dns.lookup` PASS, multiple answers | none — no claim is made about the answer set | CLOSED_FRONTIER |
| DPF-004 | `dns.lookup` UNKNOWN (budget / cancellation) | *What would the lookup have returned?* | **C-08** |
| DPF-005 | address-literal target — **no `dns.lookup` node at all** (ADR 0059) | none — a DNS finding is structurally unreachable, not suppressed | CLOSED_FRONTIER |

### 4.2 Generic TCP

| ID | State | Frontier | Candidate |
|---|---|---|---|
| DPF-006 | `TCP_CONNECTION_NOT_ESTABLISHED`, every address timed out | *Is the path dropping packets, or is nothing answering anywhere?* | **C-01**, **C-02** |
| DPF-007 | `TCP_CONNECTION_NOT_ESTABLISHED`, every address refused | *Is nothing listening, or is a filter forging the reset?* | **C-03** |
| DPF-008 | mixed classes across address families | none — ADR 0043 merges six classes into one code deliberately, and the distribution stays on the cited nodes | CLOSED_FRONTIER |
| DPF-009 | partial success — one address connects, another does not; the finding is **withheld** | *Is the failing address intentional?* | **C-04** |
| DPF-010 | `tcp.connect` UNKNOWN / SKIPPED | *not measured* versus *not reached* | **C-08** |

### 4.3 Generic TLS

| ID | State | Frontier | Candidate |
|---|---|---|---|
| DPF-011 | `TLS_CHAIN_NOT_TRUSTED` | *Is this run's trust source wrong, or the endpoint's chain?* | **C-06** |
| DPF-012 | `TLS_IDENTITY_MISMATCH` | *Is the requested name wrong, or the certificate's names?* | **C-07** |
| DPF-013 | `TLS_CERTIFICATE_NOT_VALID_NOW` | *Is the certificate outside its window, or this host's clock wrong?* | **C-09** |
| DPF-014 | `TLS_HANDSHAKE_NOT_COMPLETED` (the floor) | *Version, cipher, client certificate, or the path?* | **C-10** |
| DPF-015 | `TLS_ENDPOINT_DOES_NOT_SPEAK_TLS` | none — the claim is already *"this endpoint answered with something that was not TLS, on this attempt, from this vantage"* | CLOSED_FRONTIER |
| DPF-016 | `tls.verified=false` under `--tls-insecure` | none — the operator disabled it and the report says so twice, in the header and per handshake row (ADR 0060) | CLOSED_FRONTIER |
| DPF-017 | `TLS_VERSION_MISMATCH`, `TLS_CLIENT_CERTIFICATE_REQUIRED`, `TLS_CLIENT_CERTIFICATE_REJECTED` — declared classes, **no producer** | *Could they gain one?* | **C-10** |

### 4.4 Generic — boundary, completeness, execution

| ID | State | Frontier | Candidate |
|---|---|---|---|
| DPF-018 | `DIAG_FAILURE_BOUNDARY` | *Does the boundary say where more evidence would help?* | **C-11** |
| DPF-019 | `Result.Incomplete()` — budget or cancellation | *What was not measured?* | **C-08** |
| DPF-020 | graph-blocked (`SKIPPED`) nodes | none — the blocker owns the failure and `blockedBy` is serialized (ADR 0087, Model A) | CLOSED_FRONTIER |
| DPF-021 | a rule panicked; its output was discarded | none — a defect in svcdoctor, exit 4 (ADR 0083 §2.3) | CLOSED_FRONTIER |
| DPF-022 | multi-target run, several targets fail alike | none — cross-target reasoning is forbidden (ADR 0073, ADR 0083 §2.7) | CLOSED_FRONTIER |

### 4.5 Kafka

| ID | State | Frontier | Candidate |
|---|---|---|---|
| DPF-023 | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` — CONFIRMED | *Reachable from anywhere?* | **C-12** |
| DPF-024 | the same code — **HYPOTHESIS**, incomplete branch | *Would the unmeasured paths have succeeded?* | **C-08** |
| DPF-025 | `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE` — HYPOTHESIS, the tree's flagship open question | *Advertisement wrong for this network, or the path unavailable?* | **C-13** |
| DPF-026 | `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` — incomplete category non-empty | *the unmeasured endpoints* | **C-08** |
| DPF-027 | `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` | none — the cluster's own advertisement string cannot be turned into an endpoint; there is nothing further to observe | CLOSED_FRONTIER |
| DPF-028 | `KAFKA_CREDENTIALS_REJECTED` | *identity unknown, or secret wrong?* | **C-14** |
| DPF-029 | `KAFKA_AUTH_MECHANISM_NOT_OFFERED` | *which mechanisms were offered?* — already on the cited node | **C-15** |
| DPF-030 | `KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | none — a statement about svcdoctor | CLOSED_FRONTIER |
| DPF-031 | `KAFKA_CREDENTIAL_WITHHELD`, `KAFKA_CREDENTIAL_NOT_CONFIGURED` | none — svcdoctor's own policy and the operator's own input | CLOSED_FRONTIER |
| DPF-032 | `KAFKA_API_VERSIONS_NOT_COMPLETED`, `KAFKA_SASL_HANDSHAKE_NOT_COMPLETED`, `KAFKA_AUTHENTICATION_NOT_COMPLETED`, `KAFKA_METADATA_NOT_COMPLETED` | none — floors; the exchange ended and nothing about the peer was established | CLOSED_FRONTIER |
| DPF-033 | `KAFKA_API_VERSIONS_VERSION_REJECTED` | none — direct protocol authority | CLOSED_FRONTIER |
| DPF-034 | `KAFKA_PEER_VERIFICATION_FAILED` | none | CLOSED_FRONTIER |
| DPF-035 | an **unrepresentable** advertisement makes `complete` overclaim (ADR 0090 §9 C2) | *does the count include it?* | **C-16** |
| DPF-036 | partition / leader / ISR availability | none reachable — `Topics = []` means no partition byte arrives (ADR 0089 §3.1) | CLOSED_FRONTIER |
| DPF-037 | controller / KRaft health | none — `controller_id` measured returning 1,1,2,1,1,3,2,3 on a stable cluster (ADR 0084 §7) | CLOSED_FRONTIER |

### 4.6 PostgreSQL

| ID | State | Frontier | Candidate |
|---|---|---|---|
| DPF-038 | `POSTGRES_CONNECTION_NOT_PERMITTED`, single address | *is the host-based rule intentional?* | **C-17** |
| DPF-039 | `POSTGRES_ADMISSION_SCOPE`, **contrast** branch | *one endpoint with a rule gap, or two endpoints with different rules?* | **C-18** |
| DPF-040 | `POSTGRES_ADMISSION_SCOPE`, incomplete branch | *the undetermined addresses* | **C-08** |
| DPF-041 | `POSTGRES_CONNECTION_LIMIT_REACHED` (`53300`) | *which limit, enforced where?* | **C-19** |
| DPF-042 | `POSTGRES_CREDENTIALS_REJECTED`, `POSTGRES_AUTHENTICATION_FAILED` | *role unknown, or secret wrong?* | **C-14** |
| DPF-043 | `POSTGRES_DATABASE_NOT_FOUND`, `POSTGRES_DATABASE_CONNECT_DENIED` | none — the peer named the condition in a field its protocol defines | CLOSED_FRONTIER |
| DPF-044 | `POSTGRES_STARTUP_FAILED`, `POSTGRES_SESSION_ESTABLISHMENT_FAILED` — including a pooler's `08P01` collapse | *did I reach PostgreSQL or an intermediary?* | **C-20** |
| DPF-045 | `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` (MD5, cleartext, SCRAM-SHA-256-PLUS observed and declined) | none — a statement about svcdoctor's capability | CLOSED_FRONTIER |
| DPF-046 | `POSTGRES_TLS_DECLINED`, `POSTGRES_SSL_NEGOTIATION_FAILED`, `POSTGRES_TLS_UPGRADE_NOT_HONORED` | none — the endpoint's in-band answer is the whole of it | CLOSED_FRONTIER |
| DPF-047 | the four `POSTGRES_TLS_*` chain/identity/window/handshake codes | the generic TLS frontier, per service | **C-06, C-07, C-09, C-10** |
| DPF-048 | `postgres.in_hot_standby` + `postgres.default_transaction_read_only` on a successful session | *were my writes supposed to work here?* | **C-21** |
| DPF-049 | `POSTGRES_CREDENTIAL_WITHHELD`, `POSTGRES_CREDENTIAL_NOT_CONFIGURED`, `POSTGRES_PEER_VERIFICATION_FAILED`, `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | none | CLOSED_FRONTIER |
| DPF-050 | multi-endpoint role divergence (split brain, dual primary) | **not producible** — `internal/app/postgres.go` continues exactly one path (ADR 0041), guarded structurally | CLOSED_FRONTIER |

### 4.7 Redis / Valkey

| ID | State | Frontier | Candidate |
|---|---|---|---|
| DPF-051 | `REDIS_ENDPOINT_NOT_SERVING` — seven-plus prefixes collapsed into one sentence | *which condition did the endpoint name?* | **C-22** |
| DPF-052 | `REDIS_CREDENTIALS_REJECTED` | *user unknown, or secret wrong?* | **C-14** |
| DPF-053 | `REDIS_COMMAND_NOT_PERMITTED` (`NOPERM`) | *would the application's own commands be permitted?* | **C-23** |
| DPF-054 | `REDIS_PING_NOT_COMPLETED`, `REDIS_PROTOCOL_NOT_ESTABLISHED`, `REDIS_AUTHENTICATION_NOT_COMPLETED` | none — floors | CLOSED_FRONTIER |
| DPF-055 | `REDIS_ENDPOINT_IS_SENTINEL` | none — the expectation came from the invocation (`diagnose redis`) | CLOSED_FRONTIER |
| DPF-056 | `REDIS_CREDENTIAL_WITHHELD`, `REDIS_CREDENTIAL_NOT_CONFIGURED` | none | CLOSED_FRONTIER |
| DPF-057 | `redis.role` / `redis.mode` observation lines (replica, cluster) | *is this the role I meant?* | **C-21** |
| DPF-058 | client-limit exhaustion arrives as a bare `ERR` | *is this a resource limit?* | **C-24** |
| DPF-059 | a multi-address Redis run whose addresses disagree — **never produced** | *scope aggregate* | **C-25** |

### 4.8 RabbitMQ / LavinMQ

| ID | State | Frontier | Candidate |
|---|---|---|---|
| DPF-060 | `RABBITMQ_CONNECTION_NOT_PERMITTED`, capacity, **mapped** outcome | none since Phase 10.8B — the finding now names the node / vhost / user ceiling the endpoint named | CLOSED_FRONTIER |
| DPF-061 | the same code with `UNSPECIFIED_TRUNCATED` — the reply was cut before the limit clause | *which ceiling was it?* | **C-26** |
| DPF-062 | `RABBITMQ_VHOST_NOT_FOUND` versus `RABBITMQ_VHOST_ACCESS_REFUSED` | none — already the two causes AMQP distinguishes | CLOSED_FRONTIER |
| DPF-063 | `RABBITMQ_CREDENTIALS_REJECTED`, including the `guest` loopback restriction | *did the loopback rule apply?* | **C-27** |
| DPF-064 | `RABBITMQ_CONNECTION_NOT_ESTABLISHED`, `RABBITMQ_CONNECTION_START_NOT_COMPLETED`, `RABBITMQ_AUTHENTICATION_NOT_COMPLETED` | none — floors | CLOSED_FRONTIER |
| DPF-065 | `RABBITMQ_AUTH_MECHANISM_NOT_OFFERED`, `RABBITMQ_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR`, `RABBITMQ_CREDENTIAL_WITHHELD`, `RABBITMQ_CREDENTIAL_NOT_CONFIGURED` | none | CLOSED_FRONTIER |
| DPF-066 | `VHOST_DOWN` (`541`) — classified, forbidden to speak for want of a live measurement | *does it occur?* | **C-28** |
| DPF-067 | negotiated `channel_max` / `frame_max` / `heartbeat`; what the identity may do **inside** a vhost | *is the negotiated value right?* needs intent; the interior needs a channel | **C-21**, **C-29** |

**Totals.** **67** frontier cases: **28 `CLOSED_FRONTIER`** and **39 candidate-bearing**.
The 39 map to **29 distinct candidates**, because several frontier states share one — the
budget-cut case C-08 arises at six of them, the credential-rejection case C-14 at four, and
the PostgreSQL TLS row DPF-047 carries the four generic TLS candidates unchanged. Counting
distinct candidates rather than rows is what keeps §6.1's verdict table honest: one candidate,
one verdict.

---

## 5. Candidate case files — C-01 … C-29

Every candidate has a case file. None is sampled. Each carries the fields §33 of the brief
requires; where a field is identical for a whole group it is stated once at the group head rather
than copied, and where a field is genuinely not applicable it says so rather than being omitted.

**Fields common to every candidate below, unless the case file says otherwise:** run completeness
is `complete` (the incompleteness cases are C-08); no candidate proposes an `EvidenceBasis`
relation; no candidate proposes a new `FindingCode`; no candidate requires Phase 10.4C; no
candidate requires Phase 10.5B. Deviations are stated per case.

---

### C-01 — TCP timeout, measured again from another vantage

- **Service/layer:** generic transport, L2. **DPF-006.**
- **Existing codes:** `TCP_CONNECTION_NOT_ESTABLISHED`; also `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`
  at topology scope (see C-12).
- **Existing evidence:** one `tcp.connect` node per resolved address, all `FAIL` with
  `TCP_CONNECTION_TIMEOUT`. The finding is CONFIRMED / ERROR / HIGH, `vantageDependent: true`.
- **Failure boundary:** last success `dns` (or `target.requested` for a literal), first failure
  `tcp`.
- **Explanation A:** something on the path between this vantage and the endpoint is discarding
  the connection attempt.
- **Explanation B:** the endpoint itself does not answer a connection attempt from anywhere.
- **Why both remain possible:** a timeout is the *absence* of any response. It is the one TCP
  outcome that carries no information about which end produced it, which is why the code is named
  for what did not happen rather than for a cause.
- **Why meaningfully distinct:** A sends the operator to their own network; B sends them to the
  endpoint's host and listener. Different teams, different afternoons.
- **Observation O:** the same TCP connect to the same endpoint from a different network position.
- **Class:** `O3_ALTERNATE_VANTAGE`. **Vantage:** `ALTERNATE_VANTAGE`. **Authority:**
  measured-contrast — and **never** causal.
- **Outcome table:**

| Outcome | Contradicts | Remains possible | New admissible claim | Still forbidden |
|---|---|---|---|---|
| O1 — connects from vantage B | B, in the strong form *"answers nobody"* | A; also *"the endpoint filters by source"*, *"the endpoint was down for one interval and not the other"* | *"reachability differs by network position"* | firewall · routing · security group · NetworkPolicy · *"the problem is your network"* |
| O2 — times out from vantage B too | nothing | A (two paths, one shared segment), B, and a destination-side filter covering both sources | *"both measured positions observed the same outcome"* | *"the endpoint is down"*; *"it is not vantage-specific"* — two samples are not a population |

- **Information gain:** **MATERIAL** on O1, **LOW** on O2.
- **Already collected?** No. **Self-collectable?** **No** — see below. **Automatic collection
  appropriate?** No.
- **Credential requirements:** none for the TCP probe itself. But a vantage that only runs TCP
  answers only the TCP question; a vantage that runs a full diagnosis needs the credential
  *at that vantage*, which is a secret-distribution problem the credential model has no answer
  for. ADR 0028 binds a credential to a logical endpoint, not to a place svcdoctor runs.
- **Privilege:** none locally; whatever the second vantage's execution channel demands.
- **Side effects:** one connection attempt. Bounded.
- **Cost/budget:** the observation is bounded; **the mechanism is not.** svcdoctor holds no
  second vantage and no way to acquire one. Executing there means SSH, an agent, a scheduled pod,
  or a remote API — each a new product with its own authentication, trust boundary and attack
  surface.
- **Compatibility:** not applicable — no protocol is involved.
- **Security/privacy:** a remote-execution channel is the single largest security surface anyone
  could propose adding to this repository.
- **Data minimization:** the target's address would be disclosed to whatever executes at vantage B.
- **Fixture feasibility:** a two-network-namespace fixture is constructible on Linux; on macOS
  and under colima it is exactly the environment limitation this project has already recorded.
- **Determinism:** poor. A vantage contrast measured at two instants is two measurements, and
  the difference may be time rather than place.
- **Current domain-model fit:** **it does not fit.** `domain.VantageSource` has exactly one value,
  `LOCAL_HOST`, and `domain.NewLocalVantage` is the only constructor *by design* — its doc
  comment says a remote source "gets its own constructor with its own required fields". A report
  carries one `Vantage`. `domain.RunReport` wraps per-target reports **verbatim** and forbids
  merging them, so a two-vantage contrast has no canonical representation and building one as
  two targets would be the cross-target causal diagnosis ADR 0073 forbids.
- **Requires 10.4C?** No. **Requires 10.5B?** No. **Requires new ADR?** Several: a vantage model,
  a remote-execution contract, a two-vantage report shape, and a security review.
- **Verdict:** **DEFER_ARCHITECTURE.**
- **Reason:** the observation is real and its information gain is genuine, and everything else
  about it is missing. svcdoctor cannot take it, cannot represent its result, and the bounded
  claim it would buy — *reachability differs by network position* — is deliberately so narrow
  (§16 of the brief, ADR 0092 §2.4) that it does not justify becoming a distributed execution
  system. **This is the candidate the brief nominated as possibly strongest. It is not admitted,
  and the reason is not that the epistemics are weak — they are the best in the audit — but that
  every non-epistemic gate fails at once.**

---

### C-02 — a vantage-contrast recommendation on a transport failure (the advisory form of C-01)

- **Service/layer:** generic transport, L2. **DPF-006.**
- **Observation O:** the same as C-01, collected by the operator. **Class:**
  `O3_ALTERNATE_VANTAGE`. **Vantage:** `ALTERNATE_VANTAGE`. **Authority:** measured-contrast.
- **Shape:** a `NEXT_EVIDENCE` / `COMPARE` recommendation with `SelfCollectable: false`, on the
  existing CONFIRMED finding. Representable today: `POSTGRES_ADMISSION_SCOPE` already carries
  exactly this shape on a CONFIRMED finding, and the confidence gate constrains only
  `REMEDIATION`.
- **Information gain:** **NONE**, and that is the finding. `detailConnectionNotEstablishedShared`
  already ends: *"Connectivity depends on this network position: the source address, the route
  taken and anything inspecting traffic along it can all differ elsewhere."* The recommendation
  would restate canonical prose the finding already carries.
- **Two further objections, both repository-grounded.** First, the advice would be **identical on
  every transport failure**, and a suggestion whose content does not depend on the evidence is
  boilerplate rather than next-best evidence. Second, the only way to make it evidence-dependent
  is to key it on the failure class — *"try elsewhere"* is worth more on a timeout than on a
  refusal — and that reintroduces exactly the per-address-family arbitration ADR 0043 refused
  when it merged six classes into one code, because a dual-stack endpoint routinely produces
  `ECONNREFUSED` on one family and `ETIMEDOUT` on the other.
- **Verdict:** **REJECT_ALREADY_KNOWN.**

---

### C-03 — TCP refused: no listener, or a forged reset

- **Service/layer:** generic transport, L2. **DPF-007.**
- **Explanation A:** nothing is bound to that port on the host that answered.
- **Explanation B:** an intermediary answered with a reset on the endpoint's behalf.
- **Why both remain possible:** a `RST` is a `RST`. Nothing on the wire attributes it.
- **Observation O:** none exists. TTL analysis, banner comparison and reset-fingerprinting are
  heuristics over an adversary-influenced signal, and each would be inference dressed as
  measurement.
- **Class:** `O9_NOT_COLLECTABLE`. **Vantage:** `SAME_VANTAGE`. **Authority:** none available.
- **Information gain:** **LOW** for anything proposable; **NONE** for anything safe.
- **New admissible claim:** none. **Still forbidden:** *"nothing is listening"* — already banned
  by name in `test/diagnosis/falsepositive_test.go` FP01A.
- **Verdict:** **REJECT_NO_INFORMATION_GAIN.**
- **Note.** The distinction the operator actually needs — *a host answered and declined* versus
  *nothing answered* — is **already delivered**, on the `FailureClass` of every cited node, and
  the finding's own detail says so and says the reason behind it is unknown. That is the whole
  of what the evidence supports.

---

### C-04 — one address connects and another does not: intentional or not

- **Service/layer:** generic transport, L2. **DPF-009.**
- **Existing state:** the TCP finding is **withheld** — one PASS falsifies *"no connection
  completed"* — and every per-address node stays in the report.
- **Explanation A:** the failing address is deliberate (an `AAAA` record for a host with no IPv6
  listener; a decommissioned address still in the zone).
- **Explanation B:** the failing address is a defect, and clients that pick it will hang for a
  connect timeout before falling back.
- **Why meaningfully distinct:** A is *do nothing*; B is *fix the record or the listener*. This is
  a real and under-diagnosed incident shape.
- **Observation O:** none that is an observation. What separates A from B is **whether the address
  was meant to serve**, which no protocol, no record and no measurement states.
- **Class:** `O4_OPERATOR_DECLARED`. **Vantage:** `SAME_VANTAGE`. **Authority:** operator-declared.
- **Information gain:** **LOW** — no observation moves it; only a declaration does.
- **Verdict:** **REJECT_NO_INFORMATION_GAIN.**
- **Adjacent, and deliberately out of scope:** a per-address *reachability scope* observation for
  generic transport, in the shape `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` and
  `POSTGRES_ADMISSION_SCOPE` already have. That is an evidence-consumption question governed by
  ADR 0043's withholding rule and ADR 0034 §13's severity rule, **not** a planning candidate, and
  Phase 11.0 neither proposes nor authorizes it.

---

### C-05 — name did not resolve: ask a different resolver

- **Service/layer:** generic transport, L1. **DPF-001, DPF-002.**
- **Existing codes:** `DNS_NAME_NOT_RESOLVED`, `DNS_RESOLUTION_FAILED`.
- **Existing evidence:** one `dns.lookup` node, `FAIL` with `DNS_NO_ADDRESS`, `DNS_TIMEOUT` or
  `DNS_RESOLVER_FAILURE`. **`DNS_NXDOMAIN` exists as a class and has no producer**, deliberately:
  Go's resolver sets the same not-found flag for a name that does not exist and a name with no
  address record, so the probe refuses to draw the distinction.
- **Explanation A:** the zone genuinely publishes no usable address for this name.
- **Explanation B:** this host's resolver does not see it — split horizon, a search-domain
  interaction, a stale negative cache, a wrong `/etc/resolv.conf`.
- **Why both remain possible:** one resolver answered once. Nothing in that answer distinguishes
  the zone's content from the resolver's view of it.
- **Why meaningfully distinct:** A is a DNS-zone change; B is a host or cluster DNS
  configuration change. Genuinely different work.
- **Observation O:** the same query against a resolver outside this host's configuration.
- **Class:** `O2_PASSIVE_NEW_REQUEST`. **Vantage:** `ALTERNATE_VANTAGE` — a resolver *is* a
  network position for L1. **Authority:** resolver-authoritative-for-this-query, and no more.
- **Outcome table:**

| Outcome | Contradicts | Remains possible | New admissible claim | Still forbidden |
|---|---|---|---|---|
| O1 — the second resolver returns addresses | A | B | *"two resolvers answered differently for this name"* | *"your DNS is broken"*; *"the name exists"* — the second resolver is not authoritative either |
| O2 — the second resolver also returns nothing | nothing decisively | A; and B under split horizon, where an outside resolver is *expected* to see nothing | *"neither measured resolver returned an address"* | *"the name does not exist"* |

- **Information gain:** **MATERIAL**, and the highest in the audit. It is not DECISIVE because
  split horizon confounds O2 in exactly the deployments svcdoctor is most often pointed at.
- **Already collected?** No. **Self-collectable?** Only with a new probe capability.
- **Credential requirements:** none. **Privilege:** none. **Side effects:** one DNS query.
- **Cost/budget:** one query per target; bounded.
- **Security/privacy — the disqualifying objection for the obvious implementation.** Querying a
  public resolver would **disclose the operator's internal hostname to a third party**. svcdoctor
  is most often aimed at names that exist only inside a private zone, and a diagnostic tool that
  silently exports them is a data-exfiltration channel with a helpful name. **A public resolver
  is refused permanently.** An operator-supplied resolver is the only admissible form, and an
  operator who can name one can also query it.
- **The fidelity objection, which is subtler and equally serious.** `dns.SystemResolver`'s own
  doc comment states the model: it is *"the resolver a client on this vantage would use"*.
  svcdoctor's entire value proposition is that it behaves as the client the operator asked it to
  diagnose. **A second resolver answers a question about a different client**, and publishing its
  answer beside the first invites reading the second as the truth and the first as the error —
  which is precisely backwards when split horizon is working as designed.
- **Compatibility:** finding an authoritative server needs an `NS` lookup through the same
  suspect resolver, and querying it needs a DNS client the standard library does not provide —
  a third module, against a dependency count pinned by test at **2**.
- **Fixture feasibility:** good — two stub resolvers with different answers.
- **Determinism:** good.
- **Current domain-model fit:** poor. There is no representation for *"resolved differently
  elsewhere"*, and `dns.answers` is one attribute on one node.
- **Requires new ADR?** Yes — a probe-capability record, a CLI record, a privacy review and a
  report-representation decision.
- **Verdict:** **DEFER_ARCHITECTURE.**
- **Reason:** the epistemics are the strongest in the audit and everything around them is
  unbuilt. It is also **not planning in the sense frozen here**: it is a probe expansion whose
  result would be a second measurement, not a step chosen by reasoning over the first.

---

### C-06 — chain not trusted: re-verify the presented chain against the other trust source

- **Service/layer:** generic TLS, L3. **DPF-011.** Applies identically to
  `POSTGRES_TLS_CHAIN_NOT_TRUSTED`.
- **Existing evidence:** `tls.handshake` `FAIL` / `TLS_UNKNOWN_AUTHORITY`, plus
  `tls.trust_source`, `tls.peer_certificate_count`, `tls.peer_not_before`, `tls.peer_not_after`,
  `tls.peer_dns_names`, `tls.peer_ip_addresses`.
- **Explanation A:** the trust source this run used is the wrong one for this endpoint.
- **Explanation B:** the endpoint presented a chain no reasonable trust source would accept —
  most often a leaf with its intermediates omitted.
- **Why both remain possible:** `TLS_UNKNOWN_AUTHORITY` is by contract a claim about a *pairing*
  and names the local half first. It cannot, by design, say which half is wrong.
- **Observation O:** verify the **same presented chain** — which the probe already holds — against
  the other trust source available on this host, and record the outcome.
- **The mechanism exists and is discarded.** `observation.peerCertificates()`
  (`internal/probe/tls/handshake.go:376-386`) recovers the full chain from
  `CertificateVerificationError.UnverifiedCertificates` on a *failed* verification, extracts the
  SANs, the count and the window, and then drops the certificates at the probe boundary —
  correctly, under ADR 0010.
- **Class:** `O1_PASSIVE_EXISTING_PROTOCOL` — **zero extra bytes, zero extra connections**; it is
  local computation over data already received. **Vantage:** `SAME_VANTAGE`. **Authority:**
  local-computation, over a peer-supplied input.
- **Outcome table:**

| Outcome | Contradicts | Remains possible | New admissible claim | Still forbidden |
|---|---|---|---|---|
| O1 — verifies against the other source | B | A | *"this chain verified against the host's system roots and not against the trust source this run used"* | *"the certificate is valid"*; *"you may relax verification"* |
| O2 — verifies against neither | A in its narrow form | A (a private CA in neither store), B | *"neither available trust source accepted this chain"* | *"the certificate is invalid"* |

- **Information gain:** **MATERIAL — but only in the branch where `--tls-ca-file` was supplied.**
  In the common case, the run used the system store and there is no second source to compare
  against, so the observation has no content. That asymmetry halves the candidate.
- **Credential requirements:** none. **Privilege:** none. **Side effects:** none on the target.
- **Cost/budget:** one extra `x509.Verify` per failed handshake.
- **Security/privacy — three concerns, none fatal alone, together decisive for this phase.**
  Retaining the chain widens what a hostile peer can put into svcdoctor's memory and into
  redaction's path (certificates carry CNs, SANs and organization identity, which is
  `AttrKindIdentity` material). A second `x509.Verify` runs more parser and path-building code
  over adversary-supplied input. And publishing *"this would have been trusted by a different
  trust source"* is a fact whose main operational use is to justify changing trust configuration
  — one sentence away from the `SECURITY_WEAKENING` class the model makes unreachable on purpose.
  ADR 0058 froze that trust answers *whose certificate is this*; a second verdict from a source
  the run did not use is adjacent to that answer without being it.
- **Fixture feasibility:** good and deterministic — a private CA plus a publicly-chained cert.
- **Current domain-model fit:** it would be a new attribute, entering ADR 0090's classification.
- **Requires new ADR?** Yes — a security review of publishing an alternate-trust verdict, and a
  decision on whether a second verification pass belongs in a probe.
- **Verdict:** **DEFER_ARCHITECTURE.**
- **Reason, stated precisely: this is not a planning candidate and must not be sold as one.** It
  proposes **no observation of the target**. It is a re-interpretation of evidence svcdoctor
  already receives, which places it in the **evidence-consumption** line of work ADR 0090 governs
  — reopen condition 6, *a new attribute is recorded* — and not in Phase 11.0's. It is recorded
  here because the audit found it and no previous phase did, not because Phase 11.0 recommends it.

---

### C-07 — identity mismatch: wrong name requested, or wrong names on the certificate

- **Service/layer:** generic TLS, L3. **DPF-012.**
- **Explanation A:** the run connected by a name the endpoint was never meant to answer to.
- **Explanation B:** the certificate's subject alternative names are wrong or incomplete.
- **Observation O:** **none is needed. Both halves are already in the report.**
  `tls.server_name` records the identity checked against, and `tls.peer_dns_names` /
  `tls.peer_ip_addresses` record the identities presented. What is *not* in the report is which
  of the two was intended — and that is intent, not observation.
- **Class:** `O0_ALREADY_COLLECTED`. **Vantage:** `SAME_VANTAGE`. **Authority:** protocol-
  authoritative for both halves.
- **Information gain:** **NONE.**
- **Verdict:** **REJECT_ALREADY_KNOWN.**

---

### C-08 — the run's own budget ended: measure the rest

- **Service/layer:** all. **DPF-004, DPF-010, DPF-019, DPF-024, DPF-026, DPF-040.**
- **Run completeness:** `incomplete` — this is the only candidate for which that is true.
- **Existing state:** `RuleContext.Incomplete` is set; unmeasured subjects carry `UNKNOWN` with an
  `EXEC_*` class; `Result.Incomplete()` maps to exit 4.
- **Explanation A:** the unmeasured paths would also have failed.
- **Explanation B:** at least one would have succeeded.
- **Observation O:** re-run with a larger execution budget.
- **Class:** `O2_PASSIVE_NEW_REQUEST`. **Vantage:** `SAME_VANTAGE`. **Authority:** would be the
  same direct authority the completed measurements have.
- **Information gain:** **NONE as a planning contribution**, because it is already delivered.
- **It is already delivered, in three places, as structured advice:**
  `advertisedendpoint.go:39` (the discriminator *"re-run with a larger execution budget so the
  unmeasured paths are attempted"*), `topology.go:626` and `admission.go:428`, the latter two as
  `NEXT_EVIDENCE` / `OBSERVE` with **`SelfCollectable: true`** — the only two `true` values in the
  tree, and exactly the meaning ADR 0082 §2.4 gives the flag: *a differently configured run could*.
- **And it is excluded by the definition.** §3's exclusion list names *retrying the same probe*.
  A and B are not two explanations of one observation; they are one measurement not yet finished.
- **The Model B temptation, evaluated and refused.** This is the most plausible case in the tree
  for svcdoctor extending its own budget and re-measuring. It is refused for four independent
  reasons: it would make the operator's `--timeout` advisory rather than binding; it would make
  `Result.Incomplete()` and exit code 4 mean something that moves; it is the hidden second
  collection pass ADR 0078 §2.6 forbids and ADR 0086 §2.7 re-affirmed; and the honest remedy is
  the one svcdoctor already prints — set a larger budget.
- **Verdict:** **REJECT_ALREADY_KNOWN.**

---

### C-09 — certificate outside its window, or this host's clock is wrong

- **Service/layer:** generic TLS, L3. **DPF-013.**
- **Existing evidence:** `TLS_CERTIFICATE_EXPIRED` or `TLS_CERTIFICATE_NOT_YET_VALID`, chosen by
  a structured comparison of the certificate's own dates against the handshake's start time,
  plus `tls.peer_not_before` and `tls.peer_not_after` in evidence.
- **Explanation A:** the certificate is genuinely outside its validity window.
- **Explanation B:** this host's clock is wrong.
- **Why both remain possible:** `docs/FINDINGS.md` §7.1 states it: the comparison is against
  *this host's clock* and blames neither. The two are indistinguishable from here.
- **Observation O — three considered, none admitted.**
  *An external time source (NTP, an HTTP `Date` header):* a new network operation to a third
  party, whose answer svcdoctor would have to trust more than the local clock without any basis
  for doing so.
  *The peer's own view of time:* not available. TLS 1.3 has no timestamp, and TLS 1.2's
  `gmt_unix_time` was deprecated and is randomized by modern stacks.
  *A plausibility threshold* — *"a three-year gap is not clock skew"*: a number crossing a
  threshold, refused for the reason ADR 0034 §13 and `converge.go` both give.
- **Class:** `O9_NOT_COLLECTABLE`. **Vantage:** `SAME_VANTAGE`. **Authority:** none available.
- **Information gain:** **NONE** for any admissible observation.
- **Verdict:** **REJECT_NO_INFORMATION_GAIN.**

---

### C-10 — the handshake floor: why did it fail

- **Service/layer:** generic TLS, L3. **DPF-014, DPF-017.**
- **Existing state:** `TLS_HANDSHAKE_NOT_COMPLETED` is certain that no handshake completed and
  says nothing about why. `TLS_VERSION_MISMATCH`, `TLS_CLIENT_CERTIFICATE_REQUIRED` and
  `TLS_CLIENT_CERTIFICATE_REJECTED` are declared failure classes with **no producer**.
- **Explanations:** A version or cipher-suite disagreement · B the endpoint demanded a client
  certificate · C something on the path interfered.
- **Observation O-a — read the alert the peer sent.** The peer states the reason in the protocol.
  This would be direct authority at zero cost.
  **Measured, and it is not available.** A scratch program outside the repository, on
  **Go 1.26.6 darwin/arm64**, drove `crypto/tls` against a listener that replies with a bare
  fatal alert record. For descriptions 40 (`handshake_failure`), 70 (`protocol_version`),
  116 (`certificate_required`) and 48 (`unknown_ca`), the returned error is
  **`*tls.permanentError`** in every case, and `errors.As` against `tls.AlertError`,
  `tls.RecordHeaderError` and `*tls.CertificateVerificationError` returns **false** for all four.
  The description survives **only in the error text**, which `classifyHandshakeError` refuses by
  policy — *"Error text is never matched: it differs by platform and Go release."* The package's
  own comment says this of `protocol_version`; the measurement extends it to **every received
  alert**.
- **Observation O-b — retry with different negotiation parameters.** A search over versions and
  cipher suites, with a connection per attempt. Unbounded by construction, multiplied by every
  address and every advertised endpoint, and a downgrade probe by another name.
- **Class:** `O8_UNBOUNDED` (O-b; O-a is `O9_NOT_COLLECTABLE` on the measurement above).
  **Vantage:** `SAME_VANTAGE`. **Authority:** would be protocol-authoritative for O-a; inferred
  only for O-b.
- **Information gain:** **LOW** — O-b yields a parameter, not an explanation, and *"it works at
  TLS 1.2"* does not establish that the version was the problem.
- **Verdict:** **REJECT_UNBOUNDED.**
- **Reopen condition worth keeping:** a Go release that exposes a received alert as a typed
  error. Then the three producerless classes become **Class 1** at zero cost, and the question
  is an evidence one rather than a planning one. **Re-measure before assuming; do not read the
  text.**

---

### C-11 — does `DIAG_FAILURE_BOUNDARY` contribute to planning

- **Service/layer:** generic. **DPF-018.**
- **What it is:** per subject, the transition between the deepest stage that positively succeeded
  and the shallowest that positively failed. CONFIRMED / INFO. Both halves read from the graph.
- **The question:** does it identify *where more evidence would be useful*, or only *where the
  run stopped*?
- **Answer: only where observation stopped succeeding, and it is careful to claim no more.** It
  attaches no open question to anything. Its `detailBoundaryNotMeasured` clause — *"A stage that
  did not run was neither proven to work nor proven to fail, and none of them is cited here"* —
  is a **disclaimer**, not an unresolved question: it exists to prevent a reader inferring health
  or failure from silence, and it points at nothing to go and measure.
- **Class:** `O0_ALREADY_COLLECTED`. **Vantage:** `SAME_VANTAGE`. **Authority:** restatement of
  measured states.
- **Information gain:** **NONE.**
- **Verdict:** **REJECT_NO_INFORMATION_GAIN — no planning role.**
- **What it would be *if* a planner existed:** a localizer — it names the layer whose ambiguity
  matters. That is a consumer relationship, not a contribution, and asserting more would be
  assigning the finding semantics it does not have.

---

### C-12 — Kafka advertised endpoint unreachable, measured from another vantage

- **Service/layer:** Kafka, L6. **DPF-023.** Code `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`.
- **Structure:** identical to C-01 one layer up. The finding is already CONFIRMED / ERROR / HIGH
  with `vantageDependent: true`, and its detail already says *"this states what this vantage
  point observed, not the health of the cluster."*
- **Additional objection specific to Kafka, and it is decisive on its own:** ADR 0050 —
  *discovery may create evidence; discovery must not create secret authority*. An advertised
  endpoint gets credential-free DNS/TCP/TLS **and nothing else**. A second vantage that tried to
  do more would be exactly the credential propagation to discovered hosts that the security model
  forbids. A second vantage that did no more measures precisely what C-01 measures, so this
  candidate adds a service name and nothing else.
- **Class:** `O3_ALTERNATE_VANTAGE`. **Vantage:** `ALTERNATE_VANTAGE`. **Authority:**
  measured-contrast. **Information gain:** **MATERIAL** on the reachable-elsewhere outcome.
- **Verdict:** **DEFER_ARCHITECTURE**, subordinate to C-01. It is not a separate reopening.

---

### C-13 — Kafka: is the advertised topology the one this network expects

- **Service/layer:** Kafka, L6. **DPF-025.** Code `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE`.
- **This is the tree's flagship open question and the only HYPOTHESIS in it that names two
  explanations in its own prose.**
- **Existing evidence:** the Metadata exchange PASSed at the bootstrap endpoint and **no**
  advertised broker endpoint was reached. HYPOTHESIS / WARN / **MEDIUM**, `AuthorityNone`
  declared explicitly, `HIGH` structurally unreachable through the ladder.
- **Explanation A** (the finding's own words): *"a cluster advertising addresses this client
  cannot use"*.
- **Explanation B:** *"the path to those addresses being unavailable for some other reason"*.
- **Why both remain possible:** the rule's own comment enumerates what it did not measure —
  routing, listener exposure, a broker-side outage — and emits none of them.
- **Why meaningfully distinct:** A is a broker configuration change (`advertised.listeners`); B is
  a network change. Different teams entirely.
- **Observation O:** *"whether the advertised addresses are the ones a client on this network is
  expected to use to reach these brokers"* — the `Discriminator`, verbatim.
- **Class:** `O4_OPERATOR_DECLARED`. **Vantage:** `OPERATOR_VANTAGE`. **Authority:**
  operator-declared.
- **Outcome table:**

| Outcome | Contradicts | Remains possible | New admissible claim | Still forbidden |
|---|---|---|---|---|
| O1 — the advertised addresses match what this network expects | A | B | *"the advertisement matches the expectation and the endpoints were still not reached"* | naming which network element |
| O2 — they do not match | B, in the sense that the advertisement is already wrong | A | *"the advertisement differs from the declared expectation"* | *"the broker is misconfigured"* — an advertisement for a different client population is not a fault |
| O? — no expectation is declared | nothing | both | nothing | — |

- **Information gain:** **MATERIAL**, and it is a *declaration*, not a measurement. **There is no
  observation of the cluster, the network or the endpoint that separates A from B.** svcdoctor
  read no broker setting and holds no model of what this network expects; the rule's own comment
  says so, and the discriminator says *"which svcdoctor cannot make on its own."*
- **Already collected?** No, and it cannot be. **Self-collectable?** **No**, and the rule already
  says so with `SelfCollectable: false` and a rationale explaining why.
- **Requires 10.4C?** **No, and this is the phase's most load-bearing negative result.** Under
  ADR 0086 §2.2 a set needs **one subject** and **one open question**. The tree's two
  hypothesis-carrying codes have different subjects — `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`
  takes the advertisement's subject, this one takes the exchange's — and, decisively, **different
  open questions**: *"re-run with a larger execution budget"* versus *"compare against the
  expected addresses"*. Two different observations cannot be one open question, so no set exists
  however the subjects happen to fall.
- **Verdict:** **REJECT_ALREADY_KNOWN.**
- **Reason: it is already implemented, end to end, in Model A.** The finding carries a
  `Discriminator`, a `NEXT_EVIDENCE` / `COMPARE` recommendation built through
  `diagnosis.Recommend`, a rationale explaining why the comparison discriminates, and
  `SelfCollectable: false`; and `internal/render/terminal/findings.go` prints all of it as
  `[NEXT_EVIDENCE / COMPARE / you must collect]`. **A planner would add nothing here.**

---

### C-14 — the credential was rejected: unknown identity, or wrong secret

- **Service/layer:** all four services. **DPF-028, DPF-042, DPF-052, DPF-063.** Codes
  `KAFKA_CREDENTIALS_REJECTED`, `POSTGRES_CREDENTIALS_REJECTED`, `REDIS_CREDENTIALS_REJECTED`,
  `RABBITMQ_CREDENTIALS_REJECTED`.
- **Explanation A:** the identity does not exist at this endpoint.
- **Explanation B:** the identity exists and the secret is wrong.
- **Why both remain possible:** every one of the four protocols refuses to distinguish them on
  the wire, deliberately. PostgreSQL logs the difference and does not send it.
- **Why meaningfully distinct:** create the role versus rotate the secret.
- **Observation O — two considered, both refused.**
  *Present a deliberately wrong secret and compare the responses:* this is a **user-enumeration
  oracle**. If it worked, the endpoint would have a vulnerability, and svcdoctor would be
  exploiting it. It also sends a credential-shaped frame svcdoctor knows will fail.
  *Present a second real credential:* a second authentication attempt against a
  lockout counter, a `fail2ban` window and an audit log, for a fact the operator already holds.
- **Class:** `O6_STATE_CHANGING` — a failed authentication is remote state: a counter, a log
  line, possibly a lockout. **Vantage:** `SAME_VANTAGE`. **Authority:** none obtainable.
- **Information gain:** **NONE** for any safe observation.
- **Credential requirements:** by construction, more credential use than the run authorized.
- **Verdict:** **REJECT_UNSAFE.**
- **The result worth stating plainly: the absence of a discriminator here is a security property
  of the protocols, not a gap in svcdoctor.** `test/diagnosis/falsepositive_test.go` FP04 already
  forbids *"the password is wrong"*, *"user does not exist"* and five neighbours by name, and
  `TestWrongPassNeverBecomesWrongPassword` pins the Redis half. A planner that proposed to settle
  this would be proposing to attack the endpoint.

---

### C-15 — Kafka: which mechanisms were offered

- **Service/layer:** Kafka, L5. **DPF-029.** Code `KAFKA_AUTH_MECHANISM_NOT_OFFERED`.
- **Existing evidence:** `kafka.sasl.offered_mechanisms` is on the very node the finding cites.
- **Observation O:** none. The answer is collected.
- **Class:** `O0_ALREADY_COLLECTED`. **Vantage:** `SAME_VANTAGE`. **Authority:**
  protocol-authoritative. **Information gain:** **NONE.**
- **Verdict:** **REJECT_ALREADY_KNOWN.**
- **Why it is nonetheless not shown:** the mechanism names are copied verbatim off the wire with
  no allowlist, no length bound and no character restriction, and svcdoctor has no renderer
  sanitization boundary. That is ADR 0090 §8.1's blocker and it governs three attributes across
  two services. **It is an evidence-consumption question with an owner, not a planning gap.**

---

### C-16 — Kafka: an unrepresentable advertisement is invisible to the completeness predicate

- **Service/layer:** Kafka, L6. **DPF-035.** ADR 0090 §9, conflict C2.
- **The defect:** `complete` is computed over an exchange's children, and an advertisement whose
  text cannot become a `Subject` produces no child — so `detailTopologyComplete` can state that
  the counts *"account for the whole advertised set"* over a set that silently lost a member.
- **Explanations:** A the set is complete · B a member was dropped before counting.
- **Observation O:** `kafka.metadata.unrepresentable_entry_count` is **already recorded** and read
  by nothing. What is missing is not an observation but a **producer of the condition**: no
  supported fixture makes one, and `KAFKA_PHASE3_VALIDATION.md` records that no real run ever has.
  Producing it needs a control character, invalid UTF-8 or leading whitespace in
  `advertised.listeners`.
- **Class:** `O9_NOT_COLLECTABLE` **as a planning observation** — the fact is present and the
  *situation* is not.
- **Information gain:** **MATERIAL** for correctness, and it is a correctness bug rather than an
  open question.
- **Verdict:** **DEFER_FIXTURE**, unchanged from ADR 0090 §12.4. Phase 11.0 neither closes it nor
  reopens it, and notes only that it is **a false-positive risk, not a planning opportunity**.

---

### C-17 — PostgreSQL refused admission at the only address: was that intended

- **Service/layer:** PostgreSQL, L4. **DPF-038.** Code `POSTGRES_CONNECTION_NOT_PERMITTED`.
- **Explanation A:** the host-based rule is doing exactly what it was written to do.
- **Explanation B:** the rule set has a gap.
- **Observation O:** none. The endpoint stated the refusal in a field its protocol defines; what
  it did not state, and cannot, is whether the refusal was intended.
- **Class:** `O4_OPERATOR_DECLARED`. **Vantage:** `OPERATOR_VANTAGE`. **Authority:**
  operator-declared. **Information gain:** **LOW** — no observation moves it.
- **Verdict:** **REJECT_NO_INFORMATION_GAIN.**
- **Note:** the finding already declines to say the policy is wrong, and
  `recommendAdmissionContrast`'s sibling comment records the permanent refusal of *"add a
  host-based access rule"* — widening an admission policy is a security-relevant edit svcdoctor is
  not entitled to suggest from a connection attempt.

---

### C-18 — PostgreSQL admission contrast: one endpoint with a rule gap, or two endpoints

- **Service/layer:** PostgreSQL, L4. **DPF-039.** Code `POSTGRES_ADMISSION_SCOPE`, contrast
  branch. **This is the brief's third nominated candidate, and it is the audit's most instructive
  case.**
- **Existing evidence:** the target resolved to two or more addresses; at least one was
  positively refused before any credential was evaluated, and at least one completed the startup
  exchange. The composition root measures **every** resolved address through the credential-free
  stages precisely so this is observable. CONFIRMED / **INFO** / HIGH, one per run at most.
- **Explanation A:** one endpoint whose host-based rules select on the address reached.
- **Explanation B:** the addresses are served by different endpoints with different rules.
- **Why both remain possible:** the finding says so in its own detail — *"consistent with one
  endpoint whose admission rules select on the address reached, and equally consistent with the
  addresses being served by different endpoints; svcdoctor measured the difference and not its
  cause."*
- **Why meaningfully distinct:** A is a `pg_hba.conf` edit; B is a DNS or load-balancer change.
  The rationale already states it: *"which of the two it is decides whether this is one endpoint
  with a gap in its rules or two endpoints with different ones."*
- **The pair passes all five §4 tests.** Both are compatible with the same evidence; they are
  operationally distinct; they predict different results for a configuration comparison; each is
  representable without claiming hidden causality; and neither is a broader wording of the other
  — *one server* and *two servers* are mutually exclusive.
- **Observation O — four routes examined, and the audit looked hardest here.**

  **O-a — compare the endpoint's host-based rules across the addresses.** `O4_OPERATOR_DECLARED` /
  `O5_PRIVILEGED`. **This is what the rule already recommends**, as `NEXT_EVIDENCE` / `COMPARE`
  with `SelfCollectable: false`.

  **O-b — establish a full session at each address and compare backend identity.** **Refuted by
  the evidence's own shape.** The refused address never reaches a session: it refused *before any
  credential was evaluated*, which is the finding's premise. There is nothing to compare against.
  It would also require authenticating on more than one path, which ADR 0041 fixes at exactly one
  and a test enforces by parsing the composition root.

  **O-c — credential-free identity contrast over what is already collected.** The most promising
  route and the one that had to be checked rather than assumed. Per address, before any
  credential, svcdoctor holds `postgres.ssl.offered`, `postgres.protocol_version`,
  `postgres.sqlstate`, `postgres.error_severity`, `postgres.error_is_native`, and — when a TLS
  plan is in force — `tls.version`, `tls.cipher_suite`, `tls.peer_certificate_count`,
  `tls.peer_not_before`, `tls.peer_not_after`, `tls.peer_dns_names`, `tls.peer_ip_addresses`.
  **The contrast is asymmetric and that asymmetry disqualifies it.** A *difference* between two
  addresses is weak evidence for B; *agreement* is evidence for neither, because two servers
  provisioned from one configuration agree on every one of these values. Turning agreement into
  *"one endpoint"* would be reading absence of difference as evidence of sameness. The route is
  also unavailable under `--tls disable`, where the richest half of the attributes does not exist.

  **O-d — the DNS answer set.** `dns.answers` is already recorded and the address family is
  derivable. An `A` and an `AAAA` of one host is the single most common shape of this contrast —
  and is equally the shape of two hosts behind one name. **No gain.**

- **Class:** `O4_OPERATOR_DECLARED`. **Vantage:** `OPERATOR_VANTAGE`. **Authority:**
  operator-declared.
- **Outcome table (for O-a, the only admissible route):**

| Outcome | Contradicts | Remains possible | New admissible claim | Still forbidden |
|---|---|---|---|---|
| O1 — one host's rules explain both outcomes | B | A | *"the difference is accounted for by one endpoint's rules"* | *"the rules are wrong"* |
| O2 — the addresses belong to different hosts | A | B | *"the addresses are served by different endpoints"* | *"the topology is wrong"* |
| O? — the operator cannot compare | nothing | both | nothing | — |

- **Information gain:** **MATERIAL** for O-a; **LOW** for O-c; **NONE** for O-b and O-d.
- **Already collected?** The *contrast* is; the *cause* is not and cannot be.
  **Self-collectable?** No, for the reason the rule states: svcdoctor reads no server
  configuration and holds no model of what this target's rules are meant to permit.
- **Credential requirements:** none for the admissible route. **Privilege:** reading `pg_hba.conf`
  or the infrastructure — the operator's, never svcdoctor's. **Side effects:** none.
- **Requires 10.4C?** No — the finding is CONFIRMED, and `domain.NewFinding` structurally refuses
  a `Discriminator` on a CONFIRMED finding, so it cannot participate in a set by construction
  (ADR 0086 §2.2).
- **Requires 10.5B?** No. Its basis is the anchor plus every classified startup node, all cited as
  supporting — including an undetermined node, correctly, because the claim's subject is the
  count of decisions not observed.
- **Verdict:** **REJECT_ALREADY_KNOWN.**
- **Reason, and it is the audit's central result: the strongest genuine competing pair in the
  tree is already fully served by Model A, on a CONFIRMED finding, with the discriminating
  comparison named, classified `COMPARE`, given a rationale, and honestly marked
  `SelfCollectable: false`.** The brief predicted that *"only operator intent can distinguish
  them"*. That prediction is **confirmed with one correction**: it is not intent in the
  expectation sense but **privileged access to configuration svcdoctor does not read** — and the
  practical consequence is identical, because both are `SelfCollectable: false` and neither is an
  observation svcdoctor could ever take.

---

### C-19 — PostgreSQL `53300`: which limit, enforced where

- **Service/layer:** PostgreSQL, L4/L5. **DPF-041.** Code `POSTGRES_CONNECTION_LIMIT_REACHED`.
- **Existing state:** CONFIRMED / ERROR / HIGH on **direct authority** — the peer named the
  condition in a field its protocol defines — and `vantageDependent: false`. It already carries
  a `NEXT_EVIDENCE` / `COMPARE` recommendation with `SelfCollectable: false`.
- **Explanation A:** a `max_connections`-class limit at the endpoint fired.
- **Explanation B:** a per-role or per-database `CONNECTION LIMIT` fired.
- **Explanation C:** a pooler in front enforced its own.
- **Why both remain possible:** `53300` is raised against whichever applicable limit was reached
  and the response does not say which.
- **Observation O:** reading `pg_stat_activity`, `max_connections` or a pooler's own statistics.
  All require **SQL**, which ADR 0039 §17 forbids and an AST guard enforces, and most require a
  privilege the diagnostic role may not hold.
- **Class:** `O5_PRIVILEGED`. **Vantage:** `SERVER_SIDE`. **Authority:** would be server-side.
- **Information gain:** **LOW** for anything reachable — and note that C is arguably not a
  competing explanation at all: under ADR 0040 §18's *endpoint, never server* rule, the pooler
  **is** the endpoint, so *"a pooler enforced its own"* is an instance of the claim rather than an
  alternative to it.
- **Verdict:** **REJECT_NO_INFORMATION_GAIN.**
- **Note:** ADR 0085 §3.2 already dissolved the pair by narrowing the claim, and FP02A forbids
  nine capacity causes by name including *"increase"*. *"Increase the connection limit"* is
  refused permanently.

---

### C-20 — PostgreSQL: did I reach PostgreSQL or an intermediary

- **Service/layer:** PostgreSQL, L4. **DPF-044.**
- **Existing state:** pgBouncer collapses every SQLSTATE to `08P01`, which is why **no rule may
  assume its SQLSTATE fires and no finding may say "I reached PostgreSQL"** — a Phase 4.0
  measurement that binds every later phase.
- **Explanation A:** the endpoint is a PostgreSQL server.
- **Explanation B:** the endpoint is a pooler.
- **Observation O:** `postgres.server_version` is already recorded — **and a pooler forwards a
  cached value**, which `internal/service/postgres/vocabulary.go` states for the sibling
  attribute. Behaviour probes (`SHOW`, protocol-quirk fingerprinting) are SQL or heuristics.
- **Class:** `O5_PRIVILEGED` for anything real. **Vantage:** `SERVER_SIDE`. **Authority:** none
  obtainable. **Information gain:** **NONE**.
- **Verdict:** **REJECT_NO_INFORMATION_GAIN.**
- **Note:** ADR 0040 §18 already decided this the other way round — svcdoctor says *endpoint*,
  never *server*, and never a product name. The pair is dissolved rather than open.

---

### C-21 — observed state versus declared intent (PostgreSQL role and writability, Redis role and mode, RabbitMQ negotiated integers)

- **Service/layer:** PostgreSQL, Redis, RabbitMQ. **DPF-048, DPF-057, DPF-067.** **This is the
  brief's second nominated candidate.**
- **Existing state:** `postgres.in_hot_standby` and `postgres.default_transaction_read_only` are
  **terminal observation lines** since Phases 10.3 and 10.7B; `redis.role` and `redis.mode` have
  been observation lines since Phase 7, and a finding over either **fails the build**
  (`TestReplicaRoleProducesNoFinding`, `TestClusterModeProducesNoFinding`); RabbitMQ's six
  negotiated integers are frozen *"may not be said"* by ADR 0069 §8.
- **Explanation A:** the observed state is what the operator built.
- **Explanation B:** the observed state is wrong for this application.
- **Why both remain possible:** a standby is a standby. `default_transaction_read_only = on` is a
  deliberate safety setting on reporting roles. A replica is correct for a read-only client.
- **The question the brief asks — observation or intent? Intent, decisively.** There is no
  protocol field, no measurement and no contrast that states what the operator meant. svcdoctor
  has measured everything there is to measure here; what is missing is a **premise**, not an
  observation.
- **Class:** `O4_OPERATOR_DECLARED`. **Vantage:** `OPERATOR_VANTAGE`. **Authority:**
  operator-declared.
- **Information gain:** **MATERIAL** if declared — and the gain comes from the declaration, not
  from any act of collection.
- **Self-collectable?** **Never**, in any run, by construction. Marking a declaration
  self-collectable would claim svcdoctor could discover what the operator intended.
- **False-positive risk — the reason this is deferred rather than admitted.** A declared
  expectation is only as good as the declaration. An `expect:` block that drifts from reality
  produces confident findings about a system that is fine, and it produces them at ERROR. That is
  a **configuration-driven false positive**, a category the tree has none of today, and admitting
  it would be admitting the first.
- **Requires new ADR?** Yes, and one already has its shape: ADR 0083 §2.6 requires a **small
  closed vocabulary of typed expectations, never a policy language**, against ADR 0071's
  strict-schema contract, in its own record — and explicitly **never as a side effect of a
  service phase**, because it applies to every service the instant it exists.
- **Verdict:** **DEFER_ARCHITECTURE**, unchanged from ADR 0083 §2.6 and ADR 0085 §5.
- **The freeze this audit adds:** **operator-declared intent is a premise, not next-best
  evidence.** It may never be labelled `SelfCollectable: true`, may never be described as an
  observation svcdoctor could take, and its arrival would not make svcdoctor a planner — it would
  give existing rules a second input. ADR 0092 §2.5.

---

### C-22 — Redis: which condition did the endpoint name

- **Service/layer:** Redis, L4/L5. **DPF-051.** Code `REDIS_ENDPOINT_NOT_SERVING`.
- **Existing state:** `redis.error_prefix` is recorded from a **closed set of 23 + `UNRECOGNIZED`**,
  is svcdoctor's own constant and never peer bytes, and lands on the cited node.
  `LOADING`, `MASTERDOWN`, `BUSY`, `NOAUTH`, `DENIED`, `WRONGPASS` and a bare `ERR` all reach one
  finding whose prose names none of them.
- **Is there a competing pair?** **No.** The condition is *known*, in a closed enumeration, on the
  node the finding cites. Nothing is ambiguous; specificity is lost on the way out.
- **Class:** `O0_ALREADY_COLLECTED`. **Vantage:** `SAME_VANTAGE`. **Authority:**
  protocol-authoritative. **Information gain:** **MATERIAL** — for *presentation*, not for
  reasoning.
- **Verdict:** **REJECT_NO_COMPETING_PAIR.**
- **Where it does belong:** it is a **C1-A canonical explanation enrichment** in exactly the shape
  Phase 10.8B just delivered for RabbitMQ, and it is deferred on ADR 0088 §2.5's producer bar —
  *membership requires having watched a real endpoint produce it*, and **no fixture has ever
  produced `LOADING`, `MASTERDOWN` or `BUSY`.** Phase 11.0 changes nothing about that.

---

### C-23 — Redis `NOPERM`: try a different command

- **Service/layer:** Redis, L5. **DPF-053.** Code `REDIS_COMMAND_NOT_PERMITTED`.
- **Explanation A:** the ACL denies only `PING`, and the application's commands are permitted.
- **Explanation B:** the ACL is broadly restrictive.
- **Observation O:** issue another command.
- **Class:** `O6_STATE_CHANGING`. **Vantage:** `SAME_VANTAGE`. **Authority:** would be direct, for
  the one command tried.
- **Why it is refused, in the finding's own words:** *"svcdoctor did not try a different command
  afterwards. Each attempt would be another entry in the endpoint's ACL log and another guess."*
- **Further:** every candidate command is a **build-forbidden string literal** in any Redis
  production file (`TestNoRedisProductionFileNamesAForbiddenCommand`), no command may carry a key
  argument, and svcdoctor could not know which commands *this* application runs anyway — so the
  search is a guess with a bounded budget and an unbounded space.
- **Information gain:** **LOW** — one more command answers about one more command.
- **Verdict:** **REJECT_SIDE_EFFECT.**
- **This is the tree's own explicit refusal of a planning step, written into a finding's detail
  before this audit existed. It is worth reading as the model.**

---

### C-24 — Redis client-limit exhaustion arrives as a bare `ERR`

- **Service/layer:** Redis, L4. **DPF-058.**
- **Existing state:** `-ERR max number of clients reached` carries a **bare `ERR` prefix**, and
  ADR 0066 forbids classifying on peer text outright. RRI-017 is the authoritative rule: **Redis
  `RESOURCE_LIMIT_REACHED` may be emitted only when the wire evidence structurally and
  authoritatively identifies a resource limit.**
- **Explanations:** A a resource limit fired · B any other `ERR` condition.
- **Observation O:** none exists **structurally**. The only route is reading the server's prose,
  which is forbidden — *"inventing a distinction the prefix does not carry is the error this
  record exists to prevent."*
- **Class:** `O9_NOT_COLLECTABLE`. **Vantage:** `SAME_VANTAGE`. **Authority:** none.
- **Information gain:** **MATERIAL** if the signal existed; it does not.
- **Verdict:** **DEFER_COMPATIBILITY**, on RRI-017a's condition unchanged: a future Redis or
  Valkey release giving the condition its **own error prefix** — ADR 0066 already calls an
  additional prefix *"additive and testable"* — or a protocol expansion decided in its own record.
  **Never by text matching.**

---

### C-25 — Redis and RabbitMQ multi-address scope aggregates

- **Service/layer:** Redis L4, RabbitMQ L4. **DPF-059, DPF-066.**
- **Existing state:** both are **structurally possible and have never been produced.** Every
  Redis, Valkey, RabbitMQ and LavinMQ fixture targets `127.0.0.1`, which under ADR 0059 resolves
  nothing and yields exactly one path — so the completeness-and-contrast shape Kafka and
  PostgreSQL both use has never been reachable for either service.
- **Is there a competing pair?** Not yet, and the honest statement is that nobody knows: a
  contrast that has never been observed cannot be reasoned about.
- **Class:** `O9_NOT_COLLECTABLE` — the *situation* is not collectable, not the observation.
  **Vantage:** `SAME_VANTAGE`. **Information gain:** **MATERIAL** if produced.
- **Verdict:** **DEFER_FIXTURE**, unchanged from ADR 0088 and Phase 10.6A §5: **a measurement,
  not an argument.** A multi-address run whose addresses disagree — one requiring authentication
  and another not, one a Sentinel and another a data endpoint, or two offering different mechanism
  sets.

---

### C-26 — RabbitMQ: the close reply was truncated before the limit clause

- **Service/layer:** RabbitMQ, L5. **DPF-061.** Code `RABBITMQ_CONNECTION_NOT_PERMITTED` with
  `close_outcome = UNSPECIFIED_TRUNCATED`.
- **Existing state:** Phase 8.0C produced a **255-byte reply with the limit clause entirely
  absent**. Phase 10.8B's enrichment is gated on a mapped outcome, so a truncated reply renders
  today's text byte for byte.
- **Explanations:** A a node, vhost or user ceiling was named and lost to truncation · B no
  ceiling was named.
- **Observation O:** none. The bytes that would have distinguished them were never sent.
- **Class:** `O9_NOT_COLLECTABLE`. **Vantage:** `SAME_VANTAGE`. **Authority:** none.
- **Information gain:** **NONE.**
- **Verdict:** **REJECT_NO_INFORMATION_GAIN.**
- **The governing rule, already frozen and worth restating because it is exactly the trap a
  planner would fall into:** ADR 0090 §5.3 — **presence is evidence; absence is not.** *"No named
  ceiling"* must never become *"no ceiling was reached."*

---

### C-27 — RabbitMQ: did the `guest` loopback restriction apply

- **Service/layer:** RabbitMQ, L5. **DPF-063.**
- **Existing state:** ADR 0068 §4.1 dropped the hypothesis and kept a detail sentence gated on the
  username alone. The reason: **svcdoctor observes its own destination address while the broker
  evaluates the restriction against the client's source address.** Different ends of the
  connection.
- **Observation O:** read the local socket's source address — `conn.LocalAddr()`, available at
  zero cost.
- **Why it is refused, and this is the sharpest authority error available in the tree:** the local
  source address is **not authority for what the broker saw**. NAT, a container bridge, a service
  mesh sidecar or a proxy all mean the broker's view differs. Recording it would create a fact
  that *reads* authoritative and is not, which is the definition of causal overreach.
- **Class:** `O9_NOT_COLLECTABLE` for the fact that matters. **Vantage:** `SERVER_SIDE` — the
  observation belongs to the peer. **Authority:** would be local-kernel, misused as
  remote-peer-reported. **Information gain:** **LOW**, and negative in expectation.
- **Verdict:** **REJECT_CAUSAL_OVERREACH.**

---

### C-28 — RabbitMQ `VHOST_DOWN` (`541`)

- **Service/layer:** RabbitMQ, L5. **DPF-066.**
- **Existing state:** proven from the RabbitMQ source, **not reproduced live**, and therefore
  permitted to set a normalized attribute and forbidden to produce a restating sentence —
  `namedConditions`' membership rule (ADR 0069 §8, §9.2).
- **Is there a competing pair?** No — the condition, if it occurred, would be named by the peer.
- **Class:** `O9_NOT_COLLECTABLE` — the situation, not the observation. **Vantage:**
  `SAME_VANTAGE`. **Information gain:** **MATERIAL** if produced.
- **Verdict:** **DEFER_FIXTURE**, unchanged from ADR 0090 §12.5.

---

### C-29 — RabbitMQ: what may this identity actually do inside the vhost

- **Service/layer:** RabbitMQ, L5/L6. **DPF-067.**
- **Existing state:** `channel_max` is negotiated to **1**, no channel is ever opened, and no
  resource is ever named. RabbitMQ evaluates configure/write/read permissions **at channel
  operations**, so svcdoctor structurally cannot observe them.
- **Explanations:** A the identity can use the vhost · B `Connection.Open` succeeded and the
  identity can do nothing useful.
- **Observation O:** open a channel; passively declare a queue; call the management API.
- **Class:** `O6_STATE_CHANGING`. **Vantage:** `SERVER_SIDE`. **Authority:** would be direct.
- **Why refused, and ADR 0089 §9 already separates the three surfaces so they can never be
  grouped:** a channel is `SESSION_LOCAL_MUTATION` against a broker negotiated to
  `channel_max 1`; a passive declare touches broker-visible state and needs `configure`
  permission; the management API is a **`CONTROL_PLANE_AUTHORITY` on a second protocol, a second
  port and a second credential that must never silently reuse the AMQP one**. Each needs its own
  record; never one.
- **Information gain:** **LOW** — a passive declare of a queue svcdoctor invented answers about a
  queue the application does not use.
- **Verdict:** **REJECT_SIDE_EFFECT.**
- **Explicit guard against the obvious pressure:** Phase 10.8B's success on RabbitMQ is **not** a
  justification for expanding RabbitMQ's observation surface. 10.8B acquired **nothing**; it
  preserved specificity already in canonical evidence. The two are opposite kinds of change.

---

## 6. Aggregate results

### 6.1 Verdicts

| Verdict | Count | Candidates |
|---|---|---|
| `ADMIT_ADVISORY` | **0** | — |
| `ADMIT_SELF_COLLECTABLE` | **0** | — |
| `DEFER_ARCHITECTURE` | 5 | C-01, C-05, C-06, C-12, C-21 |
| `DEFER_FIXTURE` | 3 | C-16, C-25, C-28 |
| `DEFER_COMPATIBILITY` | 1 | C-24 |
| `REJECT_NO_COMPETING_PAIR` | 1 | C-22 |
| `REJECT_NO_INFORMATION_GAIN` | 8 | C-03, C-04, C-09, C-11, C-17, C-19, C-20, C-26 |
| `REJECT_ALREADY_KNOWN` | 6 | C-02, C-07, C-08, C-13, C-15, C-18 |
| `REJECT_UNSAFE` | 1 | C-14 |
| `REJECT_UNBOUNDED` | 1 | C-10 |
| `REJECT_PRIVILEGED` | 0 | — |
| `REJECT_SIDE_EFFECT` | 2 | C-23, C-29 |
| `REJECT_VAGUE` | 0 | — |
| `REJECT_CAUSAL_OVERREACH` | 1 | C-27 |
| `REJECT_NO_OPERATOR_VALUE` | 0 | — |
| **total** | **29** | |

**Admitted: 0. Deferred: 9. Rejected: 20.**

### 6.2 Candidates by service and layer

| Layer / service | Frontier cases | Candidates |
|---|---|---|
| generic DNS (L1) | 5 | 1 (C-05) |
| generic TCP (L2) | 5 | 4 (C-01, C-02, C-03, C-04) |
| generic TLS (L3) | 7 | 4 (C-06, C-07, C-09, C-10) |
| generic boundary / execution | 5 | 2 (C-08, C-11) |
| Kafka | 15 | 4 (C-12, C-13, C-15, C-16) |
| PostgreSQL | 13 | 4 (C-17, C-18, C-19, C-20) |
| Redis / Valkey | 9 | 4 (C-22, C-23, C-24, C-25) |
| RabbitMQ / LavinMQ | 8 | 4 (C-26, C-27, C-28, C-29) |
| cross-service | — | 2 (C-14, C-21) |
| **total** | **67** | **29** |

### 6.3 Observation classes

| Class | Count | Candidates |
|---|---|---|
| `O0_ALREADY_COLLECTED` | 4 | C-07, C-11, C-15, C-22 |
| `O1_PASSIVE_EXISTING_PROTOCOL` | 1 | C-06 |
| `O2_PASSIVE_NEW_REQUEST` | 2 | C-05, C-08 |
| `O3_ALTERNATE_VANTAGE` | 3 | C-01, C-02, C-12 |
| `O4_OPERATOR_DECLARED` | 5 | C-04, C-13, C-17, C-18, C-21 |
| `O5_PRIVILEGED` | 2 | C-19, C-20 |
| `O6_STATE_CHANGING` | 3 | C-14, C-23, C-29 |
| `O7_SECURITY_WEAKENING` | **0** | none proposed, and the class stays unreachable |
| `O8_UNBOUNDED` | 1 | C-10 |
| `O9_NOT_COLLECTABLE` | 8 | C-03, C-09, C-16, C-24, C-25, C-26, C-27, C-28 |

### 6.4 Vantage classes

| Class | Count |
|---|---|
| `SAME_VANTAGE` | 18 |
| `ALTERNATE_VANTAGE` | 4 (C-01, C-02, C-05, C-12) |
| `OPERATOR_VANTAGE` | 3 (C-13, C-18, C-21) |
| `SERVER_SIDE` | 4 (C-19, C-20, C-27, C-29) |
| `UNKNOWN` | 0 |

### 6.5 Information gain

| Gain | Count | Candidates |
|---|---|---|
| `DECISIVE` | **0** | — |
| `MATERIAL` | 12 | C-01, C-05, C-06, C-12, C-13, C-16, C-18, C-21, C-22, C-24, C-25, C-28 |
| `LOW` | 9 | C-03, C-04, C-10, C-17, C-19, C-20, C-23, C-27, C-29 |
| `NONE` | 8 | C-02, C-07, C-08, C-09, C-11, C-14, C-15, C-26 |

**Zero `DECISIVE`.** Every `MATERIAL` candidate is either already delivered (C-13, C-18, C-22),
blocked on a producer nobody has (C-16, C-24, C-25, C-28), or blocked on architecture svcdoctor
does not have (C-01, C-05, C-06, C-12, C-21).

---

## 7. The three nominated candidates, answered directly

### 7.1 Alternate vantage (brief §37) — the epistemics are the best in the audit and everything else fails

**The bounded claim is `reachability differs by network position`, and it is the ceiling.** It
does not prove a firewall, a route, a security group, a NetworkPolicy or a server-side condition,
and freezing that is the most useful thing this candidate produces (ADR 0092 §2.4).

**Is that claim valuable enough on its own?** Marginally. An operator who *has* a second vantage
can establish the same thing in ten seconds with a shell, and svcdoctor's contribution would be
the discipline of not overclaiming from it — real, but thin against the cost.

**How would the second vantage be executed?** There is no answer in the tree.
`domain.VantageSource` has one value; `NewLocalVantage` is the only constructor, deliberately.
Executing elsewhere means a remote-execution channel, which is the largest security surface
anyone could propose adding here.

**How would "the same endpoint" be proven?** It could not be, rigorously. Two vantages may
resolve one name to different addresses, and a name is not an address (ADR 0059). The honest
scope is the *requested target*, and the contrast is then partly a DNS contrast wearing a TCP
label.

**Credential implications.** A TCP-only vantage answers only the TCP question. Anything deeper
needs the credential at that vantage, which the endpoint-bound model has no mechanism for and
ADR 0050 forbids for discovered endpoints outright.

**Does it belong in svcdoctor or around it?** **Around it.** Two svcdoctor runs from two places
produce two reports, and comparing them is orchestration. Building the comparison *inside* would
require either a two-vantage report type or a cross-target correlation the Phase 9 contract
forbids. **Result: DEFER_ARCHITECTURE (C-01, C-12), and the honest summary is that it is closer
to rejected than to admitted.**

### 7.2 Operator-declared intent (brief §38) — it is intent, and intent is a premise

The missing discriminator behind `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE` and behind every role,
mode and negotiated-integer observation is **not an observation**. No protocol field, no
measurement and no contrast states what the operator expected.

**Therefore it must never be called self-collectable evidence**, and today it is not: every
intent-blocked recommendation in the tree already carries `SelfCollectable: false` with a
rationale saying why.

**Could declared intent eventually improve diagnosis?** Yes — and it would do so by giving
existing rules a second *input*, not by making svcdoctor a planner. **Its risk is
configuration-driven false positives**, a category the tree has none of, and admitting it means
admitting the first. It stays deferred exactly where ADR 0083 §2.6 put it: a small closed
vocabulary of typed expectations, never a policy language, in its own record, never as a side
effect of a service phase. **No configuration field is proposed or designed here.**

### 7.3 PostgreSQL admission contrast (brief §39) — the prediction is confirmed, with one correction

The brief predicted *"only operator intent can distinguish them"*. **Confirmed, corrected in one
respect:** what distinguishes *one endpoint with a rule gap* from *two endpoints with different
rules* is **privileged access to configuration svcdoctor does not read**, which is adjacent to
intent rather than identical with it. The practical consequence is the same — `SelfCollectable:
false`, never an observation svcdoctor could take.

**Three cheaper routes were looked for and refuted rather than assumed** (C-18, O-b/O-c/O-d): a
second session cannot exist because the refused address never reaches one; a credential-free
identity contrast is asymmetric, so agreement would have to be read as evidence of sameness; and
the DNS answer set cannot tell one host's two families from two hosts.

**And svcdoctor does not infer misconfiguration from contrast.** The finding is **INFO**, it
attributes no cause, it names no configuration file, and its recommendation is a comparison whose
sibling comment records that *"add a host-based access rule"* is refused permanently.

---

## 8. The questions the brief asked about the model

### 8.1 Is the current structured `NEXT_EVIDENCE` capability adequate?

**Yes, for every candidate that reached `MATERIAL` gain and is expressible at all.**
`domain.Recommendation` carries `action`, `kind`, `safety`, `rationale` and `selfCollectable`
since Phase 10.4B; `diagnosis.Advice` is the validated construction type and
`Advice.Recommendation` is the **single** production projection, with
`TestExactlyOneAdviceProjectionPathExists` failing the build if a second appears;
`internal/render/terminal` prints all of it. **Model A is not a plan — it is shipped.**

**One debt is open and it is not a planning debt.** NBE-021's exemption list holds exactly one
entry: `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` carries a `Discriminator` and three *unclassified*
per-layer transport recommendations that predate the advice vocabulary. Classifying them is a
Kafka judgement about Kafka's own advice, and it is the natural next small piece of work in this
line. **It adds no observation and creates no planner.**

### 8.2 Iteration model — which is the minimum justified?

**Model A, and it is already built.**

**Model B** (one bounded self-collected extra observation) has exactly one plausible instance in
the tree — C-08, re-measure after a budget cut — and it is refused on four independent grounds:
it makes the operator's timeout advisory, it makes `Result.Incomplete()` and exit 4 mean something
that moves, it is the hidden second collection pass ADR 0078 §2.6 forbids, and the honest remedy
is the one svcdoctor already prints.

**Model C** (iterative) has no input at all: there is no observation svcdoctor may take, so there
is nothing to loop over. It would be a loop with an empty body.

### 8.3 BASIC versus an explicit `INVESTIGATE` mode

**No mode is required, because no candidate was admitted.** The question is answered
conditionally and frozen so a future phase does not re-derive it: **any observation of class
`O2` and above requires explicit operator consent** — extra network operations, extra latency,
extra target-visible events and a less predictable run are all changes to what the operator asked
for. `O0` and `O1` require none, because nothing extra is sent.

**No `--investigate` flag is designed, named or reserved.**

### 8.4 Budget model

No planner exists, so nothing is required. Recorded as **architecture pressure** for whoever
proposes one: three nested budgets exist (run → target → step) and are `context`-derived, so a
per-observation or per-round budget would be a fourth nesting level with its own truthful
`Incomplete()`. **Target concurrency bounds targets and not sockets** — ADR 0073 §10.1's global
probe semaphore is still declined — so an iterative mode that multiplied observations per target
would multiply sockets with no global bound. That is stated rather than assumed.

### 8.5 Incompleteness and blocking — six kinds of absence, kept apart

A planner must know *why* evidence is absent before proposing to collect it. The six are
distinct today and none is collapsed:

| Absence | Representation | May a planner propose collection? |
|---|---|---|
| not configured (no credential supplied) | `*_CREDENTIAL_NOT_CONFIGURED`, WARN | no — it is the operator's input |
| not collected (svcdoctor's policy) | `*_CREDENTIAL_WITHHELD`, `EXEC_SKIPPED_BY_POLICY` | **no — proposing it is proposing to weaken the policy** |
| blocked by an upstream failure | `Graph.BlockedBy` + `StateSkipped` | no — the blocker owns the failure |
| budget ended | `RuleContext.Incomplete`, `EXEC_*` on `UNKNOWN` nodes | already advised (C-08) |
| cancelled | the same, plus exit 4 | no — the operator stopped it |
| genuinely unknown | `StateUnknown` with a capability class | only if an observation exists, and none does |

### 8.6 Cross-target boundary

**Not violated, and one candidate had to be checked against it.** C-01/C-12's alternate vantage
would, if implemented as two configured targets, be a cross-target comparison — which ADR 0073
forbids and ADR 0083 §2.7 re-states for aggregate observations. Recorded as architecture
pressure: **an alternate-vantage measurement of one endpoint is a same-target multi-vantage
measurement and must never be modelled as two targets.** No other candidate compares two targets.

### 8.7 Determinism and no AI dependency

Frozen in ADR 0092 §2.9. Canonical diagnostic behaviour is deterministic and rule-driven: no LLM,
no embedding similarity, no probabilistic model, no semantic matching, no external AI service.
An LLM may one day *explain* canonical output; it may never decide it.

---

## 9. Gate decisions

**Phase 10.4C — REMAINS CLOSED.** All ten reopening conditions were tested and condition 1 fails
on its own. The tree's two hypothesis-carrying codes are `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`
(incomplete branch) and `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE`. They have **different subjects**
and — decisively — **different open questions**: *"re-run with a larger execution budget"* versus
*"compare the advertised addresses against the expected ones"*. Two different observations cannot
be one open question, so no indistinguishable set exists. PostgreSQL, Redis and RabbitMQ produce
**zero** hypotheses between them. No identity mechanism was designed, no `DiscriminatorID` was
introduced, and no grouping abstraction exists.

**One correction to the record while confirming it.** ADR 0086 §1.2 says the two hypothesis
codes have *"different subjects, different layers and different codes."* **The layers are the
same** — both `advertisedendpoint.go:224` and `topology.go:662` set `domain.LayerTopology`. The
conclusion is unaffected, because subject and open question each independently prevent a set, but
the stated reason is one third wrong and is corrected here rather than repeated.

**Phase 10.5B — REMAINS CLOSED.** No candidate requires `CONTRADICTION`, `MISSING` or `BLOCKED`.
`.Contradict`, `.Miss` and `.Block` still have **zero** production producers, `.Support` still has
one site, and ADR 0087's OUTCOME C is undisturbed. `AdmitConfidence`'s two vacuous guards stay
vacuously paired, and REL-014's rule — that both must be armed in one change-set — is untouched.

**Declared operational intent — UNCHANGED.** ADR 0083 §2.6 still binds. Five candidates were
intent-blocked and none was admitted.

**PostgreSQL BASIC freeze — NOT REOPENED.** **Kafka topic surface — UNTOUCHED** (`Topics = []`
stands). **Redis command allowlist — UNTOUCHED**: no new command, no new literal.
**RabbitMQ observation ceiling — UNTOUCHED**: no channel, no passive declare, no management call.

---

## 10. Conflicts recorded, not fixed

Phase 11.0 is documentation-only, so a conflict between a record and the tree is recorded rather
than patched.

| | Conflict | Disposition |
|---|---|---|
| **P1** | **`docs/FINDINGS.md` documents Kafka, PostgreSQL, generic transport and RabbitMQ, and contains the word "Redis" exactly once — in a sentence about a *RabbitMQ* code.** The **nine `REDIS_*` finding codes have no entry in the finding catalog at all**, although §1's ownership rules and §3.1's quality bar bind them like every other code | **Documentation gap, real and previously unrecorded.** No behaviour is wrong and no claim is unsafe; the codes are specified in ADRs 0063–0066 and implemented and tested. **Recorded, not fixed** — writing a service section is a documentation phase's work, not an audit's |
| **P2** | ADR 0086 §1.2 states the two hypothesis codes have *"different layers"*. Both are `domain.LayerTopology` | Corrected in §9 above. The record's conclusion survives on the other two grounds; history is not edited |
| **P3** | `internal/probe/tls`'s comment explains that a *received* `protocol_version` alert arrives as an unexported error type | **Confirmed and generalized by measurement** (C-10): on Go 1.26.6 **every** received alert is `*tls.permanentError`, and `tls.AlertError` matches none of them. The comment is right and narrower than the truth |

Conflicts C1–C5 recorded by ADR 0090 §9 are unchanged: C1 was resolved by Phase 10.8B; C2, C3 and
C4 remain open with their conditions; C5 was corrected in ADR 0090 §3.

---

## 11. Traceability — `DPA-001` … `DPA-024`

Tiers: **F** frozen by ADR 0092 · **D** deferred with a named condition · **N** next
implementation phase.

| ID | Tier | Requirement | Where | Status |
|---|---|---|---|---|
| DPA-001 | **F** | Diagnostic planning is defined by seven conditions, and eight named shapes are excluded | ADR 0092 §2.1, §3 above | frozen |
| DPA-002 | **F** | A competing pair must pass all five tests A–E; four named shapes are invalid pairs | ADR 0092 §2.2 | frozen |
| DPA-003 | **F** | Every candidate observation carries exactly one class `O0`–`O9` | ADR 0092 §2.3, §6.3 | frozen; all 29 classified |
| DPA-004 | **F** | A candidate needs `MATERIAL` or `DECISIVE` ordinal gain; no percentages, no probability, no score | ADR 0092 §2.6, §6.5 | frozen; 0 `DECISIVE`, 12 `MATERIAL`, none admitted |
| DPA-005 | **F** | Every observation's authority is named from a closed list, and measured contrast never becomes causal authority | ADR 0092 §2.4 | frozen |
| DPA-006 | **F** | The vantage-contrast claim ceiling is *reachability differs by network position*; five causal readings are refused by name | ADR 0092 §2.4 | frozen; already enforced by FP01A |
| DPA-007 | **F** | Credential authority is untouched: endpoint-bound, no inheritance by discovered endpoints, no second-vantage distribution | ADR 0092 §2.8; ADR 0028, 0030, 0050 | frozen |
| DPA-008 | **F** | Cost, budget and side-effect analysis is mandatory per candidate | §5 case files | done, 29/29 |
| DPA-009 | **F** | Safety: no candidate may reach `RESTART`, `DISRUPTIVE` or `SECURITY_WEAKENING`; those stay unreachable by construction | ADR 0092 §2.8 | frozen; `O7` count is 0 |
| DPA-010 | **F** | *Valuable*, *collectable* and *should be collected automatically* are three separate questions, answered separately | §5 case files | done |
| DPA-011 | **F** | Advisory next evidence is distinct from self-collection; `SelfCollectable` reports capability and authorizes nothing | ADR 0092 §2.7; ADR 0082 §2.4 | frozen |
| DPA-012 | **F** | No `INVESTIGATE` mode and no `--investigate` flag; consent is required for class `O2` and above **if** anything is ever admitted | ADR 0092 §2.7, §8.3 above | frozen |
| DPA-013 | **F** | The minimum justified iteration model is **A**, and it is implemented | ADR 0092 §2.7, §8.2 above | frozen |
| DPA-014 | **F** | Phase 10.4C remains closed; all ten conditions were tested and condition 1 fails | §9 | frozen |
| DPA-015 | **F** | Phase 10.5B remains closed; no candidate needs a relation | §9 | frozen |
| DPA-016 | **F** | No cross-target causal diagnosis; an alternate-vantage measurement is same-target multi-vantage and never two targets | ADR 0092 §2.10, §8.6 above | frozen |
| DPA-017 | **F** | Canonical diagnostic behaviour is deterministic: no LLM, no embeddings, no probabilistic model, no semantic matching, no external AI service | ADR 0092 §2.9 | frozen |
| DPA-018 | **F** | The frontier audit is complete over all 65 codes and every non-finding state; 67 cases, none sampled | §4 | done |
| DPA-019 | **F** | Every candidate has a case file; 29 of 29 | §5 | done |
| DPA-020 | **F** | No intelligence is manufactured: a candidate needs a real production frontier, not an imagined one | §5, §6 | done — 0 admitted |
| DPA-021 | **F** | Operator-declared intent is a **premise**, never next-best evidence, and never `SelfCollectable: true` | ADR 0092 §2.5 | frozen |
| DPA-022 | **F** | The G01–G25 admission gates bind any future winner; no winner exists, so none was applied to select one | ADR 0092 §2.11, §12 below | frozen |
| DPA-023 | **F** | No planner abstraction exists: no `Planner`, no planning loop, no `DiscriminatorID`, no hypothesis-set engine, no observation scheduler, no planning budget, no new evidence relation | ADR 0092 §2.11 | frozen |
| DPA-024 | **D** | The nine deferred candidates, each with its own named condition | ADR 0092 §7 | deferred |

**No requirement is tier N.** An audit that admitted nothing has no next-implementation row, and
saying so is the point.

---

## 12. The admission gates, applied to the two strongest candidates

No winner exists, so no gate table selects one. Both nominated candidates are run through G01–G25
anyway, because a gate list nobody applies proves nothing.

| Gate | C-01 alternate vantage | C-18 admission contrast |
|---|---|---|
| G01 real production frontier | **PASS** | **PASS** |
| G02 two real competing explanations | **PASS** | **PASS** |
| G03 same evidence permits both | **PASS** | **PASS** |
| G04 operationally distinct | **PASS** | **PASS** |
| G05 concrete discriminator observation | **PASS** | **PASS** (O-a only) |
| G06 `MATERIAL`/`DECISIVE` gain | **PASS** (O1 only) | **PASS** |
| G07 bounded observation semantics | **PASS** | **PASS** |
| G08 authority precisely known | **PASS** — measured-contrast | **PASS** — operator-declared |
| G09 no causal overclaim | **PASS**, only because the ceiling is frozen | **PASS** |
| G10 no security weakening | **PASS** for the probe; **FAIL** for the execution channel | **PASS** |
| G11 credential authority preserved | **FAIL** — no model for a credential at a second vantage | **PASS** |
| G12 bounded cost | **FAIL** — the mechanism is unbuilt and unbounded | **PASS** |
| G13 bounded response / fan-out | **PASS** | **PASS** |
| G14 cancellation feasible | **FAIL** — cancelling a remote execution channel is a new contract | **PASS** |
| G15 deterministic fixture feasible | **FAIL** — two vantages at two instants | **PASS** |
| G16 compatibility understood | **PASS** — no protocol involved | **PASS** |
| G17 canonical report can represent the result | **FAIL** — one `Vantage` per report; no two-vantage shape | **PASS** — already represented |
| G18 convergence safety understood | **PASS** | **PASS** — CONFIRMED, one per run |
| G19 no cross-target causal diagnosis | **FAIL** if modelled as two targets | **PASS** |
| G20 no LLM dependency | **PASS** | **PASS** |
| G21 false-positive risk acceptable | **PASS** with the ceiling; **FAIL** without it | **PASS** |
| G22 existing evidence cannot already answer it | **PASS** | **PASS** |
| G23 operator value exceeds output noise | **FAIL** — a shell does it in ten seconds | **PASS** |
| G24 minimal model identified | **FAIL** — needs a model beyond C | **PASS** — Model A |
| G25 BASIC vs consent understood | consent **and** new infrastructure | **PASS** — BASIC-compatible |
| **Result** | **8 gates fail — no winner** | **25 gates pass — and it is already built** |

**C-18 passes every gate and is still not selected, because selecting it would authorize building
something that exists.** That is the audit's cleanest single result.

---

## 13. Final adversarial review

The twenty questions §46 requires, answered against the outcome rather than against a winner.

1. **Did I invent two hypotheses to justify a planner?** No — the reverse. Genuine pairs were
   found (C-01, C-05, C-13, C-18) and every one was rejected or deferred.
2. **Is one merely a restatement of the observation?** Checked per candidate; C-19's third
   explanation was struck for exactly this (a pooler *is* the endpoint).
3. **Are A and B mutually informative?** Checked in every case file's *why both remain possible*.
4. **Does O really distinguish them?** C-18's three cheaper routes were refuted rather than
   assumed; C-10's cheap route was **measured** to be unavailable.
5. **Would O1/O2 materially change the canonical claim?** Outcome tables state it, including what
   still cannot be said.
6. **Correlation for causality?** The vantage ceiling (ADR 0092 §2.4) exists precisely to stop it.
7. **Another measurement mistaken for new evidence?** C-08 and C-02 were rejected on this.
8. **Operator intent mistaken for observable fact?** C-04, C-13, C-17, C-18, C-21 — five
   candidates, all classified `O4` and none admitted.
9. **Credential authority weakened?** No. C-01/C-12 fail G11 explicitly rather than being waved
   through.
10. **Network operations added without consent?** None. No production code changed.
11. **Unbounded fan-out hidden?** C-10 is rejected for it by name.
12. **A second vantage assumed to exist?** No — §7.1 states it does not.
13. **svcdoctor assumed to control it?** No — the execution channel is named as unbuilt.
14. **Human prose used as machine identity?** No. ADR 0086 §2.2a's withdrawal stands and nothing
    here re-freezes byte-equal `Discriminator` as a key.
15. **Could structured `NEXT_EVIDENCE` deliver the same value without a planner?** **Yes, and it
    already does** — which is the outcome.
16. **10.4C reopened unnecessarily?** No — closed, with the condition-1 failure shown.
17. **10.5B reopened unnecessarily?** No — closed, with producers re-counted at zero.
18. **Useful to an operator during an incident?** The rejected candidates would mostly have added
    noise; the two valuable ones already print.
19. **Would a principal engineer trust this claim?** The claim is *no planner is justified*, and
    it is supported by a complete frontier, 29 case files and a re-measured inventory.
20. **Could less evidence ever produce a stronger claim?** Not through anything proposed, because
    nothing is proposed. The one shape that risks it — *"no named ceiling means no ceiling"* — is
    already forbidden (C-26, ADR 0090 §5.3).

**No answer exposed a semantic flaw requiring a downgrade, because there is no winner to
downgrade.**

---

## 14. Outcome

> ### DEFER DIAGNOSTIC PLANNING

**Twenty-nine candidates, zero admitted.**

The reason is not that svcdoctor has no epistemic boundaries — it has many, and §4 inventories
all sixty-seven. It is that **at every boundary where two genuinely competing explanations remain
and a discriminating observation exists, one of exactly three things is true**:

1. **the observation is not svcdoctor's to take** — it is operator intent, privileged
   configuration, or a network position svcdoctor does not occupy (C-13, C-18, C-19, C-21, C-01);
2. **svcdoctor already names it**, as a `Discriminator` and a classified `NEXT_EVIDENCE`
   recommendation with an honest `SelfCollectable` value, and a planner would add nothing
   (C-02, C-07, C-08, C-13, C-15, C-18);
3. **taking it would attack the endpoint, guess, or exceed a bound** (C-14, C-23, C-29, C-10).

**A planner is justified only when svcdoctor can say *"I cannot distinguish A from B with the
current evidence; observation O would materially distinguish them, and I could take O."* The
tree contains the first two clauses. It contains no instance of the third.**

`SELECT` is therefore not available, and `DIAGNOSTIC PLANNING NOT YET JUSTIFIED` would be the
weaker and less accurate statement: the cases exist and are found — they are **served**, not
absent.

### 14.1 What is frozen instead

ADR 0092. The definition, the competing-pair test, the observation taxonomy, the vantage claim
ceiling, the intent-is-a-premise rule, the minimum iteration model, the determinism requirement,
and an explicit list of the eight abstractions that must not be built.

### 14.2 What would reopen it

**One repository event, stated as narrowly as it can be:**

> A production diagnosis reaches a state where **two competing explanations** remain, and there
> exists an observation that (a) svcdoctor **could take from its own vantage with its existing
> credential authority**, (b) is class **`O0`, `O1` or `O2`** with a bounded response, and (c)
> whose outcomes would **materially** change what svcdoctor may claim.

Each of the nine deferred candidates carries its own narrower condition (ADR 0092 §7). None is
expected to fire from a service phase; the likeliest openers are a declared-intent record
(C-21), which would not create a planner, and a fixture that finally produces a shape nobody has
observed (C-16, C-25, C-28).

### 14.3 Recommended next direction

**Not a planner, and not Kubernetes yet.**

The smallest genuinely valuable next step in *this* line is the NBE-021 debt: classify
`KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`'s three legacy per-layer transport recommendations
through `diagnosis.Recommend`, emptying the exemption list. It adds no observation, no code, no
rule and no schema change, and it finishes what Phase 10.4B deliberately left to Kafka's own
judgement.

Beyond that, the **Kubernetes diagnostic adapter** is the next roadmap candidate to evaluate —
named here and **not designed here**. Two facts from this audit are worth carrying into that
evaluation and nothing more: `internal/platform/kubernetes` contains only a `.gitkeep`, and
`internal/platform`'s boundary is that it collects environment context and produces no diagnosis.

---

## 15. Validation

Phase 11.0 is documentation-only.

```
git rev-parse HEAD; git rev-parse origin/main    # identical, 22633f2
git status --short                                # clean at start
make check                                        # exit 0 — MANDATORY GATE, run before editing
  fmt-check OK · go test ./... · go vet ./... · golangci-lint run ./... "0 issues." · build
go test ./test/security/... -run 'Convergence|RuleContext|Schema|Reveal|SecretFor|Dependenc|FindingCode|Closure' -v
  → attributed 65 of 65 declared finding codes; 22 rules; RuleContext 3 fields;
    SchemaVersion 1; dependency count exact; Reveal one production call site per service
make check                                        # exit 0 — re-run after editing
git diff --check                                  # clean
```

**Evidence labelling.** Every claim in this document about rule behaviour, evidence attributes,
finding prose, guards and composition roots is **SOURCE-PROVEN** — read from the tree at
`22633f2` — except:

- the inventory figures in §1, which are **TEST-PROVEN** by the named guards, executed;
- `make check`, **EXECUTED**, twice;
- the TLS alert result in C-10, which is **MEASURED** by a scratch program run **outside the
  repository** at `/tmp/svcdoctor-alertprobe` on Go 1.26.6 darwin/arm64. **No repository file was
  created, modified or deleted by it**, and the directory was removed afterwards.

**Not run, and no claim is made about them:** every container integration suite — Kafka,
Redpanda, PostgreSQL, Redis, Valkey, RabbitMQ, LavinMQ, multi-target — and all eleven mutation
harnesses. Phase 11.0 changes no Go code, so no integration-green and no mutation-closure claim
is made.

**No temporary mutation or restoration experiment was performed on the repository.**
