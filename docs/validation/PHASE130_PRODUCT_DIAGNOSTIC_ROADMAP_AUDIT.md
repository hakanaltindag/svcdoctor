# Phase 13.0 — Product and diagnostic roadmap audit

- **Phase:** 13.0 — product / architecture / diagnostic roadmap audit. **No production, test, CI,
  Makefile or dependency change.**
- **Baseline:** `ef257422dc89c889dcde94e6f19118e524ad928f`, `HEAD == origin/main`, clean tree,
  `make check` green before anything was written
- **Question:** what should svcdoctor build next, and why?
- **Answer:** **not a new adapter, not more Kubernetes, and not a planner.** The highest-value next
  investment is **finishing something already built**: 61 of 69 finding codes carry a
  recommendation with no kind, no safety class, no rationale and no self-collectability answer,
  while the validated machinery to classify them has shipped, is redaction-safe, is rendered, and
  is already used by the other 8
- **Open blockers:** none

---

## 1. Baseline and method

```
HEAD        ef257422dc89c889dcde94e6f19118e524ad928f  ci(kubernetes): add real-cluster release gate
origin/main ef257422dc89c889dcde94e6f19118e524ad928f
tree        clean
make check  GREEN
```

Phase 12.2B is present and verified in the tree: `.github/workflows/kubernetes.yml`,
`scripts/install-kube-tools.sh`, `internal/cli/kubernetesworkflow_test.go`, and both `needs:`
edges in `release-oci.yml`.

**Every number below was measured against this tree.** Where a historical record and the code
disagree, §2.4 records it and the code wins.

### 1.1 What was read

Production: `internal/domain`, `internal/diagnosis` (and all six rule packages), `internal/adapter`
(all five services and their wire packages), `internal/app`, `internal/fleet`, `internal/security`,
`internal/render`, `internal/cli`, `internal/probe`, `internal/service`, `internal/vocabulary`.

Documents: `docs/ARCHITECTURE.md`, `COMPATIBILITY.md`, `BACKLOG.md`, `REPORT_SCHEMA.md`, `CI.md`,
`RELEASE_CHECKLIST.md`, `design/DIAGNOSTIC_INTELLIGENCE.md`, ADRs 0082 / 0087 / 0092 / 0094 / 0095,
and the Phase 10.x, 11.0 and 12.x validation records.

Behaviour: a real `svcdoctor diagnose postgres` run against a closed port (§5.2), and the committed
terminal goldens.

## 2. What svcdoctor actually is today

### 2.1 The product, stated from the code

**svcdoctor behaves as the client you describe, from where you are standing, and reports what that
attempt established.** It is a *client-vantage path diagnostic*. Every claim it makes is scoped to
one network position, one credential and one journey.

| | |
|---|---|
| **Solves** | *"my client cannot reach / cannot use this service, and the error message is useless"* — by separating name resolution, TCP, TLS, protocol negotiation, authentication, authorization and terminal usability into separately-stated outcomes |
| **Refuses** | server health, capacity trends, application behaviour, historical baselines, thresholds, latency verdicts, control-plane actions, anything requiring privileged server access |
| **Operator** | an SRE or platform engineer holding a client credential and a network position, not a database or cluster administrator |
| **Moment** | early triage — after "it's broken" and before "which team owns this" |
| **Requires** | an endpoint, optionally a credential, optionally trust material. For Kubernetes, a kubeconfig |
| **Refuses to require** | a server login, an admin credential, an agent, a sidecar, a metrics endpoint, telemetry |

### 2.2 Where it sits on the diagnostic taxonomy

| Kind | Status |
|---|---|
| connectivity diagnostic | **full** — DNS, TCP, TLS as first-class separately-stated stages |
| protocol diagnostic | **full** — five protocols, real handshakes, real authentication |
| topology diagnostic | **partial** — Kafka advertised endpoints and PostgreSQL resolved addresses only |
| configuration observation | **partial** — endpoint-reported facts recorded, never interpreted |
| resource/admission diagnostic | **partial** — PostgreSQL `53300`, RabbitMQ capacity scope; Redis collapsed |
| application-health diagnostic | **none, by design** |
| infrastructure diagnostic | **none, by design** |
| causal diagnosis | **none, by design** — ADR 0078's *observation != cause* |

### 2.3 What it knows, infers and refuses

- **Knows directly:** what each stage did, what the peer said in its own protocol's structured
  fields, and how long each took.
- **Infers:** the failure boundary (which stage first stopped succeeding), Kafka advertised
  topology reachability and suitability, PostgreSQL admission scope across resolved addresses,
  Kubernetes selector/endpoint semantics.
- **Refuses to infer, permanently:** cause. `MASTERDOWN` does not mean the primary is down.
  `53300` does not mean the server is overloaded. `no ready endpoint` does not mean no traffic.
  A local timeout is not a remote failure. `UNKNOWN` is not `FAIL`.

### 2.4 One historical claim corrected against the code

Phase 11.0 (`22633f2`) concluded *"the two strongest [competing hypothesis pairs] are already fully
served by structured `NEXT_EVIDENCE` advice that shipped in Phase 10.4B."*

**That is true of the two cases it named and misleading as a general statement about the product,
and this audit is the first to measure the difference.** Structured advice reaches **8** of 69
finding codes. It did not spread; it never left the phases that introduced it. §3.2 is the
measurement.

## 3. Measured diagnostic inventory

### 3.1 Totals

| | Value | Source |
|---|---|---|
| Finding codes | **69** | `TestTheConvergenceInventoryIsComplete` inventory: 1 + 8 + 15 + 21 + 9 + 11 + 4 |
| Production rules | **24** | same inventory: 1 + 3 + 5 + 6 + 4 + 3 + 2 |
| Failure classes | **42** | `internal/domain/failureclass.go`, 42 members |
| `SchemaVersion` / `RunSchemaVersion` | **1 / 1** | `internal/domain` |
| CONFIRMED producers | **58** literals | `KindConfirmed` |
| HYPOTHESIS producers | **4** literals, **2 codes**, **1 service** | both Kafka: `ADVERTISED_ENDPOINT_UNREACHABLE`, `ADVERTISED_TOPOLOGY_UNSUITABLE` |
| Confidence | **55** HIGH, **2** MEDIUM, **3** LOW | literals across all rules |
| Authority basis | `AuthorityDirect` 7, `AuthorityCompleteContrast` 7, `AuthorityNone` 10, `AuthorityNamesCoverAllGrounds` 1 | `internal/diagnosis` |
| Severity | ERROR 53, WARN 16, INFO 7 | literals |
| Discriminator-bearing findings | **2**, both Kafka | `Discriminator` appears in `basis.go`, `converge.go` and the two Kafka rules only |
| Relation producers | `.Support` **3**; `.Contradict`, `.Miss`, `.Block` **0** | unchanged since Phase 10.5A |

### 3.2 The central measurement — recommendation classification

`domain.Recommendation` has two construction paths. `NewRecommendation(action)` produces a bare
string. `diagnosis.Recommend(AdviceInput{…})` produces one carrying `kind`, `safety`, `rationale`
and `selfCollectable`, and runs ADR 0082's gate.

**Production callers of the classified path:**

| File | Codes served |
|---|---|
| `internal/diagnosis/postgres/session.go` | `POSTGRES_CONNECTION_LIMIT_REACHED` |
| `internal/diagnosis/postgres/admission.go` | `POSTGRES_ADMISSION_SCOPE` |
| `internal/diagnosis/kafka/topology.go` | `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY`, `…_UNSUITABLE` |
| `internal/diagnosis/kubernetes/shared.go` | all four `KUBERNETES_*` |

**8 codes classified. 61 codes unclassified.** And the split is not a design decision — it is
chronology. Every code added from Phase 10.2 onward is classified; every code that predates it is
not, in all six packages including the ones those later phases touched.

The operator-visible consequence, from the committed goldens:

```
next-evidence-classified.txt   → Compare the addresses this network routes … [NEXT_EVIDENCE / COMPARE / you must collect]
kafka-wrong-credential.txt     → Check the thing the finding names
```

**1 of 19 terminal goldens shows a classification tag, and it is the synthetic fixture built to
exercise the feature.** In canonical JSON the four fields are `omitempty`, so 61 codes emit
`{"action": "…"}` — a sentence, not data.

### 3.3 Three consequences that are not cosmetic

**(a) The safety gate does not run on 61 recommendations, by construction.**
`SafetyClass.Producible()` refuses `RESTART`, `DISRUPTIVE` and `SECURITY_WEAKENING` outright, and
`NewClassifiedRecommendation` refuses a next-evidence recommendation that changes the target. The
unclassified path never reaches either check. Reading all 61 texts, **at least five are
target-mutating actions carried as unlabelled advice**:

| Code | Text | Would be |
|---|---|---|
| `RABBITMQ_VHOST_ACCESS_REFUSED` | *"Grant this user permissions on the virtual host, for example with `rabbitmqctl set_permissions`"* | REMEDIATION / CONFIG_CHANGE |
| `RABBITMQ_AUTH_MECHANISM_NOT_OFFERED` | *"Enable SASL PLAIN on this endpoint"* | REMEDIATION / CONFIG_CHANGE |
| `REDIS_COMMAND_NOT_PERMITTED` | *"Grant the diagnostic identity permission to run PING"* | REMEDIATION / CONFIG_CHANGE |
| `REDIS_CREDENTIAL_WITHHELD` | *"Enable TLS for this endpoint and supply the trust material"* | REMEDIATION / CONFIG_CHANGE |
| `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` | *"…or configure a mechanism it demands"* | REMEDIATION / CONFIG_CHANGE |

None is currently unsafe to *say* — all five sit on CONFIRMED findings and would pass the
confidence gate. The defect is that **nothing checked**, and the check is the mechanism ADR 0082
exists to provide. A future recommendation that *is* security-weakening would land the same way.

**(b) `SelfCollectable` — the planner's own entry gate — is unanswered for 61 codes.** Exactly two
production recommendations say `true`, and **both are the same thing**: PostgreSQL
`recommendAdmissionUnmeasured` and Kafka `recommendUnmeasured`, each meaning *"re-run with a larger
execution budget."* That is not a discriminating observation; it is "run me again with more time."
§7 depends on this measurement.

**(c) `DIAG_FAILURE_BOUNDARY` carries no recommendation at all.** `grep -c Recommendations
internal/diagnosis/failureboundary.go` → **0**. The one generic, cross-service finding — present in
essentially every failing run, and the *only* thing a Kubernetes `401` produces — tells the
operator where observation stopped and offers nothing about what to do next.

### 3.4 Per-service inventory

| | Kafka | PostgreSQL | Redis/Valkey | RabbitMQ/LavinMQ | Kubernetes |
|---|---|---|---|---|---|
| Steps | 5 | 4 | 3 | 3 | 5 |
| Service attribute keys | 4 | 7 | 7 | 21 | 17 |
| Finding codes | 15 | 21 | 9 | 11 | 4 |
| Rules | 5 | 6 | 4 | 3 | 2 |
| Classified recommendations | 2 of 15 | 2 of 21 | **0 of 9** | **0 of 11** | 4 of 4 |
| Hypotheses | 2 | 0 | 0 | 0 | 0 |
| Topology awareness | advertised brokers | resolved addresses | none (Sentinel refused) | none | selector → Pods → EndpointSlices |
| Resource/admission | none | `53300` → `RESOURCE_LIMIT_REACHED` | collapsed into one code | capacity scope, 3 named scopes | none |
| Integration suite | committed | committed | committed | committed | committed |
| **Runs in any CI lane** | **yes** | **yes** | **no** | **no** | **yes** |

## 4. Service capability matrix

`F` full · `P` partial · `N` none · `—` not applicable. Non-obvious cells are justified beneath.

| Capability | Kafka | PostgreSQL | Redis | RabbitMQ | Kubernetes |
|---|---|---|---|---|---|
| configuration validation | F | F | F | F | F |
| DNS | F | F | F | F | — ¹ |
| TCP | F | F | F | F | — ¹ |
| TLS | F | F | F | F | — ¹ |
| authentication | F | F | F | P ² | F |
| protocol negotiation | F | F | F | F | — ³ |
| server authority | P ⁴ | F | P ⁵ | F | P ⁶ |
| topology | F | P ⁷ | N ⁸ | N | P ⁹ |
| resource / admission state | N | P | P ⁵ | F | N |
| role / state | N | P ¹⁰ | P ¹⁰ | N | N |
| endpoint suitability | F | N | N | N | P |
| discovery | F | N | N | N | F |
| multi-endpoint reasoning | F | P ⁷ | N | N | N ¹¹ |
| failure-boundary quality | F | F | F | F | P ¹² |
| diagnostic findings | F | F | P | F | P |
| next-best evidence | P ¹³ | P ¹³ | **N** | **N** | F |
| remediation | N ¹⁴ | N ¹⁴ | N ¹⁴ | N ¹⁴ | N |
| compatibility evidence | F | F | F | F | P ¹⁵ |
| real integration coverage | F | F | F | F | F |
| **CI coverage** | F | F | **N** | **N** | F |

1. Kubernetes transport belongs to `client-go`; ADR 0094 §2.9 records L1–L3 as deliberately unused.
2. RabbitMQ is PLAIN-only by ADR 0068; other mechanisms are observed and declined.
3. The Kubernetes API has no separate capability-discovery step, and no discovery request is made.
4. Kafka records `controller_id` but ADR 0084 refuses controller/KRaft inference — measured
   returning 1,1,2,1,1,3,2,3 on a stable cluster.
5. Redis classifies 23 error prefixes into a closed set, but 20+ of them collapse into one
   `REDIS_ENDPOINT_NOT_SERVING` WARN. See §9.
6. Kubernetes has no credential-rejection finding: a `401` produces no `KUBERNETES_*` code and
   exits 0 (ADR 0094 §10.4).
7. PostgreSQL reasons across resolved addresses (`POSTGRES_ADMISSION_SCOPE`) but `internal/app`
   continues exactly one path, so at most one auth node and one session node exist.
8. `REDIS_ENDPOINT_IS_SENTINEL` is a *refusal to proceed*, not topology.
9. Selector → Pod set and `service-name` → EndpointSlices; no service-to-service topology.
10. `postgres.role`/`in_hot_standby` and `redis.role` are rendered observations. Both are
    permanently refused as findings for want of declared intent.
11. One Service, one path, one API server.
12. `DIAG_FAILURE_BOUNDARY` fires, but carries no recommendation (§3.3c).
13. 2 of 15 and 2 of 21 codes respectively.
14. **Zero REMEDIATION recommendations exist anywhere** — including the five that are remediations
    in substance (§3.3a).
15. Two upstream minors, no distribution, and the CI gate has not yet had a hosted run.

## 5. Incident journeys

### 5.1 Method

Each case states the invocation, what runs, what is proven, where the operator leaves.
**Search-space reduction is judged against the alternative of not having run svcdoctor**, not
against an ideal tool.

### CASE A — "my application cannot connect to Kafka"

`svcdoctor diagnose kafka --bootstrap kafka.internal:9093 --user app --password-file …`

Runs DNS → TCP → TLS → ApiVersions → SaslHandshake → SaslAuthenticate → Metadata, then
credential-free DNS/TCP/TLS to every advertised broker.

**Proves**, from the committed golden: bootstrap completed, metadata obtained, and
`1 of 2 advertised broker endpoints reached` — with the unreachable one named and its TCP outcome
recorded. **Refuses**: that the cluster is unhealthy, that the broker is down, that partitions are
affected.

**This is svcdoctor's strongest moment.** `kcat` reports a timeout; it does not tell you that
bootstrap works and one advertised address does not resolve or route *from here*. The operator
leaves with a named broker and a network question, and goes to firewall/DNS/`advertised.listeners`.

**Search-space reduction: HIGH.**

### CASE B — "PostgreSQL connections started failing"

`svcdoctor diagnose postgres --host orders-db.internal --user app`

Measured live in this audit against a closed port (§5.2). Against a real server it separates
`SSLRequest`, TLS, `Startup`, authentication and session; distinguishes credential rejected /
credential withheld / no credential / `pg_hba` refusal / `53300` connection limit / database absent
/ CONNECT denied. With multiple resolved addresses it adds `POSTGRES_ADMISSION_SCOPE`.

**Refuses**: that the server is overloaded, what the limit is, whether a pooler is in the path.
The operator leaves for `pg_stat_activity` or the server log.

**Search-space reduction: HIGH** — five plausible causes collapse to one named stage, and
`53300` becomes a machine-readable code rather than a prose sentence.

### CASE C — "Redis is reachable but the application is failing"

`svcdoctor diagnose redis --host cache.internal --user app --password-file …`

HELLO → AUTH → PING. If the endpoint answers PING with an error, the operator gets **one WARN
finding, `REDIS_ENDPOINT_NOT_SERVING`**, whose prose appends *"The condition the endpoint named was
LOADING."* — and `redis.error_prefix` on the evidence node.

**This is the weakest journey of the five.** `LOADING` (transient, self-healing), `MASTERDOWN`
(replica refusing stale reads), `BUSY` (a script is running), `OOM` (memory ceiling) and an
unrecognized prefix all arrive as the *same code at the same severity*. The operator learns the
endpoint refused and must read the prefix out of prose or JSON to know which of five very different
situations they are in. They leave for `redis-cli INFO`.

**Search-space reduction: MEDIUM.**

### CASE D — "RabbitMQ clients are being rejected"

`svcdoctor diagnose rabbitmq --host broker.internal --vhost /app --username app --password-file …`

`Connection.Start` → SASL PLAIN → `Connection.Open`. Distinguishes authentication refusal, vhost
not found, vhost access refused, and a connection limit **with its scope named** — node, vhost or
user (Phase 10.8B).

**This is the best-served "authoritative refusal" journey**: AMQP's close method carries a reply
code, and svcdoctor normalizes it into a closed set. The operator leaves knowing which of four
distinct administrative facts applies.

**Search-space reduction: HIGH.**

### CASE E — "my Kubernetes Service has no traffic"

`svcdoctor diagnose kubernetes --namespace prod --service payments-api`

Three bounded reads. Distinguishes Service absent, RBAC denied, selector matches zero Pods, and
Pods matched but no ready endpoint.

**Proves** the *publication* half of the question. **Refuses** everything about why a Pod is not
ready, NetworkPolicy, DNS inside the cluster, and the application. A healthy publication path with
a broken application produces **zero findings and exit 0**.

The operator leaves after roughly one `kubectl` command's worth of information — but with it
already correlated, and with the RBAC case named rather than presented as an empty list.

**Search-space reduction: MEDIUM.** It answers the first question and hands over immediately.

### 5.2 Measured output, taken live in this audit

```
  ✗ ERROR  TCP_CONNECTION_NOT_ESTABLISHED  127.0.0.1:5433
    …
    → Check that the endpoint accepts connections on this port from this network position,
      and read the per-address outcomes recorded on the referenced evidence
  · INFO  DIAG_FAILURE_BOUNDARY  127.0.0.1:5433
    The first stage measured for this subject, tcp, failed
    …
    evidence: 1
```

Two things are visible and both are §3.3: the recommendation carries **no classification tag**, and
the boundary finding carries **no recommendation**.

## 6. Diagnostic depth ladder

| Service | Level | Justification | What the next level needs |
|---|---|---|---|
| **Kafka** | **D4** | Two HYPOTHESIS codes, a `Discriminator`, an aggregate with completeness *and* contrast, and classified next-evidence | D5 needs safe causal narrowing across authoritative observations; ADR 0084 refuses every candidate it weighed |
| **PostgreSQL** | **D3** | Server authority (SQLSTATE), admission scope across resolved addresses, classified next-evidence on two codes | D4 needs a competing-hypothesis pair. `internal/app` continues one path, so split-brain and one-address-refused-while-sibling-accepts are graphs no producer makes |
| **RabbitMQ** | **D2+** | Full server authority with named capacity scope; no multi-endpoint reasoning | D3 needs cluster topology, which needs the management API |
| **Kubernetes** | **D2/D3** | Server authority (structured `NotFound`, `403`) plus a two-branch publication graph; but no differential reasoning | D4 needs a second hypothesis, which needs evidence ADR 0094 does not acquire |
| **Redis** | **D2−** | Server authority exists in the wire package and **is collapsed at the finding layer**: 20+ closed-set prefixes → one WARN code | D2 proper needs severity/claim separation for the prefixes whose authority is strong (§9) |

**No service is at D5, and none should be.** D5 is causal diagnosis, which ADR 0078 refuses.

## 7. Phase 11.0 — the planner: **KEEP DEFERRED**

Phase 11.0 weighed 29 candidates and admitted zero. Re-evaluated against this tree, with Kubernetes
added and RabbitMQ enrichment landed:

- **Has a genuine competing-hypothesis set emerged?** No. HYPOTHESIS producers are still **2 codes
  in 1 service**, both Kafka, both from Phase 10.2. Kubernetes added four codes, all CONFIRMED, all
  `AuthorityDirect`, **none carrying a discriminator**. RabbitMQ's enrichment made an existing claim
  more specific; it created no second explanation.
- **Would selecting the next observation reduce uncertainty?** In principle, yes — for the cases
  10.4A already named.
- **Can svcdoctor collect it?** **Measured: essentially never.** Exactly two recommendations are
  `SelfCollectable: true` and both mean *"re-run with a larger execution budget."* Not one
  discriminating observation is svcdoctor-collectable today.
- **Is the next observation already a structured recommendation?** For 8 codes, yes. **For 61, the
  question has no answer in the report at all** — they carry no `SelfCollectable` field.

**That last point is the new argument, and it changes the shape of the deferral.** Phase 11.0
deferred the planner because the frontier looked *served*. This audit finds the frontier is
**unmeasurable**: 88% of findings do not state whether their next observation is one svcdoctor
could take. A planner cannot be designed against an inventory that does not exist, and building one
now would mean inferring the inventory from prose.

**KEEP DEFERRED**, and the reopen condition is now concrete and cheap to evaluate: *reopen when
every recommendation is classified and the resulting `SelfCollectable: true` set contains at least
one discriminating observation that is not "re-run with more budget."*

## 8. Evidence relations — **KEEP DEFERRED**

`.Contradict`, `.Miss` and `.Block` still have **0** producers; `.Support` has 3. Nothing in
Phases 11 or 12 changed the reasoning Phase 10.5A recorded, and Kubernetes — the one new
producer — reinforces it:

- **Contradiction** still fires as *suppression before a basis exists*. Kubernetes F3/F4
  disjointness is implemented as a withholding condition, not a recorded contradiction.
- **Missing** still requires a `domain.Step` for an observation that has none. Kubernetes' denied
  reads are `UNKNOWN` nodes **with identifiers** — ADR 0086 §2.1 position 4, not `Miss`.
- **Blocked** is frozen as Model A, a projection of `Graph.BlockedBy`. Kubernetes' `SKIPPED`
  downstream reads are exactly that, and `Freeze` check 4 keeps the projection subordinate.

Two guards in `AdmitConfidence` remain vacuous for the reason 10.5A gave — `basis.missing` is read
while `Miss` has no producer, safe only because `AuthorityCompleteContrast`… **is now produced 7
times.** That is a change worth naming: the pairing 10.5A relied on ("both must be armed in one
change-set") is now half-armed. It is still safe, because the complete-contrast check reads
`basis.missing` and finds it empty, which is the correct answer when nothing is missing. But the
symmetry argument is weaker than when it was written, and a future phase adding a `Miss` producer
must re-derive it rather than cite 10.5A.

**KEEP DEFERRED.** No relation has a producer that wants it; adding one for elegance would be
exactly the abstraction §15 forbids.

## 9. Redis diagnostic intelligence — **DEFER**

Not rejected: there is a real candidate here, and it is the clearest single-service gap in the
product (§5 CASE C, §6). But it does not win this round.

### 9.1 Candidate inventory

Every currently recorded Redis observation, with what it could support:

| Observation | Authority | Possible claim | Safe confidence | Risk | Verdict |
|---|---|---|---|---|---|
| `LOADING` | **strong** — closed-set prefix, endpoint's own statement | "this endpoint said it is loading its dataset" | HIGH | low; must not become "data was lost" | **candidate** |
| `MASTERDOWN` | **strong** | "this replica said its primary link is unavailable" | HIGH | **must not become "the primary is down"** — svcdoctor never observed the primary | **candidate** |
| `BUSY` | **strong** | "the endpoint said it is executing something else" | HIGH | low | candidate |
| `OOM` | **strong** prefix, but unreachable on the frozen journey — PING allocates nothing | — | — | claiming memory pressure from a keyless probe is unfounded | **reject** |
| `MISCONF` | strong prefix, unreachable on PING | — | — | — | reject |
| `READONLY` | strong prefix, unreachable — svcdoctor never writes | — | — | — | reject |
| generic `ERR` | **none** — Redis interpolates caller arguments into it (`server.c:4386`) | — | — | **the prior audit's warning: generic `ERR` is not authority for anything** | **reject** |
| `UNRECOGNIZED` | none, by construction | — | — | — | reject |
| `redis.role` | endpoint self-report | role observation | — | no declared intent exists | **already rendered; permanently not a finding** |
| `redis.mode` | endpoint self-report | already owns `REDIS_ENDPOINT_IS_SENTINEL` | — | — | built |
| `MOVED`/`ASK`/`CLUSTERDOWN` | strong prefixes, unreachable — a keyless command is never redirected (ADR 0065) | — | — | — | reject |
| `NOPERM` | strong | already owns `REDIS_COMMAND_NOT_PERMITTED` | — | — | built |

**Three candidates survive: `LOADING`, `MASTERDOWN`, `BUSY`.** All three are already *stated* — the
prefix is on the node as `redis.error_prefix` and in the finding's detail. What they lack is a
**distinct code and a defensible severity**: today `MASTERDOWN` (a replica refusing to serve) and
`LOADING` (a server that will be fine in seconds) are both WARN under one code.

### 9.2 Why it defers

- The prefix is **already machine-readable**. `Evidence.MarshalJSON` emits `attributes`, so a
  pipeline can already branch on `redis.error_prefix` without parsing prose. The gain is severity
  differentiation and claim specificity, not machine-readability.
- It benefits **one service** and adds **finding codes**, against a candidate (§12) that benefits
  **all six rule packages** and adds **none**.
- **Redis runs in no CI lane** (§4). Adding codes to the least-protected service before restoring
  its automated coverage inverts the right order.
- Two of the three would need `docs/FINDINGS.md` entries, which currently has **no entry for any
  of the nine `REDIS_*` codes** — an open backlog item that a new code would deepen.

**DEFER**, with the condition: *reopen once Redis is under a CI lane and `docs/FINDINGS.md` covers
the existing nine, as a small phase adding at most `REDIS_ENDPOINT_LOADING` and
`REDIS_REPLICA_LINK_DOWN` — and never a claim about a primary svcdoctor did not observe.*

## 10. RabbitMQ diagnostic intelligence — **DEFER (near-REJECT under current scope)**

RabbitMQ is the **best-served** authoritative-refusal journey in the product. Phase 10.8B already
turned the capacity close-outcome into three named scopes with a closed mapping, and
`rabbitmq.close_outcome` is a structured attribute.

Remaining candidates, and what each would require:

| Candidate | Provable from a direct AMQP endpoint? |
|---|---|
| authentication | **built** |
| vhost access | **built** |
| connection limits | **built**, with scope |
| protocol negotiation | **built** — Tune offered/selected recorded on both sides |
| server close outcomes | **built**, normalized, truncation-aware |
| cluster condition | **no** — needs the management API or cluster credentials |
| queue condition | **no** — needs queue enumeration; svcdoctor opens no channel |
| node partition | **no** — needs `rabbitmq-diagnostics` or the management API |

**Everything AMQP 0-9-1 direct endpoint authority can prove is already proven.** The residual
frontier is entirely on the far side of an HTTP management API, cluster credentials and queue
enumeration — which is not a RabbitMQ feature request, it is **a different product** (§11 and §13).

**DEFER**, and treat "adopt the management API" as its own product-direction candidate rather than
as RabbitMQ diagnostic intelligence.

## 11. Kubernetes — **BUILD NOTHING NOW**

Kubernetes reached a validation and release boundary three commits ago and **its CI gate has not
yet had a single hosted run**. Expanding it now would add scope on top of an unproven gate.

| | Candidate | Operator value | Authority | RBAC / credential | Cardinality | Test cost | Turns svcdoctor into kubectl? | Verdict |
|---|---|---|---|---|---|---|---|---|
| **K-A** | more findings from current acquisition | low — ADR 0094 §2.7 already argued four is the budget, and the fifth (a `401` code) is a known named gap | good | none | none | low | no | **DEFER** — the `401` code is the one worth doing, and it is already a tracked backlog item |
| **K-B** | Events | medium — Events explain *why* a Pod is unready | **poor**: Events are best-effort, deduplicated, TTL'd, and their `reason` set is unbounded | `events:list` | **high** — unbounded per namespace | high | partially | **REJECT** — ADR 0093's condition (an svcdoctor-owned exact-match `reason` allowlist, every member observed on a real cluster) is unmet, and unbounded peer prose is the thing the report model refuses |
| **K-C** | Logs | high for humans | **none** — arbitrary application bytes | `pods/log` | unbounded | high | **yes** | **REJECT** — logs are the operator's job and `kubectl logs` does it better |
| **K-D** | NetworkPolicy | high | good (declarative objects) | `networkpolicies:list` | medium | high | no | **DEFER** — the honest claim is *"a policy exists that could match"*, which is simulation, not observation. Real value would need active probing (K-E) |
| **K-E** | active Pod/Service probing | **very high** — it is the client-vantage thesis applied inside the cluster | **excellent** — svcdoctor's own measurement | none new, but requires **running inside the cluster** | low | very high | no | **DEFER, strongest candidate here** — it is `svcdoctor diagnose <service>` from a Pod, which the OCI image already supports today by hand |
| **K-F** | workload / container-state diagnosis | medium | poor — `reason` strings are unbounded | `pods:get` (have it) | low | medium | yes | **REJECT** — same unbounded-`reason` problem as K-B |
| **K-G** | Gateway/Ingress | medium | good | new CRD reads | medium | high | no | **DEFER** — CRDs multiply the compatibility matrix by every controller |
| **K-H** | cluster discovery wrapper | low | — | broad list rights | **very high** | high | **yes** | **REJECT** — "show me everything" is an inventory tool |
| **K-I** | service-to-service topology | medium | poor — requires inferring intent | broad | high | high | yes | **REJECT** — inferring which service calls which is exactly the causal overclaim ADR 0078 refuses |

**The distinction that decides most rows:** a *useful Kubernetes feature* answers "what is the state
of my cluster." An *appropriate svcdoctor feature* answers "what can this client prove about its
path." K-E is the only candidate that is squarely the second, and it is the one that needs no new
authority at all.

## 12. Generic cross-cutting opportunities

| ID | Candidate | Services | Improves diagnosis or presentation? | Schema | Renderer | Justified by current cases? |
|---|---|---|---|---|---|---|
| **G1** | **classify every recommendation** | **all 6 packages, 61 codes** | **both** — it runs a safety gate that currently does not run, and answers `SelfCollectable` for the first time | **none** — fields exist, `omitempty`, additive at v1 | **none** — `adviceTag` already renders it | **yes**, §3.2/§3.3 |
| **G2** | give `DIAG_FAILURE_BOUNDARY` a recommendation | all | diagnosis | none | none | yes — §3.3c, §5.2 |
| **G3** | CI coverage for Redis/Valkey/RabbitMQ/LavinMQ/multi-target | 3 services + fleet | neither — protection | none | none | yes — §4, 20 codes and the whole `run --config` path unguarded |
| **G4** | renderer sanitization of unbounded peer values | Redis, RabbitMQ, PostgreSQL | presentation/robustness | none | yes | partly — Redis `server_version` is bounded only by a 64 KiB reply ceiling; already a tracked item |
| **G5** | report diffing / run-to-run comparison | all | presentation | none | new surface | **no** — no current case demands it; speculative |
| **G6** | evidence timeline | all | presentation | none | yes | **no** — durations are already per-stage |
| **G7** | machine-readable recommendation *identity* (stable IDs) | all | diagnosis | **yes, additive** | yes | **no, not yet** — G1 first; an ID for an unclassified string is an ID for prose |
| **G8** | authority provenance on findings | all | diagnosis | yes | yes | **no** — `AuthorityBasis` is internal and no consumer has asked |
| **G9** | endpoint-set comparison | Kafka, PostgreSQL | diagnosis | yes | yes | **no** — `POSTGRES_ADMISSION_SCOPE` and Kafka topology already do this per service |

G5–G9 are rejected as abstraction without a current case, which is the failure mode §15 names.

## 13. New service adapters — **DEFER, none admitted**

The question is not popularity. It is: *can svcdoctor prove something `nc`, `curl` or the vendor CLI
does not already prove trivially?*

| Candidate | Incident prevalence | Client-vantage value beyond existing tools | Bounded? | Verdict |
|---|---|---|---|---|
| **HTTP/HTTPS** | very high | **low** — `curl -v` already reports DNS, TCP, TLS and status, and is universally installed | yes | **REJECT** — svcdoctor would duplicate rather than differentiate |
| **gRPC** | high | medium — TLS + ALPN + health-check protocol is fiddly; but `grpcurl` exists | yes | DEFER |
| **MySQL / MariaDB** | high | **medium-high** — auth-plugin negotiation (`caching_sha2_password` vs `mysql_native_password`) is a genuinely confusing failure, and the handshake carries structured errors | yes | **DEFER — best of the set** |
| **MSSQL** | medium | medium | TDS is large | DEFER |
| **Elasticsearch / OpenSearch** | medium | low — it is HTTP; `curl` applies | yes | REJECT |
| **NATS** | medium | medium — INFO/CONNECT is small and clean | yes | DEFER |
| **etcd** | medium | low — gRPC + mTLS, and `etcdctl` is authoritative | yes | REJECT |
| **Vault** | medium | low — HTTP + a status endpoint | yes | REJECT |

**None is admitted, and the reason is structural.** A sixth adapter would arrive carrying its own
unclassified recommendations, multiplying the §3.2 gap by 1.2× rather than closing it — and it
would land in a repository where two of five existing services already run in no CI lane. **Depth
before breadth**, and depth here means finishing what is built.

## 14. Client-vantage thesis — **supported, and it should be frozen**

> **svcdoctor explains what a specific client, from a specific network position, holding a specific
> credential, can prove about its path to a service — and refuses to claim anything that position
> cannot establish.**

The repository supports this thesis in code, not merely in prose:

- **Vantage is a first-class report concept**, and `VantageDependent` is set per finding.
- **Credentials are endpoint-bound** (ADR 0028), so a discovered endpoint gets credential-free
  probing and nothing else.
- **`UNKNOWN` is not `FAIL`**; a local timeout is not a remote failure.
- **The strongest existing output** (§5 CASE A) is precisely a vantage claim: *bootstrap works from
  here, one advertised broker does not*.
- **Every refusal recorded in ADRs 0084, 0085, 0093 and 0094** is a refusal to claim beyond the
  client's position.

**Candidates that strengthen it:** G1 (says who must take the next observation — the operator or
svcdoctor), K-E (the thesis applied from inside a cluster), MySQL (a fifth protocol, same shape).

**Candidates that violate it:** K-B/K-C/K-F (peer prose as authority), K-H/K-I (inventory and
inferred call graphs), the RabbitMQ management API (server-side administrative state), any
`pg_stat_*` reading, any metrics scrape. Each of those makes svcdoctor a *monitoring* product, and
§29's last stop condition names that as a reason to stop rather than proceed.

## 15. Tool overlap — where svcdoctor differentiates

| Tool | Overlap | Where svcdoctor differs |
|---|---|---|
| `ping`, `dig`, `nc` | D0 only | svcdoctor keeps the stages *separate and named*, and continues past the first success |
| `openssl s_client` | D0/TLS | svcdoctor separates **trust** from **identity** (ADR 0058) and states which failed |
| `curl` | HTTP only | — (why HTTP is rejected in §13) |
| `kcat` | Kafka | **the differentiating case**: `kcat` reports a timeout; svcdoctor reports *bootstrap succeeded and 1 of 2 advertised brokers is reachable from here* |
| `psql` | PostgreSQL | `psql` reports the last error; svcdoctor separates SSL negotiation, TLS, startup, auth and session, and names `53300` as a code |
| `redis-cli` | Redis | **`redis-cli` is currently better** for CASE C: `INFO` gives the operator more than one collapsed WARN |
| `rabbitmqadmin` / management UI | RabbitMQ | needs management credentials; svcdoctor proves the AMQP path with the *application's own* credential |
| `kubectl` | Kubernetes | roughly one command's worth, pre-correlated, with the RBAC case named rather than shown as an empty list |
| observability platforms | — | different axis: they aggregate over time; svcdoctor answers one question now, from here |

**Duplication risk is real in exactly two places:** HTTP (rejected) and Redis (§9 — where the vendor
CLI is currently ahead).

## 16. "Why would an SRE open this?"

**VALUE.** Because in a multi-hop service — Kafka, a pooled PostgreSQL, a Kubernetes Service —
*"cannot connect"* has six or seven candidate causes, and every ordinary tool collapses them into
one message. svcdoctor is the only thing on the list that reports **each stage separately, refuses
to guess, and states which network position the answer belongs to.** The Kafka advertised-topology
case is the moment where that is worth typing an unfamiliar command.

**LIMITATION.** Once svcdoctor names the stage, it almost always hands over. Reading all 61
unclassified recommendations: they are overwhelmingly *"Check the server's log"*, *"Review the
configuration"*, *"Compare X with Y."* svcdoctor reduces the search space and then stops — and it
does not currently even say **whether it could have looked itself**.

**MISSING MOMENT.** It becomes habitual the day its output is something a *pipeline* consumes
rather than a human reads once: when `report.json` says *this recommendation is an observation, it
is read-only, and you must take it — svcdoctor cannot*, an on-call runbook can route on it. Today
88% of recommendations are a sentence, and a sentence cannot be routed. **That is the moment G1
buys**, and it is why G1 outranks candidates that add claims.

## 17. Roadmap candidates

| ID | Title | Problem | Services | New evidence | Contract | Schema | Security | Compat | Impl | Valid | Search-space | Principal risk |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **C1** | Classify every recommendation | 61 of 69 codes carry unroutable prose; the ADR 0082 safety gate does not run | all 6 | none | additive only | **none** | **positive** — runs a gate that does not run | none | **M** | M | medium, compounding | 61 judgement calls; golden churn |
| **C2** | Recommendation for `DIAG_FAILURE_BOUNDARY` | the most-seen finding suggests nothing | all | none | additive | none | neutral | none | **S** | S | low–medium | saying something unhelpful |
| **C3** | CI coverage for the five uncovered suites | 20 codes + `run --config` guarded only by memory | Redis, RabbitMQ, fleet | none | none | none | neutral | none | **S/M** | M | none (protection) | runner cost, flake exposure |
| **C4** | Redis condition findings (`LOADING`, `MASTERDOWN`, `BUSY`) | one WARN code for five situations | Redis | none | +2 codes | none | neutral | none | **M** | M | medium (Redis only) | claiming about an unobserved primary |
| **C5** | Kubernetes `401` finding code | a rejected credential exits 0 | Kubernetes | none | +1 code | none | neutral | none | **S** | M | low | needs ADR 0094 §7 |
| **C6** | In-cluster active probing (K-E) | the thesis, applied inside a cluster | Kubernetes + all | **yes** | large | likely | needs review | new | **XL** | XL | high | scope explosion |
| **C7** | MySQL/MariaDB adapter | a sixth protocol | new | yes | large | none | new `Reveal` site | new | **XL** | L | high for MySQL users | breadth before depth |
| **C8** | Renderer sanitization of peer values | unbounded peer strings render verbatim | Redis, RabbitMQ, PG | none | none | none | positive | none | **S** | S | none | over-truncating a useful value |
| **C9** | Diagnostic planner | select the next observation | all | none | large | yes | neutral | none | **L** | L | unknown | §7 — its entry gate is unmeasurable |

## 18. Scoring

`MAINTENANCE COST` and `SCOPE RISK`: **5 = good** (low cost, low risk).

VALUE = OV×3 + DD×3 + CSL×2 + DIF×2 + AQ×3 + SF×2 + AF×3 + T×2 + MC×1 + SR×2 · max 115

| | OV | DD | CSL | DIF | AQ | SF | AF | T | MC | SR | **TOTAL** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **C1** classify recommendations | 4 | 3 | **5** | 4 | **5** | **5** | **5** | 5 | 4 | **5** | **97** |
| **C2** boundary recommendation | 3 | 2 | **5** | 3 | 4 | 5 | 5 | 5 | 5 | 5 | **86** |
| **C3** CI coverage | 2 | 1 | 4 | 1 | 5 | 5 | 5 | 4 | 3 | 4 | **72** |
| **C8** renderer sanitization | 2 | 1 | 4 | 1 | 5 | 5 | 4 | 5 | 4 | 5 | **73** |
| **C5** Kubernetes `401` code | 3 | 3 | 1 | 3 | 5 | 5 | 4 | 4 | 4 | 4 | **74** |
| **C4** Redis condition findings | 4 | 4 | 1 | 3 | 4 | 5 | 4 | 4 | 3 | 3 | **78** |
| **C7** MySQL adapter | 4 | 4 | 1 | 4 | 4 | 4 | 5 | 3 | 2 | 2 | **77** |
| **C6** in-cluster probing | 5 | 5 | 3 | 5 | 5 | 2 | 2 | 2 | 1 | 1 | **75** |
| **C9** planner | 3 | 5 | 4 | 4 | 2 | 4 | 3 | 2 | 2 | 2 | **70** |

**Weak dimensions, stated rather than hidden:**
- **C1** scores only 3 on Diagnostic Depth. **It adds no new claim about any target.** That is its
  honest ceiling and the reason it is not a 5.
- **C6** scores 5 on operator value and 1–2 on architectural fit, testability and scope risk. It is
  the most valuable *idea* and the least ready *phase*.
- **C7** scores 2 on maintenance cost: a sixth service is a permanent compatibility and CI burden.
- **C9**'s Authority Quality is 2 because §7 shows its input inventory does not exist yet.

## 19. Effort/value frontier

| Band | Candidates |
|---|---|
| **QUICK WIN** | **C2** (boundary recommendation), **C8** (sanitization) — both S, both with real operator or robustness value |
| **STRATEGIC** | **C1** (classification) — M, and it materially strengthens the product thesis by making the hand-over explicit and routable |
| **EXPERIMENT** | **C6** (in-cluster probing) — resolve scope before committing a phase |
| **DEFER** | C3, C4, C5, C7, C9 |
| **REJECT** | K-B, K-C, K-F, K-H, K-I, HTTP adapter, RabbitMQ management API under the current thesis |

## 20. The decision

### PRIMARY — C1: classify every recommendation across all services

**Why now.** The machinery is built, validated, redaction-safe, renderer-safe and proven on 8 codes
in three services including the newest. It needs no new evidence, no new probe, no new dependency,
no new finding code, no new rule and **no schema change** — the four fields are already `omitempty`
in v1 and released consumers reading `action` are unaffected. It is the only candidate in the set
that touches all six rule packages.

**Why before the runner-up (C4, Redis).** C4 benefits one service, adds finding codes, and would
land in the service with **no CI coverage** and no `docs/FINDINGS.md` entries. C1 benefits 61 codes
across six packages, adds none, and makes C4 easier to specify afterwards — because C4's
recommendations will be classified from the start rather than joining the backlog.

**What concrete incident becomes better.** Every one of §5's five cases. Today an on-call runbook
reading `report.json` gets `{"action": "Check that the endpoint accepts connections…"}` and cannot
tell an observation from a change, a safe step from a configuration edit, or a step svcdoctor could
have taken from one only a human can. After C1 it gets `kind`, `safety`, `rationale` and
`selfCollectable`, and can route on all four. That is the "missing moment" of §16.

**What svcdoctor becomes able to prove that it cannot today.** Strictly: nothing about a target.
**It gains the ability to state, per finding, what kind of action it is proposing, how disruptive
that action is, and whether it could have taken the observation itself** — and to have that
statement *checked* by ADR 0082's gate rather than left to prose. §3.3a shows five recommendations
that are target-mutating and unlabelled; that is the safety half.

**Smallest phase that tests the value.** One service. Classify all nine `REDIS_*` recommendations,
regenerate the goldens, and read the diff. If the classification decisions are contentious for nine,
they will be contentious for 61 — and that is worth learning on the smallest surface.

**Deliberately out of scope.** No new finding code. No new rule. No severity change. No claim
change. No `SelfCollectable: true` invented to make the planner look reachable — if the honest
answer is *"you must collect"* for all 61, that is the result, and it is the input §7 needs.

### SECONDARY — C3: CI coverage for the five uncovered suites

Redis, Valkey, RabbitMQ, LavinMQ and multi-target run in **no** CI lane — not the release gate, not
`validate-integration.yml`. That is 20 finding codes and the entire `svcdoctor run --config` path
protected only by a maintainer remembering the release checklist. It is cheap, it is pure
protection, and it covers exactly the two services C1 will be editing.

**Ordering note, stated honestly:** an argument exists for C3 *first*. C1's changes to Redis and
RabbitMQ rules are pure functions in the rule layer, fully covered by unit and golden tests, so the
integration gap does not materially raise C1's risk — but the two are close enough that running them
in either order is defensible.

### STRONGEST REJECTED ALTERNATIVE — C4, Redis condition findings

It loses on three measured grounds. The prefix is **already machine-readable** as
`redis.error_prefix` in canonical JSON, so the gain is severity differentiation rather than
consumability. It benefits **one** service against C1's six. And its authority is weakest exactly
where operator curiosity is highest — generic `ERR`, which Redis interpolates caller arguments into
and which the prior audit already ruled out as authority for anything.

It is a good candidate and it should be built. It is not the *next* one.

## 21. Recommended next phase

**Phase 13.1A — Recommendation classification contract freeze**

| | |
|---|---|
| **Type** | **CONTRACT FREEZE** (no production code) |
| **Question** | For each of the 61 unclassified recommendations: what is its `kind`, its `safety` class, its `rationale`, and is it `SelfCollectable`? And what happens to the five that are target-mutating? |
| **In scope** | A per-recommendation classification table; the policy for the five REMEDIATION-in-substance cases (classify as REMEDIATION, or rewrite as observations); whether `DIAG_FAILURE_BOUNDARY` gains one (C2); the `SelfCollectable: true` inventory that §7 needs; a decision on whether any recommendation is `SECURITY_WEAKENING` and must therefore be rewritten rather than classified |
| **Out of scope** | New finding codes, new rules, severity changes, claim changes, schema changes, the planner, Redis/RabbitMQ intelligence, any new adapter |
| **Expected production impact** | **zero in 13.1A.** In 13.1B: `internal/diagnosis/*` only; goldens regenerate; `SchemaVersion` stays 1 |
| **Required validation** | `make check`; the seven help goldens and all terminal goldens read rather than blind-updated; a guard that every production recommendation is classified, with a non-vacuity proof; mutation over the classification map |
| **Stop conditions** | A recommendation whose only honest class is `SECURITY_WEAKENING` (it must be rewritten, and that is a claim change needing its own phase); a classification that would require `NewClassifiedRecommendation` to relax a refusal; discovering that a recommendation's finding is not CONFIRMED/HIGH and therefore cannot carry the REMEDIATION it implies |

It is a contract freeze rather than an implementation phase because the five target-mutating
recommendations are an ADR 0082 policy question, not a mechanical edit.

## 22. Backlog triage

| Item | Verdict |
|---|---|
| `docs/FINDINGS.md` has no entry for any of the nine `REDIS_*` codes | **KEEP** — becomes a prerequisite for C4 |
| Renderer sanitization of unbounded observation values | **KEEP** — C8, quick win, still open (Redis `server_version` bounded only by a 64 KiB reply ceiling) |
| A Kubernetes target exits 0 whatever it observed | **KEEP** — C5; needs ADR 0094 §7 |
| Thirty-eight recorded evidence attributes consumed by nothing | **KEEP as recorded, not debt** — Phase 10.8A's judgement is confirmed by this audit |
| Declared operational intent (expected role, expected posture) | **KEEP** — still the blocker for every role finding in PostgreSQL and Redis |
| Phase 11.0 planner deferral | **KEEP DEFERRED**, with §7's sharper reopen condition |
| Phase 10.5A relation deferral | **KEEP DEFERRED**, with §8's note that the `AuthorityCompleteContrast` half is now armed |
| `Origin` / provenance | **KEEP DEFERRED** — its named consumer is a planner, which §7 defers |
| Generic TLS client certificates (mTLS) | **KEEP** — unchanged |
| `test/security/dependency_test.go`'s stated principle vs client-go | **ALREADY RESOLVED** — the principle was amended in 12.1B, not merely the number |
| Cross-page `continue` consistency could not be verified | **OBSOLETE** — verified in 12.1B; superseded by the later entry |
| **CI coverage gap for Redis/Valkey/RabbitMQ/LavinMQ/multi-target** | **NEW — DO NEXT (secondary)**; not currently a backlog item |
| **61 of 69 recommendations unclassified** | **NEW — DO NEXT (primary)**; not currently a backlog item |

## 23. ADR decision — one ADR

This audit establishes a **durable product boundary**, not merely a build order. Every scope
question it answered — K-B through K-I, the RabbitMQ management API, HTTP, cluster discovery — was
decided by the same test, and that test has never been written down as a decision. §26's criterion
is met: the thesis is what a future phase needs, and "build C1 next" is not.

**ADR 0096 — the client-vantage product boundary** is created. It freezes the thesis, the authority
boundary (what may be treated as authority, and that unbounded peer prose may not), and the scope
test that decides adapter and capability proposals. It deliberately does **not** freeze the
recommendation-classification contract — that is Phase 13.1A's own record.

## 24. Validation

| | Result |
|---|---|
| `make check` | **GREEN** (before and after) |
| `git diff --check` | **CLEAN** |
| Documentation and claim guards | `TestUX22TheSupplyChainPinningIsRecorded`, `TestOnlyRealTestedPlatformsClaimLevelTwoOrThree`, `TestEveryRealTestedPlatformSaysSo`, `TestNoDocument*`, `TestTheREADME*`, `TestTheReleaseCeremonyIsDocumented` — **all PASS** |
| `go test ./test/security/...` | **PASS** |

**Omitted, and why:** real-cluster suites, mutation suites, fuzz and `-race`. No Go file, workflow,
fixture or Makefile target changed, so each would re-measure code that did not move. One live
`svcdoctor diagnose postgres` run was executed (§5.2) as evidence about *output*, not as validation.

## 25. Changed files

| File | Class |
|---|---|
| `docs/validation/PHASE130_PRODUCT_DIAGNOSTIC_ROADMAP_AUDIT.md` | **DOCUMENTATION** (new) |
| `docs/decisions/0096-client-vantage-product-boundary.md` | **ADR** (new) |
| `docs/decisions/README.md` | **ADR** (index) |
| `docs/BACKLOG.md` | **DOCUMENTATION** |

**Production 0 · Test 0 · CI 0 · Config 0 · Generated 0 · Unexpected 0.**
