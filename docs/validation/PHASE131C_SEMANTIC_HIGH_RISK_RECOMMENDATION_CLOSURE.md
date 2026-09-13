# Phase 13.1C — Semantic and high-risk recommendation closure

- **Phase:** 13.1C — the semantic half of the recommendation migration. **Meaning, not metadata**,
  which is the exact inverse of 13.1B
- **Baseline:** `5419f0c027ac9f27319129aaf4d7fa6f6ada4665`, `HEAD == origin/main`, clean tree,
  `make check` green before anything was edited
- **Contract:** ADR **0097** (§2.1 every production recommendation is classified, §2.2 REMEDIATION
  has no producer), ADR **0082** (the vocabulary and the three refusals), ADR **0096** §2.2 (the
  scope test), and `docs/validation/PHASE131A_RECOMMENDATION_CLASSIFICATION_CONTRACT_FREEZE.md` §8,
  whose high-risk table prescribed **REWRITE_AND_CLASSIFY for all nine**
- **Result:** **73 recommendations, 73 classified, 0 legacy.** Nine rewritten, 64 byte-identical.
  **0 production legacy constructors**, 0 REMEDIATION, 0 CONFIG_CHANGE, 0 RESTART, 0 DISRUPTIVE,
  0 SECURITY_WEAKENING
- **Open blockers:** none

---

## 1. Baseline and pre-state

```
HEAD        5419f0c027ac9f27319129aaf4d7fa6f6ada4665  feat(diagnosis): classify mechanical recommendations
origin/main 5419f0c027ac9f27319129aaf4d7fa6f6ada4665
tree        clean
make check  GREEN
```

## 2. Pre-state inventory, re-measured from source

Measured before editing, from the AST and from the guards that derive their numbers rather than
assert them. **Every figure matched the phase brief's expectation**, which is why the phase
proceeded rather than stopping at §52's first condition.

| Fact | Pre | Post |
|---|---:|---:|
| Finding codes | **69** | **69** |
| Production rules | **24** | **24** |
| Failure classes | **42** | **42** |
| `SchemaVersion` / `RunSchemaVersion` | **1 / 1** | **1 / 1** |
| Semantic recommendations (constants) | **73** | **73** |
| Structured | **64** | **73** |
| Legacy (unclassified) | **9** | **0** |
| `NEXT_EVIDENCE` | 64 | **73** |
| `REMEDIATION` producers | **0** | **0** |
| `CONFIG_CHANGE` / `RESTART` / `DISRUPTIVE` / `SECURITY_WEAKENING` producers | **0** | **0** |
| Production `domain.NewRecommendation` callers under `internal/diagnosis/**` | **5 helpers in 4 packages** | **0** |
| Recommendations with an empty rationale | 9 (the unclassified ones) | **0** |
| Silently dropped by admission | **0** | **0** |

**The nine deferred recommendations were exactly the frozen set** — REC-012, 021, 031, 034, 036,
052, 055, 064, 067 — read from the corpus rather than from the brief.

**Safety distribution after:** OBSERVE **38**, VERIFY **20**, COMPARE **15**, everything else
**0**. `SelfCollectable` true **2**, false **71**, absent **0**.

## 3. The authority test, applied to all nine

ADR 0097 §2.2 and Phase 13.1A §8.1, in one sentence:

> svcdoctor proved the broker refused this user's access to this virtual host.
> It did **not** prove the refusal was wrong.

Each of the nine was put through the brief's four questions. **Question 3 — does it tell the
operator to change something svcdoctor has not established should be changed? — answered YES for
five of them outright**, and Question 4 — would two valid operator policies give two different
correct remediations? — answered YES for the same five plus two more. The remaining two were
ambiguous rather than mutating: one asked the reader to redo a measurement already in the report,
the other could be read as *change a password* as easily as *choose another role*.

**None required new evidence to become truthful, and no finding had to change**, which is what kept
the phase inside §22 and §23.

## 4. Two shapes the rewrites took

**Name svcdoctor's own options, not the server's configuration.** The three credential-withheld
sentences (REC-012, REC-031, REC-052) all described a channel that did not verify the peer, and all
three could be read as *configure TLS on the server*. The finding is about **svcdoctor's own
refusal** — `detailCredentialWithheld` already says *"This is svcdoctor's own refusal, not an
observation of the endpoint"* — so the honest action names this run's inputs. RabbitMQ's REC-062,
reviewed and classified in Phase 13.1B, already had exactly this shape and is the model.

`ValidateActionText` permits a **double-hyphen** token deliberately, and documents why: it is
svcdoctor naming one of its own options, which is documentation about the diagnostic tool rather
than a change to make on the target. Single-hyphen flags and shell metacharacters stay refused.

**Verify the intent, do not prescribe the policy.** The two access refusals (REC-055, REC-067) and
the two mechanism cases (REC-034, REC-064) each proved a *state*. The rewrite asks whether that
state is intended — which is the question the evidence actually leaves open — instead of naming the
grant or the configuration change that would remove it.

## 5. Before and after, all nine

Action text is byte-frozen per constant by SHA-256. These nine digests moved; the other 64 did not.

| REC | Old | New |
|---|---|---|
| **REC-012** | Establish verified TLS to this endpoint, or review the trust context this run used, then re-run | Use --tls require with a trusted certificate chain, or supply --tls-ca-file, so this broker's identity is verified before a credential crosses to it |
| **REC-021** | Check whether the advertised hostname resolves from this vantage point, and what the broker publishes in advertised.listeners | Compare the name this broker publishes in advertised.listeners with the names resolvable from this network position |
| **REC-031** | Establish a verified TLS channel to this endpoint before presenting a credential, or re-run with the transport policy this run is meant to use | Use --tls require with a trusted certificate chain, or supply --tls-ca-file, so this endpoint's identity is verified before a password crosses to it |
| **REC-034** | Diagnose this endpoint with a client that performs the authentication method it demands, **or configure a mechanism svcdoctor performs for the role this run used** | Diagnose this endpoint with a client that performs the authentication method it demands |
| **REC-036** | Re-run against a role whose password is printable ASCII, or diagnose this endpoint with a client that implements the full mechanism | Re-run this diagnosis against a role whose password is **already** printable ASCII, or diagnose this endpoint with a client that implements the full mechanism |
| **REC-052** | Enable TLS for this endpoint and supply the trust material that verifies it, then run again | Use --tls require with a trusted certificate chain, or supply --tls-ca-file, so this endpoint's identity is verified before a credential is presented |
| **REC-055** | **Grant** the diagnostic identity permission to run PING, or diagnose with an identity that already has it | **Verify whether** this identity is intended to run PING, or diagnose with an identity that already has it |
| **REC-064** | **Enable SASL PLAIN on this endpoint**, or diagnose it with a client that implements the mechanisms it offers | Diagnose this endpoint with a client that implements one of the mechanisms it offers |
| **REC-067** | Grant this user permissions on the virtual host, for example with `rabbitmqctl set_permissions` | Verify whether this identity is intended to have access to this virtual host, in the broker's own permissions configuration |

**0 removed.** Every one of the nine had a bounded observation worth stating once the policy clause
came off, so §21's removal path was available and unneeded. Nothing was replaced with filler:
no retained action says *investigate further*, *check configuration* or *contact administrator*.

## 6. Per-recommendation decisions

### REC-012

- **SERVICE:** Kafka · **FINDING CODE:** `KAFKA_CREDENTIAL_WITHHELD` (CONFIRMED, WARN, HIGH, L5,
  vantage-dependent) · **AUTHORITY:** direct, over svcdoctor's own policy
- **DIRECTLY PROVES:** a credential was configured, the broker asked for authentication, and
  svcdoctor's credential-transport policy refused to write it because the channel this path
  established did not verify the broker's identity. Zero bytes were sent.
- **DOES NOT PROVE:** anything about the broker; whether it offers TLS; what the intended transport
  policy is; whether the credential would have been accepted.
- **OLD ACTION MODE:** AMBIGUOUS · **POLICY OVERCLAIM:** NO · **SECURITY SENSITIVE:** YES
- **DECISION:** REWRITE_AND_CLASSIFY · **KIND:** NEXT_EVIDENCE · **SAFETY:** OBSERVE ·
  **SELFCOLLECTABLE:** false
- **RATIONALE:** *"svcdoctor refused to write the credential because the channel this path
  established did not verify the broker's identity, so nothing was sent and the broker took no
  position on it; what a verified channel would have produced is the observation this run did not
  take."*
- **WHY AUTHORITY-BOUNDED:** every token names one of svcdoctor's own options. The claim stops at
  what this run did.
- **WHY IT DOES NOT PRESCRIBE POLICY:** it asks for nothing on the broker. It does not say the
  broker should offer TLS, nor that this endpoint's current transport is wrong.

### REC-021

- **SERVICE:** Kafka · **FINDING CODE:** `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` at the DNS layer
  (CONFIRMED or HYPOTHESIS) · **AUTHORITY:** direct
- **DIRECTLY PROVES:** the advertised name did not resolve to a usable address from this host's
  resolver.
- **DOES NOT PROVE:** which names the broker's listener configuration was written to publish, or
  which network position the advertisement was written for.
- **OLD ACTION MODE:** OBSERVE, but its first clause asked the reader to **redo a measurement
  svcdoctor had already taken and recorded** · **POLICY OVERCLAIM:** NO · **SECURITY SENSITIVE:** NO
- **DECISION:** REWRITE_AND_CLASSIFY · **KIND:** NEXT_EVIDENCE · **SAFETY:** COMPARE ·
  **SELFCOLLECTABLE:** false
- **RATIONALE:** *"svcdoctor asked this host's resolver for the advertised name and was given no
  address it could use, so the name and this network position are the two halves; which of them the
  advertisement was written for is held in the broker's own listener configuration."*
- **WHY AUTHORITY-BOUNDED:** it names the one half svcdoctor does not hold and drops the half it
  does. `advertised.listeners` is read, never set.
- **WHY IT DOES NOT PRESCRIBE POLICY:** it does not say what the advertisement should be. A name
  resolvable only inside the cluster may be exactly what its author intended.

### REC-031

- **SERVICE:** PostgreSQL · **FINDING CODE:** `POSTGRES_CREDENTIAL_WITHHELD` (CONFIRMED, WARN,
  HIGH, L5) · **AUTHORITY:** direct, over svcdoctor's own policy
- **DIRECTLY PROVES:** no credential material was sent, because this run's policy requires a
  verified TLS channel before a password crosses it.
- **DOES NOT PROVE:** anything about the endpoint; no refusal took place.
- **OLD ACTION MODE:** AMBIGUOUS · **POLICY OVERCLAIM:** NO · **SECURITY SENSITIVE:** YES
- **DECISION:** REWRITE_AND_CLASSIFY · **KIND:** NEXT_EVIDENCE · **SAFETY:** OBSERVE ·
  **SELFCOLLECTABLE:** false
- **RATIONALE:** *"svcdoctor sent no credential material because this connection did not verify the
  endpoint's identity, so no refusal took place and nothing is known about the credential; what a
  verified channel would have produced is the observation this run did not take."*
- **WHY AUTHORITY-BOUNDED / NOT POLICY:** as REC-012. It names `--tls` and `--tls-ca-file` and
  touches nothing on the server. It does **not** name `--tls-insecure`, which would be the security
  weakening §9 forbids.

### REC-034

- **SERVICE:** PostgreSQL · **FINDING CODE:** `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE`
  (CONFIRMED, INFO on this branch, HIGH, L5, vantage-dependent) · **AUTHORITY:** direct
- **DIRECTLY PROVES:** the endpoint demanded an authentication method svcdoctor does not perform,
  and no credential was presented.
- **DOES NOT PROVE:** that the endpoint's authentication configuration is wrong, or that the
  operator's own client cannot authenticate.
- **OLD ACTION MODE:** MUTATE · **POLICY OVERCLAIM:** YES · **SECURITY SENSITIVE:** YES
- **DECISION:** REWRITE_AND_CLASSIFY — the second clause dropped · **KIND:** NEXT_EVIDENCE ·
  **SAFETY:** OBSERVE · **SELFCOLLECTABLE:** false
- **RATIONALE:** *"The endpoint demanded an authentication method svcdoctor does not perform and no
  credential was presented, so this states the tool's coverage and nothing about the endpoint; what
  a client performing that method would observe is still open."*
- **WHY AUTHORITY-BOUNDED:** it asks for a different **client**, which is a change to the diagnosis
  and not to the target.
- **WHY IT DOES NOT PRESCRIBE POLICY:** the removed clause **inverted the product** — it asked the
  server to reconfigure its authentication so that the diagnostic tool could authenticate. The
  finding's own detail already says svcdoctor is the limited party.

### REC-036

- **SERVICE:** PostgreSQL · **FINDING CODE:** `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR`
  (CONFIRMED, INFO, HIGH, L5, vantage-dependent) · **AUTHORITY:** direct, over svcdoctor's own
  defensive bounds
- **DIRECTLY PROVES:** svcdoctor declined on its own bounds — printable-ASCII passwords, a bounded
  iteration count, bounded SCRAM message sizes. The credential was neither accepted nor rejected.
- **DOES NOT PROVE:** that the endpoint's message was invalid. ADR 0038's limitation is svcdoctor's.
- **OLD ACTION MODE:** AMBIGUOUS — *"Re-run against a role whose password is printable ASCII"* reads
  as **change a password** as easily as **choose another role**, and the two differ in kind ·
  **POLICY OVERCLAIM:** NO · **SECURITY SENSITIVE:** YES (a password change is a credential
  operation)
- **DECISION:** REWRITE_AND_CLASSIFY · **KIND:** NEXT_EVIDENCE · **SAFETY:** OBSERVE ·
  **SELFCOLLECTABLE:** false
- **RATIONALE:** *"svcdoctor declined on its own defensive bounds rather than on anything the
  endpoint did, and the credential was neither accepted nor rejected; which role this run uses and
  which client performs the mechanism are both inputs this run was given."*
- **WHY AUTHORITY-BOUNDED:** *"already printable ASCII"* settles the reading on **selection** of an
  existing role. svcdoctor never suggests changing a credential.

### REC-052

- **SERVICE:** Redis/Valkey · **FINDING CODE:** `REDIS_CREDENTIAL_WITHHELD` (CONFIRMED, WARN, HIGH,
  L5, vantage-dependent) · **AUTHORITY:** direct, over svcdoctor's own policy
- **DIRECTLY PROVES:** svcdoctor presents a credential only over a channel whose peer identity was
  verified, and this one was not, so nothing was sent.
- **DOES NOT PROVE:** whether this endpoint offers TLS, or whether plaintext here is intended.
- **OLD ACTION MODE:** MUTATE — *"Enable TLS for this endpoint"* is unambiguously a server
  configuration change · **POLICY OVERCLAIM:** YES · **SECURITY SENSITIVE:** YES
- **DECISION:** REWRITE_AND_CLASSIFY — the whole sentence replaced, because the mutating clause
  *was* the sentence · **KIND:** NEXT_EVIDENCE · **SAFETY:** OBSERVE · **SELFCOLLECTABLE:** false
- **RATIONALE:** *"svcdoctor presents a credential only over a channel whose peer identity was
  verified, and this one was not, so nothing was sent and the endpoint took no position; what a
  verified channel would have produced is the observation this run did not take."*
- **WHY IT DOES NOT PRESCRIBE POLICY:** an operator running Redis on a trusted internal segment may
  have decided against TLS deliberately. svcdoctor's refusal is svcdoctor's, and the new sentence
  says so.

### REC-055

- **SERVICE:** Redis/Valkey · **FINDING CODE:** `REDIS_COMMAND_NOT_PERMITTED` (CONFIRMED, WARN,
  HIGH, L5) · **AUTHORITY:** direct — the endpoint answered `NOPERM`
- **DIRECTLY PROVES:** this identity was refused **one keyless command**.
- **DOES NOT PROVE:** that the ACL is wrong, that this identity should have the permission, or that
  the application's own commands would be refused. The finding's detail already says the last part.
- **OLD ACTION MODE:** MUTATE · **POLICY OVERCLAIM:** YES · **SECURITY SENSITIVE:** YES — it asked
  to broaden an authorization
- **DECISION:** REWRITE_AND_CLASSIFY — first clause becomes verification of intent, second survives
  unchanged · **KIND:** NEXT_EVIDENCE · **SAFETY:** VERIFY · **SELFCOLLECTABLE:** false
- **RATIONALE:** *"The endpoint refused one keyless command for one identity and that may be
  exactly what its ACL was written to do, so whether this identity was meant to run it is an intent
  the refusal itself cannot state."*
- **WHY IT DOES NOT PRESCRIBE POLICY:** *"the ACL may be doing exactly what its author wrote"* is
  the whole argument, and the rationale says it to the operator rather than only in this record.

### REC-064

- **SERVICE:** RabbitMQ/LavinMQ · **FINDING CODE:** `RABBITMQ_AUTH_MECHANISM_NOT_OFFERED`
  (CONFIRMED, ERROR, HIGH, L5) · **AUTHORITY:** direct
- **DIRECTLY PROVES:** the endpoint offered no mechanism svcdoctor implements, and **no credential
  was sent**.
- **DOES NOT PROVE:** that the endpoint is misconfigured. Its own detail says it is behaving
  correctly and svcdoctor is the limited party.
- **OLD ACTION MODE:** MUTATE · **POLICY OVERCLAIM:** YES · **SECURITY SENSITIVE:** YES — *"Enable
  SASL PLAIN on this endpoint"* carried **no TLS condition**
- **DECISION:** REWRITE_AND_CLASSIFY — first clause dropped · **KIND:** NEXT_EVIDENCE ·
  **SAFETY:** OBSERVE · **SELFCOLLECTABLE:** false
- **RATIONALE:** *"svcdoctor performs PLAIN only and sent no credential, so this states the tool's
  coverage and not a fault in the endpoint; whether a credential would be accepted here is something
  only a client implementing an offered mechanism can establish."*
- **WHY IT DOES NOT PRESCRIBE POLICY:** the sharpest of the nine. **ADR 0068 forbids svcdoctor from
  sending PLAIN without verified TLS**, so the old sentence recommended a change that svcdoctor's
  own policy would then have refused to act on — it asked an operator to weaken a listener for a
  client that would still decline to use it.
- **A bounded comparison was considered and refused.** §11 of the brief prefers *compare the
  client's mechanism with the endpoint's*, but svcdoctor already holds both halves — it recorded the
  offered list and it knows it performs PLAIN — so that sentence would repeat REC-021's original
  defect of asking for a measurement already in the report.

### REC-067

- **SERVICE:** RabbitMQ/LavinMQ · **FINDING CODE:** `RABBITMQ_VHOST_ACCESS_REFUSED` (CONFIRMED,
  ERROR, HIGH, L5) · **AUTHORITY:** direct — the broker authenticated the credential and then
  refused the virtual host
- **DIRECTLY PROVES:** the credential was **accepted**, and access to this virtual host for this
  identity was denied.
- **DOES NOT PROVE:** that the denial is wrong, what permission should exist, or anything about what
  the identity may do *inside* the virtual host — svcdoctor opens no channel and names no resource.
- **OLD ACTION MODE:** MUTATE · **POLICY OVERCLAIM:** YES · **SECURITY SENSITIVE:** YES — a
  privilege grant, **naming an administrative command**
- **DECISION:** REWRITE_AND_CLASSIFY — *"the strongest case in the table"* · **KIND:**
  NEXT_EVIDENCE · **SAFETY:** VERIFY · **SELFCOLLECTABLE:** false
- **RATIONALE:** *"The broker accepted the credential and then refused this virtual host, which is
  an authoritative refusal and not evidence that the refusal is wrong; whether this identity was
  meant to reach this virtual host is an intent held in the broker's own configuration."*
- **WHY AUTHORITY-BOUNDED:** it names a read-only administrative *view*, which §10 of the brief
  names as the preferred shape, and no command.
- **WHY IT DOES NOT PRESCRIBE POLICY:** ADR 0082 rule 3 says *state what to look at, not what to
  type*. The old sentence typed, and passed `ValidateActionText` only because `rabbitmqctl
  set_permissions` happens to carry no single-hyphen flag. **The validator was not widened; the
  sentence was replaced**, which is what ADR 0097 §5 said would happen.

## 7. Security review

| Question | Answer |
|---|---|
| Does any retained action instruct a change to the diagnosed target? | **No** — 73 checked, structurally |
| Does any retained action weaken security? | **No.** Nothing disables verification, lowers a TLS floor, broadens an authorization or enables plaintext authentication. **`--tls-insecure` is named by no recommendation at all** |
| Does any retained action assume organizational policy? | **No** — the four that touch policy ask whether the observed state is *intended* |
| Was a mutating sentence relabelled rather than rewritten? | **No.** REC-052 and REC-067 had their whole sentence replaced; REC-034 and REC-064 had the mutating clause removed. None was softened into *"consider enabling …"*, which §8 names as still being mutation advice |
| `REMEDIATION` producers | **0**, unchanged and guarded by an AST scan for the identifier |
| `SECURITY_WEAKENING` / `RESTART` / `DISRUPTIVE` producible | **No** — `Producible()` still refuses all three |
| Secrets, credentials, raw peer text or runtime errors in any new action or rationale | **None.** Every one is a package constant with no format verb |
| Rationale redacted like the action | **Yes**, through the same `t.text()` transformation; pinned, and mutation MC-13 proves the pin fires |

`go test ./test/security/... ./internal/security/...` — **all ok**. No security guard was weakened.

## 8. Zero-legacy proof

`TestNoProductionRuleBuildsAnUnclassifiedRecommendation` walks every production file in every
package under `internal/diagnosis`, derived from `allProductionPackages` so a new rule package
cannot escape it, and matches the **call expression** rather than the bytes:

```
47 production files across 7 rule packages build no unclassified recommendation
```

Five legacy helpers were **deleted**, not left unused: `kafka/protocol.go`, `postgres/shared.go`,
`redis/shared.go`, `rabbitmq/shared.go` and PostgreSQL's `mechanismAdvice`, the dispatcher that
chose between classified and unclassified construction. Kafka's `claim.recommendations()` and
`recommendation.go`'s layer loop lost their `SafetyUnspecified` branches with them, so the mixed
classified/unclassified recommendation list `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` used to carry
is now **unreachable** rather than merely unused.

`domain.NewRecommendation` itself is kept, per ADR 0097 §2.1: `internal/security/redaction` rebuilds
an unclassified recommendation through it.

## 9. Temporary debt removed

§26 asked for deletion rather than emptying, and all four went:

| Removed | Was |
|---|---|
| `legacyRecommendationSites` + `TestLegacyRecommendationConstructionIsBoundedToTheNine` | the shrink-only allowlist: 4 packages, 9 named `REC-` identifiers, pinned three ways |
| `deferredActions` (test/diagnosis) | a nine-entry exemption keyed by action text |
| five per-package `*Deferred` maps and the `deferred` parameter of `assertFrozenClassification` | the wiring guards' exemption |
| `groupS` | the corpus's third migration group |

Nothing reads *"expected legacy recommendations = []"*. `groupS` became `rewritten`, carrying the
**new** digests, so one table proves both *these nine moved* and *those 64 did not*.

## 10. The structural guards, and the verb that could not be one

**`TestTheRewrittenRecommendationsAreTheFrozenOnes`** is the primary proof: the nine new sentences
pinned byte for byte, keyed by package-qualified constant — not by finding code, because three of
the nine share a code with a recommendation 13.1B had already classified. It also scans the whole
corpus for the nine **retired** strings, so reintroducing one under a different constant name is a
named failure rather than a digest mismatch.

**`TestNoProductionRecommendationInstructsATargetMutation`** is supplemental, so that a *new*
recommendation is refused on the day it is written. Two findings are worth keeping:

- **It reads clause openings, not the whole string.** The obvious implementation has a false
  positive already in the tree: Kafka's `recommendUnsupportedExchange` ends *"this is a gap in
  svcdoctor rather than something to change on the cluster"*, which is a **refusal** to recommend a
  change. Phase 12.1D found the same class of defect in a guard that matched `"clu"` inside *"the
  cluster"*.
- **`establish` is not on the list, and that is the honest limit.** It was, and it flagged two
  correct Phase 13.1B recommendations — *"…and establish what this broker is before presenting the
  credential again"* — where the verb means *determine*, not *set up*. That ambiguity is exactly
  why REC-012 and REC-031 needed rewriting by hand. A keyword rule cannot decide whether prose
  prescribes policy, which is why the byte pin is primary and this is not.

The rule refuses **5 of the 9** retired sentences on its own; the pin covers all nine. Both have
non-vacuity companions.

## 11. Service-specific review

**Kafka.** REC-012 is a policy refusal, REC-021 an advertised-topology observation. The D4
semantics are untouched: no hypothesis pair, discriminator, reachability count, suitability claim,
convergence rule or completeness semantic moved. `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` still
carries the only self-collectable recommendation in the package.

**PostgreSQL.** No SQL was added and none is executed. Nothing infers a desired `pg_hba` policy, a
role grant, a TLS configuration or a connection limit from a rejection. The role/recovery
observation, admission-scope semantics, connection-limit finding, `ParameterStatus`-only role
evidence and host/IP contrast are all unchanged.

**Redis/Valkey.** No new condition finding. `LOADING`, `MASTERDOWN`, `BUSY`, `OOM`, `MOVED`, `ASK`,
`READONLY`, persistence and replication remain unimplemented roadmap work, and arbitrary Redis
`ERR` prose is still insufficient authority for a specific diagnosis.

**RabbitMQ/LavinMQ.** Everything stays inside AMQP 0-9-1 direct endpoint authority. No management
API, topology discovery, cluster diagnosis, queue or exchange inspection, operator API or
`rabbitmqctl` execution. **No `rabbitmqctl set_permissions`-style instruction survives anywhere.**

## 12. Finding contract, acquisition, schema and exit behaviour

**Mechanically checked, not asserted:** the production diff over `internal/diagnosis/**` contains
**zero** changed lines matching `Code:`, `Kind:`, `Severity:`, `Confidence:`, `Layer:`, `Subject:`,
`Summary:`, `Detail:`, `EvidenceRefs:`, `VantageDependent:`, `Discriminator:` or any `summary*` /
`detail*` constant. Only recommendation constants, rationale constants and the call sites that pass
them moved.

| | |
|---|---|
| Finding codes | 69 → **69** |
| Rules | 24 → **24** |
| Failure classes | 42 → **42** |
| `SchemaVersion` / `RunSchemaVersion` | 1 / 1 → **1 / 1** |
| Diagnostic claims | **unchanged** |
| Exit behaviour | **unchanged** — no severity, status or precedence moved, and a recommendation reaches none of them |
| Acquisition | **unchanged** — no probe, adapter, wire package, `internal/app` or `internal/fleet` file touched |
| Renderer source | **unchanged** — 0 files |
| Dependencies, `go.mod`, `go.sum`, CI | **unchanged** |

**Canonical JSON:** `action`, `kind`, `safety`, `rationale` and `selfCollectable` serialize exactly
as before. The nine gain `kind`/`safety`/`rationale`/`selfCollectable` where they were absent, which
is field population at schema version 1, not evolution. No recommendation was removed, so there is
no empty or invalid recommendation object anywhere.

## 13. Convergence

The deduplication key remains the **whole five-field value**. `TestRecommendationsCollapseOnlyOnFullSemanticEquality`,
`TestTheRecommendationUnionIsOrderInvariant`, `TestP10ConvergenceIsCommutativeAndAssociative`,
`TestC01`–`TestC08` and `TestClassifyingOneConstantOnceKeepsConvergenceNeutral` all pass.

One shape genuinely changed and it is a **narrowing**: `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` used
to emit a mixed list — a classified TCP/TLS sentence beside an unclassified DNS one. All three are
now classified, so the list is uniform. Because dedup keys on the whole value and the three actions,
safety classes and rationales all differ, the members that collapsed before still collapse and the
ones that did not still do not. **MC-15 proves a second classification for one constant is caught.**

## 14. Fixtures and goldens

**Zero fixture changes, and the reason is structural rather than lucky.** All three fixture classes
were inspected (the taxonomy is `PHASE131A…` §11.2 as corrected by Phase 13.1A.1):

| Class | Carries a production recommendation constant? | Effect |
|---|---|---|
| `test/golden/testdata/*.json` (6) | no — hand-built `NewRecommendation("Check that the service is listening on this port")`, a string in no production file | **unchanged** |
| `internal/render/terminal/testdata/*.txt` (19) | no — findings hand-built with `"Check the thing the finding names"` | **unchanged** |
| `internal/cli/testdata/*.txt` (8) | yes — real runs through the real CLI | **unchanged** |

The third needed checking rather than assuming, because 13.1B moved five of those eight. **Four
terminal goldens do carry two of the nine findings' codes** — `kafka-credential-withheld.txt`,
`kafka-advertised-unreachable.txt`, `kafka-advertised-partial.txt`, `kafka-shareable.txt` — and
still did not move, because they render the synthetic placeholder rather than the production
constant. The CLI fixtures reach none of the nine codes at all.

Production wiring for all nine is proven by the five per-package matrices instead, which drive every
producible outcome and assert the classification that arrives on the recommendation a rule really
built.

## 15. Output bound

| | |
|---|---|
| Bound `knownWidest` | **285**, unchanged — not raised, not disabled; `internal/cli/releaseux_test.go` is not in the diff |
| Widest emitted line | **281** columns, unchanged |
| Widest line the nine can produce | **272** columns (`kafka/rationaleCredentialWithheld`, 266 chars + 6 indent) |
| Longest new action + widest tag | **200** columns |

Every one of the nine new rationales renders under the bound. The two longest rationale constants in
the tree, at 317 and 315 characters, are pre-existing from Phases 10.3 and 10.4B and were not
touched.

## 16. Validation performed

| | Result |
|---|---|
| `make check` | **GREEN** before and after |
| `git diff --check` | **CLEAN** |
| `go test -race` over `internal/diagnosis/...`, `internal/domain/...`, `internal/render/...`, `internal/security/...`, `test/diagnosis`, `test/security` | **all ok** |
| Phase 13.1C mutation suite | **15 planted / 15 caught / 0 survivors** |
| Mutation restoration | **independently verified** — see §17 |
| `phase104b` | **17 / 17 / 0** (after the NBE-M17 re-anchor, §18) |
| `phase102` | **25 / 25 / 0** |
| `phase102a` | **8 / 8 / 0** |
| `phase103` | **27 / 27 / 0** |
| `phase101b` | **21 / 21 / 0** |

**Fuzz: omitted, with justification.** No domain constructor, serializer, parser, wire path or
input-handling helper changed. The diff is recommendation constants, rationale constants and the
call sites that pass them; the existing fuzz targets cover `domain.Recommendation` construction and
validation, which this phase did not touch. Claiming fuzz coverage for a run that would re-measure
unmoved code would be dishonest.

**Integration: omitted, with justification.** No acquisition, protocol, adapter or wire change, so
no real service can observe a difference. The wiring that *did* change is exercised hermetically by
the five per-package producer matrices, which drive every producible outcome of every rule — which
is stronger coverage for the nine than any integration fixture, because no integration fixture
reaches them either.

## 17. Mutation closure — 15 planted / 15 caught / 0 survivors

```
MC-01 a production rule builds an unclassified recommendation again
MC-02 a retained NEXT_EVIDENCE becomes a REMEDIATION
MC-03 a retained safety class becomes CONFIG_CHANGE
MC-04 the one frozen SelfCollectable:true is dropped
MC-05 a rewritten recommendation loses its rationale
MC-06 a retired target-mutating action comes back
MC-07 one of the 64 mechanically frozen actions changes
MC-08 a helper wraps the unclassified constructor under another name
MC-09 a classification is invalid, so the recommendation is silently dropped
MC-10 a Phase 13.1C action changes without its pin
MC-11 SECURITY_WEAKENING reaches a production rule
MC-12 a production call site stops passing its classification
MC-13 redaction stops transforming the rationale
MC-14 the unclassified constructor is reached through an aliased import
MC-15 one constant is given two classifications
```

The harness is committed as `scripts/phase131c-mutations.sh`, which is the reproducibility mistake
Phase 13.1B made and this phase does not repeat.

### 17.1 The first run caught 14 of 15, and the survivor was real

**MC-14 survived**, and it was a genuine gap in the guard this whole phase rests on.
`callsUnclassifiedConstructor` matched a selector whose package identifier was literally `domain`.
An aliased import —

```go
import dom "github.com/hakanaltindag/svcdoctor/internal/domain"
...
r, err := dom.NewRecommendation(action)
```

— evaded it completely. Nothing about that plant is exotic: this repository already imports packages
under an alias in a dozen places, `servicekafka` among them. **Renaming an import would have
silenced the zero-legacy invariant.**

The detector now **resolves the import path** and collects every local name bound to the domain
package, including a dot import, which would put the constructor in file scope with no selector to
match at all. `TestTheUnclassifiedConstructorScanIsNotVacuous` gained two fixtures: the aliased form,
which must fire, and a `NewRecommendation` selector belonging to a *different* package under the
local name `domain`, which must not — so the fix is a match on the package, not on the method name.

### 17.2 Restoration, verified two independent ways

Phase 13.1B's harness kept its write-set by hand, backed up from it, restored from it **and
verified from it**; two plants landed in files absent from that list and it still reported success.
This harness proves restoration twice:

1. the declared `FILES` write-set, compared before and after — the check 13.1B had;
2. **the whole working tree**, hashed by a `find` that knows nothing about `FILES`.

```
declared write-set restored byte-for-byte (11 files)
working tree restored byte-for-byte (975 files, verified independently of FILES)
```

It also refuses to plant into a file that is not declared, so the two cannot drift apart silently in
the first place. The same whole-tree manifest was taken around the five historical suites and
compared afterwards: identical. **No `git stash`, `reset`, `checkout` or `restore` was used
anywhere.**

## 18. `scripts/phase104b-mutations.sh` — NBE-M17 re-anchored a second time

`NBE-M17` plants a service-local lossy projection helper into `internal/diagnosis/postgres/shared.go`
and requires `TestNoServiceLocalAdviceProjectionHelperExists` to notice. Its anchor was `func
recommend`, which **this phase deleted**, so it reported `COULD NOT PLANT` — the harness's own
unplantable path working correctly, and the reason the whole suite was re-run rather than assumed.

Repaired rather than retired, per the Phase 9.x precedent: it now anchors on `func advise`, the
classified helper that replaced it, which is the more durable choice because it is the helper the
mutation exists to contrast with. **The planted body, the assertion and the catching test are
byte-identical.** Phase 13.1A.1 re-anchored the same plant off a comment 13.1B had reworded; this is
the second move and the mutation has never been weakened.

## 19. Planner reassessment

The Phase 13.1A trigger, measured rather than recalled. **All three must hold.**

| Condition | Result |
|---|---|
| 1 — every production recommendation classified, zero-legacy guard green | **PASS** |
| 2 — at least one `NEXT_EVIDENCE` with `SelfCollectable == true` that is **not** merely rerun / retry / larger budget | **FAIL** |
| 3 — that recommendation sits on a finding carrying a `Discriminator` | **FAIL** |

`SelfCollectable: true` is **2**, and both are literally *"Re-run with a larger execution budget so
…"* — `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` and `POSTGRES_ADMISSION_SCOPE`. Condition 2 excludes
exactly that sentence. Condition 3 fails independently: neither finding carries a discriminator.
Kafka's only discriminator is on `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE`, whose recommendation is
**not** self-collectable.

**PLANNER: KEEP DEFERRED.** Phase 13.1C added no self-collectable recommendation and manufactured
nothing to satisfy the trigger — the count is unchanged at 2, which is the honest answer and the one
§50 asked for.

## 20. Omissions

| Omitted | Why |
|---|---|
| Fuzz | no constructor, serializer, parser or input path changed (§16) |
| Real-service integration | no acquisition, protocol, adapter or wire change; the wiring is covered hermetically (§16) |
| `phase91*`, `phase92b`, `phase93a`, `phase107b`, `phase108b`, `phase121*` mutation suites | they guard fleet execution, release, Redis/RabbitMQ protocol and Kubernetes invariants, none of which this phase touches. Not run in 13.1C |
| A new ADR | ADR 0097 already holds the durable rule. §29's bar — a genuinely new durable decision the existing contract cannot represent — was not met. ADR 0097 received a factual correction only |

## 21. Open blockers

**None.**
