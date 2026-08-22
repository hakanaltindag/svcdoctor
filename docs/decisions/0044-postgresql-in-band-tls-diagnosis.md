# ADR 0044: A handshake belongs to whoever asked for it

## Status

Accepted as **policy**. No rule is implemented here.

This record decides who owns a failed PostgreSQL in-band TLS handshake and what
svcdoctor may conclude from it. It adds no production diagnosis code, no finding
code in Go, no `FailureClass`, no schema field, no dependency and no engine
behaviour.

It **supersedes one bullet of ADR 0040** — the one declining `POSTGRES_TLS_*`
findings over the `tls.handshake` node — and §2 argues that reversal rather than
performing it quietly. ADR 0041, ADR 0042 and ADR 0043 are unchanged. Generic
requested-target TLS remains deferred and is **not** authorized here (§13).

## Problem

A run can produce this, and does:

```text
target.requested       L0  PASS
  └── dns.lookup       L1  PASS
       └── tcp.connect L2  PASS
            └── postgres.ssl_request  L3  PASS
                 └── tls.handshake    L3  FAIL

findings: []        status: OK        firstBrokenLayer: L3
```

`status: OK` beside a broken layer. It is pinned by a committed test —
`internal/app/anchor_test.go::TestNoTLSFindingIsProduced` — which asserts the
handshake fails, that no finding names it, and that `firstBrokenLayer` is L3.

The node falls between two correct boundaries:

- **ADR 0043** gives generic diagnosis the sweep whose handshake is a *direct
  child of a requested* `tcp.connect`. This one's direct parent is
  `postgres.ssl_request`, so the generic walk cannot reach it — by construction,
  and measured.
- **ADR 0040** anchors every PostgreSQL rule at a `postgres.*` step.
  `tls.handshake` is not one, so no PostgreSQL rule reaches it either.

Neither boundary is wrong. The node is simply unowned, and after ADR 0043 that
absence stopped being uniform: **L1 and L2 now produce findings and L3 does not.**

## Decision

### 1. PostgreSQL owns a handshake it caused

| Model | Verdict |
|---|---|
| A. Generic transport owns every `tls.handshake` | **Rejected.** It would own Kafka's advertised handshakes too, which ADR 0034 owns outright, and would make a generic claim about a node whose meaning is service context |
| B. Widen ADR 0043's walk through `postgres.ssl_request` | **Rejected.** Either the walk becomes transitive — which reintroduces the Kafka duplication hazard ADR 0043 §1 exists to prevent — or it learns a service step name, which makes a generic rule service-aware |
| **C. PostgreSQL owns `tls.handshake` when its direct parent is `postgres.ssl_request`** | **Chosen** |
| D. The composition root synthesizes a `postgres.*` node | **Rejected.** `internal/app` creates exactly one kind of evidence (ADR 0042 §3), and orchestration that diagnoses is not orchestration |
| E. The adapter mints a second, PostgreSQL-specific TLS node | **Rejected.** Two nodes for one handshake is two sources of truth for one fact, which ADR 0013 refuses. The probe already recorded the observation; a service-shaped copy would have to be kept in step with it forever |
| F. No finding; the evidence is enough | **Rejected.** This is the status quo, and §2 answers it |

The principle generalizes past PostgreSQL, which is why it is stated as one
sentence rather than as a PostgreSQL rule:

> **A generic probe's evidence belongs to the layer that caused the probe to run.
> Ownership is read from the parent edge the causing layer already recorded, never
> from the step name of the node itself.**

Redis, MySQL and any future protocol that negotiates encryption in band inherits
it unchanged: the handshake hangs off that service's negotiation node, and that
service's rules own it.

### 2. Why ADR 0040's refusal is reversed, stated openly

ADR 0040's "What this does not own" says:

> *TLS verification quality — an untrusted CA, a hostname mismatch, an expired
> certificate on a PostgreSQL endpoint. ADR 0034 §14 assigned this to a future
> TLS-consistency policy and it stays there. A `POSTGRES_TLS_*` finding over the
> `tls.handshake` node would add nothing the node does not already state, which is
> the duplicate test.*

The deferral was reasonable and the reason was wrong. Three things:

**The duplicate test does not say that.** ADR 0034 §3 defines duplicates as *two
findings* where one makes no claim the other does not already make. It is a test
between findings, not between a finding and its evidence. Applied as ADR 0040
applied it, it would delete `POSTGRES_TLS_DECLINED` — which adds nothing its
`postgres.ssl_request` node does not state — and every one of ADR 0043's three
codes.

**A finding is not a restatement of a node; it is a different kind of object.**
`SummaryStatus` is derived from findings and never from evidence, so a node
cannot make a report say `PROBLEMS_FOUND`. Severity, confidence, vantage
dependence and a recommendation exist only on findings. The measured consequence
of the absence is `status: OK` on a run that failed at L3 — not "the same
information, differently arranged".

**The situation changed.** When ADR 0040 was written no transport layer had an
owner, so the silence at L3 was uniform and invisible. ADR 0043 gave L1 and L2
owners. What was a consistent deferral became an inconsistency, and the honest
response is to close it rather than to preserve the sentence.

**What is not reversed:** ADR 0034 §14's Kafka TLS-consistency item stays open.
That item is about whether a certificate failing on one path while another
succeeds may support a *reachability* claim. This record makes per-endpoint TLS
claims and no reachability claim, so it neither closes that item nor depends on it.

### 3. The ownership predicate

A `tls.handshake` node is PostgreSQL's **iff all of**:

1. `Step == tls.handshake` and `Layer == L3`;
2. `State == FAIL`;
3. it has **exactly one** parent, and that parent's `Step == postgres.ssl_request`;
4. the parent's `State == PASS`;
5. the parent's `Subject` equals the node's `Subject`.

Graph APIs only — `Node`, `Parents`, `Step`, `State`, `Subject`. No identifier
parsing, no `SweepScope`, no `Origin`, no rootness, no service-name matching, no
transitive search. `diagnosis.Rule` is unchanged.

Each condition earns its place:

- **(2) FAIL, not "not PASS".** The adapter mints a **SKIPPED** `tls.handshake`
  node with `EXEC_SKIPPED_PREREQUISITE_FAILED` and a `blockedBy` edge when the
  negotiation did not succeed. Requiring FAIL excludes it structurally, and
  `docs/FINDINGS.md` §11 forbids citing a blocked step as a cause. It also
  excludes the UNKNOWN states cancellation and budget exhaustion produce (§8).
- **(4) the parent passed.** This is what makes the claim *"the endpoint agreed to
  encrypt and then the handshake failed"* rather than *"TLS failed"*. It also
  guarantees §12's separation: an `SSLRequest` that was declined or errored is a
  different failure with a different owner.
- **(5) subjects agree.** Free, and it closes the malformed case where a handshake
  is attached to a negotiation of a different address.
- **Exactly one parent.** Production records one. More is a shape nobody produces.

**No requested-target anchor is required.** ADR 0040's rules anchor at
`postgres.*` and demand no anchor; requiring one here would be inconsistent and
would make the rule silent on any graph a test builds by hand.

**Malformed shapes withhold.** A handshake with no parent, with a parent of
another step, with several parents, or under a non-passing negotiation produces
nothing. Diagnosis does not guess at a graph it does not recognize.

### 4. What the evidence can actually be

Read from `internal/probe/tls/handshake.go`, the only producer, rather than from
the declared class list.

| State | Class | What it means | Reachable in band? |
|---|---|---|---|
| PASS | `NONE` | handshake completed | yes — no finding |
| FAIL | `TLS_PEER_NOT_TLS` | the peer's first record was not a TLS record | yes |
| FAIL | `TLS_HOSTNAME_MISMATCH` | no name in the certificate matched the requested identity | yes |
| FAIL | `TLS_UNKNOWN_AUTHORITY` | the chain did not verify against this run's trust source; **also the fallback for any unrecognized verification failure**, including opaque platform-verifier errors | yes |
| FAIL | `TLS_CERTIFICATE_EXPIRED` | outside the validity window, later end | yes |
| FAIL | `TLS_CERTIFICATE_NOT_YET_VALID` | outside the validity window, earlier end | yes |
| FAIL | `TLS_HANDSHAKE_FAILURE` | floor; **includes a received `protocol_version` alert**, because that arrives as an unexported type the probe refuses to match on text | yes |
| UNKNOWN | `EXEC_CANCELLED` / `EXEC_LOCAL_TIMEOUT` | svcdoctor's own budget or a cancellation | yes — no finding |
| SKIPPED | `EXEC_SKIPPED_PREREQUISITE_FAILED` | the negotiation did not deliver a socket | yes — no finding |

**Three declared classes have no producer** and this record writes no policy for
them: `TLS_VERSION_MISMATCH`, `TLS_CLIENT_CERTIFICATE_REQUIRED`,
`TLS_CLIENT_CERTIFICATE_REJECTED`. A version mismatch is recorded as the floor,
which is why the floor is not a rare case.

**The verification context is the run's, and it is recorded.** `ServerName`
defaults to the host of the logical endpoint and is never derived from the
resolved address; `tls.trust_source` says whether roots were the system store or
supplied; `tls.verified` says whether identity was checked at all. Every
certificate fact a reader needs is already a structured attribute on the node:
`tls.server_name`, `tls.peer_dns_names`, `tls.peer_ip_addresses`,
`tls.peer_not_before`, `tls.peer_not_after`. The probe deliberately extracts the
chain from the *error* as well as from a successful state, so a rejected
certificate still reports which names it carried.

### 5. Five codes, and the merge that was made

The test is `docs/FINDINGS.md` §11: merge only when all user-visible semantics
are the same. Asked as *would an operator's next move differ?*, five families
survive and one merge happens.

| Code | Classes | The claim | First move it implies |
|---|---|---|---|
| `POSTGRES_TLS_UPGRADE_NOT_HONORED` | `TLS_PEER_NOT_TLS` | the endpoint agreed to encrypt, and what answered next did not speak TLS | find what is terminating the connection |
| `POSTGRES_TLS_IDENTITY_MISMATCH` | `TLS_HOSTNAME_MISMATCH` | the certificate presented carries no name matching the identity this run asked for | compare the certificate's names with the name used |
| `POSTGRES_TLS_CHAIN_NOT_TRUSTED` | `TLS_UNKNOWN_AUTHORITY` | the chain presented did not verify against this run's trust source | check the trust material this run was given |
| `POSTGRES_TLS_CERTIFICATE_NOT_VALID_NOW` | `TLS_CERTIFICATE_EXPIRED`, `TLS_CERTIFICATE_NOT_YET_VALID` | the certificate presented is outside its validity window as measured against this host's clock | compare the window with this host's clock |
| `POSTGRES_TLS_HANDSHAKE_FAILED` | `TLS_HANDSHAKE_FAILURE` | the handshake did not complete, and svcdoctor could not attribute why | read the evidence |

**The merge.** Expired and not-yet-valid pose one question — *is this certificate
valid now, and whose clock says so?* — and the answer to that question is what
tells an operator which way to go. `tls.peer_not_before` and `tls.peer_not_after`
distinguish the two ends exactly, so the distinction is preserved where a machine
reads it rather than duplicated as a code.

**The splits.** A name mismatch, an untrusted chain and an out-of-date
certificate send a reader to three different places, and often to three different
people: whoever issued the certificate, whoever configured this client's trust,
and whoever renews. `CHAIN_NOT_TRUSTED` is the sharpest case — it is frequently a
defect in **svcdoctor's own configuration**, not the target's, which is a
different conclusion entirely.

**No code mirrors a `FailureClass` name.** `UPGRADE_NOT_HONORED` names the
service-level claim rather than the wire observation `PEER_NOT_TLS`, and
`IDENTITY_MISMATCH` is wider than `HOSTNAME_MISMATCH` because certificate
identity includes addresses.

### 6. Kind, severity, confidence

All five are **`CONFIRMED` / `ERROR` / `HIGH`**, on ADR 0040's own reasoning
rather than by inheritance.

- **CONFIRMED**: each restates a positively evidenced FAIL with an exact class.
  `FindingKindConfirmed` explicitly does not require a proven root cause, which is
  why the floor qualifies too. No discriminator; the model would reject one.
- **ERROR**: severity is the impact of the claim about its own subject
  (ADR 0034 §13). The run required encryption, this endpoint did not deliver it,
  and nothing further could be attempted on this path. That is what prevents
  correct use. It matches `POSTGRES_TLS_DECLINED`, the adjacent claim.
- **HIGH**: the claim is the measurement. The floor's claim includes *"and
  svcdoctor could not attribute why"*, which is also exactly what was measured.

**No contract tension.** ERROR is not chosen to force an exit code; it is chosen
per subject, and the exit code follows. Had the honest severity been WARN, the
right response would have been to record that a real failure produces exit 0 —
not to inflate the severity.

### 7. Every finding is vantage-dependent, and none of them by default

ADR 0040 §6.1 fixes two grounds for `true`: **(1)** the observation is
path- or source-dependent; **(2)** the cause is unattributed by construction, so
a source-keyed cause cannot be excluded. Where neither applies, `false` is
asserted deliberately.

| Code | Vantage | Ground |
|---|---|---|
| `POSTGRES_TLS_UPGRADE_NOT_HONORED` | **true** | 1, and the strongest instance: something on the path answered, and what answers can differ per path |
| `POSTGRES_TLS_IDENTITY_MISMATCH` | **true** | 1. A certificate is *presented*, and ADR 0040 marked `POSTGRES_PEER_VERIFICATION_FAILED` true on exactly this reasoning — an intermediary on one path can present material another path never sees |
| `POSTGRES_TLS_CHAIN_NOT_TRUSTED` | **true** | 1, plus a second ground: it depends on this run's configured trust source, recorded as `tls.trust_source` |
| `POSTGRES_TLS_CERTIFICATE_NOT_VALID_NOW` | **true** | 1. Which certificate is presented is path-dependent |
| `POSTGRES_TLS_HANDSHAKE_FAILED` | **true** | 2, exactly as the three PostgreSQL floors |

**All five are `true`, and that is asserted rather than defaulted.** The `false`
set in ADR 0040 is the findings where the peer reached a **catalog or credential**
decision — the class of fact that does not move with the observer. Nothing here is
in that class: every one of these is about material a peer *presented*, and what
is presented is exactly what an element on the path can change.

**The clock, and why it is not a vantage flag.** `NOT_VALID_NOW` also depends on
this host's clock, and the repository's `vantageDependent` means *network
position* (ADR 0012, `docs/FINDINGS.md` §8). Forcing the clock into that boolean
would redefine the field for one finding. Instead the claim names the dependence —
*"as measured against this host's clock"* — and the evidence carries both the
window and the node's own `startedAt`, so a reader can check the comparison.
**Reopen if** a second finding needs to express a non-network dependence; at that
point the field, not this finding, is what should change.

### 8. No aggregation, no partial-success withholding — and this is deliberate

**ADR 0043's withholding rule must not be copied here.** The difference is what
the claim is *about*.

- ADR 0043's `TCP_CONNECTION_NOT_ESTABLISHED` claims *"no measured connection to
  **the requested endpoint** completed"*. One working path makes it false, so one
  working path withholds it.
- These findings claim *"**this endpoint** presented a certificate that…"*. A
  second endpoint working does not make that false.

That is not a new position: it is ADR 0040's, unchanged. Every PostgreSQL finding
is per-node with a concrete `ip:port` subject, and its prose says *"this
endpoint"*. So:

> **One failing handshake yields one finding. A passing handshake on another path
> withholds nothing.**

A dual-stack endpoint whose IPv4 address presents a bad certificate while IPv6
works is a real defect that a client will meet whenever it selects IPv4, and
suppressing it would hide a fact the operator needs. The report says both things:
a finding about the failing endpoint, and — through ADR 0041's selection — a
session that succeeded elsewhere.

**FAIL + UNKNOWN needs no rule.** Because the claim is per-node, an unmeasured
path says nothing about a measured one. The FAIL node yields its finding; the
UNKNOWN node yields nothing. `Result.Incomplete()` and exit code 4 continue to
report that the run did not finish, and `SCOPE.md` already ranks code 4 above
code 1 so incompleteness qualifies the conclusion.

### 9. Subject and evidence references

**Subject: the handshake node's own subject** — the concrete `ip:port`. It is
already there, it needs no upward walk, and it matches ADR 0040's rule that every
PostgreSQL finding's subject is the concrete endpoint. Using the logical target
would require walking up from a service node through transport to the anchor,
which is the reverse traversal ADR 0042 §10 warns about, and it would be wrong
anyway: the claim is about the endpoint that presented the certificate.

**Evidence: the `postgres.ssl_request` node and the `tls.handshake` node.**

Minimal, and both halves are proof rather than decoration. The handshake carries
the failure, its class and every certificate attribute. The negotiation carries
the other half of the claim — that this endpoint *agreed* to encrypt — without
which "the upgrade was not honored" has no antecedent, and it is the node that
establishes the rule's own ownership precondition. `docs/FINDINGS.md` §10 requires
enough to establish the claim, and ADR 0040 cites the establishing parent in the
same way for `POSTGRES_DATABASE_NOT_FOUND`.

The `tcp.connect` node and the anchor are **not** cited: neither proves anything
about TLS.

### 10. Recommendations

One each, naming what to inspect and asserting no cause.

| Code | Recommendation |
|---|---|
| `UPGRADE_NOT_HONORED` | Check what terminates connections at this endpoint after PostgreSQL SSL negotiation, and whether it is the component expected to serve TLS |
| `IDENTITY_MISMATCH` | Compare the names recorded on the referenced certificate evidence with the server identity this run requested |
| `CHAIN_NOT_TRUSTED` | Check the trust material this run was given against the chain recorded on the referenced evidence |
| `CERTIFICATE_NOT_VALID_NOW` | Compare the certificate validity window on the referenced evidence with this host's clock |
| `HANDSHAKE_FAILED` | Read the referenced evidence for what the handshake recorded, and check whether the protocol versions this run offered are acceptable to this endpoint |

Forbidden throughout: naming a load balancer, proxy, middlebox, firewall or
certificate authority as the cause; asserting that a certificate was misissued or
should be renewed; any executable command; any Kubernetes or vendor assumption;
any SQL. Where the evidence does not distinguish causes, the recommendation points
at the evidence.

### 11. Ownership matrix

| Case | Owner |
|---|---|
| requested DNS failure | generic (ADR 0043) |
| requested TCP failure | generic (ADR 0043) |
| `postgres.ssl_request` declined | `POSTGRES_TLS_DECLINED` (ADR 0040) |
| `postgres.ssl_request` `E`-answer / malformed / peer close | **still no finding** — ADR 0040's recorded gap, untouched here |
| PostgreSQL in-band `tls.handshake` FAIL | **this record** |
| PostgreSQL startup / authentication / session | ADR 0040, unchanged |
| Kafka advertised TLS | Kafka (ADR 0034); its handshake parents to a `tcp.connect` inside the advertised sweep, so predicate condition 3 can never match |
| future generic requested-target TLS | generic; same reason — parent is `tcp.connect` |
| cancellation, budget exhaustion, prerequisite skip | **no finding anywhere**; the states are UNKNOWN and SKIPPED |

Disjoint by construction. No suppression, no precedence, no first-match-wins.

### 12. What this record does not touch

**Authentication and everything after it.** The rule reads two nodes and stops.
It must not mention credentials, inspect authentication or session nodes, infer
authentication outcomes, or change path selection, credential-attempt counts,
retry or fallback. ADR 0041 is unaffected.

**`SSLRequest` rejection.** A declined or errored negotiation is a `FAIL`
`postgres.ssl_request` node, and predicate condition 4 requires that node to have
**passed**. The two can never both fire.

**TLS verification semantics.** Nothing about how the handshake is performed,
verified or classified changes. This record reads evidence the probe already
produces.

### 13. Generic requested-target TLS stays deferred

Unchanged, and re-verified: no production run yields a `tls.handshake` whose
direct parent is a requested `tcp.connect`. `internal/app` calls `transport.Run`
with `TLS` unset because PostgreSQL negotiates in band, and Kafka has no
composition root. A producer arrives when Kafka bootstrap composition exists.

**PostgreSQL in-band TLS does not justify widening generic ownership**, and the
reason is §1: this handshake exists because a *service* asked for it, so a generic
rule claiming it would be claiming a fact whose context it cannot see.

Generic TLS needs **its own ADR**, and this record does not write it. The backlog
item stays open.

## Acceptance matrix

| # | Scenario | Owner | Findings | Subject | Status | fBL |
|---|---|---|---|---|---|---|
| 1 | TLS succeeds | — | per later stages | — | per later | per later |
| 2 | peer not TLS | this record | 1 × `UPGRADE_NOT_HONORED` | `ip:port` | PROBLEMS_FOUND | L3 |
| 3 | hostname mismatch | this record | 1 × `IDENTITY_MISMATCH` | `ip:port` | PROBLEMS_FOUND | L3 |
| 4 | unknown authority | this record | 1 × `CHAIN_NOT_TRUSTED` | `ip:port` | PROBLEMS_FOUND | L3 |
| 5 | expired certificate | this record | 1 × `CERTIFICATE_NOT_VALID_NOW` | `ip:port` | PROBLEMS_FOUND | L3 |
| 6 | not-yet-valid certificate | this record | 1 × `CERTIFICATE_NOT_VALID_NOW` | `ip:port` | PROBLEMS_FOUND | L3 |
| 7 | unclassifiable handshake failure | this record | 1 × `HANDSHAKE_FAILED` | `ip:port` | PROBLEMS_FOUND | L3 |
| 8 | one path FAIL, one PASS | this record | **1**, for the failing endpoint | failing `ip:port` | PROBLEMS_FOUND | L3 |
| 9 | all paths FAIL, same class | this record | **one per failing node** | each `ip:port` | PROBLEMS_FOUND | L3 |
| 10 | all paths FAIL, mixed classes | this record | one per node, codes differ | each `ip:port` | PROBLEMS_FOUND | L3 |
| 11 | one FAIL, one UNKNOWN | this record | 1, for the FAIL node | `ip:port` | PROBLEMS_FOUND | L3 |
| 12 | cancellation during handshake | — | **none** | — | OK | unset¹ |
| 13 | local timeout during handshake | — | **none** | — | OK | unset¹ |
| 14 | `SSLRequest` declined | ADR 0040 | 1 × `POSTGRES_TLS_DECLINED` | `ip:port` | PROBLEMS_FOUND | L3 |
| 15 | TCP fails before `SSLRequest` | ADR 0043 | 1 × `TCP_CONNECTION_NOT_ESTABLISHED` | logical endpoint | PROBLEMS_FOUND | L2 |
| 16 | TLS passes, then wrong password | ADR 0040 | 1 × `POSTGRES_CREDENTIALS_REJECTED` | `ip:port` | PROBLEMS_FOUND | L5 |
| 17 | TLS passes, then missing database | ADR 0040 | 1 × `POSTGRES_DATABASE_NOT_FOUND` | `ip:port` | PROBLEMS_FOUND | L5 |
| 18 | dual-stack healthy | — | none | — | OK | unset |
| 19 | handshake with no parent | — | **none** — malformed | — | — | — |
| 20 | handshake under a non-`ssl_request` parent | — | **none** | — | — | — |
| 21 | two handshakes under one negotiation | — | **none** — malformed | — | — | — |
| 22 | handshake under a *failed* `ssl_request` | — | **none**; ADR 0040 owns the negotiation | — | — | — |
| 23 | SKIPPED handshake under a failed negotiation | — | **none**; a blocked step is not a cause | — | — | — |
| 24 | generic requested-target TLS fixture | generic, when it exists | **none from this record** | — | — | — |
| 25 | Kafka advertised TLS fixture | Kafka | **none from this record** | — | — | — |
| 26 | redacted report | — | subject pseudonymized; certificate names pseudonymized as declared identity | — | — | — |
| 27 | permuted node insertion order | — | byte-identical findings | — | — | — |

¹ Assuming no other layer failed; the handshake is UNKNOWN, and UNKNOWN is not a
broken layer.

**Reproducibility.** Rows 3 and 2 are producible today — a committed test in
`internal/adapter/postgres` already produces `TLS_HOSTNAME_MISMATCH` through the
in-band path, and `internal/app` produces `TLS_PEER_NOT_TLS`. Rows 5 and 6 need
fixture certificates with shifted validity windows and are **unit-only**; the
integration environment serves one valid certificate and must not be made to
serve a broken one. Rows 19 to 23 are graph-shape cases and are unit-only by
nature. **No row may be satisfied by faking a real-server capability.**

## Mutation matrix

| | Mutation | Caught by |
|---|---|---|
| A | rule owns every `tls.handshake` | rows 24, 25 |
| B | ownership uses a transitive ancestor search | rows 19–22, plus an AST guard on self-recursion |
| C | ownership parses an `EvidenceID` | AST guard, as in `internal/diagnosis/kafka` |
| D | ownership matches a service-name string | AST guard on string literals |
| E | fires without an `ssl_request` parent | rows 19, 20 |
| F | fires when the `ssl_request` itself failed | rows 22, 14 |
| G | duplicates a generic requested-target TLS finding | row 24 |
| H | diagnoses Kafka advertised TLS | row 25 |
| I | UNKNOWN counted as FAIL | rows 12, 13 |
| J | FAIL + UNKNOWN suppresses the FAIL finding | row 11 |
| K | partial TLS success suppresses the finding | row 8 |
| L | subject becomes the logical target | rows 2–7 assert the node's own subject |
| M | omits the `ssl_request` from evidence refs | rows 2–7 assert both refs |
| N | one vantage flag applied without per-code reasoning | a table test asserting all five values |
| O | validity finding marked `false` | same table test |
| P | chain-not-trusted marked `false` | same table test |
| Q | cancellation produces ERROR | rows 12, 13 |
| R | recommendation asserts a proxy or load-balancer cause | prose guard, as in `internal/diagnosis/transport` |
| S | a code mirrors a raw `FailureClass` | a naming test asserting the five codes |
| T | rule reads authentication nodes or changes selection | AST guard plus ADR 0041's existing tests |
| U | retry or fallback introduced | ADR 0041's credential-attempt tests |
| V | a sixth code appears | `internal/vocabulary`'s allow-list, extended to these five |
| W | a generic `TLS_` code added | the same allow-list, which still rejects every `TLS_` code |
| X | `schemaVersion` changes | `internal/domain` JSON tests |
| Y | `FailureClass` changes | class-count guard |
| Z | `security.Reveal` count changes | `forbidigo` plus the count guard |

## Security and redaction

**No new redaction rule is required, and this is structural rather than lucky.**
Every identity-bearing certificate attribute is *declared* by the producer:
`tls.server_name` is a `HostAttr`, `tls.peer_dns_names` and
`tls.peer_ip_addresses` are `HostListAttr`. ADR 0022 moved sensitivity onto the
value, so the redactor pseudonymizes them without knowing any key. The finding's
subject is a `SubjectKindEndpoint` `ip:port`, which `redactSubject` already
rewrites through the same table as every other endpoint.

**The prose carries none of it.** No summary or detail may contain a hostname, an
address, a certificate subject, an issuer, a SAN, a filesystem path or a raw TLS
error. The probe already discards the error text — *"a resolver error string can
name the resolver's own address … in prose that structural redaction cannot
recognize"* is the same reasoning — and this record does not reintroduce it. No
certificate blob enters a finding.

**No credential material is involved at any point**, and `security.Reveal` is
untouched.

## The BASIC boundary

Every fact here is learned **while attempting to be the PostgreSQL client the
operator asked svcdoctor to be**. The handshake is one the run had to perform to
proceed; the certificate facts are what the peer presented during it. Nothing
requires a privileged read, a query, or a second connection.

Explicitly **not** authorized by this record, and not needed to explain a failed
client attempt: certificate inventory scanning, SAN enumeration as a feature,
renewal advice, certificate lifecycle management, OCSP, expiry monitoring, TLS
configuration grading and cipher hardening advice. This is diagnosis, not a TLS
scanner.

The one adjacent temptation worth naming: a **PASS** handshake whose certificate
expires next week is `DEGRADED`-shaped, not FAIL-shaped, and it is *expiry
monitoring* wearing a diagnosis costume. Not authorized here.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Generic ownership of all handshakes | Captures Kafka advertised TLS, which ADR 0034 owns | Never |
| Widening ADR 0043's walk | Transitive descent or a service-aware generic rule; both were rejected by ADR 0043 §1 | Never |
| A second, PostgreSQL-shaped TLS evidence node | Two sources of truth for one handshake | Never |
| Keeping ADR 0040's refusal | Rests on a misapplied duplicate test and leaves `status: OK` on a failed run | Never |
| One PostgreSQL TLS code | Five genuinely different first moves; §11 of FINDINGS.md forbids the merge | A remediation study shows operators act identically |
| Separate codes for expired and not-yet-valid | One question, and the evidence answers which end | A consumer needs the distinction and cannot read attributes |
| Withholding when another path's TLS passes | The claim is per-endpoint; withholding would hide a real defect | The claim is ever restated at target level |
| Logical target as subject | Requires an upward walk, and misdescribes which endpoint presented the certificate | Never |
| Marking the validity finding non-vantage-dependent | Which certificate is presented is path-dependent | Never |
| A new `FailureClass` | The six reachable classes express every measured outcome | A producer records an outcome none of them fits |

## Consequences

- The last transport-layer silence in a PostgreSQL run closes. `status: OK` beside
  a broken L1, L2 or L3 becomes impossible.
- PostgreSQL gains five codes: 12 → 17, and the repository 17 → 22.
- One principle generalizes: generic evidence belongs to the layer that caused it,
  read from the parent edge. Redis and MySQL inherit it without a new mechanism.
- ADR 0040 gains an amendment note; its twelve findings are untouched.
- Generic requested-target TLS remains deferred and still needs its own record.
- `FailureClass`, `schemaVersion`, `Reveal`, the dependency set and
  `diagnosis.Rule` are all unchanged.

## Reopen conditions

- **A production requested-target generic TLS producer** — the deferred generic
  ADR.
- **A second finding needing a non-network dependence** — `vantageDependent`
  itself, not this finding.
- **A measured `SSLRequest` `E`-answer** — ADR 0040's remaining negotiation gap.
- **A `DEGRADED` handshake policy** — certificate expiry on a *passing* handshake,
  which is a different product question.
