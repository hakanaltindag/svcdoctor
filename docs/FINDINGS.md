# Finding Catalog and Conventions

This document defines the conventions findings must follow. It is deliberately **not** an
enumeration of every future svcdoctor finding.

The goal is to fix the conventions before coding, so that finding identifiers stay stable
once they are exposed to users and automation.

See `docs/REPORT_SCHEMA.md` for the finding model itself, and `docs/DIAGNOSIS_EXAMPLES.md`
for what the findings svcdoctor actually produces look like.

## 1. Finding code convention

Finding codes are uppercase, underscore-separated, stable identifiers:

```text
<NAMESPACE>_<DESCRIPTION>
```

### Service findings

Service findings use the service name as the namespace:

```text
KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE
KAFKA_SECURITY_PROTOCOL_MISMATCH
POSTGRES_TLS_DECLINED
```

### Generic transport findings

Generic transport findings use the layer as the namespace:

```text
DNS_RESOLUTION_FAILED
TCP_CONNECTION_REFUSED
TLS_CERTIFICATE_EXPIRED
```

> **Three generic codes are authorized and none is implemented yet.** ADR 0043 fixes
> `DNS_NAME_NOT_RESOLVED`, `DNS_RESOLUTION_FAILED` and `TCP_CONNECTION_NOT_ESTABLISHED` for the
> operator-requested target; section 7 carries them. The codes svcdoctor *produces* today are
> still the two `KAFKA_ADVERTISED_ENDPOINT_*` codes and the twelve `POSTGRES_*` codes in
> section 6.
>
> The blocker was run intent — "is this a Kafka diagnosis or a bare endpoint check?" — which
> `diagnosis.Rule` cannot see, receiving only a `Graph`. ADR 0042 put it in the graph as an L0
> requested-target anchor, so a rule now identifies the operator's sweep by walking down from
> it rather than by asking where an endpoint came from.
>
> **`TLS_CERTIFICATE_EXPIRED` above remains a naming example only.** Generic TLS is deferred:
> no production run produces a `tls.handshake` node whose direct parent is a requested
> `tcp.connect`, because PostgreSQL negotiates in band and Kafka has no composition root. See
> ADR 0043 section 14.
>
> ADR 0034 still gives advertised-endpoint transport failures to the Kafka rule outright, and
> the generic walk cannot reach them: an advertised sweep parents to its advertisement, never
> to a target anchor.

This is the chosen convention: **the namespace names the owner of the rule.** A rule owned by
`internal/diagnosis/transport/` is namespaced by its transport layer; a rule owned by
`internal/diagnosis/<service>/` is namespaced by its service.

The layer namespaces (`DNS`, `TCP`, `TLS`) are unambiguous and read naturally, so no extra
generic prefix is introduced.

### Ownership

Code constants live with the rules that produce them. The core knows only that a code is a
namespaced string.

> There is no central enumeration listing every service's codes.

A central enum would recreate the coupling that central service branching creates, in a
different shape: every new service would have to edit shared core code.

## 2. Finding lifecycle

Finding identifiers are machine-consumed contracts. Automation, dashboards, and alert rules
will match on them.

- Avoid renaming a code without a real reason.
- Once exposed, a code's semantics must remain stable. If the meaning must change, introduce
  a new code rather than redefining the old one.
- Message text may improve freely without changing the code.
- Renderer formatting must never affect code identity.

A code is the stable part. Everything a human reads around it is not.

## 3. Finding properties

Every finding should eventually provide:

```text
code
kind
severity
confidence
layer
summary
evidenceRefs
vantageDependent
```

Recommended when relevant:

```text
detail
recommendations
discriminator
affectedResources
help / reference
```

Phase 1.4a settled which of these are required at the type level:

- **Required:** `code`, `kind`, `severity`, `confidence`, `layer`, `summary`,
  `evidenceRefs` (at least one), and `vantageDependent` (a bool, always encoded,
  because `false` is a statement rather than an absence).
- **Optional:** `subject`, `detail`, `recommendations`, `discriminator`.
- **Deferred:** `affectedResources`, and a reference link or remediation risk on a
  recommendation. Nothing consumes them yet and no renderer exists.

`layer` is supplied by the caller and never derived from `code`, so the core never holds a
code-to-layer mapping that every new service would have to edit. It is the layer the finding's
**claim** belongs to, not the layer its failure was observed at — the two differ routinely, and
`docs/REPORT_SCHEMA.md` section 7.5 defines the distinction and says which field a consumer
should read for "where did it break?".

A `CONFIRMED` finding must not carry a discriminator: a discriminator states what would
settle an open question, and a confirmed finding has none. A `HYPOTHESIS` without one is
accepted — this document says to *prefer* stating it and `docs/REPORT_SCHEMA.md` says the
model *allows* one, so requiring it would be diagnosis policy rather than structural
validation.

## 3.1 The finding quality bar

Reviewed against the first real finding in Phase 3.6.5, and binding on every finding after it.
A rule that cannot satisfy a line here is either not ready or is describing a claim the model
does not yet support — and the second case is an ADR, not a workaround.

**The claim**

1. **One finding is one independent claim.** If removing another finding would not change what
   this one asserts, they are independent. If it would, they are the same finding or a
   causal parent and child, and section 5 decides which survives.
2. **Never claim more than the evidence carries.** Including in prose: a sentence that names a
   value the graph does not hold is as wrong as a field that does.
3. **The three outcomes stay distinct.** *Proven*, *not proven*, and *not measured* are
   different claims. Collapsing the last two is the fastest way to make the tool untrustworthy.
4. **Partial success never becomes total failure**, and withholding a finding is not
   withholding information — the evidence stays in the report either way.

**The fields**

5. **Severity is the impact of this finding's claim about its own subject.** Never a count,
   never a cluster verdict, never a proxy for confidence.
6. **Confidence is epistemic strength only.** If the belief weakened, do not lower severity;
   change the claim and let the impact follow.
7. **`kind` matches the evidence.** `HYPOTHESIS` when alternatives remain, with a
   discriminator that names the *observation* that would settle it — never a remediation.
8. **`vantageDependent` is set whenever the claim depends on network position**, and set
   unconditionally where it always does.
9. **`layer` is the claim's layer**, per section 3 above.

**The evidence**

10. **`evidenceRefs` is minimal sufficient proof**: enough to establish the claim, and nothing
    that merely decorates it. Both halves of a contrast are part of the proof.
11. **A blocked step is never cited as a cause.** Its blocker owns the failure.
12. **Every reference resolves in the report's graph** — enforced at assembly (ADR 0014), and
    a rule must not knowingly produce a dangling one.

**The presentation**

13. **A renderer must never parse `summary` to recover semantics.** Anything a consumer needs
    structurally must be a field, or derivable from `evidenceRefs` plus the graph. Prose is for
    humans and is free to change; the code and the fields are the contract.
14. **`summary` is one stable sentence a human can act on.** Technical specifics belong in
    `detail` or on the evidence.
15. **Prose carries no identity that structure already carries.** Put the hostname on the
    subject and the evidence, where redaction transforms it; a finding whose prose must be
    rewritten to be shareable is a finding that will leak the day someone edits it.
16. **The finding still makes sense after pseudonymization.** Read it with every host and
    address replaced before deciding it reads well.
17. **Recommendations follow the evidenced failure and nothing else.** No guessed root cause,
    no single generic catch-all, and never an executable command.
18. **Text is deterministic.** Same graph, same bytes: sort anything collected from a map or a
    traversal.

**The check that catches the rest:** render the finding with the hostnames removed and ask
whether an on-call engineer who has never read this repository knows what failed, how sure we
are, and what to look at next. If answering needs the raw graph, the finding is not finished.

## 4. Claim discipline

These rules exist to keep svcdoctor from producing confident, wrong answers.

- Never claim an absolute root cause unless the evidence truly proves it.
- Prefer `kind: HYPOTHESIS` when alternative explanations remain, and state the discriminator.
- An unsupported diagnostic capability must not be converted into a service failure. If
  svcdoctor cannot check something, that is a gap in svcdoctor.
- Privilege-related missing evidence must not be interpreted as healthy.
- Downstream findings must not be generated when their prerequisite layer failed.
- Findings that depend on network location must be marked `vantageDependent`.

The shared theme: **"I could not measure it" and "it is broken" are different claims.**
Collapsing them is the fastest way to make a diagnostic tool untrustworthy.

## 5. First-broken-layer behavior

The report must make the earliest evidenced failing layer obvious.

```text
DNS       FAIL
  |
TCP       SKIPPED
  |
TLS       SKIPPED
  |
PROTOCOL  SKIPPED
```

This must not produce separate, misleading TCP/TLS/auth failure findings. One evidenced
failure plus explicit skips is correct. Four failures is noise that hides the real cause.

Layer order is defined in `docs/ARCHITECTURE.md` section 2:

```text
L0 config -> L1 DNS -> L2 TCP -> L3 TLS -> L4 protocol -> L5 auth -> L6 topology
```

## 6. Known findings

### `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`

The flagship finding for the Kafka vertical slice, described conceptually only.

**Condition**

- The bootstrap path succeeds far enough to obtain Kafka Metadata.
- Metadata returns one or more broker endpoints.
- One or more discovered broker endpoints fail connectivity verification from the current
  vantage point.

**Expected characteristics**

| Property | Value |
|---|---|
| `kind` | `CONFIRMED` or `HYPOTHESIS`, depending on the strength of the evidence |
| `severity` | typically `ERROR` |
| `confidence` | `HIGH` when the discovered-endpoint failure is directly evidenced |
| `vantageDependent` | `true` |

**Evidence references**

The finding must reference both:

- the evidence showing successful bootstrap and Metadata discovery, and
- the evidence showing the discovered endpoint failing

Both halves are required. The finding's entire meaning is the contrast between them: the
cluster answered, and then advertised an address this client cannot reach.

**Why vantage matters here**

This finding is a statement about the network position of the client, not about the health of
the cluster. The same cluster may be perfectly reachable from another vantage. Reports
carrying this finding must make that unmistakable.

No code structures are defined here. Verification of discovered endpoints uses credential-free
probes by default, per `docs/SECURITY.md`.

### Settled by ADR 0034

Phase 3.5 turned the conceptual description above into an exact policy, against the real
Phase 3.4 evidence graph, and Phase 3.6 implemented it as
`internal/diagnosis/kafka.AdvertisedEndpointUnreachable` — inventing nothing, because every
field below was already fixed. The binding parts:

| | |
|---|---|
| **Trigger** | For one advertisement whose endpoint is usable: the `kafka.metadata` exchange is PASS, no path of the sweep derived from that advertisement reached the sweep's terminal layer in PASS, at least one node is FAIL, and no node is UNKNOWN or skipped for budget |
| **Terminal layer** | TLS when the sweep's TCP nodes have TLS children, TCP otherwise. The chain mints a TLS node — real or SKIPPED — under every TCP node **iff** the plan required TLS, which is pinned by `internal/probe/transport/terminallayer_test.go` |
| **Kind** | `CONFIRMED`. `HYPOTHESIS` only for the mixed FAIL/UNKNOWN sweep, with a discriminator naming the observation that would settle it |
| **Severity** | `ERROR` per unreachable advertised broker — impact of the finding's claim about its own subject, never a count-derived cluster verdict. The hypothesis is `WARN`, because it states a weaker claim, not because belief is weaker |
| **Confidence** | `HIGH` for the confirmed finding; `LOW` for the hypothesis |
| **Subject** | The advertised endpoint, taken from the advertisement node's subject. Never a resolved address, never the node identifier |
| **Vantage** | `vantageDependent: true`, always |
| **Evidence** | The `kafka.metadata` node, the `kafka.broker_advertised` node, and **the minimal causal set: each measured path's earliest non-PASS node**, or the DNS node alone when the lookup did not pass. That one rule handles every shape — it cannot reach a downstream `SKIPPED` node, because a skip's blocker is its parent and therefore earlier on the same path. In the authorized cases no PASS node is ever referenced. The HYPOTHESIS additionally cites its unmeasured paths, as evidence of the incompleteness it asserts rather than as causes. ADR 0034 §11 carries the exact per-case table |

**No generic transport finding is produced for the same evidence.** The Kafka finding entails
the transport observation and adds the broker identity and the contrast with a successful
bootstrap; a generic one would add nothing the evidence node does not already state. Section 5
below forbids the analogous noise, and ADR 0034 section 3 gives the duplicate/complementary
test in general form.

**Withheld deliberately:** no finding when any path reaches the terminal layer (a client that
selects that path succeeds), no partial-reachability finding, no cluster-level aggregate, and
no `KAFKA_CLUSTER_UNHEALTHY`, `KAFKA_BROKER_DOWN` or `KAFKA_NETWORK_BROKEN`. Each is recorded
with the fact whose absence blocks it.

---

### `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE`

The second Kafka finding, and the counterpart to the one above. Settled and implemented
together by **ADR 0035**, because every structural question it could have raised was already
answered by ADR 0034.

| | |
|---|---|
| **Trigger** | The `kafka.metadata` exchange is PASS, and the advertisement it carried is FAIL with `PROTOCOL_UNEXPECTED_RESPONSE` — the producer's record that the reported host and port do not name somewhere a client could connect |
| **Claim** | The cluster answered Metadata, and the endpoint it reported for this broker cannot be used. Never that a configuration is wrong: Metadata says what a broker reports, not how it arrived at it |
| **Kind / severity / confidence** | `CONFIRMED` / `ERROR` / `HIGH`. ERROR on the same per-subject reading as the reachability finding — a broker no client can connect to prevents correct use of that broker — and not by inheritance from it |
| **Vantage** | **`vantageDependent: false`**, and this is the sharpest contrast with the finding above. The defect is in the values that arrived, so every client reading the same response receives the same unusable pair from any position. Saying `true` would invite a retry that cannot help |
| **Subject** | The advertisement's own subject, unrepaired: `:9093` for a missing host, `broker.internal:-1` for an impossible port |
| **Evidence** | The `kafka.metadata` node and the `kafka.broker_advertised` node. No transport evidence, because none exists — Phase 3.4 runs no sweep for an advertisement it cannot turn into a target |
| **Layer** | `L6`, and here it coincides with `summary.firstBrokenLayer`, because the advertisement is the only FAIL node in such a run. In the reachability finding the two differ; `docs/REPORT_SCHEMA.md` section 7.5 explains why both are correct |

**The two Kafka findings are mutually exclusive by construction.** An advertisement is PASS
exactly when it names a usable endpoint and FAIL exactly when it does not; the reachability
rule requires PASS and this one requires FAIL. No engine suppression exists, and none is needed.

**The subcase is structural, not prose.** `kafka.broker.advertised_host` and
`kafka.broker.advertised_port` on the cited node distinguish "no host" from "impossible port"
exactly, so the summary states one stable claim and does not vary across them. Section 3.1
item 13 is the reason: a consumer that needs the distinction reads the evidence, never the
sentence.

**Not covered, and recorded as a gap rather than as coverage:** an entry whose text cannot be a
subject reference at all — a control character, invalid UTF-8, leading whitespace — produces
**no evidence node**, and survives only as `kafka.metadata.unrepresentable_entry_count` on the
exchange. A finding with nothing to reference is not expressible under ADR 0014. See ADR 0035
section 1.

---

### The twelve PostgreSQL findings

Fixed by ADR 0040 as ADR 0034 did for Kafka, and **implemented in Phase 4.6b** as
`internal/diagnosis/postgres` — four rules, one per anchor step.

| Code | Anchor step | Severity | `vantageDependent` |
|---|---|---|---|
| `POSTGRES_TLS_DECLINED` | `postgres.ssl_request` | ERROR | false |
| `POSTGRES_STARTUP_FAILED` | `postgres.startup` | ERROR | true |
| `POSTGRES_CONNECTION_NOT_PERMITTED` | `postgres.startup` / `postgres.authentication` | ERROR | true |
| `POSTGRES_CREDENTIALS_REJECTED` | `postgres.authentication` | ERROR | false |
| `POSTGRES_PEER_VERIFICATION_FAILED` | `postgres.authentication` | ERROR | true |
| `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` | `postgres.authentication` | WARN on FAIL, INFO on UNKNOWN | true |
| `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | `postgres.authentication` | INFO | true |
| `POSTGRES_CREDENTIAL_WITHHELD` | `postgres.authentication` | WARN | false |
| `POSTGRES_AUTHENTICATION_FAILED` | `postgres.authentication` | ERROR | true |
| `POSTGRES_DATABASE_NOT_FOUND` | `postgres.session` | ERROR | false |
| `POSTGRES_DATABASE_CONNECT_DENIED` | `postgres.session` | ERROR | false |
| `POSTGRES_SESSION_ESTABLISHMENT_FAILED` | `postgres.session` | ERROR | true |

Every one is `CONFIRMED` / `HIGH`, and none is a `HYPOTHESIS`: each states a deliberately
narrow claim that is directly evidenced, and not knowing a root cause is grounds for making
the claim narrower rather than for hedging the kind or the confidence. See ADR 0040 §6.2.

Five properties of the set are worth reading before the record itself:

- **At most one primary Phase 4.6 diagnosis per node.** Each non-passing `postgres.*` node
  yields at most one of the twelve, and a failed one yields exactly one, so section 5's noise
  is prevented structurally rather than by suppression. **This is a scope, not a permanent
  invariant** — a future complementary claim on the same node (security posture, certificate
  posture) is explicitly not foreclosed, per ADR 0034 section 3's duplicate-versus-
  complementary test. There is no engine deduplication and none is wanted.
- **Each step has a floor**, and the floors name only the boundary: *the exchange did not
  complete*. A pooler's `08P01` lands there. It never becomes a credential, database or
  capacity claim. The floors' codes say `FAILED` rather than `REJECTED` because their triggers
  include peer closes and malformed frames, where nothing rejected anything.
- **Severity varies within one code, once.** `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE`
  is WARN when the endpoint offers nothing svcdoctor performs and INFO when svcdoctor lacks
  what the endpoint demands. The claim is identical; the impact is not.
- **Seven of the twelve are vantage-dependent**, on two distinct grounds: proved, where
  `pg_hba` matches the source address to select both the refusal and the demanded
  authentication method, and where an element on the path can answer in the endpoint's place;
  and unassertable, where a floor deliberately does not attribute a cause and so cannot
  exclude a source-keyed one. `false` is a positive claim of position-independence, not a
  default.
- **Authentication has a direction, and the two directions never share a `FailureClass`.**
  *The peer refused what svcdoctor presented* and *the peer could not prove itself to
  svcdoctor* are different observations leading to opposite actions, so
  `POSTGRES_CREDENTIALS_REJECTED` and `POSTGRES_PEER_VERIFICATION_FAILED` rest on different
  classes rather than on a predicate that inspects a SQLSTATE. This is a generic
  authentication invariant, not a PostgreSQL one — see ADR 0040 section 5.1.
- **No PostgreSQL finding fires on `dns.lookup`, `tcp.connect` or `tls.handshake`.** Those are
  generic transport nodes. ADR 0043 gives the first two an owner — see section 7 — so a
  PostgreSQL run failing at L1 or L2 will produce a generic finding once those rules exist.
  **`tls.handshake` under `postgres.ssl_request` remains unowned**: it is not generic, because
  its parent is a service node, and no PostgreSQL rule anchors there. That gap is measured in
  ADR 0043 section 15 and is still a release-gate item in `docs/BACKLOG.md`.

See ADR 0040 for the trigger, claim, must-not-claim list, evidence set and recommendation
boundary of each, and `docs/validation/POSTGRES_PHASE46_DIAGNOSIS_STUDY.md` for the evidence.


## 7. The three generic transport findings

Fixed by **ADR 0043** and **not yet implemented**. They are the first findings owned by
`internal/diagnosis/transport/`, and the first that speak about the operator's target rather
than about a service.

They are possible because ADR 0042 records the requested target as an L0 evidence node and
parents the sweep it caused to it. A rule enumerates those anchors and descends by typed step
— direct `dns.lookup` children, then their direct `tcp.connect` children. **Direct, never
transitive**: a Kafka advertised sweep sits transitively below a bootstrap target, and a
descendant walk would diagnose a discovered broker and duplicate the Kafka finding that owns
it.

| Code | Anchor | Trigger | Severity | `vantageDependent` |
|---|---|---|---|---|
| `DNS_NAME_NOT_RESOLVED` | `dns.lookup` | FAIL with `DNS_NO_ADDRESS` | ERROR | true |
| `DNS_RESOLUTION_FAILED` | `dns.lookup` | FAIL with `DNS_TIMEOUT` or `DNS_RESOLVER_FAILURE` | ERROR | true |
| `TCP_CONNECTION_NOT_ESTABLISHED` | `tcp.connect` | every node FAIL, none PASS, none UNKNOWN or SKIPPED | ERROR | true |

All three are `CONFIRMED` / `HIGH`, and all three take the **anchor's subject** — the logical
`db.example.com:5432`, never a resolved address. That subject is the point of ADR 0042: before
it, a run that failed at DNS carried the requested `host:port` in no subject at all.

**What they refuse to say is the substance of the policy.**

- `DNS_NAME_NOT_RESOLVED` says the hostname did not resolve to a usable address from this
  vantage. It never says the name does not exist — the DNS probe deliberately emits
  `DNS_NO_ADDRESS` rather than `DNS_NXDOMAIN`, because Go's resolver folds "no such name" and
  "no address record" together, and the finding inherits that restraint rather than undoing it.
- `TCP_CONNECTION_NOT_ESTABLISHED` says no measured connection completed. It never says
  *unreachable*: a refused connection proves a host answered. It names no firewall, route,
  security group or listener, because the evidence distinguishes none of them.

**One TCP code covers six failure classes, deliberately.** Refused and timed-out do suggest
different remediation, but the split is not stable across one endpoint — an IPv4 address with
nothing listening and a filtered IPv6 address produce both in one run, and every tiebreak
would make the public code depend on address family. The distribution stays in `FailureClass`
on the cited evidence, which is the vocabulary that exists to carry it; a consumer that needs
refused-versus-timeout reads there, never the finding code.

**Withheld, and the evidence stays in the report either way:**

- **any path succeeded** — a client that selects it succeeds, so "could not connect" would be
  false. One usable address out of twenty still withholds.
- **some paths failed and others were never measured** — the run did not establish that every
  path fails. `Result.Incomplete()` and exit code 4 already report incompleteness, and a
  HYPOTHESIS here would add a weaker second copy of that fact.
- **cancellation and budget exhaustion** — the probes already record these as `UNKNOWN` with an
  `EXEC_*` class, so a rule that fires only on FAIL cannot turn them into a target failure.

**A consequence worth knowing before reading a report.** In a dual-stack run where one family
fails and the other works, `summary.firstBrokenLayer` is `L2` and there is no TCP finding.
That is not a contradiction: the field reports the earliest positively evidenced failure, and
the finding reports a conclusion about the target — which was reached.

**Generic TLS is deferred, not forgotten.** No production run produces a `tls.handshake` node
whose direct parent is a requested `tcp.connect`, so a TLS policy today would govern evidence
that cannot occur. See ADR 0043 sections 14 and 15.
