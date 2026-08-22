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
POSTGRES_TLS_POLICY_MISMATCH
```

### Generic transport findings

Generic transport findings use the layer as the namespace:

```text
DNS_RESOLUTION_FAILED
TCP_CONNECTION_REFUSED
TLS_CERTIFICATE_EXPIRED
```

> **These remain naming examples. No generic transport rule is authorized, and none exists.**
> The only finding code svcdoctor produces today is `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`.
> ADR 0034 gives advertised-endpoint transport failures to the Kafka rule outright, so a
> generic rule firing on the same evidence would duplicate it. Whether generic transport
> findings should exist *at all* is still open, and it is blocked on a fact rather than on
> effort: it needs run intent — "is this a Kafka diagnosis or a bare endpoint check?" — which
> `diagnosis.Rule` cannot see, because it receives only a `Graph`. The bootstrap path, the
> other place such a rule would fire, has no owner until application orchestration exists.

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

## 6. Initial known finding

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
