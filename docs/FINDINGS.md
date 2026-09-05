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

> **Three generic codes exist, implemented in Phase 4.9b.** `DNS_NAME_NOT_RESOLVED`,
> `DNS_RESOLUTION_FAILED` and `TCP_CONNECTION_NOT_ESTABLISHED` are produced by
> `internal/diagnosis/transport` for the operator-requested target; section 7 carries them.
> With the two `KAFKA_ADVERTISED_ENDPOINT_*` and the twelve `POSTGRES_*` codes in section 6,
> svcdoctor produces **twenty-four**.
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

   **7a. A discriminator is one open question, and it is prose.** ADR 0086 §2.2 freezes what it
   means for two hypotheses to be *indistinguishable* — competing explanations of one subject
   that one observation would separate — and deliberately **does not** freeze how "the same open
   question" is decided mechanically. `Discriminator` is human-facing text, so making it a
   runtime grouping key would let a wording-only edit change what svcdoctor groups, which is the
   coupling Phase 10.2A spent a phase removing; the identity mechanism is deferred to the phase
   that has a real competing pair to decide it against (ADR 0086 §2.2a). What **is** permanent is
   that fuzzy or semantic matching of a discriminator is forbidden, exactly as it is for
   convergence prose.

   Two things bind a rule author today. **Keep the sentence constant** across the explanations
   one observation would settle — it costs nothing now and is what makes the later decision
   cheap. And **never widen a claim to manufacture a pair**: a competing pair is usually a sign
   the claim was drawn too wide, and the repository's own three worst candidates — a TCP timeout,
   PostgreSQL `53300`, a pooler's `08P01` — were each resolved into one narrow `CONFIRMED` claim
   instead (ADR 0086 §4.3). A set is never itself a finding, and no code exists for one.
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
19. **Two findings merge only when they already agree about everything a merged finding
    *takes*.** This is the rule-authoring contract, and it is mechanical — answering "can these
    two merge?" needs no knowledge of rule names, wiring order or the merge implementation:

    ```text
    same code  AND  same subject          -> they are candidates
      AND same layer
      AND compatible discriminator         (at most one distinct non-empty value)
      AND byte-identical summary
      AND byte-identical detail
                                           -> they merge into one finding whose
                                              evidence is the union
    otherwise                              -> they remain two findings
    ```

    Everything else — severity, confidence, kind, vantage dependence, the evidence union, the
    recommendation union — is reconciled by an order-independent operation and never chosen.

    **Remaining distinct is the safe outcome.** Two findings that look like duplicates are two
    claims that were both made; one finding whose sentence describes half of its own evidence is
    a claim nobody made. Phase 10.2A measured three reachable Kafka shapes where the old
    tie-break produced the second, including one that promoted a hypothesis about an unmeasured
    broker into a confirmed claim. See ADR 0081 §2.2b.

    **The practical consequence for a rule author:** if your prose names something your subject
    does not carry — a broker number, an address, a count — then two of your findings about one
    subject will *not* merge, and that is correct. If you want two rules to converge, have them
    share the constant that states the claim.
20. **A blocked step may be cited only when it is what the claim is about.** Rule 11 says a
    blocked step is never cited as a *cause*. This is its other half, and both are needed because
    the repository does each of them today.

    ```text
    the claim is about the subject's condition   -> a blocked node is evidence for nothing.
                                                    Cite its blocker, or make no claim at all.
    the claim's subject IS the step that did      -> cite the blocked node, and cite its blocker
    not run                                         so a reader can check why
    ```

    Three findings are instances of the second: `KAFKA_CREDENTIAL_WITHHELD` and
    `POSTGRES_CREDENTIAL_WITHHELD` both state *why nothing was attempted*, and
    `POSTGRES_ADMISSION_SCOPE` counts addresses at which *no admission decision was observed*. All
    three cite a node the graph records as blocked, and all three are correct.

    **The consequence for a rule author who reaches for `diagnosis.BasisBuilder`:**
    `BasisBuilder.Freeze` refuses a blocked node in the supporting set unconditionally, so a rule
    of the second shape cannot express itself through a basis today. That is a recorded limitation
    rather than a verdict on the finding — see ADR 0087 §2.5. Build `EvidenceRefs` directly, as
    those three do.

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

### 4.1 The same discipline applies to presentation

A renderer produces no findings, and it can still publish a claim nobody made. Three ways it
has been caught trying, all now under test:

- **An endpoint svcdoctor's own budget never measured is not one that refused.** The Kafka
  `topology` line counts them separately — `2 of 3 advertised broker endpoints reached, 1 not
  measured` — because without the second clause the first asserts a failure nobody observed.
- **A step that was never timed is not one that took no time.** `domain.Elapsed` carries
  whether a measurement was taken, and the terminal renderer renders an absence as an empty
  cell and a measured zero as `0s`. Before it existed, both were the same blank column.
- **A failed peer verification is not a rejected credential.** `AUTH_PEER_VERIFICATION_FAILED`
  and `KAFKA_PEER_VERIFICATION_FAILED` are rendered as themselves. Translating either into
  "wrong password" would send an operator to rotate a credential that is correct.

A renderer also never *hides* a claim it did not expect. A node the service's journey does not
place is rendered anyway — including beneath an advertised broker, where an authentication row
would mean ADR 0050 had been broken upstream. Concealing that in the one output an operator
reads is worse than reporting it.

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

### 5.1 The failure boundary states it positively

Section 5 forbids the worst mistake — a DNS failure followed by three fabricated
downstream failures. What it does not give an operator is the *positive*
statement, which is the one that narrows an investigation.

`DIAG_FAILURE_BOUNDARY` is that statement, activated in Phase 10.1B (ADR 0079).
For each **subject**, it names the deepest stage that positively succeeded and
the shallowest that positively failed, and cites both.

```text
DNS       PASS   <- last confirmed-good
TCP       FAIL   <- first evidenced failure
TLS       SKIPPED
```

Four properties make it honest, and each is a test:

1. **It is per subject, never per run.** A healthy bootstrap and one unreachable
   discovered endpoint produce two boundaries. Merging them would say "the
   service is unreachable", which is true of neither.
2. **`SKIPPED` and `UNKNOWN` are neither half.** A stage that did not run is not
   a confirmed-good boundary and is not a failure. A subject whose only
   non-passing stage is unmeasured has **no boundary at all**.
3. **It is not a cause.** It states where observation stopped succeeding. "TLS
   configuration caused the incident" is a hypothesis and this rule produces
   none.
4. **A missing half is reported as missing.** When the first stage measured is
   the one that failed, the finding cites one node and says so, rather than
   promoting some earlier success into a contrast that did not happen.

It is `CONFIRMED` at `INFO`: it restates measured states and infers nothing, and
it describes *where* rather than *how bad*. `INFO` never affects an exit code
(`docs/CI.md`), so a boundary cannot turn an otherwise clean run into exit 1.

It is the first member of the generic `DIAG_` namespace — produced by generic
machinery over any service's graph, alongside the existing `DNS_`, `TCP_` and
`TLS_` codes. A second `DIAG_` code needs the same kind of frozen contract ADR
0079 gave this one.

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

### The two Kafka topology-scoped findings

**Added in Phase 10.2** and settled by **ADR 0084**, which reopens ADR 0034 §10 on the condition
that record named for itself. They are the first *service* intelligence built on the Phase 10
reasoning model, and they are deliberately the only two: every per-endpoint claim the evidence
supports was already covered by the thirteen Kafka codes above, and duplicating one would add
nothing.

Both are about **the set** a Metadata response advertised rather than about a member of it, and
both are filed against the endpoint the Metadata question was asked at — never an advertised
endpoint. That is what keeps them from colliding with the per-endpoint findings, whose subject
is the advertised endpoint: semantic identity is `(Code, Subject)` and both halves differ.

#### `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY`

| | |
|---|---|
| **Trigger** | The `kafka.metadata` exchange is PASS, it carried at least one advertisement, and at least one advertised endpoint was **positively** observed not to be reachable |
| **Claim** | The measured scope of advertised-endpoint reachability: how many were reached, how many were not, and how many were not measured. Never a cause, never a verdict |
| **Kind / severity / confidence** | `CONFIRMED` / **`INFO`** / `HIGH` |
| **Subject** | The `kafka.metadata` node's own subject |
| **Layer** | `L6` |
| **Vantage** | `vantageDependent: true` |
| **Evidence** | The exchange, every advertisement node, one reaching node per reached endpoint, and the causal failure node of each unreached one |

**Why `INFO`.** ADR 0034 §13 fixed the rule and Phase 10.2 had to re-apply it: severity is the
impact of this finding's own claim about its own subject, and never a count-derived cluster
verdict. Escalating because three endpoints failed rather than one *is* that verdict. The impact
of an unreachable broker endpoint is already reported at `ERROR`, once per endpoint, by
`KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`. A useful consequence: Phase 10.2 cannot change any exit
code.

**Three sentences, and the third is the one that matters.**

| Condition | Sentence |
|---|---|
| complete, none reached | *None of the N broker endpoints this cluster advertised could be reached from this vantage point* |
| complete, some reached | *K of the N … could not be reached …; the other M were reached* |
| **not complete** | *K of the N … could not be reached …; M were reached and P were not measured* |

On a set with anything unmeasured, both "none of them" and "only that one" assert a total nobody
established — they fail in opposite directions and need the same missing fact. Completeness has
two halves and needs both: no advertised endpoint unmeasured, **and** `RuleContext.Incomplete`
false. Neither implies the other.

**Nothing is emitted for a healthy run.** Every endpoint reached produces no finding; the
terminal already prints `topology  3 of 3 advertised broker endpoints reached`. The two counts
are proven to agree, over all 512 three-endpoint shapes, because `internal/app`,
`internal/render/terminal` and `internal/diagnosis/kafka` each hold ADR 0051's classification and
depguard forbids any two of them sharing an implementation.

#### `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE`

| | |
|---|---|
| **Trigger** | Metadata PASS; **every** advertised endpoint measured and the run not cut short; at least one positively failed; and **none** was reached |
| **Claim** | The endpoints this cluster advertised **may not be usable** from this client's network position |
| **Kind / severity / confidence** | `HYPOTHESIS` / `WARN` / **`MEDIUM`, and `HIGH` is unreachable** |
| **Subject** | The exchange's subject — the same as the observation's, and a different code |
| **Vantage** | `vantageDependent: true` |
| **Discriminator** | *whether the advertised addresses are the ones a client on this network is expected to use to reach these brokers* |
| **Recommendation** | One `NEXT_EVIDENCE` / `COMPARE`, not self-collectable |

**Why `HIGH` is impossible rather than merely unused.** The rule declares
`diagnosis.AuthorityNone`, and ADR 0081 §2.3 admits `HIGH` only on direct peer authority or
complete contrast. No Kafka field says "my advertised address is unreachable from where you
are", and routing, packet filtering, a bootstrap-side proxy and a broker-side outage are all
unexcluded. Raising the ceiling would mean declaring an authority the rule does not have — a
source change a reviewer sees, rather than a threshold that drifts. **Commonness is not
evidence**: the advertised-listener misconfiguration being the best-known Kafka failure in the
field is a fact about the population of incidents, not about this one.

**Why it is topology-scoped and there is no per-endpoint version.** *"broker-3 failed and its
peers succeeded, so broker-3's advertisement may be unsuitable"* is not a weaker form of this
claim — it is **contradicted by its own premise**. Two advertised addresses in the same plane
were reached from this client, so the advertised addresses demonstrably work here. A reachable
peer is observed evidence inconsistent with the claim, and a rule holding contradicting evidence
emits nothing (ADR 0081 §2.4).

**Distinguished from `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` by vantage, and the names are close on
purpose.** UNUSABLE is `vantageDependent: false` — the cluster reported a pair no client anywhere
could act on. This is `vantageDependent: true` — the pair is well formed and may serve other
clients perfectly, and what is in question is whether it serves one *here*. That is the same
contrast ADR 0035 drew between UNUSABLE and UNREACHABLE, reused rather than reinvented.

#### What the prose may not say, and why it is a test

svcdoctor knows the endpoint a Metadata response reported. It does **not** know any broker's
configuration, and it never will in BASIC.

| Admissible | Inadmissible |
|---|---|
| *cluster metadata advertised this endpoint* | *`advertised.listeners` is set to X* |
| *these endpoints may not be usable from this client's network position* | *`advertised.listeners` is misconfigured* |
| *no measured path reached them* | *a firewall is blocking them* |
| *the bootstrap endpoint was reached* | *the cluster is up but the brokers are down* |

No value a peer chose is interpolated into any of this prose — only integers counted off the
graph's own structure. The advertised hostname, port and node identifier travel on the subject
and on the evidence, where redaction transforms them. The property is asserted as **byte equality
of the prose across different advertised names**, which is stronger than a substring search: the
first version of that check was a substring search, and a fuzzer refuted it in under a second
with the hostname `Brok`, which is a substring of the word "broker" that every one of these
sentences contains and none of them copied.

#### What stays refused

`KAFKA_CLUSTER_UNHEALTHY`, `KAFKA_BROKER_DOWN` and `KAFKA_NETWORK_BROKEN` remain unauthorized. So
do controller and KRaft inference, partition, replication, ISR and consumer-group claims, a
per-endpoint suitability hypothesis, partial multi-address reachability within one advertisement
(ADR 0034 §6, untouched), and **address-shape heuristics** — a reachable loopback, RFC 1918 or
`.internal` advertisement produces nothing at all, because a broker on the same host as the
client is a correct deployment. See ADR 0084 §7.

#### The refusal that is a feature

One advertised endpoint, unreachable, after a reachable bootstrap: svcdoctor emits the confirmed
unreachability, the boundary, the topology observation and the hypothesis at `MEDIUM` — and it
does **not** choose between *a network path that is unavailable* and *an advertisement unsuitable
for this client*. Golden incident fixture K14 forbids "the cause", "therefore", "this proves" and
"the only explanation" for exactly that reason.

---

### The ten Kafka protocol findings

**Implemented in Phase 6.1c-P2** as `internal/diagnosis/kafka.Protocol`, one rule over four
steps. They exist because ADR 0054 stopped Phase 6.1c: until they landed, every Kafka protocol
outcome — a rejected credential included — would have reached a report as `findings: []`,
`status: OK`, exit 0 the moment a composition root existed.

| Code | Anchor step | State | Severity | `vantageDependent` |
|---|---|---|---|---|
| `KAFKA_API_VERSIONS_VERSION_REJECTED` | `kafka.api_versions` | FAIL | ERROR | false |
| `KAFKA_API_VERSIONS_NOT_COMPLETED` | `kafka.api_versions` | FAIL | ERROR | true |
| `KAFKA_AUTH_MECHANISM_NOT_OFFERED` | `kafka.sasl_handshake`, `kafka.sasl_authenticate` | FAIL | ERROR | false |
| `KAFKA_SASL_HANDSHAKE_NOT_COMPLETED` | `kafka.sasl_handshake` | FAIL | ERROR | true |
| `KAFKA_CREDENTIALS_REJECTED` | `kafka.sasl_authenticate` | FAIL | ERROR | false |
| `KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | `kafka.sasl_authenticate` | UNKNOWN | INFO | false |
| `KAFKA_CREDENTIAL_WITHHELD` | `kafka.sasl_authenticate` | SKIPPED | WARN | true |
| `KAFKA_CREDENTIAL_NOT_CONFIGURED` | `kafka.sasl_authenticate` | SKIPPED | WARN | false |
| `KAFKA_AUTHENTICATION_NOT_COMPLETED` | `kafka.sasl_authenticate` | FAIL | ERROR | true |
| `KAFKA_METADATA_NOT_COMPLETED` | `kafka.metadata` | FAIL | ERROR | true |

All ten are `CONFIRMED` with `HIGH` confidence: each restates a positively recorded outcome
with no inferential step, so none carries a discriminator. The subject is always the **concrete
endpoint** the exchange ran against, never the logical bootstrap target — a protocol outcome is
a fact about the peer that produced it.

**Three floors, not one.** "The exchange did not complete" is a different sentence at L4, L5
and L6: *this may not be a Kafka broker*, *the negotiation broke down*, and *the cluster
answered nothing about itself*. Each floor names the conclusions it is **not** drawing, and
those denials are asserted by test rather than trusted.

**Five authentication outcomes stay disjoint** — the distinction `docs/ARCHITECTURE.md` §5.7c
fixes. Disjointness comes from the evidence `State` and `FailureClass`, never from runtime
precedence or suppression:

| Fact | State | Class | Code |
|---|---|---|---|
| the peer does not offer the mechanism | FAIL | `AUTH_MECHANISM_NOT_OFFERED` | `KAFKA_AUTH_MECHANISM_NOT_OFFERED` |
| svcdoctor cannot perform the mechanism | UNKNOWN | `AUTH_MECHANISM_UNSUPPORTED` | `..._UNSUPPORTED_BY_SVCDOCTOR` |
| a credential existed and policy withheld it | SKIPPED | `EXEC_SKIPPED_BY_POLICY` | `KAFKA_CREDENTIAL_WITHHELD` |
| the run configured no credential | SKIPPED | `EXEC_REQUIRED_INPUT_MISSING` | `KAFKA_CREDENTIAL_NOT_CONFIGURED` |
| the peer evaluated a credential and refused it | FAIL | `AUTH_CREDENTIALS_REJECTED` | `KAFKA_CREDENTIALS_REJECTED` |

**`vantageDependent` diverges from PostgreSQL deliberately, and the divergence is the point.**
`internal/diagnosis/postgres` sets `true` on its comparable claims because `pg_hba.conf`
selects the authentication method by **source address**, so what the endpoint required is partly
a fact about who asked. Kafka has no such rule: `sasl.enabled.mechanisms` is configured per
**listener**, and one address and port is one listener. So the Kafka claims that name what a
listener required are `false`, and only the three floors — which attribute no cause and
therefore cannot exclude a path-keyed one — plus the channel-dependent withheld claim are
`true`. Copying PostgreSQL's answer would have been wrong in five places.

**The table is closed.** A `(step, state, failureClass)` triple absent from it produces no
finding, including a class a later phase adds. `UNKNOWN` with `EXEC_LOCAL_TIMEOUT` or
`EXEC_CANCELLED` is deliberately unmapped at every step: svcdoctor's own budget ended the
measurement and nothing was learned about the endpoint, so those reach the operator through
`Result.Incomplete()` and exit code 4. No `PASS` produces a finding — ADR 0052 makes the success
line a renderer concern.

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

### The two PostgreSQL server-authority findings

Added by **ADR 0085** in Phase 10.3. Both are still `CONFIRMED` / `HIGH`, so the paragraph above
stands: PostgreSQL produces no hypothesis.

| Code | Anchor | Severity | `vantageDependent` |
|---|---|---|---|
| `POSTGRES_CONNECTION_LIMIT_REACHED` | `postgres.session` | ERROR | **false** |
| `POSTGRES_ADMISSION_SCOPE` | the requested target, over every `postgres.startup` node | **INFO** | true |

**`POSTGRES_CONNECTION_LIMIT_REACHED`** is the exemplar of the phase's whole point. PostgreSQL
answers `53300` — `too_many_connections` — in a field its own protocol defines, so *the endpoint
authoritatively rejected this attempted session with its `too_many_connections` condition* is
`HIGH` on **direct authority**: the peer said so and svcdoctor is repeating it.

Two things it does **not** carry, and the second is the one easy to get wrong.

*It does not carry why.* A leak, a limit set low, a pool sized wrongly, a burst, and a condition
that has already passed are all compatible with the same five characters, and the remedy differs
for every one — so the finding carries a `NEXT_EVIDENCE` / `COMPARE` recommendation (*identify the
connection limits applicable to this attempted session and compare their current usage with their
configured limits*, `SelfCollectable: false`, because BASIC executes no SQL) and never a
remediation. The identification step is part of the advice on purpose: the advice names **no**
member of the applicable set, because sending an operator straight to one setting would assert by
implication the thing the response does not say.
"Increase the connection limit" is refused permanently.

*It does not carry endpoint-wide scope.* `53300` is raised when **a** connection limit applicable
to the session being admitted has been reached, and PostgreSQL has several — `max_connections`,
the reserved-slot margins, a database's `CONNECTION LIMIT` and a role's — and the `ErrorResponse`
identifies none of them. The repository's own integration fixture is the counterexample: a role
with `CONNECTION LIMIT 0` yields `53300` on a server with connections to spare. So the finding
says *a connection limit that applied to this attempted session had been reached* and *which
limit was reached is not in the response*, and it never says that no slot was available, that the
endpoint was out of connections, or that another session would have been refused. Widening the
scope of an authoritative statement is the same error as inventing a cause for it.

It replaces the session floor for this class, which used to restate the condition in prose. A
consumer must not parse `detail` to recover semantics (§3.1 rule 13), and what was missing was a
code. `vantageDependent` moved `true` → `false` with it, and that flag means **this claim is not
inferred from a source-address-dependent observation** — the endpoint named the condition in its
own protocol, and nothing is read off the address svcdoctor dialled from. It does *not* mean the
condition is an endpoint-wide invariant: vantage dependence describes how a claim was derived,
not how widely what it asserts holds. The floor's own restatement, which still serves
`postgres.startup` and `postgres.authentication`, carries the same scope for the same reason.

**`POSTGRES_ADMISSION_SCOPE`** is the completeness-and-contrast aggregate, and it is the
PostgreSQL counterpart of the two Kafka topology findings. `POSTGRES_CONNECTION_NOT_PERMITTED`
already says *this address was refused before any credential*, once per address; two facts are
not in that conjunction and cannot be recovered from it — **whether the set was complete**, and
**whether the addresses answered alike**. `pg_hba.conf` matches on address, so "one refused and
one admitted" is a materially different diagnosis from "every address refused", and before this
finding a dual-stack target with a rule for its A record and none for its AAAA record reported
one ERROR and exit 1 while its selected path succeeded completely, with nothing saying so.

Three categories, never two: refused, admitted, **undetermined**. It fires only with at least two
addresses classified and at least one positively refused — with one address it would restate what
the per-address finding already says — and only a complete set, with nothing undetermined *and*
`Incomplete` false, may say "at all N addresses". It is `INFO` because severity is the impact of
this finding's own claim and never a count-derived verdict (ADR 0034 §13), so it moves no exit
code.

### The observed role is not a finding, and that is a decision

`postgres.in_hot_standby` is the closest thing svcdoctor has to `pg_is_in_recovery()` without
executing SQL, and against a real Patroni cluster it tracked that function exactly. **No rule
reads it and none may.** It reaches the operator as a terminal *observation line* — `recovery
in recovery` — in the mechanism `internal/render/terminal` already carried for endpoint-reported
facts, beside a note stating what the observation is and is not.

The reasoning is ADR 0085 §4, and the short form is that a role finding would restate one
attribute the report already carries, while ADR 0040 §19's rule stands: findings are for what a
reader must act on, and without declared intent there is nothing to act on. A pooler forwards a
cached value, so *"this endpoint is a replica"* is not even a supported observation; a standby is
not a fault; and `default_transaction_read_only` was `off` on a real standby, so nothing here
answers "can I write". `POSTGRES_PHASE46_DIAGNOSIS_STUDY.md` §5 rejected all three sentences by
name and they stay rejected.

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
- **No PostgreSQL finding fires on `dns.lookup` or `tcp.connect`.** Those are generic transport
  nodes and ADR 0043 owns them — see section 7.
- **`tls.handshake` under `postgres.ssl_request` is PostgreSQL's**, decided by ADR 0044 and
  implemented in Phase 4.9d as the `TLS` rule. It is not generic, because its parent is a
  service node: the handshake exists only because PostgreSQL negotiated the upgrade. Five
  codes — `POSTGRES_TLS_UPGRADE_NOT_HONORED`, `_IDENTITY_MISMATCH`, `_CHAIN_NOT_TRUSTED`,
  `_CERTIFICATE_NOT_VALID_NOW`, `_HANDSHAKE_FAILED` — all `CONFIRMED` / `ERROR` / `HIGH` /
  `vantageDependent: true`, subjected to the concrete endpoint.
- **These findings are endpoint-scoped, and that is the deliberate difference from section 7.**
  A generic transport finding claims something about *the requested target*, so one working
  path withholds it. A PostgreSQL finding claims something about *this endpoint*, so a second
  address working withholds nothing: a dual-stack target whose IPv4 address presents a bad
  certificate is a defect every client that selects IPv4 will meet.
- The predicate requires the negotiation itself to have **passed**, which is what keeps the
  rule disjoint from `POSTGRES_TLS_DECLINED` and excludes the SKIPPED handshake node the
  adapter mints when the negotiation failed. ADR 0044 supersedes this record's earlier refusal
  and argues why.
- **`POSTGRES_SSL_NEGOTIATION_FAILED`** is the L3 floor, added by ADR 0045: the negotiation
  failed for a reason that is not a decline — an answer the protocol does not define, a peer
  that closed, a reply that could not be decoded. `CONFIRMED` / `ERROR` / `HIGH`, and
  `vantageDependent: true` where `POSTGRES_TLS_DECLINED` on the same node is `false`, because a
  floor attributes nothing and cannot exclude a cause keyed on the path. It is what stops a
  wrong port reading as healthy.
- **`POSTGRES_CREDENTIAL_NOT_CONFIGURED`** is added by ADR 0046: the endpoint required
  authentication and the run held nothing to present. `CONFIRMED` / **`WARN`** / `HIGH` /
  `vantageDependent: true`. It is the only PostgreSQL finding produced by a graph in which
  **nothing failed** — every node passed, and the run simply could not continue. Severity is
  WARN because the endpoint did nothing wrong, and `SummaryStatus` stays `OK`; whether a run
  that never reached a session should look clean in a terminal is a renderer question that
  ADR 0046 names rather than answers with severity.
- **Absence is never evidence.** `POSTGRES_CREDENTIAL_NOT_CONFIGURED` fires on an explicit
  SKIPPED authentication node carrying `EXEC_REQUIRED_INPUT_MISSING`, never on the *absence* of
  an authentication node — because a run cancelled before the credentialed step leaves exactly
  that absence, and a rule reading it would claim the wrong thing about the wrong run.

See ADR 0040 for the trigger, claim, must-not-claim list, evidence set and recommendation
boundary of each, and `docs/validation/POSTGRES_PHASE46_DIAGNOSIS_STUDY.md` for the evidence.


## 7. The eight generic transport findings

Three fixed by **ADR 0043** and implemented in Phase 4.9b, five by **ADR 0053** and
implemented in Phase 6.1b — `internal/diagnosis/transport`, three rules, `DNS`, `TCP` and
`TLS`. They are the findings that speak about the operator's target rather than about a
service.

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

### 7.1 The five generic TLS findings

**ADR 0053, implemented in Phase 6.1b.** They own a `tls.handshake` that is a **direct child**
of a `tcp.connect` in a requested-target sweep, and nothing else.

| Code | Triggering `FailureClass` | Severity | `vantageDependent` |
|---|---|---|---|
| `TLS_ENDPOINT_DOES_NOT_SPEAK_TLS` | `TLS_PEER_NOT_TLS` | ERROR | true |
| `TLS_IDENTITY_MISMATCH` | `TLS_HOSTNAME_MISMATCH` | ERROR | true |
| `TLS_CHAIN_NOT_TRUSTED` | `TLS_UNKNOWN_AUTHORITY` | ERROR | true |
| `TLS_CERTIFICATE_NOT_VALID_NOW` | `TLS_CERTIFICATE_EXPIRED`, `TLS_CERTIFICATE_NOT_YET_VALID` | ERROR | true |
| `TLS_HANDSHAKE_NOT_COMPLETED` | `TLS_HANDSHAKE_FAILURE` (floor) | ERROR | true |

All five are `CONFIRMED` / `HIGH`. **The mapping is closed**: the three declared classes with
no producer — `TLS_VERSION_MISMATCH`, `TLS_CLIENT_CERTIFICATE_REQUIRED`,
`TLS_CLIENT_CERTIFICATE_REJECTED` — gain no code, and a class added later produces nothing
until somebody decides what it may claim.

**They take the endpoint's subject, not the anchor's**, which is the one place they differ
from the three above. A reachability claim is about the address set and one PASS falsifies it;
a certificate is presented by one endpoint, and a sibling succeeding cannot falsify what this
one presented. So **there is no partial-success withholding**, and two failing addresses
produce two findings.

**No code mirrors its `FailureClass` spelling.** Generic codes carry no service prefix, so a
report holds `failureClass` and `code` in the same shape — and `TLS_PEER_NOT_TLS` as a code
would have been indistinguishable from the class of the same name. That is why the peer code
and the floor were renamed during review.

**What they refuse to say:**

- `TLS_ENDPOINT_DOES_NOT_SPEAK_TLS` says this endpoint answered with something that was not
  TLS, **on this attempt, from this vantage**. It never says the endpoint cannot speak TLS,
  that the port is wrong, or that a proxy or firewall intervened.
- `TLS_CHAIN_NOT_TRUSTED` is a claim about a *pairing*, and names the local half first: the
  trust context is this run's, and a missing or wrong CA on this side produces exactly this
  observation. It never says the certificate is objectively invalid.
- `TLS_CERTIFICATE_NOT_VALID_NOW` compares a window against **this host's clock** and blames
  neither. A certificate outside its window and a host with a wrong clock are
  indistinguishable from here.
- `TLS_HANDSHAKE_NOT_COMPLETED` is certain that no handshake completed and says nothing about
  why — not the version, the cipher suites, a client certificate, or anything on the path.

**UNKNOWN and SKIPPED produce no TLS finding.** A cancelled or budget-exhausted handshake
learned nothing about the endpoint, and a blocked step is never a cause; those reach
`Result.Incomplete()` through the application boundary instead.

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

**One guard is worth knowing about before adding a fourth code.** `internal/vocabulary` holds a
module-wide allow-list of exactly these three, and `internal/diagnosis/transport` asserts the
same three locally. A new generic code has to be added to both, which is the point: it cannot
arrive as a local constant, and every `TLS_` code is still rejected outright.

## 8. The eleven RabbitMQ findings

Frozen by **ADR 0069 §7** in Phase 8.1 and implemented in Phase 8.2 by
`internal/diagnosis/rabbitmq`, whose three rules produce exactly these and nothing else.

**A twelfth was struck in Phase 8.2-R1.** `RABBITMQ_PEER_VERIFICATION_FAILED` was frozen
before implementation and proved unproducible: SASL PLAIN is not a mutual mechanism, so the
peer returns no proof and `AUTH_PEER_VERIFICATION_FAILED` has no RabbitMQ producer. TLS trust
and identity failures stay with the generic `TLS_*` codes of section 7.1, exactly as they do
for Redis. ADR 0069 §7.1 records the correction.

| Code | Kind | Severity | Owner step |
|---|---|---|---|
| `RABBITMQ_CONNECTION_START_NOT_COMPLETED` | CONFIRMED | ERROR | `rabbitmq.connection_start` |
| `RABBITMQ_AUTH_MECHANISM_NOT_OFFERED` | CONFIRMED | ERROR | `rabbitmq.authentication` |
| `RABBITMQ_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | CONFIRMED | WARN | `rabbitmq.authentication` |
| `RABBITMQ_CREDENTIALS_REJECTED` | CONFIRMED | ERROR | `rabbitmq.authentication` |
| `RABBITMQ_AUTHENTICATION_NOT_COMPLETED` | CONFIRMED | ERROR | `rabbitmq.authentication` |
| `RABBITMQ_CREDENTIAL_NOT_CONFIGURED` | CONFIRMED | WARN | `rabbitmq.authentication` |
| `RABBITMQ_CREDENTIAL_WITHHELD` | CONFIRMED | WARN | `rabbitmq.authentication` |
| `RABBITMQ_VHOST_NOT_FOUND` | CONFIRMED | ERROR | `rabbitmq.connection_open` |
| `RABBITMQ_VHOST_ACCESS_REFUSED` | CONFIRMED | ERROR | `rabbitmq.connection_open` |
| `RABBITMQ_CONNECTION_NOT_PERMITTED` | CONFIRMED | ERROR | `rabbitmq.connection_open` |
| `RABBITMQ_CONNECTION_NOT_ESTABLISHED` | CONFIRMED | ERROR | `rabbitmq.connection_open` |

Three properties of the set are worth stating before it is built.

**Every code reuses an existing generic failure class.** The RabbitMQ-specific knowledge lives
in the code and the detail, never in the class — which is the division section 1 already
requires, and it is why eleven codes cost one failure class rather than eleven.

**No `HYPOTHESIS` finding is authorized.** The one candidate — RabbitMQ's default `guest`
loopback restriction — was dropped because svcdoctor observes its own destination address while
the broker evaluates the restriction against the client's source address. Different ends of the
connection. What survives is a detail sentence gated on the username alone (ADR 0068 §4.1).

**Two conditions may classify but may not speak.** A `541` vhost-down refusal and a
backend-qualified vhost denial are proven from the RabbitMQ source and were **not** reproduced
live, so each may set a normalized attribute and neither may produce a restating sentence. That
is the `namedConditions` rule PostgreSQL already lives under — a restatement requires having
watched a real endpoint produce it — applied before the table exists (ADR 0069 §8).
