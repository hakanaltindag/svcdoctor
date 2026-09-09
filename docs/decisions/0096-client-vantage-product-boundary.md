# ADR 0096 — The client-vantage product boundary

- **Status:** Accepted
- **Date:** 2026-09-09
- **Phase:** 13.0 (product and diagnostic roadmap audit; no production, test or CI change)
- **Upholds:** ADR 0012 (vantage is first-class), ADR 0010 (no raw objects in canonical evidence),
  ADR 0028 (credentials are endpoint-bound), ADR 0078 (*observation != cause*), ADR 0082
  (recommendation safety), ADR 0085 (*observed state != violated intent*), ADR 0092 (planning
  deferred), ADR 0093 §2 and ADR 0094 §2 (the Kubernetes scope decisions)
- **Decides:** nothing about any single feature. It states the test every future scope proposal is
  measured against, and it is written down because the same test has already decided a dozen
  proposals without ever being recorded.

---

## 1. Context

Twelve phases have made scope decisions — Kafka controller inference, PostgreSQL `pg_stat_*`,
PostgreSQL role mismatch, Redis cluster topology, RabbitMQ queue state, Kubernetes Events, logs,
NetworkPolicy, cluster discovery — and **every one of them was refused, or admitted, on the same
ground**. Each record argued the case from first principles again, and each arrived at the same
place by a slightly different route.

Phase 13.0 audited the whole product to decide what to build next. It found that the recurring
question is not "is this feature useful?" — several refused candidates plainly are — but **"is this
something a client, standing where the operator stands, can prove?"**

That test has never been a record. Without one, each proposal is re-litigated, and the risk is not
that a bad decision gets made once: it is that a sequence of individually reasonable expansions
turns svcdoctor into a monitoring or control-plane product without anyone deciding to.

## 2. Decision

### 2.1 The thesis

> **svcdoctor explains what a specific client, from a specific network position, holding a specific
> credential, can prove about its path to a service — and refuses to claim anything that position
> cannot establish.**

Everything below follows from that sentence.

### 2.2 The three questions a scope proposal must answer

A proposal to add an adapter, a finding, an acquisition or a capability is admitted only if all
three are answered affirmatively, and the answers are recorded rather than assumed.

**Q1 — Is it something *this client* can observe?**
The observation must be available to a client holding the credential the operator already has,
from the position the operator is already standing in. An observation that requires an
administrative credential, a server login, an agent, a sidecar or a metrics endpoint fails Q1.

**Q2 — Is the authority *structured*?**
The evidence must come from a field the protocol or API defines — a SQLSTATE, an AMQP reply code, a
Redis error prefix, a Kubernetes `Status.Reason`, an EndpointSlice condition. **Peer prose is not
authority.** A `reason` string, a log line, an error message body or any field whose value set the
peer chooses cannot support a claim, and cannot enter canonical evidence (ADR 0010).

**Q3 — Does the claim stop where the observation stops?**
The finding must restate what was observed and infer no cause from it. *"This replica said its
primary link is unavailable"* passes. *"The primary is down"* fails, because svcdoctor never
observed the primary.

### 2.3 What is permanently outside the boundary

Each of these fails at least one question, and the failing question is named so that a future
proposal argues against the right thing rather than against a mood.

| Outside | Fails |
|---|---|
| Server-side administrative state (`pg_stat_*`, queue depth, cluster membership, node partitions) | Q1 |
| Management and admin APIs used to obtain state the data-plane credential cannot reach | Q1 |
| Metrics scraping, historical baselines, thresholds, trends | Q1, Q3 |
| Container and application logs | Q2 |
| Unbounded peer-chosen `reason` and message strings as the basis of a claim | Q2 |
| Cluster or fleet inventory ("show me everything") | Q1, Q3 |
| Inferred service-to-service call graphs | Q3 |
| Causal narrowing across authoritative observations | Q3 |
| Any control-plane mutation | all three; svcdoctor changes nothing, ever |

**Latency is a special case and stays outside.** Stage durations are measured and reported;
`docs/SCOPE.md` and the PostgreSQL BASIC freeze make duration a *measurement only*. A latency
threshold or verdict fails Q3, because "slow" is a judgement about an expectation svcdoctor was
never given.

### 2.4 Two things this boundary explicitly does not forbid

**Running from a different position is in scope, not out of it.** Executing svcdoctor from inside a
cluster, from a container, or from a second vantage is the thesis applied, not an exception to it —
the OCI image exists for exactly that (ADR 0062). A capability that lets a client stand somewhere
new is admissible; a capability that lets it read something a client cannot is not.

**Observing a self-reported property is in scope; interpreting it is not.** `in_hot_standby`,
`redis.role`, `rabbitmq.cluster_name` and the Kubernetes Service type are recorded and rendered.
They become findings only when a *declared intent* exists to compare them against, which ADR 0085
established and which nothing yet provides.

### 2.5 The recommendation is part of the boundary

A finding says what was proven; a recommendation says what to do about it. Both are subject to the
thesis. A recommendation must therefore state **who can take it** — svcdoctor or the operator —
because "svcdoctor could look further" and "you must look elsewhere" are different statements about
the same boundary, and only one of them is a hand-over.

This is the machinery ADR 0082 built. Phase 13.0 measured that it reaches **8 of 69 finding
codes**, and that the remaining 61 carry prose that states neither. Closing that is Phase 13.1's
work; the *rule* is fixed here: **a recommendation that does not say who can take it is
incomplete**, because the hand-over is the boundary made visible.

### 2.6 Depth before breadth

Where a proposal to deepen an existing service and a proposal to add a new one score comparably,
**depth wins**, and the reason is measurable rather than aesthetic: a new adapter arrives carrying
its own share of every unfinished cross-cutting contract, so breadth multiplies debt that depth
retires. This is a tie-break, not a ban — ADR 0005's "Kafka first" and every adapter since were
breadth decisions made deliberately.

## 3. Consequences

- Adapter and capability proposals are argued against §2.2 rather than from first principles, and a
  refusal cites the question it failed.
- **A useful feature may be refused, and that is the intended behaviour.** Kubernetes Events would
  help an operator; they fail Q2. Reading `pg_stat_activity` would answer the most common
  PostgreSQL question; it fails Q1.
- The three questions are stated so they can be *failed*, which means a future phase can also argue
  one of them is wrong. Q2 in particular has a plausible future challenger: an svcdoctor-owned
  exact-match allowlist over a peer's `reason` field, which ADR 0093 already named as the condition
  under which Pod-state findings could be reconsidered.
- No production code, no finding, no schema and no compatibility grade changes here.

## 4. Rejected alternatives

**Leave the thesis implicit.** It has worked for twelve phases and cost a re-derivation each time.
The failure mode is not a single bad decision but drift, which is invisible per-commit.

**Freeze a list of permitted services and capabilities instead of a test.** A list cannot judge a
candidate nobody thought of, and it would be wrong the first time a protocol exposed something
structured that the list did not anticipate.

**Make the thesis "svcdoctor diagnoses distributed services."** True and useless: it admits
everything, including the monitoring product this record exists to avoid becoming.

**Adopt a management-API tier behind a flag.** It would answer real questions — RabbitMQ cluster
state, queue depth — and it fails Q1 with a second credential class, a second authority model and a
second security review. It is a different product and deserves its own record if anyone wants it,
rather than arriving as a flag on this one.

## 5. Security implications

The boundary is also a blast-radius decision. Every capability it refuses would require a broader
credential than the one the operator's application already holds: an administrative database role,
a management-API account, cluster-wide list rights. Keeping svcdoctor to the client's own credential
is what makes it safe to run during an incident without a change request — and ADR 0028's
endpoint-bound credential rule is the mechanism that enforces it.

**A proposal that needs a wider credential is a proposal to change the product's security posture**,
and it is reviewed as one.

## 6. Verification

`docs/validation/PHASE130_PRODUCT_DIAGNOSTIC_ROADMAP_AUDIT.md` is the measurement: the capability
matrix, the five incident journeys, the depth ladder, and the candidate scoring that this record
generalizes. §11 and §13 of that document apply §2.2 to nine Kubernetes candidates and eight adapter
candidates and show the test discriminating between them.

No test enforces this ADR, and none should: it is a decision procedure for humans reviewing scope,
not a property of the code. The properties it protects — no raw objects, no peer prose, no causal
claims, endpoint-bound credentials — are each already enforced by their own guards.

## 7. Reopen conditions

| Item | Condition |
|---|---|
| Q2 (structured authority) | An svcdoctor-owned exact-match allowlist over a peer-chosen field, every member observed on a real instance, with the unbounded remainder still refused — ADR 0093's standing condition |
| Q1 (client credential) | A named operator question that a data-plane credential provably cannot answer, plus a security review of the second credential class it would need |
| Q3 (no causal claim) | None under this thesis. Causal diagnosis is a different product |
| Depth-before-breadth | It is a tie-break; a proposal that wins on the scores wins outright |
| The thesis itself | A measured account of operators using svcdoctor for something this sentence does not describe |
