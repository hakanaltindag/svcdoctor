# ADR 0085 — PostgreSQL server authority, admission scope and the observed role

**Status:** Accepted
**Date:** 2026-09-05
**Phase:** 10.3
**Refines:** ADR 0078-0083 (the Phase 10 reasoning model) applied to a second service.
**Reopens:** ADR 0040 §17, on the condition that section states for itself.
**Upholds:** ADR 0040 §19 and §20, ADR 0039 §7.1, ADR 0083 §2.6.

---

## 1. Context

Phase 10.2 demonstrated topology-aware reasoning for Kafka. Phase 10.3 exists to demonstrate a
different capability, and PostgreSQL is the right exemplar because of an asymmetry no other
service in the tree shows so plainly:

> **The server often tells svcdoctor exactly *what* happened, and almost nothing about *why*.**

A SQLSTATE is a field the protocol defines, chosen by the peer, in a closed vocabulary. When
PostgreSQL answers `53300`, that is not an inference — it is the server naming its own condition.
And it is *still* not a cause: a connection limit reached at an instant is compatible with a
leak, a limit set low, a burst, a pool sized wrongly and a condition that has already passed.
Direct authority about an observation is not authority about the system around it.

It is also not authority about anything **wider than the observation**. `53300` is raised when
*a* connection limit applicable to the session being admitted has been reached, and PostgreSQL has
several — `max_connections`, the reserved-slot margins, a database's `CONNECTION LIMIT` and a
role's — and the `ErrorResponse` identifies none of them. So the server's statement is scoped to
*this attempted session at this instant*, and "the endpoint has no connection left" is a strictly
stronger claim. This repository's own integration fixture is the counterexample: a role created
with `CONNECTION LIMIT 0` yields `53300` on every login while the server has connections to spare.
**Widening the scope of an authoritative statement is the same error as inventing a cause for
it**, and §3 is written to make neither.

So the phase adds one epistemic rule to Phase 10's *observation ≠ cause*:

> **observed state ≠ violated intent**, unless the intent itself is explicitly known.

### 1.1 The archaeology, because most of the candidates were already built

An inventory of what `internal/adapter/postgres` can prove found nineteen PostgreSQL finding
codes already covering nearly every per-endpoint claim the evidence supports. Of the seven
candidate domains the phase brief listed, five were already implemented and one is
unreachable:

| Candidate | Verdict |
|---|---|
| `PG_HBA_ADMISSION_REJECTION` | **already built** — `POSTGRES_CONNECTION_NOT_PERMITTED`, from `28000` → `AUTHZ_NOT_PERMITTED`, CONFIRMED/ERROR/HIGH, vantage-dependent, with a review-the-rules recommendation |
| `SERVER_REJECTION_AFTER_HEALTHY_TRANSPORT` | **already built** — `DIAG_FAILURE_BOUNDARY` (ADR 0079), and a second PostgreSQL boundary code is explicitly refused |
| policy rejection vs bad credentials | **already built** — `AUTHZ_NOT_PERMITTED` and `AUTH_CREDENTIALS_REJECTED` are different classes reached by different SQLSTATEs at different steps |
| credential withholding vs auth failure | **already built** — `POSTGRES_CREDENTIAL_WITHHELD` on a SKIPPED node, never a FAIL |
| TLS reinterpretation | **already built and owned elsewhere** — five `POSTGRES_TLS_*` codes (ADR 0044) |
| `MULTI_ENDPOINT_ROLE_CONTRAST` | **unreachable** — §5 |
| `PARTIAL_ENDPOINT_ADMISSION` | **built here** — §2 |
| `SERVER_RESOURCE_LIMIT_REJECTION` | **built here** — §3 |
| `ROLE_OBSERVATION` | **built here, and not as a finding** — §4 |

Three additions, and one of the three is deliberately not a finding at all.

## 2. Decision: the admission scope is one new finding

`POSTGRES_ADMISSION_SCOPE` — CONFIRMED, **INFO**, HIGH, `LayerProtocol`, subject the requested
target, produced at most once per run.

### 2.1 What it adds that the conjunction does not

`POSTGRES_CONNECTION_NOT_PERMITTED` answers *"was this one address refused before any credential
was evaluated"*, once per address. Two facts are not in the conjunction of those findings and
cannot be recovered from it. They are the same two ADR 0084 reopened ADR 0034 §10 for, arriving
in a second service:

- **completeness.** Two refused addresses beside a third svcdoctor never reached look exactly
  like two out of two. The conjunction is two findings either way.
- **contrast.** *"One address was refused and the other completed the startup exchange"* is a
  different diagnosis from *"every address was refused"*. The first says the endpoint's decision
  differs between two addresses of one name — which is what `pg_hba.conf` does, since its rules
  match on address — and the second says this client is refused wherever it connects.

Neither was expressible before `RuleContext.Incomplete` existed.

The scenario is not hypothetical. `internal/app/postgres.go` measures every resolved address
through the credential-free stages *precisely so this is observable*, and its own doc comment
records why: "one family may be offered SCRAM while another is refused outright". A target with
an A record covered by a host-based rule and an AAAA record that is not is the ordinary shape of
it — and before this record, such a run reported one ERROR and exit 1 while its selected path
succeeded completely, with nothing saying so.

### 2.2 Three categories, never two

**refused** (FAIL + `AUTHZ_NOT_PERMITTED`), **admitted** (PASS), **undetermined** (everything
else: another failure, a local timeout, a skipped step, a blocked step). An address that reached
no decision is not an address that was refused.

**Complete** requires both that nothing is undetermined *and* that `RuleContext.Incomplete` is
false. Neither implies the other: a run cancelled after the last startup exchange finished has
the second without the first. Only a complete set may say *"at all N addresses"*.

### 2.3 Three gates, each of which is the rule declining to duplicate

1. **Exactly one requested-target anchor.** The subject is the anchor's own; a graph with two has
   no defensible answer and picking one would make output depend on traversal order.
2. **At least two addresses classified.** With one there is no contrast and no completeness
   question the per-address finding does not settle. This keeps every single-address run — nearly
   all of them — byte-identical to what it produced before.
3. **At least one address positively refused.** A target where nothing was refused has no
   admission scope worth stating.

### 2.4 INFO, and never anything else

ADR 0034 §13, re-applied: **severity is the impact of this finding's own claim and is never a
count-derived verdict.** The impact of a refusal is already carried at ERROR, once per address.
Escalating on how many addresses were refused would move an exit code on arithmetic. Phase 10.3
therefore cannot change any run's exit code through this finding.

### 2.5 What it must never say

That an admission policy is misconfigured, wrong, or should be changed; that a rule should be
added; that a credential is bad; that an address is unreachable; that the addresses belong to one
server or to different ones. Its one recommendation on the contrast branch is a **COMPARE**, and
"add a host-based access rule" is refused permanently: an admission policy that refuses an address
may be exactly what it was written to do, and widening one is a security-relevant change svcdoctor
is not entitled to suggest from a connection attempt.

## 3. Decision: `53300` gets a code of its own

`POSTGRES_CONNECTION_LIMIT_REACHED` — CONFIRMED, ERROR, HIGH, `LayerAuth`,
`vantageDependent: false`, anchored at `postgres.session`, triggered by
`RESOURCE_LIMIT_REACHED`.

### 3.1 Why now, when ADR 0040 §17 declined it

That section declined it in one sentence, with its dependency stated in the sentence:

> ADR 0039 §10 declined to add a capacity class for it — one producer and no authorizing record
> is not enough to grow a service-neutral vocabulary — **and this record declines the matching
> finding for the same reason.**

Phase 8.1 satisfied both halves of that condition and added `RESOURCE_LIMIT_REACHED`, with
RabbitMQ's three ceilings as the further producers and ADR 0069 as the record. **The reason was
gone; the refusal was not.** This closes it, on the ground ADR 0040 §17 named for itself.

ADR 0083 §2.2's acceptance table, Accepted in Phase 10.0, already specifies the outcome: for
SQLSTATE `53300`, *emit* "the server rejected the connection at its resource limit (`HIGH`,
direct authority)" and *must not emit* "a connection leak", "the pool is misconfigured",
"increase `max_connections`".

### 3.2 The other half of §17's argument stands, and shapes the wording

> a pooler reports its own `max_client_conn` limit as `08P01`, and svcdoctor cannot distinguish
> exhaustion at the endpoint from exhaustion behind it.

True, and unchanged. The claim is therefore about **this endpoint's** refusal and never about
"PostgreSQL", a backend, or where the limit is enforced (ADR 0040 §18). The detail says so.

### 3.2a The claim is scoped to the attempted session, not to the endpoint's capacity

This is the correction the phase's first cut needed, and it is stated here as the contract rather
than as a wording preference.

**What `53300` proves:** the endpoint authoritatively rejected *this attempted session* with
PostgreSQL's `too_many_connections` condition, and therefore that **a connection limit applicable
to this attempted session had been reached** at that moment.

**What it does not prove:** *which* limit. The response does not distinguish among the admission
limits that can apply, so the finding may not say `max_connections` was exhausted, that no slot
was free, that a reserved margin was consumed, or that a role limit specifically was hit. The
applicable limit can depend on the session's own context — the role most obviously — so a
different session at the same instant may be admitted, and the claim asserts nothing either way.

The prose states its scope **positively** rather than by denial, because naming a limit in order
to exclude it puts the word in the report.

**`vantageDependent: false` means one thing and not the other.** It means this claim is not
inferred from a source-address-dependent observation: the endpoint named the condition itself, in
its own protocol, and nothing here is read off where svcdoctor happened to dial from (ADR 0012).
It does **not** mean the condition is an endpoint-wide invariant. Vantage dependence is a property
of how a claim was *derived*; it is not a scope quantifier.

### 3.3 It is an escalation, not an addition

`RESOURCE_LIMIT_REACHED` at `postgres.session` used to fall to
`POSTGRES_SESSION_ESTABLISHMENT_FAILED`, whose detail restated the condition through
`namedConditions`. It is now a fourth branch of the same `switch`, beside `3D000` and `42501`.
The floor no longer sees `53300` at this step; **`namedConditions` stays alive and is not
orphaned**, because `53300` arriving *before* authentication is classified
`PROTOCOL_UNEXPECTED_RESPONSE` at `postgres.startup`, where the floor and its restatement are
still what states it.

One semantic field moved: `vantageDependent` goes **true → false**. A floor attributes no cause
and so cannot exclude a source-keyed one; this claim restates a condition the endpoint named in
its own protocol, and that is not read off the address a client connects from. That is the ground
the two sibling escalations already stand on (ADR 0040 §6.1). §3.2a bounds what the flag means:
it is about how the claim was derived and not about how widely what it asserts holds.

### 3.4 The rule reads the class and never the SQLSTATE

ADR 0039 §7.1 stands: the adapter classifies a SQLSTATE **per step**, because the only answerable
question is what a code proves *there*. A rule that re-read the five characters to escalate at
`postgres.startup` or `postgres.authentication` — where nothing establishes that authentication
completed — would be building the shared dictionary that record forbids. Phase 10.3 adds **no
attribute read to diagnosis at all**.

### 3.5 Next evidence, not remediation

The finding carries one `NEXT_EVIDENCE` / `COMPARE` recommendation, `SelfCollectable: false`:
*identify the connection limits applicable to this attempted session and compare their current
usage with their configured limits.* svcdoctor cannot take it — PostgreSQL BASIC executes no SQL
and the credential may not hold the privilege — and ADR 0082 §2.4 makes saying so more useful than
implying it looked.

**The identification step is part of the advice, and the advice names no limit.** §3.2a says the
response identifies none and that PostgreSQL applies more than one to a single admission; an
operator sent straight to a comparison has been told implicitly which setting to suspect, which is
the §3.2a overclaim arriving through the recommendation field instead of the detail. So
`max_connections`, a database or role `CONNECTION LIMIT` and the reserved margins are all absent
from it, and the recommendation is held to a **stricter** vocabulary than the detail — which may
name the role as an example of session context precisely because that bounds the claim rather than
directing an action.

*"Increase the connection limit"* is refused permanently. It can worsen memory pressure and it
hides an application holding connections it does not need, and svcdoctor does not know which is
happening.

## 4. Decision: the observed role is a renderer observation, not a finding

`in_hot_standby` is the closest thing svcdoctor has to `pg_is_in_recovery()` without executing
SQL. Against a real three-node Patroni cluster it tracked that function exactly, through a
failover and a rejoin (Phase 7.3A). It is authoritative about **what the endpoint said** and
about nothing else.

**It becomes a terminal observation line and a conditional note. It does not become a finding,
and ADR 0040 §20 is not reopened.**

### 4.1 Why not a finding

ADR 0040 §20 rejected `POSTGRES_ENDPOINT_IN_RECOVERY` on two grounds and named three reopen
conditions. Phase 10.2's `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` dissolved the first ground —
an INFO observational finding is now a settled shape — but **none of the three reopen conditions
has fired**: svcdoctor still executes no SQL, run intent is still not expressible, and no second
non-SQL fact distinguishes a writable session.

The second ground stands untouched and is decisive: without declared intent there is no notion of
"the operator wanted a primary", so the claim has no actionable half. And there is a plainer
argument. Kafka's aggregate earned a code because **completeness and contrast are not in the
evidence**. A role observation adds *nothing* the session node's own attribute does not already
carry — it restates one attribute in a sentence. ADR 0040 §19 already answers that case:
findings are for what a reader must act on, and the report is not silent because the evidence is
in it.

### 4.2 Why the renderer is the right place, and why it was already built

`internal/render/terminal/service.go` has carried an `observations` mechanism since Phase 7,
whose own doc comment says what it is for:

> endpoint-reported facts a reader should see … what it calls itself, what version it reports,
> what mode it is in, **what replication role it holds** — and none of them is a problem without
> an expected-state contract svcdoctor does not have. **Rendering them in the Result block rather
> than as findings is that distinction made visible.**

Redis and RabbitMQ use it. PostgreSQL's slice was empty. This fills it, with one line.

That is the whole decision: **the finding layer refuses, and the presentation layer shows the
fact.** An operator sees `recovery   in recovery`; svcdoctor claims nothing, produces no finding,
changes no status and moves no exit code.

### 4.3 The render function is a closed two-value map, for two reasons

`"on"` → `in recovery`, `"off"` → `not in recovery`, **anything else drops the line**.

It reads better than the GUC's own spelling. And it is structurally immune to a hostile endpoint:
`wire.SessionParameters` allowlists four *keys* and retains each one's value as the server's own
string with **no length or character bound**, so `in_hot_standby` is a peer-controlled field, and
a closed map is the only rendering a peer cannot steer.

An absent parameter renders nothing. `in_hot_standby` arrived in PostgreSQL 14 and a pooler may
not forward it; absence is a third value and never "off".

### 4.4 `server_version` is deliberately **not** a second line

It is unbounded peer-controlled text and would put arbitrary bytes on an operator's terminal.
Redis and RabbitMQ already render a verbatim version, which is a **pre-existing cross-service
question** needing one decision about sanitizing observation values at the renderer boundary for
every service at once. Phase 10.3 declines to widen the surface while that decision is
outstanding; the version is in the report's evidence either way. Recorded as a backlog item
rather than fixed here.

### 4.5 The conditional note, and why only one

A note fires when `in_hot_standby == "on"`, saying what the observation is and is not. It exists
because the *silence* beside that line would be misread: an operator who sees "in recovery" and
no finding has to be told the absence is deliberate.

There is no matching note for `"off"`. "Not in recovery" invites no action and no alarm, and a
note beside it would be svcdoctor reassuring a reader about something it did not measure.

## 5. Declared intent: `ROLE_INTENT_NOT_AVAILABLE`, and role mismatch is deferred

svcdoctor has **no** representation of expected role. The CLI, the target YAML
(`internal/fleet/config`), the adapter parameters and the canonical report were all searched, and
none carries one. ADR 0083 §2.6 froze that deliberately for the whole of Phase 10: *"No
configuration change in Phase 10 … Until an `expect:` block exists, a standby is a standby and
not a fault."*

**No role-mismatch diagnosis is implemented and none is authorized.** Nothing is smuggled through
rule configuration, through a detail string or through a subject. Adding one requires a target
configuration field, which is ADR 0071's strict-schema contract and is its own record.

The property that matters is therefore stated in its strongest available form: **no PostgreSQL
finding, and no prose any PostgreSQL rule can produce, expresses an expectation at all.** When an
`expect:` block arrives, the test holding that is what will have to change deliberately.

## 6. Multi-endpoint role contrast is structurally unreachable

Not forbidden — **unreachable**, and the difference matters.

`internal/app/postgres.go` measures every resolved address through the credential-free stages and
then **continues exactly one path** (ADR 0041 §§5-9). A run therefore holds at most one
authentication node and at most one session node, whatever the target resolved to.

So *"endpoint A reports primary and endpoint B reports standby"*, *"two primaries observed"*, and
*"one address returns 53300 while its sibling accepts"* are graphs **no producer makes**. There is
no evidence from which to draw a split-brain conclusion, a dual-primary conclusion or a
failover-broken conclusion, and a test that merely forbade those words would be describing a
suppression rather than a property.

The guard is therefore structural: it reads the composition root and requires `selectPath` and
`continuePath` to be called exactly once each. A change that continued two paths would make those
claims reachable, and it fails there rather than in a report.

## 7. What stays refused

Longer than what was built, and each entry is a sentence svcdoctor will not say:

**For `53300`:** a connection leak, `max_connections` configured too low, a misconfigured pool, a
traffic spike, memory pressure, that the condition outlasted the instant, that the limit is
enforced at the endpoint rather than behind it, and any recommendation to raise a limit.

**And, for `53300`, every widening of scope** (§3.2a): that no connection slot was available, that
the endpoint was out of connections, that global `max_connections` was exhausted, that a reserved
margin was consumed, that a role limit specifically was responsible, or that another session would
have been refused at the same instant.

**For an admission refusal:** that `pg_hba.conf` is misconfigured, that a rule should be added or
widened, that the credential is bad, that the role does not exist, that the addresses are or are
not the same server.

**For a reported recovery state:** that the endpoint is a primary, a replica or a standby (a
pooler forwards a cached value, so nothing distinguishes a replica from a primary that was in
recovery when the pooler cached); that it is writable or read-only (`default_transaction_read_only`
was `off` on a real standby, and the parameter that settles it is session-local and needs SQL);
that it is the wrong server; that replication is broken; that failover failed; that anything
should be promoted.

**For two addresses:** split brain, dual primary, fencing failure, a Patroni failure, or any
statement that they belong to one replication topology.

**For an authentication rejection:** a bad password or an unknown role. `28P01` is issued
identically for a wrong secret, an unknown role, a corrupted proof and a correct secret needing
Unicode preparation — PostgreSQL issues a mock salt for a non-existent role *deliberately*.

**Generally:** no diagnosis by error-text regex. Where the protocol provides a SQLSTATE the
structured code is used, and no English server string is examined anywhere in this phase.

## 8. Consequences

**Finding codes move 63 → 65**, both `POSTGRES_`. The generic `DIAG_` namespace stays at one and
no other service's count moves. PostgreSQL goes 19 → 21.

**Release state, stated once so nothing below is misread.** Phase 10.3 is an **uncommitted,
unreleased candidate**: not committed, not tagged, in no published release. The most recent
release tag is `v0.4.0`, and the branch this candidate sits on is already several commits past it,
so the behaviour it changes is the behaviour `v0.4.0` published. Every consequence below is
therefore a change to **candidate public behaviour** — what an operator would see if this
candidate were released — and not a description of anything shipped.

**One candidate change to behaviour last published in `v0.4.0`**: a run whose session is refused
with `53300` would report `POSTGRES_CONNECTION_LIMIT_REACHED` instead of
`POSTGRES_SESSION_ESTABLISHMENT_FAILED`, with `vantageDependent` false rather than true. Severity,
kind, confidence and the exit code are unchanged, and the condition was already restated in the
floor's detail — a consumer matching on the *code* would see a new one, which is why this is in a
record rather than in a changelog line.

**The floor's restatement was corrected in the same change-set**, from *"it refused because no
connection slot was available to it at that moment"* to the §3.2a scope. That sentence predates
this record (Phase 7.3B) and still serves `postgres.startup` and `postgres.authentication`, where
`53300` is not escalated; leaving it would have given one SQLSTATE two meanings depending on which
window observed it. Detail prose is not a stability contract — ADR 0039 §7.1 and `docs/FINDINGS.md`
§3.1 rule 13 both require a consumer to read the code and the SQLSTATE attribute, never `detail` —
and no finding code, class, severity, status or exit code moves with it.

**One candidate addition to that behaviour**: a PostgreSQL run that establishes a session and
receives `in_hot_standby` would print one more line in the terminal Result block. No finding, no
status change, no exit-code change, no JSON change.

**Nothing else moves.** `SchemaVersion` 1, `RunSchemaVersion` 1, failure classes 42, `Reveal` 4,
`SecretFor` 4, external modules 2, exit codes 5.

**PostgreSQL BASIC's feature freeze is respected.** This adds no probe stage, no SQL, no timeout
semantic, no fallback, no retry, no latency interpretation and no target-health inference. It adds
two BASIC findings, which the freeze rule makes a deliberate reopen — and this record is it.

## 9. Alternatives considered

**A `POSTGRES_ENDPOINT_ROLE_OBSERVED` finding at INFO.** Rejected — §4.1. It restates one
attribute, ADR 0040 §20's reopen conditions have not fired, and the mechanism for endpoint-reported
facts already exists one layer up. Reconsider when declared intent exists, at which point the
finding would carry something the attribute does not.

**Introducing an `expect: role` target field to make mismatch expressible.** Rejected — ADR 0083
§2.6 froze it for Phase 10, and it is a configuration-contract change against ADR 0071 that needs
its own record and its own security review. Deferred, not declined.

**Keeping `53300` in the floor and improving its prose further.** Rejected. A consumer must not
parse `detail` to recover semantics (`docs/FINDINGS.md` §3.1 rule 13), and the condition was
already stated as well as prose can state it. What was missing was a code.

**A `POSTGRES_FAILURE_BOUNDARY`.** Rejected outright — ADR 0079 owns the boundary generically, and
a second one would be two implementations of one idea.

**A per-address admission *hypothesis* beside the observation.** Rejected. For Kafka the
hypothesis said something the counts did not — *unsuitable for this network position*. Here the
interpretation and the observation collapse: "admission differs between these two addresses" *is*
what the counts say, and a hypothesis restating its own observation is noise.

**Escalating `53300` wherever it appears.** Rejected — §3.4, ADR 0039 §7.1.

**Reading `default_transaction_read_only` to answer "can I write here".** Rejected — it was `off`
on a real standby, so the rule would call a replica writable. The parameter that settles it needs
SQL.

## 10. Security implications

Diagnosis gains no new input. Phase 10.3 adds **no attribute read** to any rule, so ADR 0040 §22's
authorized attribute surface is unchanged and the path by which a replica claim would arrive
without a decision stays closed.

Two peer-controlled surfaces were examined:

- **SQLSTATE and severity are bounded at the wire.** `validSQLState` accepts exactly five
  alphanumeric ASCII characters and `validSeverity` a closed set of eight words, so an endpoint
  cannot put arbitrary text in either. The SQLSTATE's verbatim appearance in a `detail` is safe
  because of that bound, and it appears in no summary, discriminator or recommendation.
- **ParameterStatus values are unbounded.** That is the real hostile surface, and the recovery
  render function's closed two-value map is the control. §4.4 records why no second unbounded
  value was added.

`Reveal` and `SecretFor` production call sites stay at 4 each. No rule can reach a secret, a file,
an environment variable or a socket; `diagnosis-is-pure` makes that a build failure.

## 11. Compatibility implications

`SchemaVersion` 1 and `RunSchemaVersion` 1. Two additive finding codes; an unknown code is a
finding like any other and `docs/CI.md`'s exit contract is unaffected — one of the two is INFO and
never affects an exit code, and the other replaces an ERROR with an ERROR.

`docs/COMPATIBILITY.md` is unchanged: no platform's tested level moved and no mechanism became
supported.

## 12. Validation requirements

- Unit: both rules' shape matrices, including every input for which each must emit nothing.
- Property: PG-P01 through PG-P20 in `test/diagnosis/postgresproperties_test.go`, over the
  production rule set, a real report, real redaction and both renderers.
- Corpus: fifteen golden incidents, P01-P15, each with a non-empty `forbidden` list
  (`test/diagnosis/postgrescorpus_test.go`).
- Structural: the composition root continues exactly one path (§6); the harnesses run exactly the
  rules `internal/app/postgres.go` wires (`test/security/postgres_rule_wiring_test.go`).
- Fuzz: `FuzzPostgresRules` over arbitrary address sets, states, classes, SQLSTATEs and session
  parameters.
- Mutation: `scripts/phase103-mutations.sh`, PG-M01 through PG-M27. PG-M25 and PG-M26 plant the
  §3.2a scope overclaim in the claim and in the floor's restatement respectively; PG-M27 plants it
  in the recommendation, by naming one applicable limit (§3.5).
- Integration: against a real PostgreSQL 18 server, with `53300` produced deterministically by
  `CONNECTION LIMIT 0` rather than by racing clients.
