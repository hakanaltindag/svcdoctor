# ADR 0046: A run that could not start says so, and the graph proves which run it was

## Status

**Accepted, and implemented in Phase 4.11b.**

`internal/domain` gains one generic `FailureClass`,
`internal/adapter/postgres.Authenticate` records it, and
`internal/diagnosis/postgres` reads it as `POSTGRES_CREDENTIAL_NOT_CONFIGURED`.
Measured against a real SCRAM server: `postgres.authentication` SKIPPED with
`EXEC_REQUIRED_INPUT_MISSING`, one WARN finding, no session, no credential
attempt, and `status: OK` because nothing about the endpoint is broken.

`FailureClass` 39 → **40**, `FindingCode` 22 → **24** (with ADR 0045, implemented
in the same phase). `schemaVersion` **1**, `security.Reveal` **two**, the
dependency set one. `Result.Incomplete()` and `Summary` are untouched.

It closes the gap ADR 0041 recorded in its own implementation note. ADR 0030's
policy-skip shape, ADR 0040's twelve findings and ADR 0044's TLS findings are
unchanged.

## Problem

An operator runs svcdoctor against a PostgreSQL endpoint and forgets the
password. Measured, against a real server:

```text
target.requested  PASS
  dns.lookup      PASS
  tcp.connect     PASS
  postgres.ssl_request  PASS
  tls.handshake         PASS
  postgres.startup      PASS    auth_method = scram-sha-256

findings: []   status: OK   firstBrokenLayer: none   incomplete: false
```

Every step svcdoctor took passed, so nothing failed and nothing is missing from
the report — and the report says the target is fine while the thing the operator
asked for never happened. **This is worse than the transport silences closed in
Phases 4.9b and 4.9d**, because there is not even a FAIL node or a broken layer
to hint at it. The absence is invisible.

### The reason it stayed open: absence is ambiguous

The obvious rule — *startup passed, it asked for authentication, and there is no
authentication node* — cannot be written truthfully. ADR 0041 §13 records nothing
when the budget ends before the credentialed step, so a run cancelled between
Startup and `Authenticate` produced a **byte-identical graph**.

A rule reading that shape would claim "no credential was configured" about a run
that had one. Diagnosis sees only a `Graph`; `Result.Incomplete()` is not an
input and must not become one.

## Decision

### 1. The producer states the fact; nothing infers it

> **A step that cannot run because the run was not given something it needs
> records that, at the step, at the moment it is discovered.**

`Authenticate` is now entered whenever a path is selected, and returns a recorded
outcome when it holds nothing to present. The graphs stop being identical:

| Run | `postgres.authentication` | `Incomplete()` |
|---|---|---|
| cancelled before the credentialed step | **absent** | `true` |
| entered with no credential | **SKIPPED**, `EXEC_REQUIRED_INPUT_MISSING` | `false` |

Orchestration still checks its budget before entering the step, which is what
keeps the first row true. That ordering is now load-bearing and is guarded
structurally, because a cancellation timed into that window is not reproducible
in a test.

**Rejected alternatives**, each for a stated reason:

| Model | Verdict |
|---|---|
| Diagnosis infers it from absence | **Rejected.** Claims it about a cancelled run |
| Accept the false positive, mitigated by exit 4 outranking exit 1 | **Rejected.** A wrong claim is a wrong claim |
| `internal/app` records the fact | **Rejected.** ADR 0042 §3 gives the run one evidence authority — the anchor — and protocol evidence belongs to the producer |
| No finding; let the CLI say "no session established" | **Rejected**, though it was close. It puts a semantic conclusion in a renderer, and every consumer of the JSON would have to re-derive it |

### 2. `EXEC_REQUIRED_INPUT_MISSING`

> **The step could not run because an input that step required was not supplied
> to the run.**

Generic, in `internal/domain`, naming no service, no protocol and no kind of
input. A future step needing a certificate, a token or a file it was never given
reaches the same condition; the step's own evidence says which input was wanted.

**It does not state** that the target is broken, that the missing input is
invalid anywhere else, that whoever started the run erred, that the step was
attempted, or that the peer refused, answered or observed anything. Nothing was
sent.

**It is none of the three classes it sits beside**, and the distinctions are what
a reader acts on:

| Class | What happened |
|---|---|
| `EXEC_SKIPPED_BY_POLICY` | the input exists and a policy refused to use it |
| `EXEC_UNSUPPORTED_BY_SVCDOCTOR` | svcdoctor cannot perform the operation at all |
| `EXEC_INSUFFICIENT_PRIVILEGE` | it was attempted with an identity that was not enough |
| **`EXEC_REQUIRED_INPUT_MISSING`** | svcdoctor can do it, nothing objected, and the run had nothing to do it with |

**Names considered.** `EXEC_MISSING_INPUT` and `EXEC_INPUT_UNAVAILABLE` were both
weaker: *missing* suggests something was lost, and *unavailable* suggests it
exists somewhere and could not be fetched. `REQUIRED_INPUT_MISSING` says the step
required an input and the run did not have it, which is the whole fact.

### 3. Why SKIPPED

`StateSkipped` is *"the step was intentionally not executed"* — exactly what
happened. svcdoctor decided not to proceed, deliberately, for a reason it can
state.

- **FAIL** would be a positively evidenced failure, and nothing failed. No byte
  was sent and the peer was never asked.
- **UNKNOWN** would say the result could not be determined. It was determined
  precisely: there was nothing to determine it with.

It is the same shape ADR 0030's policy refusal produces, with a different class,
because the two are the same *kind* of event — svcdoctor declining to continue —
for reasons a reader acts on differently.

### 4. Ordering, and why the missing input is checked second

```text
1. the peer demanded nothing            -> no node at all, session continues
2. svcdoctor cannot perform what it asked -> the capability gap
3. the run holds nothing to present     -> this record
4. may a credential cross this channel  -> ADR 0030
5. which endpoint authorizes it
6. SecretFor  ->  wire  ->  security.Reveal
```

**Second, not first.** A mechanism svcdoctor cannot perform is refused above
whatever the run holds, because that refusal is true regardless — so an endpoint
demanding `md5` reports the capability gap rather than a missing credential, and
an operator is not sent to configure a password for a mechanism svcdoctor could
not use anyway.

**Before everything below.** With nothing to present, the channel policy has no
question to answer and there is no endpoint binding to check — the same reasoning
the trust branch at step 1 already used.

**The security consequence is the point.** The check precedes `SecretFor`, the
wire package and `security.Reveal`, so a run with no credential cannot reach any
layer that derives, reveals or transmits. It is guarded structurally, by reading
the order the source has, rather than only by the paths a behaviour test happens
to exercise.

### 5. Trust, selection and multi-path

**Trust produces nothing.** An endpoint answering `AuthenticationOk` asks for
nothing, so a run without a credential is not limited by anything. `Authenticate`
returns at step 1 above and records no node at all — unchanged from ADR 0038 §12.

**Only the selected path can produce it.** ADR 0041 continues exactly one path,
and only a continued path enters `Authenticate`. An unselected path that would
have demanded authentication produces no node and no finding: the diagnosis
describes what the run could not do, not what every theoretical path would have
required.

| Scenario | Result |
|---|---|
| trust + SCRAM, no credential | ADR 0041 §8.1 prefers the path it can carry furthest — trust — the session succeeds, **no finding** |
| SCRAM + SCRAM, no credential | one selected path, **one** node, **one** finding |
| md5 + SCRAM, no credential | selection unchanged; only the selected path can record anything |
| an unselected auth-required path | **no node, no finding** |

Credential attempts remain **zero** in every no-credential case, which is the
same limit ADR 0028 §7 sets from the other direction.

### 6. `POSTGRES_CREDENTIAL_NOT_CONFIGURED`

| | |
|---|---|
| **Trigger** | `postgres.authentication` is SKIPPED with `EXEC_REQUIRED_INPUT_MISSING` |
| **Claim** | *The endpoint required authentication and this run had no credential to present.* |
| **Kind** | `CONFIRMED` |
| **Severity** | `WARN` |
| **Confidence** | `HIGH` |
| **`vantageDependent`** | **`true`** |
| **Layer** | `L5` |
| **Subject** | the authentication node's concrete `ip:port` |
| **Evidence** | the authentication node and the `postgres.startup` node |
| **Recommendation** | *Supply a credential for this endpoint and the role this run used, or check whether this endpoint was expected to accept the connection without one* |

**Must not claim**: that a credential is wrong or was rejected; that
authentication failed at the peer; that the endpoint is unhealthy; that
authorization was denied; that the connection is broken; that any byte was sent.

**Why "not configured".** `REQUIRED` would name the endpoint's demand, which the
startup node already records and which is not the news. `MISSING` suggests
something was lost. What happened is that this run was not given a credential for
this endpoint — a statement about the run's configuration, which is the thing an
operator changes.

**Why WARN.** Severity is the impact of the claim about its own subject, and this
subject is an endpoint that did nothing wrong: it answered, it asked for
authentication, and nothing here proves it unhealthy. What did not happen is that
*this run* could not continue — real, and unfixable by any change to the
endpoint. It is the same reading `POSTGRES_CREDENTIAL_WITHHELD` already carries
at this step. **ERROR is deliberately not used to force a non-zero exit**;
severity and process status are different contracts.

**Why `true`.** The compound claim is what makes this vantage-dependent, and the
credential half alone is not. That the run held nothing is no property of network
position; that *this endpoint demanded authentication* is, because `pg_hba`
selects the method by source address. A claim naming both inherits the weaker —
the same ground `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` rests on,
where a gap in svcdoctor is vantage-dependent because the claim names what the
endpoint required.

**Why both refs.** The authentication node proves the step did not run; the
startup node proves the endpoint asked. Each carries one half of the claim, and
neither alone establishes it.

### 7. Distinct from credential withheld, permanently

| | Withheld | Not configured |
|---|---|---|
| **Class** | `EXEC_SKIPPED_BY_POLICY` | `EXEC_REQUIRED_INPUT_MISSING` |
| **State** | a credential exists | none exists |
| **Cause** | svcdoctor's channel policy refused | the run was not given one |
| **Next move** | fix the channel, or change the policy | supply a credential |
| **Vantage** | `false` — about svcdoctor's policy and this channel | `true` — names what the endpoint required |

No umbrella "credential unavailable" finding. They share a step and a state and
nothing else, and merging them would send half of each audience to the wrong
place.

### 8. Report and exit semantics, unchanged

`SummaryStatus` stays **OK**: it is derived from findings, WARN is not ERROR, and
nothing about the target is broken. `firstBrokenLayer` stays **unset**: it is
derived from FAIL evidence, and no evidence failed. `Result.Incomplete()` stays
**false** and keeps its meaning — cancellation and budget exhaustion, nothing
else. **No `Summary` special case, and no widening of `Incomplete`.**

**Recommended future CLI mapping**, recorded here and implemented nowhere:

| Outcome | Exit |
|---|---|
| session established, no ERROR finding | `0` |
| **no credential + WARN finding** | **`0`**, and the renderer must surface the warning and that no session was established |
| target ERROR finding | `1` |
| invalid invocation | `2` |
| cancellation or budget exhaustion | `4` |

Exit 0 is honest here: `docs/SCOPE.md` defines it as *"the run completed and no
ERROR/CRITICAL finding exists"*, and exit 1 means *"a target-side problem"*, which
this is not. Exit 2 means no usable diagnosis was produced, and one was — the
report says the endpoint requires SCRAM and that everything up to L4 works. Exit 4
is reserved and stays reserved.

**The discomfort is real and belongs to the renderer**, not to severity. A run
that never reached a session must not *look* like a clean run in a terminal, and
that is a presentation decision the CLI phase owns.

## Acceptance matrix

| # | Scenario | Node | Finding | Status |
|---|---|---|---|---|
| 1 | SCRAM + credential | per outcome | no missing-input finding | per outcome |
| 2 | SCRAM + no credential | SKIPPED, `EXEC_REQUIRED_INPUT_MISSING` | `POSTGRES_CREDENTIAL_NOT_CONFIGURED` WARN | OK |
| 3 | trust + no credential | **none** | none | OK, session PASS |
| 4 | trust + credential | none | none; no credential sent | OK |
| 5 | credential withheld by policy | SKIPPED, `EXEC_SKIPPED_BY_POLICY` | `POSTGRES_CREDENTIAL_WITHHELD` only | OK |
| 6 | wrong credential | FAIL | `POSTGRES_CREDENTIALS_REJECTED` only | PROBLEMS_FOUND |
| 7 | endpoint offers nothing svcdoctor performs | FAIL | mechanism finding only | OK |
| 8 | svcdoctor cannot perform what was asked | UNKNOWN | mechanism finding only | OK |
| 9 | md5 + no credential | FAIL | **mechanism finding, not this one** | OK |
| 10 | two SCRAM paths, no credential | one node | **exactly one** finding | OK |
| 11 | trust + SCRAM, no credential | none | none — trust is selected | OK |
| 12 | unselected auth-required path | none | none | — |
| 13 | cancelled before the credentialed step | **none** | none; `Incomplete() = true` | OK |
| 14 | selected, no credential | SKIPPED | finding; `Incomplete() = false` | OK |
| 15 | no credential: zero `Reveal`, zero bytes, no nonce, no PBKDF2 | — | — | — |
| 16 | redacted report | subject pseudonymized, refs resolve | — | — |
| 17 | deterministic output | — | — | — |

Rows 2 and 3 are proved against a **real PostgreSQL server**; the rest are
deterministic unit or structural tests.

## Mutation matrix

All applied, all caught, all restored.

| | Mutation | Caught by |
|---|---|---|
| A | reuse `EXEC_SKIPPED_BY_POLICY` | `TestAZeroCredentialIsRecordedRatherThanRefused` |
| B | reuse `EXEC_UNSUPPORTED_BY_SVCDOCTOR` | same |
| C | map it to credentials-rejected | compile + the disjointness matrix |
| D | infer from absence (`Children`) | `TestNoRuleInfersAMissingCredentialFromAbsence` |
| E | trust records the node | `TestTrustAuthenticationRecordsNoNode` |
| G | cancellation records the node | `TestTheRunChecksItsBudgetBeforeTheCredentialedStep` |
| H | withheld collapses into missing | the acceptance matrix |
| J | check moved after `Reveal` | `TestTheMissingInputCheckPrecedesEveryCryptographicStep` |
| M | severity ERROR | `TestAMissingCredentialIsDiagnosed` |
| N | vantage `false` | same |
| O | finding omitted | same |
| R | the class names a service concept | `TestTheMissingInputClassIsServiceNeutral` |

ADR 0045's eleven mutations are carried in that record; all were caught in the
same run.

## Security

`security.Reveal` stays **two**, and the no-credential path reaches neither. No
attribute describes the absent credential — not its length, not that it was
empty, not that one was sought — because there is no value to describe. The
authentication node carries **zero** attributes, which is asserted rather than
assumed, and no mechanism name is written because svcdoctor selected none.

Redaction needs no change: the subject is an endpoint reference already rewritten
through the pseudonym table, and the prose carries no identity. Proven
non-vacuously — the role appears in the local document and is absent from the
shareable one.

## Consequences

- The last known PostgreSQL BASIC diagnosis gap that produces a silent healthy
  report is closed.
- One generic `FailureClass` enters the vocabulary, reusable by any future step
  that needs an input it was not given.
- `Authenticate` gained a recorded outcome and lost an invocation error; callers
  that relied on the error now receive evidence instead, which is the point.
- Orchestration's budget check before the credentialed step became load-bearing
  and is guarded structurally.
- `Summary`, `Result.Incomplete()`, the exit contract, path selection and the
  one-attempt limit are all unchanged.

## Reopen conditions

- **A second consumer of `EXEC_REQUIRED_INPUT_MISSING`** — the class was written
  generic and should be checked against its second use before a third.
- **Field evidence that exit 0 misleads** on a run that never reached a session —
  a CLI decision, not a severity one.
- **A run that legitimately holds several credentials** — selection among them is
  not a question this record answers.
