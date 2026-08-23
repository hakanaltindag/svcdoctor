# 0060 — TLS option validity and verification-state projection

## Status

**Accepted and implemented in Phase 6.8A.**

It closes the three gaps [ADR 0058](0058-tls-trust-and-peer-identity-authority.md) §14
recorded and Phase 6.7 deferred. Phase 6.7 measured them and found them to be **one coupled
defect with one fix order**; this record follows that order and closes all three in one
change-set.

It changes released PostgreSQL CLI behaviour. §5 is the compatibility packet.

`SchemaVersion` stays **1**. No `FindingCode`, `FailureClass`, `State`, `Step`, flag or
dependency was added or removed.

## 1. Context — three symptoms, one cause

ADR 0058 §14 recorded three gaps. Each was reproduced again in Phase 6.8A against a
release-shaped binary before anything was changed, because a gap described in prose is a
hypothesis.

**Gap A — PostgreSQL accepts TLS-only flags that `--tls disable` makes inert.**

```console
$ svcdoctor diagnose postgres --host 127.0.0.1 --port 1 --user u --database d \
    --tls disable --tls-insecure
(accepted; runs plaintext; exit 1)

$ svcdoctor diagnose kafka --host 127.0.0.1 --port 1 --sasl-mechanism PLAIN \
    --tls disable --tls-insecure
svcdoctor: invalid invocation: --tls-insecure has no effect with --tls disable
(exit 2)
```

All three flags reproduce, for PostgreSQL, in both directions:

| invocation | PostgreSQL before | Kafka before |
|---|---|---|
| `--tls disable --tls-ca-file ca.pem` | accepted, ignored | exit 2 |
| `--tls disable --tls-server-name x` | accepted, ignored | exit 2 |
| `--tls disable --tls-insecure` | accepted, ignored | exit 2 |

**Cause.** `internal/cli/postgres.go` built its plan from the mode alone — `tlsPlan(mode)` never
saw the other three flags. `internal/cli/kafka.go` built its plan from all four, and refused.
Two services held one contract in two places, and nothing in the build compared them.

**Gap B — a plaintext PostgreSQL run reports `tlsVerificationDisabled: true`.**

```console
$ svcdoctor diagnose postgres --host 127.0.0.1 --port 1 --user u --database d \
    --tls disable --tls-insecure --output json
{... "tlsVerificationDisabled":true ... "nodes":[{"step":"target.requested"...},
                                                 {"step":"tcp.connect"...}] ...}
```

A TLS fact, on a run whose graph holds no `tls.handshake` node at all.

**Cause.** `internal/app/postgres.go` passed `params.TLSOptions.InsecureSkipVerify` into
`domain.NewReportSecurity` unconditionally. `internal/app/kafka.go` gated the identical boolean
on `params.TLS != nil`. The same divergence as Gap A, one layer down.

**Gap C — the terminal never says verification was disabled.**

Measured against a self-signed loopback TLS listener, twice — once with `--tls-ca-file`
naming that certificate, once with `--tls-insecure`:

```text
    ✓ PASS     TCP                         426µs          ← verified run
    ✓ PASS     TLS                         5.1ms

    ✓ PASS     TCP                         246µs          ← unverified run
    ✓ PASS     TLS                         1.4ms
```

Byte-identical apart from timings. One run validated a chain and matched an IP SAN; the other
established who was on the other end of the socket to no degree whatsoever. The canonical JSON
distinguished them correctly throughout (`security.tlsVerificationDisabled`, `tls.verified`),
so this was a **projection gap and not a semantic one** — which is why it was a recorded gap
rather than a STOP.

**Why the three are one defect.** Gap A is the only way to reach Gap B from the command line.
Gap C could not be fixed while Gap B stood: a terminal that surfaced
`tlsVerificationDisabled` would have printed a TLS security warning on *plaintext* runs, making
Gap B visible to every operator — worse than the gap it fixed. Hence one change-set, in the
order A → B → C.

## 2. Decision

1. **TLS-only flags are refused when TLS is disabled**, for every service, from one function.
2. **`tlsVerificationDisabled` is gated on the run's TLS plan**, in both composition roots.
3. **The terminal states disabled verification** twice: once in the header for the run, once
   on each affected handshake row.

## 3. TLS-only flags are refused when TLS is disabled

Three models were considered.

**Model A — reject.** A TLS-only flag under `--tls disable` is a usage error. *Chosen.*

**Model B — accept as inert configuration.** Document them as no-ops under `disable`.

**Model C — accept and warn.** Run, but emit a warning.

### Why Model A

- **Inert security flags create false operator expectations.** A flag that is accepted and
  ignored is indistinguishable, at the call site, from one that is accepted and honoured. The
  invocation an operator pastes into a runbook keeps whatever meaning they first read into it,
  and nothing ever corrects them.
- **`--tls-insecure` is the sharpest case and it points the *opposite* way to intuition.** An
  operator who passes it believes they are running an unverified TLS connection. Under `--tls
  disable` they are running no TLS connection. Accepting it silently lets someone believe they
  made a small, deliberate security compromise when in fact they made a total one.
- **A plaintext run cannot truthfully consume TLS verification configuration.** There is no
  handshake for a trust source to apply to and no identity for an override to name.
- **Kafka already refused all three**, and the divergence was itself the defect. Any resolution
  had to pick one answer; picking the looser one would have loosened a shipped guard to match
  the service that never had one.

### Why not Model B

It is the status quo for one service and it is what produced Gap B. Documenting an inert flag
does not make it safe: the operator reading `--help` and the operator reading a runbook are
different people, and only the first sees the documentation.

### Why not Model C

A warning on stdout would corrupt the JSON artifact; a warning on stderr is invisible to the
automation that most needs it, and `svcdoctor` has no warning channel and should not grow one
for this. A warning also leaves the run's semantics ambiguous — the flag was neither honoured
nor rejected — which is exactly the state this record exists to remove.

### Shape

One function, `refuseInertTLSFlags`, in `internal/cli/tls.go`, called by both services.
`internal/cli/tls.go` now holds the whole TLS-flag contract — the refusals, `trustSource` and
its bounds — so a third service inherits it rather than re-deriving it, and
`TestTLSOnlyFlagsAreRefusedWhenTLSIsDisabled` drives both services from one table so a
divergence is a failure rather than a gap.

The refusal is **before** the trust file is read. A missing CA file under `--tls disable` must
be reported as *this flag does not apply here*, not as *that file is unreadable*: the second
invites an operator to go and create a trust file for a run that would ignore it.

One flag is named per message, in a fixed order. Listing all three reads as though they
interact, and they do not.

## 4. `tlsVerificationDisabled` describes execution, not configuration

`insecure := params.TLS == postgres.TLSRequired && params.TLSOptions.InsecureSkipVerify`.

Kafka's `buildKafkaReport` already computed the same predicate over its own plan type.

### It is gated on the *plan*, not on a handshake having happened

The alternative — derive it by scanning the frozen graph for a `tls.handshake` node with
`tls.verified: false` — was considered and declined. It would go silent on a run whose TCP
attempt failed before any handshake existed, which is precisely the run where an operator most
needs to be told what their flags asked for. It would also change Kafka's released semantics
for no benefit.

The plan is what the run *intended*, and `security` is run metadata. What each individual
handshake *achieved* is already recorded, per node, as `tls.verified`.

### The three states, without a schema change

This is the part §5 of the Phase 6.8A brief asked to be proved rather than asserted. The brief
asked that a plaintext run make *no TLS verification state claim*. `tlsVerificationDisabled` is
a non-nullable boolean in `schemaVersion` 1, so "no claim" cannot be a third value of that
field without breaking the schema — and breaking it was a STOP condition.

It does not need to be, because the claim is carried by **two** fields, not one:

| run | `security.tlsVerificationDisabled` | `tls.handshake` node |
|---|---|---|
| plaintext | `false` | **absent** |
| verified TLS | `false` | present, `tls.verified: true` |
| unverified TLS | `true` | present, `tls.verified: false` |

`false` is the correct answer to the boolean question *was TLS verification disabled?* on a run
where no verification existed to disable. It is emphatically **not** the claim *verification
happened and succeeded* — that claim lives on the handshake node, and on a plaintext run there
is no node to make it. The three states are already distinguishable. `SchemaVersion` stays 1.

### Guarded at `internal/app`, not only at `internal/cli`

§3 makes the combination unreachable from the command line, so a test only at the CLI layer
would pass for the wrong reason and keep passing if this gate were deleted. `internal/app` is
its own boundary and a truthful report is its contract rather than a consequence of who
happened to call it. `internal/app/tlssecurity_test.go` drives both composition roots directly
and fails if they disagree.

## 5. Compatibility packet — a released PostgreSQL CLI change

This is the one part of Phase 6.8A that changes behaviour an operator may depend on. PostgreSQL
BASIC shipped in v0.1.0 and is a regression-sensitive public contract.

| | before (v0.1.0) | after |
|---|---|---|
| `--tls disable --tls-ca-file ca.pem` | exit 0/1/4, plaintext run, flag ignored | **exit 2**, `--tls-ca-file has no effect with --tls disable` |
| `--tls disable --tls-server-name x` | exit 0/1/4, plaintext run, flag ignored | **exit 2**, `--tls-server-name has no effect with --tls disable` |
| `--tls disable --tls-insecure` | exit 0/1/4, plaintext run, flag ignored | **exit 2**, `--tls-insecure has no effect with --tls disable` |
| `--tls disable` alone | plaintext run | **unchanged** |
| `--tls require` with any of the three | honoured | **unchanged** |
| Kafka, all of the above | already exit 2 | **unchanged** |

**Classification: intentional input-validation tightening.** Not a bug fix and not a feature.
An invocation that was accepted is now rejected, and that is the point.

**User impact.** Narrow, and bounded above by the number of runbooks that pass a TLS flag to a
plaintext run — a combination that never did anything. No working diagnosis stops working: the
three refused invocations produced exactly the same report as `--tls disable` alone, because
the flags were ignored. What breaks is a script that passed one of them and checked the exit
code; it now gets 2 instead of 0, 1 or 4.

**Security value.** The `--tls-insecure` row is the one that matters. An operator who wrote
`--tls disable --tls-insecure` was told nothing and got a plaintext connection. Two people can
read that invocation as "TLS, with verification off". Now nobody can.

**Migration guidance.** Delete the flag, or change `--tls disable` to `--tls require`. The
error message names the flag and the conflict, so the fix is mechanical and needs no
documentation lookup. Exit code 2 has always meant *svcdoctor was invoked with something it
cannot act on*, and stdout stays empty, so a pipeline parsing JSON on stdout sees no malformed
document.

**Not deprecated first.** svcdoctor has no deprecation channel — no warning stream that would
not corrupt the JSON artifact — and a deprecation cycle for three invocations that were
already no-ops would cost more than it protects. It is recorded here and in the README instead.

## 6. Terminal projection of disabled verification

Two readings, from two places:

```text
header   security.tlsVerificationDisabled   the run-level fact
row      the node's own tls.verified        one handshake at a time
```

```text
svcdoctor · kafka · kafka.internal:9093
Peer verification disabled · TLS proves the channel is encrypted, not who answered

  Path 198.51.100.10:9093 · continued
    ✓ PASS  TCP                         190µs
    ✓ PASS  TLS                         1.7ms  peer verification disabled
```

### It uses the established security surface

ADR 0058 §14.1 specified "a header annotation next to the shareable banner, and the handshake
row distinguishing a verified handshake from an unverified one", and that is what this is. The
header already carries `Shareable report · identities redacted`, so the terminal's security
section is a header line; this is a second one, not an invented widget.

### It is not a finding

No `FindingCode` was added and none was needed. The operator asked for this, the endpoint did
nothing wrong, and a target-side ERROR would change the exit code — which would make
`--tls-insecure` unusable in the situation it exists for. `status` stays `OK`, the exit code is
unchanged, and `TestDisabledVerificationIsNotAFinding` pins all of it.

This satisfies ADR 0054's owner-before-producer rule trivially: the change produces no outcome
needing an owner.

### The row stays PASS

The handshake completed and the channel really is encrypted. Downgrading the state would claim
the endpoint failed at something.

### Why the row reads the node and the header reads the report

They are read from different places so that a fixture can make them disagree, which is the only
way to write a guard that a renderer inventing either from the other would fail. Two tests do
exactly that: one sets the run-level fact with a verified node and requires the row to stay
clean, one sets the run-level fact on a run whose TCP attempt failed and requires the header to
still appear.

In production they agree, because one option produced both. A future per-endpoint TLS plan
would make them diverge correctly rather than make the header quietly wrong.

Reading the node is also what annotates **advertised-broker** handshakes. A Kafka run sweeps
every advertised endpoint with the same options, so those handshakes are unverified too, and
they are the ones an operator is least likely to have thought about.

### A failed handshake keeps its failure class

`tls.verified` is false for a *failed* handshake as well as a disabled one, so the annotation is
restricted to `PASS` nodes. That restriction is what makes the wording exact: a passing
handshake with `tls.verified: false` can have arisen one way only. A `FAIL` node keeps
`TLS_UNKNOWN_AUTHORITY` or `TLS_IDENTITY_MISMATCH` in the note column, which is the actionable
fact.

### The wording

Not "insecure TLS". `--tls-insecure` is the flag; what it did is disable *peer verification*,
and the channel is still encrypted. "Insecure TLS" overstates in the other direction, and a
renderer that overstates in either direction is the thing this record is fixing.

`TestTheRowNeverClaimsVerificationHappened` asserts that the words `verified`, `trusted`,
`authenticated` and `identity confirmed` appear nowhere in an unverified run's output.

### It survives redaction

The fact qualifies the diagnosis, and a reader who was not at the terminal is exactly the reader
who cannot otherwise know. `kafka-insecure-tls-shareable.txt` pins it.

## 7. What an unverified handshake proves

Recorded here because §7 of the Phase 6.8A brief required the audit and the answer belongs with
the decision.

With `--tls-insecure`, svcdoctor may state:

- a TLS handshake completed
- the channel is encrypted

It may **not** state, and no output does:

- the peer's identity was verified
- the certificate chain was trusted
- a hostname matched
- an IP SAN matched
- the endpoint was authenticated by PKI

The help text, the README and the terminal were audited against this list. `--tls-insecure`'s
help entry now states what such a handshake proves and what it does not, and the README section
does the same above its worked example.

## 8. Where `tls.verified` lives now

`internal/render/terminal` had to read the attribute, and depguard denies a renderer the
`internal/probe` import — correctly, because a renderer that could reach a probe could run one.

`internal/vocabulary`'s doc comment already named the trigger: *no attribute key without a
consumer outside the package that produces it*, with `tls.verified` cited by name as one that
stays put until a reader appears. A reader appeared. `AttrTLSVerified` moved to
`internal/vocabulary` and `internal/probe/tls.AttrVerified` is now an alias, exactly as the
three step names were moved. One spelling, every caller unchanged, and the literal scan in
`internal/vocabulary/ownership_test.go` covers it.

`dns.answers`, `tls.cipher_suite` and the rest still have one reader each inside their producing
package and stay there.

## 9. Rejected alternatives

| Alternative | Why not |
|---|---|
| Accept TLS-only flags under `disable` as documented no-ops | §3 — the status quo that produced Gap B |
| Warn instead of refusing | §3 — corrupts the JSON artifact or is invisible; leaves the run ambiguous |
| Loosen Kafka to match PostgreSQL | Resolves the divergence by deleting a shipped guard |
| Make `tlsVerificationDisabled` nullable to express "no claim" | Schema break; §4 shows the distinction already exists across two fields |
| Derive `tlsVerificationDisabled` from the graph | §4 — goes silent exactly when the operator needs it, and changes Kafka's released semantics |
| An ERROR finding for disabled verification | §6 — the operator asked for it; changes the exit code |
| A new `FindingCode` for the annotation | §6 — no claim is being made that a finding would carry |
| Annotate the row from the run-level flag | §6 — wrong the moment a per-endpoint plan exists, and untestable against invention |
| Deprecation cycle before refusing | §5 — no warning channel; three no-op invocations do not justify one |

## 10. Reopen conditions

- **a per-endpoint TLS plan** — the header would stop being true of every row, and would need
  to become a count or a per-path statement. The row already reads the node and needs no change.
- **mTLS / client certificates** — a fourth TLS flag arrives, and it joins `tlsFlags` and the
  refusal list. Its credential authority is ADR 0058 §17's open question and is not decided
  here.
- **an operator reporting a real deployment that needs a TLS flag accepted under `disable`** —
  reopen §3. None is known, and by construction none can exist, because the flags did nothing.
