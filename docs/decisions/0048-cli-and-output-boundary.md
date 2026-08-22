# ADR 0048: The report is the product, and the process status is the only thing said about the run

## Status

**Accepted. Not implemented — Phase 5.1 onwards.**

It fixes the command tree, the ownership split between `cmd`, `internal/cli`,
`internal/app` and `internal/render`, the JSON artifact, the stdout/stderr
contract, the exit-code mapping, and the presentation invariants PostgreSQL
BASIC's committed semantics force on any renderer.

No `FindingCode`, no `FailureClass`, no schema field, no dependency and no
diagnosis behaviour changes. `FindingCode` stays **24**, `FailureClass` **40**,
`schemaVersion` **1**, `security.Reveal` **two**, the dependency set one.

Credential input is deliberately **not** here. It is a separate security
decision with a different risk profile and is recorded in ADR 0049.

## 1. Context

PostgreSQL BASIC is complete and feature-frozen. Everything below consumes it;
nothing below may extend it. The CLI is the first user-facing boundary, and the
frozen semantics it has to carry are unusually easy to render wrongly:

- `SummaryStatus == OK` means *no ERROR or CRITICAL target-side problem was
  proven*. It is not a claim that a session was established.
- `POSTGRES_CREDENTIAL_NOT_CONFIGURED` is WARN with status `OK`, a complete run,
  and no session (ADR 0046).
- `Result.Incomplete()` is orthogonal to status, and `OK` + incomplete is a valid
  state meaning svcdoctor's own budget ended the run (ADR 0047).

A renderer that collapses those into one green word would publish a falsehood the
diagnosis layer spent four phases refusing to state.

## 2. The command tree

Action-first, as ADR 0041 §3 fixed and as ADR 0011 is superseded on:

```text
svcdoctor diagnose postgres [flags]
svcdoctor --help | --version
svcdoctor diagnose --help
svcdoctor diagnose postgres --help
```

Rejected, unchanged: `svcdoctor postgres`, `svcdoctor postgres diagnose`.

**`inspect` and `diagnose kafka` are not exposed.** ADR 0041 reserved the
`inspect` namespace and deferred its output contract; a stub that parses and then
refuses is a non-functional product surface, and Kafka has no composition root to
call. The service token is `postgres`, matching `domain.NewServiceID("postgres")`.

ADR 0011's original reason for service-scoped flags survives intact: each service
owns its own flag set, help text and validation, because `diagnose postgres
--user` and a future `diagnose kafka --bootstrap` have nothing in common.

## 3. Ownership

| Layer | Owns |
|---|---|
| `cmd/svcdoctor` | process bootstrap, root signal context, `os.Exit` |
| `internal/cli` | command dispatch, input validation, credential source, params, output-security choice, renderer choice, **exit code** |
| `internal/app` | composition and execution |
| `internal/render` | presentation, and nothing else |
| `internal/domain`, `internal/diagnosis` | unchanged |

A renderer **must not** choose an exit code, diagnose, parse an `EvidenceID`,
read raw protocol values to invent a claim, or import `internal/app`,
`internal/adapter`, `internal/probe`, `internal/diagnosis` or
`internal/security`. A command **must not** format a finding.

`internal/security/redaction` is denied to the renderer too, and that is the
sharper half of the rule: redaction happens at the output boundary, *before* a
renderer runs, and a renderer able to redact could produce a shareable-looking
report from a local one without the report's own security metadata agreeing
(ADR 0018).

## 4. `Result` carries the run; `Report` carries the diagnosis

`app.Result` holds the `Report` and `Incomplete()`. The CLI consumes `Result`.
The renderer receives the smallest thing that lets it present without becoming
orchestration — the report plus the one run fact that is not in it:

```go
// internal/render
type Input struct {
    Report     domain.Report
    Incomplete bool
}
```

The renderer therefore depends on `internal/domain` and on service vocabulary for
labels, and never on `internal/app`. Passing `app.Result` itself was rejected: it
would make an orchestration type the renderer's input, and a future `inspect`
result or Kafka result would each drag their own orchestration type into
presentation.

## 5. JSON is the canonical report, and nothing wrapped

`--output json` emits exactly `domain.Report`'s marshalling: `schemaVersion` at
the top level, then `run`, `target`, `vantage`, `evidence`, `findings`,
`summary`, `security`. It is already deterministic and already the canonical
artifact (ADR 0016). No CLI DTO, no envelope, no second schema.

**The consequence is that `Result.Incomplete()` is not serialized**, and that is
committed policy rather than an omission. `docs/REPORT_SCHEMA.md` §8: *"Exit
codes 2, 3 and 4 stay outside the summary: they describe usage errors, internal
failures and partial runs, none of which a report can observe about itself."*

A machine consumer learns incomplete execution from **process exit code 4**. The
report still carries the evidence — UNKNOWN nodes with `EXEC_LOCAL_TIMEOUT` or
`EXEC_CANCELLED`, and `summary.unknownEvidenceCount`.

**Reopen when** a real consumer must detect incompleteness from a JSON file
detached from the process that produced it. That is a `schemaVersion`
conversation, not a flag.

## 6. Output modes

`--output text|json`, default `text`. `--shareable` derives the shareable form.

```text
app produces a truthful LOCAL_FULL report
    ↓
CLI optionally applies internal/security/redaction.Redact
    ↓
renderer receives whichever report was chosen
```

Diagnosis is never re-run, redaction is never performed twice, the renderer never
redacts, and no third `OutputMode` is created. `--shareable` names the intent;
`--redact` would name the mechanism. Terminal output states
`Shareable report · identities redacted`; JSON needs no addition because
`security.outputMode` already carries `LOCAL_FULL` or `SHAREABLE_REDACTED`
— verified in `ReportSecurity.MarshalJSON`.

## 7. stdout, stderr, and exit codes

**stdout carries the report artifact** — exit 0, 1 and 4. **stderr carries usage
errors and internal failures** — exit 2 and 3, which produce no report.

A target-side ERROR does not move the report to stderr. `docs/SCOPE.md` is
explicit that exit 1 means svcdoctor worked and found a target-side problem, so
its report is a success artifact. Under `--output json`, stdout is valid
canonical JSON on 0, 1 and 4, with no status line before or after it, and empty
on 2 and 3.

The exit contract is `docs/SCOPE.md`'s, unchanged, including its precedence:

```text
3 > 2 > 4 > 1 > 0
```

| Code | Meaning |
|---|---|
| 0 | report exists, no ERROR/CRITICAL finding, execution complete |
| 1 | report exists, ERROR/CRITICAL finding, execution complete |
| 2 | invalid invocation or input |
| 3 | internal svcdoctor failure |
| 4 | report exists, execution incomplete (cancellation or local budget) |

**Exit 4 outranks exit 1**, because incompleteness qualifies every conclusion in
the report; a partial run that found an ERROR still exits 4 and keeps the
finding. WARN + `OK` + complete exits **0**.

One pure function owns the mapping, takes no I/O, and is table-tested:

```go
func ExitCode(res app.Result, err error) int
```

## 8. Signals, and no live progress

`cmd/svcdoctor` builds the root context with `signal.NotifyContext` for SIGINT
and SIGTERM. Probes and adapters install no handlers. `DiagnosePostgres` already
returns a report on a cancelled context, so Ctrl-C prints the partial report,
`Incomplete()` is true, and the process exits 4.

**v0.1 emits no live progress.** Run first, render once. A spinner or a
`connecting…` line would put non-artifact bytes on stdout, complicate the JSON
contract, make golden tests inexact and introduce a TTY dependency. Reopen only
against a real UX complaint.

## 9. What the terminal renderer must say

It answers, in order: what was diagnosed, whether the measurement completed,
whether a session was established, where the journey stopped, what each stage
observed and how long it took, and which findings matter.

**Three facts are rendered separately and none may stand for another:**

```text
status      OK              no target-side error was proven
session     NOT established
execution   complete
```

That shape is required for `POSTGRES_CREDENTIAL_NOT_CONFIGURED`. `status OK` is
never printed bare; it always carries its gloss.

**Normative, and the reason this ADR exists:**

- A WARN finding **must** be rendered even when `SummaryStatus == OK`.
- `SummaryStatus == OK` **must not** suppress any finding.
- Session establishment **must** be rendered independently of `SummaryStatus`.
- No wording may imply a session was established unless session evidence proves
  it. `✓ PostgreSQL OK` is forbidden where it could be read that way.

## 10. Session establishment is structural

A `postgres.session` node in state `PASS`, read through `domain.Graph`. Never
from `SummaryStatus`, never from the absence of findings, never from the exit
code, never by parsing an identifier.

**No `sessionEstablished` field is added to the schema.** The graph already
carries the fact, and duplicating graph truth into the report is what ADR 0016
declines.

## 11. The stage tree, labels and durations

The tree is built from `Graph.Nodes`, `Parents`, `Children` and each node's
`Step`, `State`, `Subject` and `Duration`. Human labels live in the renderer as a
`map[domain.Step]string` whose fallback prints the canonical step name verbatim —
so an unlabelled step still renders, no service switch is ever written, and Kafka
later adds rows rather than a branch. Canonical step names are machine contracts
and are not made presentation-friendly.

Durations: a stage may show its own elapsed time; a local timeout means *how long
svcdoctor waited before its own limit stopped the step*. No threshold, no
colour-by-magnitude, no averaging across paths, and never the words `slow`,
`fast`, `high latency` or `degraded`. Multi-path durations stay per path.

Overall elapsed time comes from `RunMetadata.Duration()`. **Never** `Σ(stage
durations)` — orchestration gaps exist between stages and the sum is measurably
not the total.

## 12. Glyphs, colour and non-TTY

`✓` PASS · `✗` FAIL · `?` UNKNOWN · `·` SKIPPED or not reached · `⚠` WARN.

Every state is also readable as text; no meaning is encoded only by a glyph or a
colour. **v0.1 ships no colour and no terminal dependency**, so piped,
redirected and interactive output are byte-identical and golden tests are exact.
`--color` is a purely additive follow-up.

## 13. Dependencies

**CLI: the standard library's `flag`.** With one leaf command, dispatch is two
switches over `os.Args` plus a `flag.FlagSet` per command. Cobra would add two
modules to a repository that has defended a single dependency for four phases,
and buys shell completion v0.1 does not require. **Reopen when** the command
surface grows materially or completion becomes a product requirement.

**Renderer: the standard library only**, with `text/tabwriter` for alignment. No
`lipgloss`, `termenv` or `tablewriter`.

## 14. Package boundary

```text
cmd/svcdoctor/            process bootstrap only
internal/cli/             dispatch, input, output selection, exit semantics
internal/render/          presentation only (terminal/, json/)
internal/platform/local/  the local vantage fact
```

Filenames are implementation detail; the responsibilities are the decision.
Explicit command wiring inside `internal/cli` is the single composition point
ADR 0009 permits — a runtime generic adapter registry remains rejected.

A `render-is-presentation-only` depguard rule is required when the package gains
its first Go file, denying `internal/app`, `internal/adapter`, `internal/probe`,
`internal/diagnosis`, `internal/security`, `internal/security/redaction`,
`net/http` and `os/exec`. It is deliberately **not** added in the decision phase:
depguard rules are keyed on files, and a rule guarding an empty directory guards
nothing while reading as though it guards something.

## 15. The v0.1 flag surface

Required: `--host`, `--user`. Optional: `--database`, `--tls-ca-file`,
`--tls-server-name`, `--tls-insecure`, `--shareable`, and ADR 0049's credential
flags. Defaulted: `--port 5432`, `--output text`, `--tls require`,
`--timeout 30s`, `--step-timeout 10s`.

The two timeout values are **implementation direction, not contract**:
`docs/ARCHITECTURE.md` §13 and `CLAUDE.md` both hold that exact timeout values
are implementation decisions. Both are exposed and both default non-zero, so
there is no hidden infinite run. Exposing `--step-timeout` is a product decision
rather than a leak: a black-holed address must not consume the whole budget, and
Phase 4.11d's first defect was precisely a step budget silently not applied.

`--tls` takes `require` or `disable`, mirroring `TLSPlan`. It is deliberately not
libpq's `sslmode`, and there is no `prefer`: falling back from a failed handshake
to a working plaintext one would swallow the very defect a diagnostic run exists
to find (ADR 0036 §4).

`--tls-insecure` is explicit, never automatic, and its help text must state both
consequences: identity verification is disabled, and the resulting channel is
`tls-unverified`, which the committed credential-transport policy refuses — so a
credential supplied alongside it is **withheld**, producing
`POSTGRES_CREDENTIAL_WITHHELD` rather than an authentication attempt. That is the
existing policy being surfaced, not changed.

`--user` is required and has **no OS-user default**: silently diagnosing as
`$USER` would make the report ambiguous about what was actually sent.
`--database` may be left empty, because the wire genuinely omits it and the
server defaults it to the role name; svcdoctor invents no client-side
`database = user`, so the report reflects exactly what it supplied.

The credential-transport policy is not a flag: `security.CredentialTransportPolicy`
has exactly one member.

## 16. Local vantage

`domain.NewLocalVantage(host)` is the only constructor and `LOCAL_HOST` the only
source. `internal/platform/local` builds it from `os.Hostname()`; the renderer
never constructs platform identity. Redaction already pseudonymizes the vantage
host and fails closed on an unknown vantage source, so the hostname is safe under
the shareable model. No further machine identity is collected.

## 17. Help and version

`svcdoctor --help`, `--version`, `diagnose --help`, `diagnose postgres --help`.
An unknown action or service exits 2 on stderr with a concise deterministic error
and a usage hint — no fuzzy matching and no command suggestions in v0.1. The
version is a build-time string with a development fallback, and lands in
`run.svcdoctorVersion`. The release pipeline is out of scope here.

## 18. Rejected alternatives

| Alternative | Why rejected | Reopen when |
|---|---|---|
| A CLI JSON DTO or envelope around the report | Creates a second schema to keep in step with the canonical one and displaces `schemaVersion` from the top level (ADR 0016) | — |
| Add `incomplete` to the report schema | `REPORT_SCHEMA.md` §8 holds that a report cannot observe its own partiality | A detached-JSON consumer genuinely needs it |
| Add `sessionEstablished` to the schema | Duplicates a fact the graph already carries | — |
| Pass `app.Result` to the renderer | Makes an orchestration type the presentation input | — |
| Let the renderer redact | Redaction is an output-boundary transformation, and the report's own security metadata would no longer be authoritative | — |
| Report to stderr on exit 1 | Exit 1 means svcdoctor produced its artifact successfully | — |
| Cobra or another CLI framework | Two modules for one leaf command, against four phases of dependency discipline | Command surface grows, or completion is required |
| Colour in v0.1 | Meaning must survive `NO_COLOR` anyway, so colour is additive; omitting it keeps golden tests byte-exact | A real readability complaint |
| Live progress | Non-artifact bytes on stdout, inexact tests, TTY dependency | A real UX complaint |
| Exposing `inspect` as "not implemented" | A non-functional product surface | Its output contract is decided |

## 19. What would falsify this

- A report where `status OK` was read as "the session worked".
- A JSON consumer that could not tell a complete run from an incomplete one and
  had no access to the exit code.
- A renderer that needed an adapter import, an `EvidenceID` parse or a diagnosis
  rule to render a PostgreSQL run.
