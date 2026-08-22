# svcdoctor

`svcdoctor` is an on-demand, evidence-linked connection diagnostic CLI for distributed
services. You point it at a service endpoint, it attempts the journey a real client would,
and it reports what it measured at every stage — and, just as deliberately, what it did not
learn.

**PostgreSQL is supported today.** No APM, OpenTelemetry collector, sidecar or agent is
required for a diagnostic run.

## What it does

For PostgreSQL, svcdoctor behaves as the client you describe and walks the same path:

```text
requested target → DNS → TCP → SSLRequest → TLS → Startup → Authentication → Session
```

At the end you get:

- what was measured, stage by stage, and where the journey stopped;
- the elapsed duration of each attempted stage;
- findings, each one linked to the exact evidence that produced it;
- whether a PostgreSQL session was actually established;
- whether svcdoctor's own execution completed.

The design goal is a report that separates **what was measured** from **what can honestly be
claimed**. `UNKNOWN` is not a failure. A local timeout is not a target timeout. Missing
credentials are not a rejected password.

## Quick start

```sh
svcdoctor diagnose postgres \
  --host db.prod.internal \
  --user svcdoctor \
  --password-file /run/secrets/postgres
```

Text output is the default, so no output flag is needed. To select a database explicitly:

```sh
svcdoctor diagnose postgres \
  --host db.prod.internal \
  --user svcdoctor \
  --database appdb \
  --password-file /run/secrets/postgres
```

A credential is optional input. Running without one is a valid diagnostic run — see
[Credentials](#credentials).

Help and version:

```sh
svcdoctor --help
svcdoctor --version
svcdoctor diagnose --help
svcdoctor diagnose postgres --help
```

## Flags

`svcdoctor diagnose postgres` is the only leaf command in v0.1.

| Flag | Default | Meaning |
|---|---|---|
| `--host <host>` | *required* | the endpoint to diagnose |
| `--user <role>` | *required* | the role to connect as |
| `--port <uint>` | `5432` | the port to connect to |
| `--database <name>` | *empty* | database to select; empty lets the server default it to the role name |
| `--timeout <duration>` | `30s` | bound on the whole run |
| `--step-timeout <duration>` | `10s` | bound on each individual exchange |
| `--output text\|json` | `text` | output form — see [Output modes](#output-modes) |
| `--shareable` | off | emit the redacted projection — see [Shareable reports](#shareable-reports) |

TLS flags are described under [TLS](#tls), and credential flags under
[Credentials](#credentials). `svcdoctor diagnose postgres --help` is authoritative.

## Example output

A run that reached a session. Durations below are illustrative, not a benchmark.

```text
svcdoctor · postgres · db.prod.internal:5432

  ✓ PASS  DNS  2.3ms

  Path 10.0.4.17:5432 · continued
    ✓ PASS  TCP             1.8ms
    ✓ PASS  SSLRequest      0.9ms
    ✓ PASS  TLS             4.1ms
    ✓ PASS  Startup         1.2ms
    ✓ PASS  Authentication  2.8ms
    ✓ PASS  Session         0.4ms

Findings
  none

Result
  status     OK           no target-side error was proven
  session    established
  execution  complete
  duration   13.5ms
```

A run that stopped at TLS:

```text
svcdoctor · postgres · db.prod.internal:5432

  ✓ PASS  DNS  2.1ms

  Path 10.0.4.17:5432
    ✓ PASS     TCP             1.7ms
    ✓ PASS     SSLRequest      0.9ms
    ✗ FAIL     TLS             15.5ms  TLS_UNKNOWN_AUTHORITY
    · SKIPPED  Startup                 EXEC_SKIPPED_PREREQUISITE_FAILED
    ·          Authentication          not reached
    ·          Session                 not reached

Findings
  ✗ ERROR  POSTGRES_TLS_CHAIN_NOT_TRUSTED  db.prod.internal:5432
    The certificate chain presented for the PostgreSQL TLS upgrade did not verify
    against this run's trust context
    ...
    → Check the trust material this run was given against the chain recorded on the
      referenced evidence
    evidence: 2

Result
  status       PROBLEMS FOUND
  session      NOT established
  execution    complete
  first break  L3               tls
  duration     18.2ms
```

Three lines are always printed, and they are independent of one another: `status`, `session`
and `execution`.

### What "OK" means

> **An overall status of `OK` means no ERROR or CRITICAL target-side problem was proven. It
> does not mean a PostgreSQL session was established.**

That distinction is load-bearing, and the most common way to reach it is running without a
credential against an endpoint that requires authentication:

```text
    · SKIPPED  Authentication         EXEC_REQUIRED_INPUT_MISSING
    ·          Session                not reached

Findings
  ⚠ WARN  POSTGRES_CREDENTIAL_NOT_CONFIGURED  db.prod.internal:5432
    The PostgreSQL endpoint required authentication and this run had no credential
    to present

Result
  status     OK               no target-side error was proven
  session    NOT established
  execution  complete
```

This exits **0**. It is not an invocation error: svcdoctor was asked to measure an endpoint
and it did, truthfully reporting that nothing was sent and nothing was refused. Read the
`session` line, not the exit code, to learn whether a session existed.

### Stage durations

Each attempted stage records its own elapsed duration, and the run records its own total. The
total is measured for the run; it is not the sum of the stage durations.

These are point-in-time measurements taken from the svcdoctor execution vantage for that one
exchange. They are not historical latency analysis, and svcdoctor applies no thresholds,
baselines or comparisons to them. No finding is derived from a duration.

## What PostgreSQL BASIC checks

PostgreSQL BASIC is what svcdoctor can learn *while acting as the PostgreSQL client you asked
it to be*. It issues **no SQL**.

| Stage | What is measured |
|---|---|
| Requested target | the host and port the run was asked to diagnose |
| DNS | resolution from this vantage point, and every address returned |
| TCP | a connection attempt per resolved address |
| SSLRequest | PostgreSQL's in-band negotiation of an encrypted channel |
| TLS | handshake, chain verification, identity match, validity window |
| Startup | the startup exchange and the authentication the endpoint requests |
| Authentication | mechanism negotiation and the outcome of SCRAM-SHA-256 |
| Session | whether the session reached `ReadyForQuery` |

Representative findings include name not resolved, TCP connection not established, TLS
declined, SSL negotiation failed, TLS chain not trusted, TLS identity mismatch, credential
not configured, credential withheld, credentials rejected, database not found, and database
connect denied.

For the finding conventions and the full catalog, see [`docs/FINDINGS.md`](docs/FINDINGS.md),
with worked examples in [`docs/DIAGNOSIS_EXAMPLES.md`](docs/DIAGNOSIS_EXAMPLES.md).

## Credentials

There are exactly two credential sources:

| Flag | Reads the credential from |
|---|---|
| `--password-file <path>` | a file |
| `--password-stdin` | standard input |

They are **mutually exclusive** — supplying both is an invocation error rather than a
precedence rule, so a run can never quietly authenticate with the source you did not mean.

Supplying neither is valid input. If the endpoint then requires authentication, the run
reports `POSTGRES_CREDENTIAL_NOT_CONFIGURED` at `WARN` with no session established, and
nothing is sent.

Reading from a pipe, for example from a secret-provider command:

```sh
secret-provider read postgres/svcdoctor | \
  svcdoctor diagnose postgres --host db.prod.internal --user svcdoctor --password-stdin
```

There is **no** literal `--password` flag, no environment-variable source, no interactive
prompt and no DSN input. A password on a command line is visible in the process table and in
shell history, which is why it is not offered.

Credential material is not part of the report, in either output mode.

## TLS

TLS is required by default and the endpoint's identity is verified by default.

| Flag | Meaning |
|---|---|
| `--tls require\|disable` | negotiate an encrypted channel, or do not (default `require`) |
| `--tls-ca-file <path>` | PEM trust source; empty uses the system trust store |
| `--tls-server-name <name>` | identity to verify and send in SNI; empty uses `--host` |
| `--tls-insecure` | do not verify the endpoint's identity |

There is no automatic fallback: a failed TLS negotiation is reported, never retried in
plaintext. libpq's `sslmode` vocabulary is deliberately not reproduced.

`--tls-insecure` disables verification and is recorded in the report. It does **not** mean
"connect insecurely and authenticate anyway": the resulting channel is unverified, and the
credential-transport policy refuses to present a password over an unverified channel. Such a
run reports `POSTGRES_CREDENTIAL_WITHHELD` and sends nothing.

## Output modes

| `--output` | Result |
|---|---|
| `text` | human-readable terminal report (**default**) |
| `json` | the canonical Report document |

JSON is the canonical representation and the one to use for automation; the terminal form is
derived from the same report. Markdown and HTML renderers are planned but **not implemented**
— see [Roadmap](#roadmap).

### JSON for automation

For exit codes **0, 1 and 4**, stdout contains exactly one JSON document and stderr is empty.
For exit codes **2 and 3**, stdout is empty and the error is written to stderr; no report is
produced.

The JSON is the canonical Report and nothing else. In particular the CLI does not inject a
process exit code, an execution-completeness flag, or a session-established flag into the
document — those are process- and presentation-level facts, and the schema does not carry
them. `schemaVersion` is `1`.

Parse the JSON. Do not parse the terminal text; its layout is a presentation detail.

The report model is specified in [`docs/REPORT_SCHEMA.md`](docs/REPORT_SCHEMA.md).

## Shareable reports

```sh
svcdoctor diagnose postgres --host db.prod.internal --user svcdoctor \
  --password-file /run/secrets/postgres --shareable --output json
```

`--shareable` emits the `SHAREABLE_REDACTED` projection of the same report instead of the
local one. Identity-bearing fields covered by the redaction policy — hostnames, addresses,
role and database names, the local vantage — are replaced with stable pseudonyms, applied
consistently so that relationships between target, evidence and findings remain readable.
Findings, evidence references and durations are preserved, and the exit code is unchanged:
redaction changes what a shared copy reveals, never what was concluded.

Redaction **fails closed**. If the residual identity check cannot confirm that a covered
value was replaced, svcdoctor emits no report at all and exits 3 rather than writing a
partially redacted artifact to stdout.

This applies the redaction policy recorded in [`docs/SECURITY.md`](docs/SECURITY.md). It is
not a claim of anonymization or of regulatory compliance; review a shared report against your
own disclosure requirements.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | a report was produced, execution completed, and no ERROR/CRITICAL target-side finding exists |
| 1 | a report was produced, execution completed, and an ERROR/CRITICAL target-side finding exists |
| 2 | svcdoctor was invoked with something it cannot act on; no report |
| 3 | svcdoctor itself failed and produced no usable report |
| 4 | a report was produced, but svcdoctor's own execution did not finish |

Precedence is `3 > 2 > 4 > 1 > 0`.

- **Exit 1 means svcdoctor worked** and found a target-side problem. It is not a svcdoctor
  failure.
- **Exit 4 outranks exit 1.** A run that was cut short and also proved an ERROR exits 4, and
  the finding stays in the report — incompleteness qualifies every conclusion in it. Exit 4
  is reached by cancellation (`SIGINT`/`SIGTERM`) or by an expired local execution budget; a
  partial report is still written to stdout.
- **A `WARN` finding with overall status `OK` still exits 0.** Do not read exit 0 as "a
  connection succeeded" — the no-credential run above is the counterexample.

## Build and install

Go 1.26 or newer, from a checked-out repository:

```sh
go install ./cmd/svcdoctor      # into $GOBIN
go build -o svcdoctor ./cmd/svcdoctor
```

The binary is statically linkable and builds with `CGO_ENABLED=0`. It needs no source tree,
no configuration file and no runtime data directory.

There are currently no Homebrew, Docker, apt, RPM or prebuilt-binary distributions.

`svcdoctor --version` reports the release the binary was built as, and the same value is
recorded in every report. A binary installed from a tagged module —
`go install github.com/hakanaltindag/svcdoctor/cmd/svcdoctor@v0.1.0` — reports that tag. A
build from a working checkout reports `dev`, as does a build from a modified tree, because
neither corresponds to a released commit. Release builders can also inject a value with
`-ldflags "-X main.version=v0.1.0"`, which takes precedence over both.

## Current scope

**PostgreSQL BASIC is complete and feature-frozen.** The PostgreSQL-only v0.1 CLI is
implemented: one leaf command, `svcdoctor diagnose postgres`, with text and JSON output,
file and stdin credential input, shareable redaction, and the exit-code contract above.

BASIC is bounded on purpose: it learns what svcdoctor can observe while acting as the
PostgreSQL client for this run. Inspecting a server's operational state is a separate future
body of work (PostgreSQL DEEP) and is not part of v0.1.

### Not in v0.1

These are deliberate boundaries, not defects:

- no Kafka CLI (the Kafka adapter exists internally; no command is exposed)
- no `inspect` command — the namespace is reserved, its output contract deferred
- no PostgreSQL DEEP, no diagnostic SQL of any kind
- no `pg_stat_*` inspection, connection-pool, blocking-query or replication analysis
- no table or query latency diagnosis
- no monitoring, historical state, baselines or thresholds
- no generic TLS diagnosis command
- no Kubernetes integration, agent mode or eBPF
- no Markdown or HTML output
- no color or progress UI, no shell completion
- no literal-password flag, environment-variable password or interactive prompt
- no DSN or `sslmode` input
- no retries and no protocol fallbacks

Deferred until PostgreSQL and Kafka are both validated as products: Redis/Valkey, RabbitMQ,
MySQL/MariaDB, Elasticsearch/OpenSearch.

Out of scope for v0.1 entirely: host mode, eBPF, MCP server, PDF generation, tuning advisor,
long-term monitoring, LLM-based core diagnosis, and generic rule scripting DSLs.

## How it fits together

```text
CLI  →  application composition  →  probes / adapters  →  evidence graph
                                                              ↓
        text / JSON  ←  optional shareable redaction  ←  Report  ←  diagnosis
```

The separation is the architecture's primary rule:

> **Probes collect facts. Adapters understand protocols. Diagnosis correlates evidence.
> Renderers explain results.**

Probes gather DNS, TCP and TLS facts and know nothing about PostgreSQL. Adapters own protocol
semantics and normalize wire responses into evidence. Diagnosis runs over a frozen evidence
graph and performs no I/O — when evidence is missing it emits `UNKNOWN` or `SKIPPED` rather
than going to look. Renderers create no findings and compute no severity.

The layer order the report reasons about:

```text
L0  Input / config normalization      L4  Protocol / capability discovery
L1  DNS                               L5  Authentication / authorization
L2  TCP                               L6  Topology discovery
L3  TLS
```

svcdoctor has **one runtime dependency**: `github.com/twmb/franz-go/pkg/kmsg` (BSD-3-Clause,
no transitive dependencies), used only by the Kafka adapter's wire package.

Full detail is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); the product boundary is in
[`docs/SCOPE.md`](docs/SCOPE.md); design records are in
[`docs/decisions/`](docs/decisions/README.md).

## Claim discipline

One idea distinguishes svcdoctor from a connectivity check: **it separates what it measured
from what it can safely claim.**

- `UNKNOWN` is not `FAIL`. An unsupported capability, or a stage svcdoctor could not
  complete, is a gap in the tool rather than a defect in the target.
- A local execution timeout is not a remote failure. It means the budget expired, and
  nothing was learned about the target.
- No credential is not a bad password. Nothing was sent, so nothing was refused.
- A finding is valid from the vantage point it was recorded at, unless the evidence proves
  otherwise.
- Every finding references the exact evidence identifiers that produced it, and severity and
  confidence are reported separately — never fused into one score or a percentage.

## Development

```sh
make check                 # fmt-check, test, vet, lint, build — mirrors CI
make fmt                   # format sources in place
make help                  # list targets

make integration-postgres  # full PostgreSQL validation against a real server (needs Docker)
```

`make check` is fast and hermetic. The integration gate is deliberately excluded from it
because it requires Docker; it starts a real PostgreSQL 18 server, runs the suite against it
and tears it down. See [`test/integration/postgres/README.md`](test/integration/postgres/README.md).

Linting uses [golangci-lint](https://golangci-lint.run) `v2.13.1` (v2 config format).

Package-level fixtures live in package-adjacent `testdata/` directories; `test/` holds
cross-package and environment-dependent tests.

## Roadmap

PostgreSQL-only v0.1 is **release-ready** and not yet tagged or distributed.

Next, in no committed order:

- Markdown and HTML renderers, derived from the canonical report
- a Kafka command, once a Kafka composition root exists (the adapter, topology discovery and
  diagnosis rules are already implemented and validated against a real cluster)
- the `inspect` namespace, once its output contract is decided
- PostgreSQL DEEP

The authoritative phase numbering and checklist live in
[`docs/BACKLOG.md`](docs/BACKLOG.md).

| | |
|---|---|
| Repository | `github.com/hakanaltindag/svcdoctor` |
| Go module path | `github.com/hakanaltindag/svcdoctor` |
| Go version | 1.26 |
| License | Apache-2.0 |
