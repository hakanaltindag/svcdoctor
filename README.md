# svcdoctor

`svcdoctor` is an on-demand, evidence-linked connection diagnostic CLI for distributed
services. You point it at a service endpoint, it attempts the journey a real client would,
and it reports what it measured at every stage — and, just as deliberately, what it did not
learn.

**PostgreSQL BASIC and Kafka BASIC are supported today.** No APM, OpenTelemetry collector,
sidecar or agent is required for a diagnostic run.

## What it does

svcdoctor behaves as the client you describe and walks the same path:

```text
postgres   requested target → DNS → TCP → SSLRequest → TLS → Startup → Authentication → Session
kafka      requested target → DNS → TCP → TLS → ApiVersions → SASL negotiation → Authentication → Metadata
                                                                                   └→ per advertised broker: DNS → TCP → TLS
```

For Kafka it then measures DNS, TCP and TLS for every broker endpoint the cluster advertised —
**credential-free**. A discovered broker is an endpoint you never named, learned from
peer-supplied data, so it receives transport probing and nothing else.

At the end you get:

- what was measured, stage by stage, and where the journey stopped;
- the elapsed duration of each attempted stage;
- findings, each one linked to the exact evidence that produced it;
- whether the service's terminal exchange succeeded — a PostgreSQL session, or Kafka
  metadata obtained;
- for Kafka, how many advertised broker endpoints were reached and how many were never
  measured;
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
svcdoctor diagnose kafka --help
```

## Flags

Two leaf commands: `svcdoctor diagnose postgres` and `svcdoctor diagnose kafka`. Each owns its
own flag set, help text and validation.

### `diagnose postgres`

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

### `diagnose kafka`

| Flag | Default | Meaning |
|---|---|---|
| `--host <host>` | *required* | the bootstrap endpoint to diagnose |
| `--sasl-mechanism <name>` | *required* | the SASL mechanism to propose, uppercase |
| `--user <principal>` | *empty* | the principal to authenticate as; required with a credential source and refused without one |
| `--port <uint>` | `9092` | the port to connect to |
| `--timeout <duration>` | `30s` | bound on the whole run |
| `--step-timeout <duration>` | `10s` | bound on each individual exchange |
| `--output text\|json` | `text` | output form — see [Output modes](#output-modes) |
| `--shareable` | off | emit the redacted projection — see [Shareable reports](#shareable-reports) |

**svcdoctor can perform `PLAIN` and `SCRAM-SHA-256`, and no other Kafka SASL mechanism.**
Naming any other registered mechanism is allowed and useful: svcdoctor proposes it, records
what the broker answered, and reports that it cannot perform it — sending no credential and no
byte derived from one. `SCRAM-SHA-512`, `SCRAM-SHA-256-PLUS`, `OAUTHBEARER`, `GSSAPI`,
`AWS_MSK_IAM` and mTLS client-certificate authentication are **not** implemented.

`--sasl-mechanism` has no default and svcdoctor never picks one. A default would be a silent
decision about the framing that carries your password. There is no fallback in either
direction and no retry: one mechanism, one credential-bearing attempt (ADR 0057).

TLS flags are described under [TLS](#tls), and credential flags under
[Credentials](#credentials). `svcdoctor diagnose <service> --help` is authoritative.

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
  status     OK                   no target-side error was proven
  outcome    session established
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
  outcome      session NOT established
  execution    complete
  first break  L3                       tls
  duration     18.2ms
```

And a Kafka run whose bootstrap journey succeeded while one advertised broker did not answer:

```text
svcdoctor · kafka · kafka.prod.internal:9093

  ✓ PASS  DNS  1.9ms

  Path 10.0.4.21:9093 · continued
    ✓ PASS  TCP                         1.4ms
    ✓ PASS  TLS                         4.2ms
    ✓ PASS  Kafka API versions          0.4ms
    ✓ PASS  SASL mechanism negotiation  0.2ms
    ✓ PASS  Authentication              1.1ms
    ✓ PASS  Kafka metadata              0.9ms

  Advertised broker 1 · broker-1.prod.internal:9093
    ✓ PASS  Broker advertisement
    ✓ PASS  DNS                   0.3ms

    Path 10.0.4.21:9093
      ✓ PASS  TCP  1.3ms
      ✓ PASS  TLS  3.9ms

  Advertised broker 2 · broker-2.prod.internal:9093
    ✓ PASS  Broker advertisement
    ✓ PASS  DNS                   0.3ms

    Path 10.0.4.22:9093
      ✗ FAIL  TCP  2.1ms  TCP_CONNECTION_REFUSED
      ·       TLS         not reached

Findings
  ✗ ERROR  KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE  broker-2.prod.internal:9093
    ...

Result
  status       PROBLEMS FOUND
  outcome      Kafka metadata obtained
  topology     1 of 2 advertised broker endpoints reached
  execution    complete
  first break  L2                                          tcp
  duration     16.4ms
```

The Result lines are independent of one another: `status`, `outcome`, `execution`, and — when
a run discovered a topology — `topology`. None is derived from another. A run can be `OK` with
no metadata obtained, or `PROBLEMS FOUND` with metadata obtained, and both are coherent.

**`topology` counts, and judges nothing.** `reached` means at least one required transport path
for that endpoint completed from this vantage during this run. When svcdoctor's own budget
stopped a sweep, the line says so separately — `1 of 3 reached, 1 not measured` — because an
endpoint nobody measured is not one that refused.

**Kafka has no session.** There is no `ReadyForQuery`, no server message meaning *the
connection is now ready for ordinary work*, so the outcome line names the exchange that
happened: `Kafka metadata obtained`. That claims an authenticated, authorized API call
succeeded against **the one broker that answered** — not that the cluster is reachable, usable
or healthy.

### What "OK" means

> **An overall status of `OK` means no ERROR or CRITICAL target-side problem was proven. It
> does not mean a PostgreSQL session was established, or that Kafka metadata was obtained.**

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
  status     OK                       no target-side error was proven
  outcome    session NOT established
  execution  complete
```

This exits **0**. It is not an invocation error: svcdoctor was asked to measure an endpoint
and it did, truthfully reporting that nothing was sent and nothing was refused. Read the
`outcome` line, not the exit code, to learn whether the terminal exchange succeeded. Kafka
behaves identically, with `KAFKA_CREDENTIAL_NOT_CONFIGURED` and
`outcome  Kafka metadata NOT obtained`.

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

## What Kafka BASIC checks

Kafka BASIC is what svcdoctor can learn *while acting as the Kafka client you asked it to
be*. It produces and consumes **nothing**.

| Stage | What is measured |
|---|---|
| Requested target | the bootstrap host and port the run was asked to diagnose |
| DNS | resolution from this vantage point, and every address returned |
| TCP | a connection attempt per resolved address |
| TLS | handshake, chain verification, identity match, validity window |
| Kafka API versions | the capability exchange; a broker answers it **before** authentication |
| SASL mechanism negotiation | whether the endpoint offers the mechanism you named |
| Authentication | `PLAIN` or `SCRAM-SHA-256`, on exactly one selected path |
| Kafka metadata | whether an authenticated, authorized API call succeeded |
| Advertised broker endpoints | DNS, TCP and TLS for every endpoint the cluster named — credential-free |

Representative findings include name not resolved, TCP connection not established, TLS chain
not trusted, API versions not completed, auth mechanism not offered, authentication
unsupported by svcdoctor, credential not configured, credential withheld, credentials
rejected, peer verification failed, metadata not completed, advertised endpoint unreachable
and advertised endpoint unusable.

**What it is not.** No topic, partition, consumer-group, offset, lag or throughput
inspection. No cluster, broker or partition health claim. No producing, no consuming, no
administrative operation. The Metadata request asks for metadata about **no topics**, so none
of that state is even in the response.

**A credential never leaves the endpoint you named.** Metadata is a question, not a grant: a
broker the cluster advertises receives DNS, TCP and TLS and nothing else, whatever certificate
it presents. TLS proves you are talking to that host; nothing in the Kafka protocol proves
that host belongs to the cluster you asked about.

**`KAFKA_PEER_VERIFICATION_FAILED` is not a rejected credential.** SCRAM verifies the server
back, and a server whose proof does not verify is reported as exactly that — never as a wrong
password, which would send you to rotate a credential that is correct.

## Credentials

There are exactly two credential sources:

| Flag | Reads the credential from |
|---|---|
| `--password-file <path>` | a file |
| `--password-stdin` | standard input |

They are **mutually exclusive** — supplying both is an invocation error rather than a
precedence rule, so a run can never quietly authenticate with the source you did not mean.

Both commands use them, and both read them the same way.

Supplying neither is valid input. If the endpoint then requires authentication, the run
reports `POSTGRES_CREDENTIAL_NOT_CONFIGURED` or `KAFKA_CREDENTIAL_NOT_CONFIGURED` at `WARN`
with no terminal exchange completed, and nothing is sent.

For Kafka, `--user` is required alongside a credential source and refused without one: a Kafka
run sends an identity only inside the SASL exchange, so `--user` on a credential-free run
would do nothing, and a flag that is silently ignored is worse than one that is refused.

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

TLS is required by default and the endpoint's identity is verified by default. The full
policy is [ADR 0058](docs/decisions/0058-tls-trust-and-peer-identity-authority.md).

| Flag | Meaning |
|---|---|
| `--tls require\|disable` | negotiate an encrypted channel, or do not (default `require`) |
| `--tls-ca-file <path>` | PEM trust source. **It replaces the system trust store** — see below |
| `--tls-server-name <name>` | identity to verify and send in SNI; empty uses `--host` |
| `--tls-insecure` | do not verify the endpoint's identity |

There is no automatic fallback: a failed TLS negotiation is reported, never retried in
plaintext. libpq's `sslmode` vocabulary is deliberately not reproduced.

**Trust and identity are two separate questions**, and svcdoctor reports them separately:
`TLS_CHAIN_NOT_TRUSTED` means the chain did not verify against this run's trust source, and
`TLS_IDENTITY_MISMATCH` means it verified and named something else. A trusted chain with the
wrong identity is never reported as a verified peer.

### `--tls-ca-file` replaces the system trust store

When you name a CA file it becomes the **complete** trust source for the run; system roots are
not consulted. That is what makes "only this issuer is acceptable here" expressible, and it is
why naming the wrong CA fails rather than quietly passing against a public certificate. To
trust both, concatenate the PEMs into one file.

An unusable CA file — missing, unreadable, empty, or holding no certificate — is an invocation
error (exit 2). svcdoctor never falls back to the system store when you asked for a specific
one.

### Identity is the name you asked for

The identity verified is exactly `--host`, unless `--tls-server-name` overrides it. **DNS
resolution never changes it**: one hostname resolving to five addresses produces five
handshakes that all verify that hostname, which is what a real client does.

`--tls-server-name` sets both the identity verified and the name sent in SNI — they are one
setting, and svcdoctor will not verify one name while announcing another. It applies to the
**requested target only**. Kafka brokers learned from Metadata are verified against their own
advertised names, because a bootstrap address and a broker are different endpoints and
frequently carry different certificates.

Certificates are matched on subject alternative names. A `CN`-only certificate does not verify,
matching every modern client; svcdoctor adds no compatibility exception for one.

### `--tls-insecure`

It disables identity verification — both chain and name, which in Go are one operation. It is
explicit, per-run, and never an automatic fallback after a verification failure.

It does **not** mean "connect insecurely and authenticate anyway": the resulting channel is
unverified, and the credential-transport policy refuses to present a password over an
unverified channel. Such a run reports `POSTGRES_CREDENTIAL_WITHHELD` or
`KAFKA_CREDENTIAL_WITHHELD` and sends nothing.

> **Read the JSON to see that verification was disabled.** The canonical report records it as
> `security.tlsVerificationDisabled` and marks each handshake `tls.verified: false`. **The
> terminal output does not yet say so** — it shows `✓ PASS TLS` for a handshake whose peer was
> never identified. That gap is recorded in [ADR 0058](docs/decisions/0058-tls-trust-and-peer-identity-authority.md)
> §14.1 and is scheduled for the next phase.

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
  connection succeeded" — the no-credential run above is the counterexample. The exit mapping
  is service-independent: it reads the report's summary status and whether execution finished,
  and nothing else.

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

**PostgreSQL BASIC is complete and feature-frozen. Kafka BASIC is implemented and exposed.**
Two leaf commands, `svcdoctor diagnose postgres` and `svcdoctor diagnose kafka`, with text and
JSON output, file and stdin credential input, shareable redaction, and the exit-code contract
above.

BASIC is bounded on purpose: it learns what svcdoctor can observe while acting as the client
for this run. Inspecting a server's operational state is a separate future body of work
(PostgreSQL DEEP) and is not part of v0.1.

### Not in v0.1

These are deliberate boundaries, not defects:

- no `inspect` command — the namespace is reserved, its output contract deferred
- no Kafka SASL mechanism beyond `PLAIN` and `SCRAM-SHA-256`: no `SCRAM-SHA-512`, no
  `SCRAM-SHA-256-PLUS`, no channel binding, no `OAUTHBEARER`, no `GSSAPI`, no `AWS_MSK_IAM`,
  no mTLS client-certificate authentication
- no Kafka topic, partition, consumer-group, lag or throughput inspection, and no cluster,
  broker or partition health claim
- no literal IPv4/IPv6 target support — `--host` expects a name that resolves; the graph
  semantics for a literal are an open design item
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

PostgreSQL-only v0.1.0 is tagged. Kafka BASIC is implemented, exposed and closed on `main`,
pending release validation.

Next, in no committed order:

- Kafka BASIC release validation
- literal IPv4/IPv6 target semantics, for both services, and the three gaps ADR 0058 recorded
- client certificates / mTLS, whose credential authority ADR 0058 deliberately left open
- managed-service protocol compatibility: Redpanda, Confluent Cloud, AWS MSK, Azure Event
  Hubs' Kafka API; RDS, Aurora, Cloud SQL, Azure Database for PostgreSQL
- Markdown and HTML renderers, derived from the canonical report
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
