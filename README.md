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

| Flag                        | Default    | Meaning                                                                                                             |
| --------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------- |
| `--host <host>`             | _required_ | the endpoint to diagnose: a hostname or an IPv4 or IPv6 address literal — see [Address literals](#address-literals) |
| `--user <role>`             | _required_ | the role to connect as                                                                                              |
| `--port <uint>`             | `5432`     | the port to connect to                                                                                              |
| `--database <name>`         | _empty_    | database to select; empty lets the server default it to the role name                                               |
| `--timeout <duration>`      | `30s`      | bound on the whole run                                                                                              |
| `--step-timeout <duration>` | `10s`      | bound on each individual exchange                                                                                   |
| `--output text\|json`       | `text`     | output form — see [Output modes](#output-modes)                                                                     |
| `--shareable`               | off        | emit the redacted projection — see [Shareable reports](#shareable-reports)                                          |

### `diagnose kafka`

| Flag                        | Default    | Meaning                                                                                                                       |
| --------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `--host <host>`             | _required_ | the bootstrap endpoint to diagnose: a hostname or an IPv4 or IPv6 address literal — see [Address literals](#address-literals) |
| `--sasl-mechanism <name>`   | _required_ | the SASL mechanism to propose, uppercase                                                                                      |
| `--user <principal>`        | _empty_    | the principal to authenticate as; required with a credential source and refused without one                                   |
| `--port <uint>`             | `9092`     | the port to connect to                                                                                                        |
| `--timeout <duration>`      | `30s`      | bound on the whole run                                                                                                        |
| `--step-timeout <duration>` | `10s`      | bound on each individual exchange                                                                                             |
| `--output text\|json`       | `text`     | output form — see [Output modes](#output-modes)                                                                               |
| `--shareable`               | off        | emit the redacted projection — see [Shareable reports](#shareable-reports)                                                    |

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

**Kafka has no session.** There is no `ReadyForQuery`, no server message meaning _the
connection is now ready for ordinary work_, so the outcome line names the exchange that
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

PostgreSQL BASIC is what svcdoctor can learn _while acting as the PostgreSQL client you asked
it to be_. It issues **no SQL**.

| Stage            | What is measured                                                  |
| ---------------- | ----------------------------------------------------------------- |
| Requested target | the host and port the run was asked to diagnose                   |
| DNS              | resolution from this vantage point, and every address returned    |
| TCP              | a connection attempt per resolved address                         |
| SSLRequest       | PostgreSQL's in-band negotiation of an encrypted channel          |
| TLS              | handshake, chain verification, identity match, validity window    |
| Startup          | the startup exchange and the authentication the endpoint requests |
| Authentication   | mechanism negotiation and the outcome of SCRAM-SHA-256            |
| Session          | whether the session reached `ReadyForQuery`                       |

Representative findings include name not resolved, TCP connection not established, TLS
declined, SSL negotiation failed, TLS chain not trusted, TLS identity mismatch, credential
not configured, credential withheld, credentials rejected, database not found, and database
connect denied.

For the finding conventions and the full catalog, see [`docs/FINDINGS.md`](docs/FINDINGS.md),
with worked examples in [`docs/DIAGNOSIS_EXAMPLES.md`](docs/DIAGNOSIS_EXAMPLES.md).

## What Kafka BASIC checks

Kafka BASIC is what svcdoctor can learn _while acting as the Kafka client you asked it to
be_. It produces and consumes **nothing**.

| Stage                       | What is measured                                                        |
| --------------------------- | ----------------------------------------------------------------------- |
| Requested target            | the bootstrap host and port the run was asked to diagnose               |
| DNS                         | resolution from this vantage point, and every address returned          |
| TCP                         | a connection attempt per resolved address                               |
| TLS                         | handshake, chain verification, identity match, validity window          |
| Kafka API versions          | the capability exchange; a broker answers it **before** authentication  |
| SASL mechanism negotiation  | whether the endpoint offers the mechanism you named                     |
| Authentication              | `PLAIN` or `SCRAM-SHA-256`, on exactly one selected path                |
| Kafka metadata              | whether an authenticated, authorized API call succeeded                 |
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

| Flag                     | Reads the credential from |
| ------------------------ | ------------------------- |
| `--password-file <path>` | a file                    |
| `--password-stdin`       | standard input            |

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

| Flag                       | Meaning                                                              |
| -------------------------- | -------------------------------------------------------------------- |
| `--tls require\|disable`   | negotiate an encrypted channel, or do not (default `require`)        |
| `--tls-ca-file <path>`     | PEM trust source. **It replaces the system trust store** — see below |
| `--tls-server-name <name>` | identity to verify and send in SNI; empty uses `--host`              |
| `--tls-insecure`           | do not verify the endpoint's identity                                |

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

### Address literals

`--host` accepts a hostname or an IPv4 or IPv6 address literal, for both services.

An address is already the address, so **svcdoctor resolves nothing and claims nothing about
resolution**: the report holds no `dns.lookup` node for a literal target, no DNS finding can
fire for one, and no prose says a hostname resolved. A hostname target is unchanged and still
records its resolution. Transport, TLS, the protocol journey and the findings are otherwise
identical — a literal is a first-class target, not a degraded one.

```sh
svcdoctor diagnose postgres --host 10.20.30.40 --user svcdoctor
svcdoctor diagnose kafka    --host ::1 --port 9092 --sasl-mechanism PLAIN
```

Give IPv6 unbracketed and separately from the port. Brackets belong to the rendered
`[2001:db8::1]:9092` endpoint form, which svcdoctor produces itself. One address has one
spelling: `2001:0db8:0:0:0:0:0:1` and `2001:db8::1` are canonicalized to the same value, so
they cannot appear as two endpoints in one report.

**TLS against a literal verifies IP SANs.** With a bare address and no override, the
certificate is checked against its IP SANs and no SNI is sent, because SNI carries names only.
A DNS SAN does not satisfy a raw address. If the endpoint's certificate carries a name rather
than an address, name the identity explicitly:

```sh
svcdoctor diagnose kafka --host 10.20.30.40 --tls-server-name kafka.internal \
  --sasl-mechanism SCRAM-SHA-256 --user svcdoctor --password-stdin
```

That connects to `10.20.30.40` and verifies `kafka.internal`, sending it in SNI. It does not
propagate to Kafka brokers learned from Metadata, which are verified against their own
advertised endpoints.

**A Kafka cluster may advertise addresses**, and svcdoctor measures those as transport
endpoints exactly as it measures advertised names: DNS is skipped because there is nothing to
resolve, TCP and TLS are measured, and the endpoint is counted in the topology line like any
other. Advertised endpoints stay credential-free whatever form they take — no credential, no
SASL, no bytes beyond transport.

An address does not widen what a credential is authorized for. A credential bound to
`10.20.30.40:9093` is not authorized for `10.20.30.41:9093`, and is never authorized for an
advertised broker.

Certificates are matched on subject alternative names. A `CN`-only certificate does not verify,
matching every modern client; svcdoctor adds no compatibility exception for one.

### `--tls-insecure`

It disables identity verification — both chain and name, which in Go are one operation. It is
explicit, per-run, and never an automatic fallback after a verification failure.

It does **not** mean "connect insecurely and authenticate anyway": the resulting channel is
unverified, and the credential-transport policy refuses to present a password over an
unverified channel. Such a run reports `POSTGRES_CREDENTIAL_WITHHELD` or
`KAFKA_CREDENTIAL_WITHHELD` and sends nothing.

**What such a handshake proves, exactly:** the channel is encrypted. Nothing else. No chain was
validated, no name or address was matched against the certificate, and nothing established who
answered. An unverified TLS connection is not an authenticated one.

**Both outputs say so.** The canonical report records
`security.tlsVerificationDisabled: true` and marks each handshake `tls.verified: false`. The
terminal states it under the run banner and again on every affected handshake row:

```text
svcdoctor · kafka · kafka.internal:9093
Peer verification disabled · TLS proves the channel is encrypted, not who answered

  Path 198.51.100.10:9093 · continued
    ✓ PASS  TCP                         190µs
    ✓ PASS  TLS                         1.7ms  peer verification disabled
```

It is **not** a finding and not a target-side problem: the operator asked for it, the endpoint
did nothing wrong, and the status and exit code are unchanged. See
[ADR 0060](docs/decisions/0060-tls-option-validity-and-verification-state-projection.md).

### TLS-only flags require TLS

`--tls-ca-file`, `--tls-server-name` and `--tls-insecure` all describe a handshake. Under
`--tls disable` there is none, so all three are **refused** with exit 2 rather than accepted
and ignored:

```console
$ svcdoctor diagnose postgres --host db.internal --user app --tls disable --tls-insecure
svcdoctor: invalid invocation: --tls-insecure has no effect with --tls disable
```

Both services behave identically. Before v0.2.0 PostgreSQL accepted these combinations and
ignored them; see [ADR 0060](docs/decisions/0060-tls-option-validity-and-verification-state-projection.md)
§5 for the compatibility impact. `--tls disable` on its own is unchanged.

## Output modes

| `--output` | Result                                       |
| ---------- | -------------------------------------------- |
| `text`     | human-readable terminal report (**default**) |
| `json`     | the canonical Report document                |

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

| Code | Meaning                                                                                      |
| ---- | -------------------------------------------------------------------------------------------- |
| 0    | a report was produced, execution completed, and no ERROR/CRITICAL target-side finding exists |
| 1    | a report was produced, execution completed, and an ERROR/CRITICAL target-side finding exists |
| 2    | svcdoctor was invoked with something it cannot act on; no report                             |
| 3    | svcdoctor itself failed and produced no usable report                                        |
| 4    | a report was produced, but svcdoctor's own execution did not finish                          |

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

There are currently no Homebrew, apt or RPM distributions.
Published container images are on GHCR: `ghcr.io/hakanaltindag/svcdoctor`, `linux/amd64` and
`linux/arm64`. See [Running in a container](#running-in-a-container).

Prebuilt binary archives were attached to the v0.1.0 GitHub Release. They are not part of the
current delivery model, which is the container image plus `go install`; the archives are kept
for that older release rather than produced for new ones.
`svcdoctor --version` reports the release the binary was built as, and the same value is
recorded in every report. A binary installed from a tagged module —
`go install github.com/hakanaltindag/svcdoctor/cmd/svcdoctor@v0.3.3` — reports that tag. A
build from a working checkout reports `dev`, as does a build from a modified tree, because
neither corresponds to a released commit. Release builders can also inject a value with
`-ldflags "-X main.version=v0.3.3"`, which takes precedence over both.

## Running in a container

Official images are published to `ghcr.io/hakanaltindag/svcdoctor`:

```sh
docker run --rm ghcr.io/hakanaltindag/svcdoctor:v0.3.3 \
  diagnose postgres --host db.internal --user app
```

Pin the digest for anything that matters — a tag is a name resolved at pull time, a digest is
the artifact. There is deliberately no `latest`, no `v0` and no `v0.3`: a moving tag has no
reproducible identity, so none is published.

The `Dockerfile` in the repository also builds one locally:

```sh
scripts/build-image.sh --dev --platform linux/arm64   # or linux/amd64
docker run --rm svcdoctor:sha-$(git rev-parse --short HEAD) \
  diagnose postgres --host db.internal --user app
```

The build recipe derives the version from Git rather than accepting one, so a local build
reports `0.0.0-dev+<commit>` and is addressed by its commit. It cannot label itself with a
release version at all: an image that claimed one would be indistinguishable from a published
release, and only the tag-triggered pipeline may make that claim.

The image is `gcr.io/distroless/static-debian12:nonroot` plus one static binary. It has **no
shell and no package manager**, runs as **UID 65532**, and works with a **read-only root
filesystem and all capabilities dropped**:

```sh
docker run --rm \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges --user=65532:65532 \
  -v /run/secrets/pg:/run/secrets:ro \
  svcdoctor:sha-$(git rev-parse --short HEAD) diagnose postgres --host db.internal --user app \
    --password-file /run/secrets/password --output json
```

### Why run it in a container at all

Because every connectivity finding svcdoctor makes is qualified by **where it was measured
from**, and a container is a network position, not just packaging. Docker bridge, a Kubernetes
Pod and `hostNetwork` can each see different DNS, routes, firewall policy and TLS
interception.

The clearest case is Kafka: a bootstrap endpoint can answer perfectly while the brokers it
advertises are unreachable from inside the cluster. Run in the Pod, svcdoctor reports both:

```
outcome    Kafka metadata obtained
topology   0 of 3 advertised broker endpoints reached
```

Credentials never follow that discovery — the bootstrap endpoint you named is the only one
ever offered a credential.

### Trust and secrets in the image

- With no `--tls-ca-file`, the image's **system trust store** is used.
- With one, it **replaces** the system roots rather than adding to them, so only its issuers
  are accepted. A malformed, missing or unreadable file exits 2 before any connection.
- Credentials come from `--password-file` or `--password-stdin`. **There is no
  environment-variable secret source** — svcdoctor's production code reads no environment
  variable at all, so `SVCDOCTOR_PASSWORD` and friends are ignored because nothing can read
  them.

### Kubernetes

svcdoctor runs, reports and exits, so it belongs in a **Job**, not a Deployment. It requires
**no Kubernetes API access**, no capabilities and no `hostNetwork`. Worked examples are in
[`examples/kubernetes/`](examples/kubernetes/), and the runtime model is
[ADR 0062](docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md).

### The release contract for images

Fixed in [ADR 0062](docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md)
§12–§20, and in force:

- **The canonical registry is `ghcr.io/hakanaltindag/svcdoctor`** — one registry, not
  mirrored.
- **The Git semver tag is the only version authority.** The binary version, the
  `org.opencontainers.image.version` label and the OCI tag are all projections of it. An OCI
  `:vX.Y.Z` will never exist before the Git tag `vX.Y.Z`, and once published it is never
  rebuilt or re-pointed — a defect ships as the next patch version.
- **Official images are reproducible.** Building the same commit with
  [`scripts/build-image.sh`](scripts/build-image.sh) yields identical *platform image
  manifest* digests. That scope is deliberate: build attestations legitimately contain
  build-time data, so the multi-arch index digest does not reproduce, and claiming otherwise
  would mean giving up provenance.
- **Every release will carry a CycloneDX SBOM, a build-provenance attestation, and a keyless
  cosign signature over the image digest** — three separate artifacts answering three
  different questions. OCI labels are none of them: they are self-declared metadata, never
  provenance.
- **Production should pin the digest**, not the tag.

Reproducibility is a consistency property, not a safety proof: a reproducible build of
compromised source reproduces the compromise. Signing and provenance are what address
authenticity.

Releases are produced by [`.github/workflows/release-oci.yml`](.github/workflows/release-oci.yml),
which is triggered by a `v*` tag, stages the image under `sha-<commit>`, validates that digest —
scan, SBOM, provenance, signature, and a native amd64 pull-by-digest smoke — and only then points
the semver tag at the digest that passed. **That workflow has never run**, so nothing exists at
GHCR yet.

Build an image yourself with the same recipe a release uses:

```sh
make image-dev          # development build, tagged svcdoctor:sha-<commit>
make image              # official build; refuses unless HEAD is a clean semver tag
```

Neither pushes anything.

## Current scope

**PostgreSQL BASIC is complete and feature-frozen. Kafka BASIC is implemented and exposed.**
Two leaf commands, `svcdoctor diagnose postgres` and `svcdoctor diagnose kafka`, with text and
JSON output, file and stdin credential input, shareable redaction, and the exit-code contract
above.

**Redpanda self-hosted v25.1.9 is tested** as well, `PLAIN` and `SCRAM-SHA-256`, by a committed
fixture with its own `make` target. That evidence is about **v25.1.9 specifically** and says
nothing about Redpanda Cloud or any other version — Redpanda's SCRAM salt size is a
compile-time constant in its source, so another version is another measurement. See
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) for what each evidence level means.

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
- no scoped IPv6 — a zone identifier such as `fe80::1%en0` is refused with an invocation
  error, because the zone is a vantage-local interface name with no decided representation in
  the evidence subject, the credential binding key, the TLS identity or the pseudonym
  namespace. Deferred, not rejected; see ADR 0059
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

Built since: Redis/Valkey (`diagnose redis`) and RabbitMQ/LavinMQ (`diagnose rabbitmq`).
Still deferred: MySQL/MariaDB, Elasticsearch/OpenSearch.

Out of scope for v0.1 entirely: host mode, eBPF, MCP server, PDF generation, tuning advisor,
long-term monitoring, LLM-based core diagnosis, and generic rule scripting DSLs.

## Compatibility

**svcdoctor is validated against Apache Kafka, PostgreSQL, Redis, Valkey, RabbitMQ and
LavinMQ.** Those are the ones it has been run against, repeatedly, from committed fixtures.

Other implementations of the same protocols are a separate question with a
separate answer, and [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) is where it is kept. That
document grades every platform by what was actually done to it — whether svcdoctor ran against
a real instance, or whether only the vendor's documentation was read — because those are not
the same claim and reading a table that conflates them is worse than having no table.

**No managed service has been validated.** None was contacted, and no cloud credential was used
at any point.

The one thing worth stating here, because it is a limit rather than an absence: svcdoctor
performs `PLAIN` and `SCRAM-SHA-256` and nothing else. A platform that requires
`SCRAM-SHA-512`, `OAUTHBEARER`, `GSSAPI`, `AWS_MSK_IAM` or mTLS is not usable with svcdoctor
today, however standard that mechanism is.

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

svcdoctor has **two runtime dependencies**, each confined to a single package and each with
no transitive dependencies of its own:

- `github.com/twmb/franz-go/pkg/kmsg` (BSD-3-Clause) — Kafka protocol encoding, used only by
  the Kafka adapter's wire package.
- `go.yaml.in/yaml/v3` (MIT and Apache-2.0) — multi-target configuration decoding, used only
  by `internal/fleet/config`. The configuration format it parses is implemented; multi-target
  **execution is not**, and no command exposes it.

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

make integration-postgres  # PostgreSQL 18, real server          (needs Docker)
make integration-kafka     # Apache Kafka 4.0.0, 3-broker KRaft   (needs Docker)
make integration-redpanda  # Redpanda v25.1.9, real broker        (needs Docker)
```

`make check` is fast and hermetic. The integration gates are deliberately excluded from it
because they require Docker; each starts a real server, runs its suite against it and tears it
down. **Run them one at a time** — the Kafka and Redpanda clusters compete for cores, and a
Kafka run under that contention once failed in a way that did not reproduce alone.

See [`test/integration/postgres/README.md`](test/integration/postgres/README.md),
[`test/integration/kafka/README.md`](test/integration/kafka/README.md) and
[`test/integration/redpanda/README.md`](test/integration/redpanda/README.md).

Linting uses [golangci-lint](https://golangci-lint.run) `v2.13.1` (v2 config format).

Package-level fixtures live in package-adjacent `testdata/` directories; `test/` holds
cross-package and environment-dependent tests.

## Roadmap

PostgreSQL-only v0.1.0 is tagged, and v0.2.0 added Kafka BASIC. Both are release-validated
against real Apache Kafka 4.0.0 and PostgreSQL 18. v0.3.3 is the current release and the first
published as a signed, attested container image.


Next, in no committed order:

- client certificates / mTLS — not implemented, and its credential authority is a question
  ADR 0058 deliberately left open rather than one the trust policy already answered
- managed-service protocol compatibility: Redpanda Cloud, Confluent Cloud, AWS MSK, Azure Event
  Hubs' Kafka API; RDS, Aurora, Cloud SQL, Azure Database for PostgreSQL — none validated,
  see the compatibility document
- Markdown and HTML renderers, derived from the canonical report
- the `inspect` namespace, once its output contract is decided
- PostgreSQL DEEP

The authoritative phase numbering and checklist live in
[`docs/BACKLOG.md`](docs/BACKLOG.md).

|                |                                      |
| -------------- | ------------------------------------ |
| Repository     | `github.com/hakanaltindag/svcdoctor` |
| Go module path | `github.com/hakanaltindag/svcdoctor` |
| Go version     | 1.26                                 |
| License        | Apache-2.0                           |
