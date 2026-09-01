# svcdoctor

`svcdoctor` is an on-demand, evidence-linked connection diagnostic CLI for distributed
services. You point it at a service endpoint, it attempts the journey a real client would,
and it reports what it measured at every stage — and, just as deliberately, what it did not
learn.

**Four services are supported: PostgreSQL, Apache Kafka, Redis/Valkey and RabbitMQ/LavinMQ.**
One command diagnoses one endpoint; one configuration file diagnoses many. No APM,
OpenTelemetry collector, sidecar or agent is required for a diagnostic run.

```sh
svcdoctor diagnose postgres --host db.prod.internal --user app --password-file /run/secrets/db
svcdoctor run --config services.yaml
```

New here? [**Quickstart**](docs/QUICKSTART.md) — five minutes, install to shareable report.

## What it does

svcdoctor behaves as the client you describe and walks the same path:

```text
postgres   requested target → DNS → TCP → SSLRequest → TLS → Startup → Authentication → Session
kafka      requested target → DNS → TCP → TLS → ApiVersions → SASL negotiation → Authentication → Metadata
                                                                                   └→ per advertised broker: DNS → TCP → TLS
redis      requested target → DNS → TCP → TLS → HELLO → Authentication → PING
rabbitmq   requested target → DNS → TCP → TLS → Connection.Start → Authentication → Connection.Open
```

For Kafka it then measures DNS, TCP and TLS for every broker endpoint the cluster advertised —
**credential-free**. A discovered broker is an endpoint you never named, learned from
peer-supplied data, so it receives transport probing and nothing else.

At the end you get:

- what was measured, stage by stage, and where the journey stopped;
- the elapsed duration of each attempted stage;
- findings, each one linked to the exact evidence that produced it;
- whether the service's terminal exchange succeeded — a PostgreSQL session, Kafka metadata, a
  Redis `PING`, a RabbitMQ virtual host;
- for Kafka, how many advertised broker endpoints were reached and how many were never
  measured;
- whether svcdoctor's own execution completed.

The design goal is a report that separates **what was measured** from **what can honestly be
claimed**. `UNKNOWN` is not a failure. A local timeout is not a target timeout. Missing
credentials are not a rejected password.

## What it is not

It is a **client-vantage diagnostic**, run on demand, from wherever you run it. It is not
monitoring, not APM, not distributed tracing, not service discovery, not a daemon, not an
agent, not a secret manager, and not a replacement for Prometheus, Grafana or your service's
own admin tooling. It changes nothing and repairs nothing.

It reads no application data. It names no key, no queue, no exchange and no table, and it runs
no SQL, so no customer data is touched and none can appear in a report.

## Install

```sh
go install github.com/hakanaltindag/svcdoctor/cmd/svcdoctor@v0.3.3
```

Or run the published image, which needs no Go toolchain:

```sh
docker run --rm ghcr.io/hakanaltindag/svcdoctor:v0.3.3 \
  diagnose postgres --host db.internal --user app
```

Go 1.26 or newer to build from source. The binary is statically linkable, builds with
`CGO_ENABLED=0`, and needs no source tree, configuration file or runtime data directory.

```sh
go build -o svcdoctor ./cmd/svcdoctor
```

`svcdoctor --version` reports the release the binary was built as, and the same value is
recorded in every report. A build from a working checkout — or from a modified one — reports
`dev`, because neither corresponds to a released commit.

Published images are on GHCR: `ghcr.io/hakanaltindag/svcdoctor`, `linux/amd64` and
`linux/arm64`. Pin the digest for anything that matters. There is deliberately no moving tag,
so every reference names an exact version. There are no Homebrew, apt or RPM distributions,
and prebuilt binary archives exist only for `v0.1.0`.

### One platform note, because it affects what svcdoctor measures

A `CGO_ENABLED=0` binary uses Go's own DNS resolver rather than the operating system's. **On
macOS that resolver does not consult `/etc/resolver/*`** — split-horizon DNS, which a corporate
VPN commonly installs — **or mDNS.** So a name your Mac resolves can be reported as
`DNS_NAME_NOT_RESOLVED` by a `CGO_ENABLED=0` macOS build, and the report would be describing
the resolver rather than your network.

If that is your situation, run with `GODEBUG=netdns=cgo`, or run the container image. **The
Linux container image is unaffected**, and so is any build where `cgo` is enabled.

## Diagnose one endpoint

```sh
svcdoctor diagnose postgres --host db.prod.internal --user app
svcdoctor diagnose kafka    --host kafka.prod.internal --sasl-mechanism SCRAM-SHA-256 --user app
svcdoctor diagnose redis    --host cache.prod.internal --username app
svcdoctor diagnose rabbitmq --host mq.prod.internal --username app --vhost /production
```

Each command owns its flags, help and validation. `svcdoctor diagnose <service> --help` is
authoritative for that service.

A credential is optional input. Running without one is a valid diagnostic run: an endpoint that
demands authentication is reported as demanding it, and nothing is sent.

`--host` accepts a hostname or an IPv4 or IPv6 address literal. An address is already the
address, so svcdoctor resolves nothing and claims nothing about resolution: the report holds no
name-resolution node for a literal target, and no DNS finding can fire for one.

## Diagnose many

```sh
svcdoctor run --config services.yaml
```

```yaml
version: 1

run:
  concurrency: 4          # targets in flight at once; 1-16, default 4

targets:
  - id: orders-db
    type: postgres
    host: orders-db.internal.example.com
    tls:
      mode: require
      ca_file: /etc/ssl/internal-ca.pem
    credentials:
      username: svcdoctor
      password:
        env: ORDERS_DB_PASSWORD      # a reference; never the value
    config:
      database: orders

  - id: task-queue
    type: rabbitmq
    host: rabbit.internal.example.com
    port: 5671
    credentials:
      username: svcdoctor
      password:
        file: /run/secrets/rabbitmq
    config:
      vhost: /production
```

**`diagnose` is one endpoint you name on the command line. `run` is many endpoints a file names
for you.** They perform exactly the same measurement — `run` schedules the diagnoses that
`diagnose` performs, one per target — and the only reason both exist is that a password belongs
to one endpoint, so N endpoints need N credential references and a file is where those live.

**Targets are independent.** One target's failure never stops another, there is no dependency
ordering, and svcdoctor draws no conclusion across targets: it will not tell you Kafka is
failing because PostgreSQL is down, because it measured two endpoints and has no evidence of
any relationship between them. Results appear in the order the file declares them.

Copy [`examples/minimal.yaml`](examples/minimal.yaml) to start,
[`examples/services.yaml`](examples/services.yaml) for one target per service, or
[`examples/production.yaml`](examples/production.yaml) for private CAs and mounted secrets.
Every field is documented in [**`docs/CONFIGURATION.md`**](docs/CONFIGURATION.md).

## Credentials

**A password is never a command-line argument**, in any command, because an argument is visible
to every process on the host. There is no `--password` flag, no interactive prompt and no DSN
input.

| Where | Sources |
|---|---|
| `svcdoctor diagnose …` | `--password-file <path>`, `--password-stdin` |
| `svcdoctor run --config …` | `password: {env: NAME}`, `password: {file: PATH}` |

The two leaf sources are mutually exclusive — supplying both is an invocation error rather than
a precedence rule, so a run can never quietly authenticate with the source you did not mean.

```sh
vault kv get -field=password secret/orders-db | \
  svcdoctor diagnose postgres --host db.prod.internal --user app --password-stdin
```

**In a configuration file, `password:` names a source and never holds a value.** `env:` names an
environment variable — the name, not the value — which is what suits CI. `file:` names a path,
which is what suits a Kubernetes or systemd secret mount. A plaintext value is refused by the
decoder's type before anything is dialled.

**The four `diagnose` commands read no environment variable at all.** `SVCDOCTOR_PASSWORD` and
anything like it is ignored because nothing reads it. An environment variable is a credential
source only when a configuration file names one explicitly, and two targets naming the same
variable resolve it independently — a shared reference is not a shared authority, and no secret
is cached.

A credential is bound to the endpoint you named, crosses only a verified-TLS channel, and never
appears in a report in either output mode. Full detail in
[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md#credentials).

## TLS

TLS is required by default and the endpoint's identity is verified by default. The full policy
is [ADR 0058](docs/decisions/0058-tls-trust-and-peer-identity-authority.md).

| Flag | Configuration | Meaning |
|---|---|---|
| `--tls require\|disable` | `tls.mode` | negotiate an encrypted channel, or do not (default `require`) |
| `--tls-ca-file <path>` | `tls.ca_file` | PEM trust source. **It replaces the system trust store** |
| `--tls-server-name <name>` | `tls.server_name` | identity to verify and send in SNI; empty uses the host |
| `--tls-insecure` | `tls.insecure` | do not verify the endpoint's identity |

There is no automatic fallback: a failed TLS negotiation is reported, never retried in
plaintext. libpq's `sslmode` vocabulary is deliberately not reproduced.

**Trust and identity are two separate questions**, and svcdoctor reports them separately:
`TLS_CHAIN_NOT_TRUSTED` means the chain did not verify against this run's trust source, and
`TLS_IDENTITY_MISMATCH` means it verified and named something else. A trusted chain with the
wrong identity is never reported as a verified peer.

**`--tls-ca-file` replaces the system roots rather than adding to them.** Only its issuers are
accepted, which is what makes "only this issuer is acceptable here" expressible, and why naming
the wrong CA fails rather than quietly passing against a public certificate. An unusable CA
file — missing, unreadable, empty, or holding no certificate — is a configuration error (exit
2) and svcdoctor never falls back to the system store when you asked for a specific one.

**`--tls-insecure` is an explicit per-run opt-in**, never an automatic fallback, and it is
recorded in the report and on every affected row of the terminal output. A handshake performed
that way proves the channel is encrypted and proves nothing about who answered: no chain was
validated and no name or address was matched. The channel is then unverified, which the
credential transport policy refuses — so a credential is **withheld rather than sent**, and an
insecure run with a password authenticates nothing.

Under `--tls disable` the other three are refused rather than ignored, because they describe
nothing.

## Output

| `--output` | Result |
|---|---|
| `text` | human-readable terminal report (**default**) |
| `json` | the canonical document |

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

A run that stopped at TLS reports what it reached and refuses to guess at the rest:

```text
Result
  status       PROBLEMS FOUND
  outcome      session NOT established
  execution    complete
  first break  L3                       tls
```

And a Kafka run reports its own terminal question, plus what it learned about the endpoints the
cluster advertised:

```text
Result
  status     OK                   no target-side error was proven
  outcome    Kafka metadata obtained
  topology   0 of 3 advertised broker endpoints reached
  execution  complete
```

That last one is the case a container makes vivid: a bootstrap endpoint can answer perfectly
while the brokers it advertises are unreachable from where your application actually runs.

**JSON is canonical and the terminal form is derived from it.** Parse the JSON; do not parse the
terminal text, whose layout is a presentation detail. `schemaVersion` is `1`. Markdown and HTML
renderers are planned but **not implemented**.

`--shareable` emits a redacted projection of the same report: hostnames, addresses, logical
identities and evidence identifiers become stable pseudonyms, applied consistently so the
relationships stay readable. It is pseudonymization, **not anonymization**, and the exit code is
unchanged.

Everything above, in full: [**`docs/OUTPUT.md`**](docs/OUTPUT.md).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | a report was produced, execution completed, and no ERROR/CRITICAL target-side finding exists |
| `1` | a report was produced, execution completed, and an ERROR/CRITICAL target-side finding exists |
| `2` | svcdoctor was invoked with something it cannot act on; no report |
| `3` | svcdoctor itself failed and produced no usable report |
| `4` | a report was produced, but svcdoctor's own execution did not finish |

Precedence is `3 > 2 > 4 > 1 > 0`.

- **Exit 0 is not "the service works."** It means no error-level target-side problem was
  *proven*. A run that withheld its credential over a plaintext channel exits 0 having
  established nothing. Read the report's `outcome` line.
- **Exit 1 means svcdoctor worked** and found a target-side problem. It is not a svcdoctor
  failure.
- **Exit 4 outranks exit 1.** A run that was cut short and also proved an ERROR exits 4, and the
  finding stays in the report — incompleteness qualifies every conclusion in it.

[**`docs/CI.md`**](docs/CI.md) is authoritative for exit codes, and carries the three pipeline
policies, the artifact pattern that preserves the code, and worked examples for GitHub Actions,
GitLab CI and Azure DevOps.

## Documentation

| | |
|---|---|
| [Quickstart](docs/QUICKSTART.md) | five minutes, install to shareable report |
| [Configuration](docs/CONFIGURATION.md) | every `run --config` field, and credential references |
| [Output](docs/OUTPUT.md) | terminal anatomy, the JSON contract, shareable semantics |
| [CI](docs/CI.md) | exit codes, pipeline policies, artifacts |
| [Compatibility](docs/COMPATIBILITY.md) | what has actually been tested, and how |
| [Security policy](SECURITY.md) | reporting a vulnerability |

Engineering records — [architecture](docs/ARCHITECTURE.md), the
[report schema](docs/REPORT_SCHEMA.md), the [security model](docs/SECURITY.md),
[findings](docs/FINDINGS.md) and the [decision log](docs/decisions/README.md) — are evidence
rather than user documentation. You should not need any of them to run svcdoctor.

## Running in a container

```sh
docker run --rm \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges --user=65532:65532 \
  -v /run/secrets/pg:/run/secrets:ro \
  ghcr.io/hakanaltindag/svcdoctor:v0.3.3 \
  diagnose postgres --host db.internal --user app \
    --password-file /run/secrets/password --output json
```

The image is `gcr.io/distroless/static-debian12:nonroot` plus one static binary. It has **no
shell and no package manager**, runs as **UID 65532**, and works with a read-only root
filesystem and all capabilities dropped.

**Why a container at all:** every connectivity finding svcdoctor makes is qualified by *where it
was measured from*, and a container is a network position rather than just packaging. Docker
bridge, a Kubernetes Pod and `hostNetwork` can each see different DNS, routes, firewall policy
and TLS interception.

svcdoctor runs, reports and exits, so in Kubernetes it belongs in a **Job**, not a Deployment.
It requires no Kubernetes API access, no capabilities and no `hostNetwork`. Worked manifests are
in [`examples/kubernetes/`](examples/kubernetes/), and the runtime model is
[ADR 0062](docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md).

Build one locally with the same recipe a release uses:

```sh
make image-dev          # development build, tagged svcdoctor:sha-<commit>
make image              # official build; refuses unless HEAD is a clean semver tag
```

Neither pushes anything. A local build derives its version from Git and reports
`0.0.0-dev+<commit>`: it cannot label itself with a release version at all, because an image
that claimed one would be indistinguishable from a published release.

### The release contract for images

Fixed in [ADR 0062](docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md)
§12–§20, and in force:

- **The canonical registry is `ghcr.io/hakanaltindag/svcdoctor`** — one registry, not mirrored.
- **The Git semver tag is the only version authority.** The binary version, the
  `org.opencontainers.image.version` label and the OCI tag are all projections of it. An OCI
  `:vX.Y.Z` will never exist before the Git tag `vX.Y.Z`, and once published it is never rebuilt
  or re-pointed — a defect ships as the next patch version.
- **Official images are reproducible.** Building the same commit with
  [`scripts/build-image.sh`](scripts/build-image.sh) yields identical *platform image manifest*
  digests. That scope is deliberate: build attestations legitimately contain build-time data, so
  the multi-arch index digest does not reproduce, and claiming otherwise would mean giving up
  provenance.
- **Every release carries a CycloneDX SBOM, a build-provenance attestation, and a keyless cosign
  signature over the image digest** — three separate artifacts answering three different
  questions. OCI labels are none of them: they are self-declared metadata, never provenance.
- **Production should pin the digest**, not the tag.

Reproducibility is a consistency property, not a safety proof: a reproducible build of
compromised source reproduces the compromise. Signing and provenance are what address
authenticity.

Releases are produced by [`.github/workflows/release-oci.yml`](.github/workflows/release-oci.yml),
which is triggered by a `v*` tag, stages the image under `sha-<commit>`, validates that digest —
scan, SBOM, provenance, signature, and a native amd64 pull-by-digest smoke — and only then points
the semver tag at the digest that passed.

## Compatibility

**svcdoctor is validated against Apache Kafka, PostgreSQL, Redis, Valkey, RabbitMQ and
LavinMQ.** Those are the ones it has been run against, repeatedly, from committed fixtures.

**Redpanda self-hosted v25.1.9 is tested** as well, `PLAIN` and `SCRAM-SHA-256`, by a committed
fixture with its own `make` target. That evidence is about **v25.1.9 specifically** and says
nothing about Redpanda Cloud or any other version — Redpanda's SCRAM salt size is a compile-time
constant in its source, so another version is another measurement.

**No managed service has been validated.** None was contacted, and no cloud credential was used
at any point.

[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) grades every platform by what was actually done
to it — whether svcdoctor ran against a real instance, or whether only the vendor's
documentation was read — because those are not the same claim, and reading a table that
conflates them is worse than having no table.

The one limit worth stating here, because it is an absence with consequences: svcdoctor performs
`PLAIN` and `SCRAM-SHA-256` and nothing else. A platform that requires `SCRAM-SHA-512`,
`OAUTHBEARER`, `GSSAPI`, `AWS_MSK_IAM` or mTLS client certificates is not usable with svcdoctor
today, however standard that mechanism is.

## Scope

**PostgreSQL BASIC is complete and feature-frozen. Kafka, Redis/Valkey and RabbitMQ/LavinMQ
BASIC are implemented and exposed.** Five commands — `diagnose postgres`, `diagnose kafka`,
`diagnose redis`, `diagnose rabbitmq` and `run --config` — with text and JSON output, file,
stdin and configuration-reference credential input, shareable redaction, and the exit-code
contract above.

BASIC is bounded on purpose: it learns what svcdoctor can observe *while acting as the client
for this run*. Inspecting a server's operational state is a separate future body of work.

### Not implemented

These are deliberate boundaries, not defects:

- no `inspect` command — the namespace is reserved, its output contract deferred
- no Kafka SASL mechanism beyond `PLAIN` and `SCRAM-SHA-256`: no `SCRAM-SHA-512`, no
  `SCRAM-SHA-256-PLUS`, no channel binding, no `OAUTHBEARER`, no `GSSAPI`, no `AWS_MSK_IAM`,
  no mTLS client-certificate authentication
- no Kafka topic, partition, consumer-group, lag or throughput inspection, and no cluster,
  broker or partition health claim
- no Redis cluster topology and no Sentinel diagnosis — cluster mode is observed and reported,
  a Sentinel endpoint is detected and the run stops there
- no RabbitMQ queue, exchange, permission, cluster or management-API inspection
- no scoped IPv6 — a zone identifier such as `fe80::1%en0` is refused with a configuration
  error, because the zone is a vantage-local interface name with no decided representation in
  the evidence subject, the credential binding key, the TLS identity or the pseudonym
  namespace. Deferred, not rejected; see ADR 0059
- no PostgreSQL DEEP, no diagnostic SQL of any kind
- no `pg_stat_*` inspection, connection-pool, blocking-query or replication analysis
- no table or query latency diagnosis
- no monitoring, historical state, baselines or thresholds
- no generic TLS diagnosis command
- no Kubernetes API integration, agent mode or eBPF
- no Markdown or HTML output
- no color or progress UI, no shell completion
- no literal-password flag, no interactive prompt
- no DSN or `sslmode` input
- no retries and no protocol fallbacks
- no cross-target correlation, no dependency ordering, no target filtering

Still deferred as services: MySQL/MariaDB, Elasticsearch/OpenSearch.

Out of scope entirely: host mode, eBPF, MCP server, PDF generation, tuning advisor, long-term
monitoring, LLM-based core diagnosis, and generic rule scripting DSLs.

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

svcdoctor has **two runtime dependencies**, each confined to a single package and each with
no transitive dependencies of its own:

- `github.com/twmb/franz-go/pkg/kmsg` (BSD-3-Clause) — Kafka protocol encoding, used only by
  the Kafka adapter's wire package.
- `go.yaml.in/yaml/v3` (MIT and Apache-2.0) — multi-target configuration decoding, used only
  by `internal/fleet/config`.

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

## Security

Report a vulnerability privately through GitHub's private vulnerability reporting: see
[`SECURITY.md`](SECURITY.md). Please do not open a public issue for an undisclosed one.

## Development

```sh
make check                 # fmt-check, test, vet, lint, build — mirrors CI
make fmt                   # format sources in place
make help                  # list targets
```

`make check` is fast and hermetic. The integration gates are excluded from it because they
require Docker; each starts a real server, runs its suite against it and tears it down.
**Run them one at a time** — the clusters compete for cores.

```sh
make integration-postgres  # PostgreSQL 18
make integration-kafka     # Apache Kafka 4.0.0, 3-broker KRaft
make integration-redpanda  # Redpanda v25.1.9
make integration-redis     # Redis 8.2.1
make integration-valkey    # Valkey 8.1.1
make integration-rabbitmq  # RabbitMQ 3.13.7, 4.0.9, 4.2.0
make integration-lavinmq   # LavinMQ 2.3.0
make integration-multitarget  # `svcdoctor run --config` against real services
```

Linting uses [golangci-lint](https://golangci-lint.run) `v2.13.1` (v2 config format).
Package-level fixtures live in package-adjacent `testdata/` directories; `test/` holds
cross-package and environment-dependent tests.

## Roadmap

`v0.1.0` was PostgreSQL only. `v0.3.3` is the current release, the first published as a signed,
attested container image, and it carries PostgreSQL and Kafka. Redis/Valkey, RabbitMQ/LavinMQ
and `svcdoctor run --config` are implemented and **not yet in a published release**.

Next, in no committed order:

- client certificates / mTLS — not implemented, and its credential authority is a question
  ADR 0058 deliberately left open rather than one the trust policy already answered
- managed-service protocol compatibility: Redpanda Cloud, Confluent Cloud, AWS MSK, Azure Event
  Hubs' Kafka API; RDS, Aurora, Cloud SQL, Azure Database for PostgreSQL — none validated,
  see the compatibility document
- Markdown and HTML renderers, derived from the canonical report
- the `inspect` namespace, once its output contract is decided
- PostgreSQL DEEP

The authoritative phase numbering and checklist live in [`docs/BACKLOG.md`](docs/BACKLOG.md).

|                |                                      |
| -------------- | ------------------------------------ |
| Repository     | `github.com/hakanaltindag/svcdoctor` |
| Go module path | `github.com/hakanaltindag/svcdoctor` |
| Go version     | 1.26                                 |
| License        | Apache-2.0                           |
