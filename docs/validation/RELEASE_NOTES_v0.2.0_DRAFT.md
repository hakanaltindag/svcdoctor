# DRAFT release notes — v0.2.0

**Not published. Not tagged.** This is the text Phase 6.8E proposes, held here so the claims can
be reviewed against the evidence that produced them before anything is public.

Every line below is traceable to something measured. Where it is not, it says so.

---

## svcdoctor v0.2.0

**Kafka BASIC arrives.** v0.1.0 diagnosed PostgreSQL; this release adds a Kafka vertical of the
same shape and depth, and closes the last inconsistency in how TLS options are validated and
reported.

### Supported

What the product contract covers, and what is validated by committed tests against real servers.

**PostgreSQL BASIC** — unchanged from v0.1.0, and re-validated.
DNS · TCP · in-band `SSLRequest` · TLS · `Startup` · SCRAM-SHA-256 authentication · session
establishment at `ReadyForQuery`. One socket, no redial, no SQL.

**Kafka BASIC** — new.
DNS · TCP · TLS · `ApiVersions` · SASL mechanism negotiation · one credential-bearing
authentication · `Metadata` · transport reachability of every advertised broker endpoint.

Both services support:

- hostname, IPv4-literal and IPv6-literal targets
- TLS with system roots, a replacement CA (`--tls-ca-file`), a verification identity override
  (`--tls-server-name`), or verification explicitly disabled (`--tls-insecure`)
- credentials from a file or stdin, never from the command line
- terminal and canonical JSON output, `schemaVersion` 1
- shareable redacted reports

Kafka SASL mechanisms: **`PLAIN` and `SCRAM-SHA-256`.** There is no default, no fallback and no
retry.

### Tested against

Real software, real versions, exercised by this release's validation.

- **Apache Kafka 4.0.0** — three-broker KRaft cluster, SASL_SSL, `PLAIN` and `SCRAM-SHA-256`,
  advertised-topology scenarios including literal, unreachable and unmeasured endpoints.
  Committed fixture.
- **PostgreSQL 18** — TLS and plaintext servers, SCRAM-SHA-256, `trust`, wrong credential,
  absent database, refused CONNECT. Committed fixture.
- **Redpanda v25.1.9** — real instance. **`PLAIN` over TLS completes the whole BASIC journey.**
  `SCRAM-SHA-256` **does not work**: Redpanda issues a 130-byte SCRAM salt and svcdoctor bounds
  a salt at 128. The cause is measured and the fix is proven, and it is deferred because that
  bound is a security parameter that needs its own review. See
  `docs/validation/KAFKA_PHASE68_REDPANDA_STUDY.md`.

### Changed — one released CLI behaviour

**PostgreSQL now refuses TLS-only flags when TLS is disabled**, as Kafka always did.

```console
$ svcdoctor diagnose postgres --host db --user app --tls disable --tls-insecure
svcdoctor: invalid invocation: --tls-insecure has no effect with --tls disable
```

`--tls-ca-file`, `--tls-server-name` and `--tls-insecure` all describe a handshake, and
`--tls disable` performs none. Before v0.2.0 PostgreSQL accepted all three and ignored them,
which let an operator believe they had configured — or deliberately relaxed — the security of a
connection that was never going to be encrypted.

**Three invocations that previously exited 0, 1 or 4 now exit 2.** None of them was doing
anything: the flags were inert, so the report was identical to `--tls disable` alone. Remove the
flag, or use `--tls require`. `--tls disable` on its own is unchanged. See ADR 0060 §5.

### Fixed

- **A plaintext PostgreSQL run no longer reports `tlsVerificationDisabled: true`** — a TLS fact
  about a run that attempted no TLS. Both composition roots now gate it on the run's TLS plan.
- **The terminal now says when peer verification was disabled.** Two runs — one verifying a
  certificate against a supplied CA, one verifying nothing — used to render identically, down to
  `✓ PASS  TLS`. Now:

  ```text
  svcdoctor · kafka · kafka.internal:9093
  Peer verification disabled · TLS proves the channel is encrypted, not who answered

      ✓ PASS  TLS  1.7ms  peer verification disabled
  ```

  It is not a finding and not a target-side problem: the operator asked for it, and the status
  and exit code are unchanged.

### Not supported

Absent from the product, not merely untested. A platform requiring any of these cannot be
diagnosed by svcdoctor today:

**None of these is implemented:** `SCRAM-SHA-512` · `OAUTHBEARER` · `GSSAPI`/Kerberos ·
`AWS_MSK_IAM` · mTLS client certificates · connection strings and DSNs · any cloud SDK,
credential refresh, authentication retry or mechanism fallback.

### Not validated

Researched against primary documentation and **never run against**. Documentation is not
evidence, and none of these is a support claim:

Redpanda Cloud · Confluent Cloud · Azure Event Hubs' Kafka API · AWS RDS PostgreSQL · Aurora
PostgreSQL · Google Cloud SQL PostgreSQL · Azure Database for PostgreSQL.

**AWS MSK is not in that list**, because it is worse than unvalidated: MSK's SASL/SCRAM is
`SCRAM-SHA-512` only, which svcdoctor does not implement. MSK IAM needs `AWS_MSK_IAM`, which it
also does not implement.

`docs/COMPATIBILITY.md` grades every platform by what was actually done to it. No cloud
credentials were used at any point in this release's validation.

### What svcdoctor still does not tell you

Unchanged, and worth repeating because it is the boundary of the product rather than a gap in
it. No topic, partition, consumer-group, lag or throughput inspection. No cluster, broker or
partition health claim. No `pg_stat_*`, connection-pool, blocking-query or replication analysis.
No latency interpretation, thresholds or baselines. `SummaryStatus == OK` means *no ERROR or
CRITICAL target-side problem was proven* — not that the target is healthy.

### Under the hood

`schemaVersion` stays **1**. No finding code, failure class, state or step was added or removed.
The dependency count is unchanged at one external module
(`github.com/twmb/franz-go/pkg/kmsg`), and there are still exactly two production
`security.Reveal` call sites, one per service.
