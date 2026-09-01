# Configuration reference

**This document is authoritative for the `svcdoctor run --config` schema and for credential
references.** It describes the schema this build implements and nothing that is planned.

Worked examples: [`examples/minimal.yaml`](../examples/minimal.yaml),
[`examples/services.yaml`](../examples/services.yaml),
[`examples/production.yaml`](../examples/production.yaml). All three are parsed by the test suite,
so an example that stops being valid fails the build.

## The document

One YAML document, decoded strictly. An unknown field is an error, not a warning: a
`hostname:` where the schema says `host:` is a typo that would otherwise be silently ignored and
diagnose the wrong endpoint.

```yaml
version: 1

run:
  concurrency: 4
  timeout: 2m

targets:
  - id: orders-db
    type: postgres
    host: orders-db.internal.example.com
    port: 5432
    timeout: 45s
    step_timeout: 15s
    tls:
      mode: require
      ca_file: /etc/svcdoctor/pki/internal-ca.pem
      server_name: orders-db.internal.example.com
      insecure: false
    credentials:
      username: svcdoctor
      password:
        env: ORDERS_DB_PASSWORD
    config:
      database: orders
```

### `version`

| | |
|---|---|
| Required | yes |
| Value | `1` |

The configuration's own version. It is **not** the report's `schemaVersion` and not svcdoctor's
release version; the three move independently. A version this build does not implement is
refused by number rather than guessed at.

### `run`

Optional. Every field has a default.

| Field | Default | Meaning |
|---|---|---|
| `concurrency` | `4` | How many targets run at once. `1`–`16` |
| `timeout` | none | Bound on the whole run |

**`concurrency` bounds targets, not sockets.** One target may open a connection per resolved
address, and a Kafka target additionally sweeps the endpoints its cluster advertised. The ceiling
of 16 is what bounds the total.

`0` is refused rather than read as "unlimited" or as "use the default" — one of those two
readings opens every connection at once, and which one a reader assumes is not something a
configuration should leave open.

`run.timeout` must not be below any target's own `timeout`. A run budget under a target budget
guarantees that target is cut short, which is a configuration that cannot do what it says.

Both are overridable per invocation with `--concurrency` and `--timeout`, validated identically:
there is no path by which `--concurrency 0` is accepted because it arrived on the command line.

### `targets`

Required, and at least one. Order matters: **results appear in declared order**, whatever order
they finished in.

| Field | Required | Default | Meaning |
|---|---|---|---|
| `id` | **yes** | — | Your identifier for this target |
| `type` | **yes** | — | `postgres`, `kafka`, `redis` or `rabbitmq` |
| `host` | **yes** | — | Hostname, or IPv4 or IPv6 address literal |
| `port` | no | the service's default | `5432`, `9092`, `6379`, `5672` |
| `timeout` | no | `30s` | Bound on this target's whole journey |
| `step_timeout` | no | `10s` | Bound on each individual exchange |
| `tls` | no | `mode: require` | Transport encryption; see below |
| `credentials` | no | none | Identity and credential *reference*; see below |
| `config` | no | none | The service's own configuration; see below |

#### `id`

Written, never derived. An identifier taken from list position moves when a target is inserted
above it, and one taken from `host:port` cannot tell two targets on the same endpoint apart.

It must be unique. A repeat is refused rather than resolved by position.

It is operator-chosen text and it can carry deployment structure, tenancy and geography, so a
shareable report replaces it with `target-001`, numbered in declared order.

#### `host`

A hostname, an IPv4 literal or an IPv6 literal. Write IPv6 unbracketed, and put the port in
`port:`.

**An address is not a name.** A target given a literal resolves nothing and records nothing about
resolution: its report holds no name-resolution node at all, so a DNS finding is structurally
unreachable for it rather than suppressed.

A zone identifier — `fe80::1%en0` — is refused. The zone is a vantage-local interface name with no
decided representation in the evidence subject, the credential binding key, the TLS identity or
the pseudonym namespace. Deferred, not rejected.

#### `timeout` and `step_timeout`

Durations with a unit: `45s`, `2m`, `1500ms`. A bare number is refused.

`step_timeout` must be below `timeout`, or no step could complete inside the target's own budget.

RabbitMQ requires `step_timeout` above `3s`: it delays several refusals by exactly that long on
purpose, and a shorter budget reports the delay as a local timeout instead of the refusal it is.

A budget expiring is **not** a statement about the target. It produces `UNKNOWN` evidence, marks
the run incomplete, and exits 4.

#### `tls`

| Field | Default | Meaning |
|---|---|---|
| `mode` | `require` | `require` or `disable` |
| `ca_file` | none | PEM trust source. **Replaces** the system trust store |
| `server_name` | `host` | The identity to verify, and the name sent in SNI |
| `insecure` | `false` | Do not verify the peer's identity |

**`ca_file` replaces the system roots; it does not add to them.** Only its issuers are accepted.
That is what makes "only this issuer is acceptable here" expressible, and it is why naming the
wrong CA fails rather than quietly succeeding against a public certificate. To trust both,
concatenate the PEMs into one file.

An unusable `ca_file` — missing, unreadable, too large, or holding no certificate — is a
**configuration error**. The run exits 2 before any target is dialled. svcdoctor never falls back
to the system store when you asked for a specific one.

**`server_name` sets both the identity verified and the name announced**, because they are one
setting and svcdoctor will not verify one name while announcing another. `host: 10.20.30.40` with
`server_name: db.internal` connects to the address and verifies the name. With a bare address and
no override, the certificate is checked against its IP SANs and no SNI is sent — SNI carries names
only.

**`insecure: true` is explicit, per-run, and recorded in the report.** It is never an automatic
fallback. A handshake performed this way proves the channel is encrypted and proves nothing about
who answered. The channel is then unverified, which the credential transport policy refuses — so
a credential is **withheld rather than sent**, and an `insecure` target with a password
authenticates nothing.

Under `mode: disable` the other three fields describe nothing and are **refused** rather than
ignored.

#### `credentials`

| Field | Meaning |
|---|---|
| `username` | The identity to authenticate as |
| `password` | A **reference** to the credential — never the credential |

Supplying no credentials is a valid run. An endpoint that demands authentication is reported as
demanding it, and nothing is sent.

PostgreSQL requires `username` whether or not a password is configured: it is the role named in
the startup message, and that has no anonymous form.

#### `config`

The service's own configuration. Every field is optional.

| `type` | Field | Default | Meaning |
|---|---|---|---|
| `postgres` | `database` | the role name | The database to select |
| `kafka` | `sasl_mechanism` | none | `PLAIN` or `SCRAM-SHA-256`, uppercase |
| `redis` | — | — | Redis has no service-owned configuration |
| `rabbitmq` | `vhost` | `/` | The virtual host to open |

`sasl_mechanism` has no default and svcdoctor never picks one: a default would be a silent
decision about the framing that carries your password. Any other registered name is proposed to
the broker and reported as one svcdoctor cannot perform — sending no credential and no byte
derived from one.

## Credentials

**A password is never written into this file.** `password:` names an environment variable or a
file, and nothing else.

```yaml
credentials:
  username: svcdoctor
  password:
    env: ORDERS_DB_PASSWORD        # the NAME of a variable, not its value
```

```yaml
credentials:
  username: svcdoctor
  password:
    file: /run/secrets/orders-db   # a path; the file's contents are the password
```

Exactly one source per reference. Both, or neither, is an error.

### `env` names a variable, not a value

`env: ORDERS_DB_PASSWORD` means *read the environment variable called `ORDERS_DB_PASSWORD`*. It
does not mean the password is the string `ORDERS_DB_PASSWORD`. The variable must be exported
where svcdoctor runs.

This is what suits CI: the platform injects a masked variable and the configuration — which is in
version control — names it.

### `file` reads the whole file

`file: /run/secrets/orders-db` reads that file's contents as the password. This is what suits
Kubernetes and systemd, where a secret arrives as a mounted file.

A single trailing newline is stripped, because that is what `echo`, an editor and most secret
mounts add. Nothing else is trimmed: a password may legitimately begin or end with a space.

### A plaintext password cannot be written

```text
password: hunter2      # refused
```

This is not rejected by a check. The decoder's type for `password` is a mapping naming one
source, so a plain scalar cannot be decoded at all. The refusal happens before anything is
dialled, and the error names the file and the line.

### No secret is cached

Two targets naming the same variable resolve it **independently**. A shared reference is not a
shared authority.

References are proved resolvable in a preflight pass before any target runs, so a run with one
missing variable dials nothing rather than measuring forty-nine targets and failing on the
fiftieth. That preflight retains no value; each target resolves its own credential immediately
before it executes, and the value goes out of scope when it finishes.

### There is no third source

No `--password` flag, in any command, because an argument is visible to every process on the
host. No interactive prompt. No DSN or connection-string input. No secret-manager integration.

The four leaf `diagnose` commands take `--password-file` and `--password-stdin`, and read no
environment variable at all. `env:` exists only in this file, where a reference is *named* rather
than inherited from an ambient process environment.

## What the run does with all this

Targets are **independent**. One target's failure never stops another, there is no dependency
ordering, and svcdoctor draws no conclusion across targets: it will not tell you Kafka is failing
because PostgreSQL is down, because it measured two endpoints and has no evidence of any
relationship between them.

There is no retry, no rediscovery and no filtering. `svcdoctor run` takes only run-global flags —
`--config`, `--timeout`, `--concurrency`, `--output` and `--shareable`. There is deliberately no
`--host` or `--target`: a flag that edited one target would mean the file no longer describes the
run.

## Errors

A configuration error means **zero targets are dialled** and no report is produced. The run exits
2 and names the file, the location and the reason.

```text
svcdoctor: services.yaml: line 6: field hostname is not a field this schema defines
svcdoctor: services.yaml: targets[1] (target "a"): target identifier "a" is already used by targets[0]
svcdoctor: services.yaml: run.concurrency: run.concurrency 99 is above the maximum of 16
svcdoctor: services.yaml: line 3: "banana" is not a duration; write it with a unit, such as "30s"
svcdoctor: target "orders-db": host: fe80::1%en0 carries an IPv6 zone identifier
svcdoctor: target "orders-db": tls.ca_file: cannot be read: no such file
svcdoctor: target "orders-db": credential resolution failed: credential env ORDERS_DB_PASSWORD: the environment variable is not set
```

The last three are the pre-execution checks: the host, the trust material and the credential
reference are all validated before the first socket is opened. All of them exit 2.

A local failure that happens *after* that — a secret file removed while the run is in flight — is
a different thing and gets a different answer: the run produces an aggregate, that target is
`EXECUTION_FAILED`, and the run exits 4. [`OUTPUT.md`](OUTPUT.md#execution-state-versus-diagnosis)
explains the distinction.
