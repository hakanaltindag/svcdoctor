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
| `type` | **yes** | — | `postgres`, `kafka`, `redis`, `rabbitmq` or `kubernetes` |
| `host` | **yes** | — | Hostname, or IPv4 or IPv6 address literal |
| `port` | no | the service's default | `5432`, `9092`, `6379`, `5672` |
| `timeout` | no | `30s` | Bound on this target's whole journey |
| `step_timeout` | no | `10s` | Bound on each individual exchange. **Refused on a `kubernetes` target**, which has no per-step budget |
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

**A `kubernetes` target writes neither, and both are refused there.** Its API server is derived
from the kubeconfig context the target already names, or is the API Service's own name in-cluster,
so a written `host` or `port` would be read by nothing — and a field that looks configured and is
not is worse than one that is absent.

**An address is not a name.** A target given a literal resolves nothing and records nothing about
resolution: its report holds no name-resolution node at all, so a DNS finding is structurally
unreachable for it rather than suppressed.

A zone identifier — `fe80::1%en0` — is refused. The zone is a vantage-local interface name with no
decided representation in the evidence subject, the credential binding key, the TLS identity or
the pseudonym namespace. Deferred, not rejected.

#### `timeout` and `step_timeout`

Durations with a unit: `45s`, `2m`, `1500ms`. A bare number is refused.

`step_timeout` must be below `timeout`, or no step could complete inside the target's own budget.

**A `kubernetes` target refuses `step_timeout` outright.** It has no per-step exchange to bound —
three API requests run under the target's own `timeout` — so the value would be inert, and an
inert input is refused rather than silently ignored.

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
| `kubernetes` | `kubeconfig` | none | Path to exactly one kubeconfig file. Required unless `in_cluster` |
| | `context` | none | The kubeconfig context. **Required** with `kubeconfig`, forbidden with `in_cluster` |
| | `in_cluster` | `false` | Authenticate as the pod's own ServiceAccount. Mutually exclusive with `kubeconfig` |
| | `namespace` | none | **Required.** Never taken from the context, never `default` |
| | `service_name` | none | **Required.** The one Service this target is about |

`sasl_mechanism` has no default and svcdoctor never picks one: a default would be a silent
decision about the framing that carries your password. Any other registered name is proposed to
the broker and reported as one svcdoctor cannot perform — sending no credential and no byte
derived from one.

### `kubernetes` targets

```yaml
targets:
  - id: payments-api
    type: kubernetes
    config:
      kubeconfig: /etc/svcdoctor/kubeconfig
      context: prod-eu
      namespace: payments
      service_name: payments-api
```

A `kubernetes` target is decoded, validated and executed, and it produces a report containing the
evidence it gathered — the API access, the Service, the Pod set and the endpoint publication — and
up to four findings drawn from it. The same target is reachable as
`svcdoctor diagnose kubernetes`, and **one Service is one target and one report through both entry
points**: the two produce the same canonical report, proven against a real cluster.

**A `kubernetes` target writes no `step_timeout`, and one is refused.** Its three API requests run
under the target's own `timeout`; a per-step budget would change nothing, and an inert value is
refused rather than accepted, because an operator who wrote it believes it configured something.
The leaf command refuses it the same way, by defining no `--step-timeout` at all.

**One Service is one target.** There is no selector, no Pod, no workload, no wildcard, no regular
expression, no list of Services and no all-namespaces mode. Each of those is a field that does not
exist rather than a value that is rejected.

**Nothing is defaulted.** `KUBECONFIG` is not consulted, `~/.kube/config` is not a fallback, a
merge list is not supported, and the file's own `current-context` is never used — a defaulted
context makes one configuration read a different cluster on a different machine, and its failure
mode is indistinguishable from a real finding.

**In-cluster mode is explicit and is never a fallback.** A mounted ServiceAccount token must never
cause svcdoctor to acquire an identity nobody asked for.

**Five kubeconfig constructs are refused, before anything is sent:**

| Construct | Why |
|---|---|
| `exec` | A configuration file must not make svcdoctor run a local program. No flag enables it |
| `auth-provider` | The cloud providers shipped as auth-providers execute local commands, and none is registered in this build |
| `as`, `as-groups`, `as-uid`, `as-user-extra` | A diagnostic that silently acts as another principal produces a report whose authority cannot be reconstructed |
| `proxy-url` | A proxy changes the network position every claim in the report is scoped to |
| `insecure-skip-tls-verify` | svcdoctor presents a credential to the API server and will not do so over a channel it cannot verify |

`username`/`password` is refused too: basic authentication is deprecated in Kubernetes and is not a
supported mode. So is a context whose user declares no credential at all — svcdoctor does not read
a Kubernetes API anonymously.

Each of these is a **configuration error**, reported before any network operation and exiting 2.

**EKS, GKE and AKS kubeconfigs use exec plugins by default**, so those clusters are reachable only
through in-cluster identity or a token materialized outside the file. That is the price of not
running programs a file names.

**Four authentication modes, and only these:** a bearer token the target's own `credentials:`
block names; a kubeconfig `tokenFile`, which svcdoctor reads itself; a client certificate and key;
and the in-cluster ServiceAccount. Exactly **one** credential may be declared between the target
and the selected kubeconfig user — two is an ambiguity svcdoctor refuses rather than ranks.

The `tls:` block is refused entirely for a `kubernetes` target: the API server's trust material
comes from the kubeconfig's own `certificate-authority`, or from the projected ServiceAccount CA.
So is `credentials.username`, because no supported mode carries one — a bearer token and a client
certificate each *are* the identity.

**The RBAC it needs is a namespaced `Role` with three resources and two verbs:**

```yaml
rules:
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["list"]
```

No `ClusterRole`, no cluster-scoped grant, and no `watch`, `create`, `patch`, `update`, `delete`,
`impersonate`, `escalate`, `bind`, `pods/log`, `pods/exec`, `secrets`, `configmaps`, `events`,
`nodes` or `namespaces`. **A label selector narrows the request; it does not narrow the grant** —
svcdoctor holds `pods:list` and `endpointslices:list` for the whole namespace.

**A Kubernetes credential authorizes the API server and nothing else.** It does not authorize a
Pod IP, a cluster IP, an endpoint address, a node address, or any PostgreSQL, Kafka, Redis or
RabbitMQ endpoint. No discovered endpoint inherits it, and svcdoctor connects to none of them.

**Exactly three API requests are made**, server-side filtered and issued in order: `GET` the
Service, `LIST` Pods by that Service's own selector, `LIST` EndpointSlices by
`kubernetes.io/service-name`. There is no watch, no discovery call, no version negotiation and no
retry of any kind — a `429` or a `5xx` ends the read and the set becomes **incomplete**, because
retrying would turn one bounded diagnosis into a small monitoring loop.

**A budget reached is never "nothing found".** Pages are bounded at 500 objects each, 8 pages per
list, 4,000 Pods, 256 EndpointSlices and 10,000 endpoints. Reaching any of them — or a `410`, a
failed request or a cancellation — makes that set **incomplete**, marks the run incomplete and
exits 4. An empty *complete* set and an incomplete one are different facts, and only the first
supports a conclusion.

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

The four endpoint leaf `diagnose` commands take `--password-file` and `--password-stdin`;
`diagnose kubernetes` takes `--token-file` and `--token-stdin`, because its credential is a
bearer token rather than a password. All five read no
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
