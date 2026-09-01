# Quickstart

About five minutes, from nothing to a shareable report. No Docker required.

You need a service to point at — any PostgreSQL, Kafka, Redis/Valkey or RabbitMQ/LavinMQ endpoint
you can already reach from where you are running this.

## 1. Install

```sh
go install github.com/hakanaltindag/svcdoctor/cmd/svcdoctor@v0.3.3
```

Or run the published image, which needs no Go toolchain:

```sh
docker run --rm ghcr.io/hakanaltindag/svcdoctor:v0.3.3 --version
```

Check it:

```sh
svcdoctor --version
```

A release tag means a released build. `dev` means you built from a working checkout, which is
fine — it just corresponds to no release. The same value is recorded in every report.

## 2. Diagnose one endpoint

Start without a credential. That is a valid, useful run.

```sh
svcdoctor diagnose postgres --host db.internal.example.com --user app
```

```text
svcdoctor · postgres · db.internal.example.com:5432

  ✓ PASS  DNS  2.3ms

  Path 10.0.4.17:5432 · continued
    ✓ PASS     TCP             1.8ms
    ✓ PASS     SSLRequest      0.9ms
    ✓ PASS     TLS             4.1ms
    ✓ PASS     Startup         1.2ms
    · SKIPPED  Authentication         EXEC_REQUIRED_INPUT_MISSING
    ·          Session                not reached

Findings
  ⚠ WARN  POSTGRES_CREDENTIAL_NOT_CONFIGURED  db.internal.example.com:5432
    This endpoint requires authentication and this run was given no credential
    → Supply the credential your application uses for this endpoint and run again

Result
  status     OK                   no target-side error was proven
  outcome    session NOT established
  execution  complete
```

You have already learned a lot: the name resolves, the port accepts, TLS verifies against your
system trust store, PostgreSQL answered, and it wants a password.

## 3. Read the result

Three lines, three different questions:

- **`status`** — did svcdoctor prove a target-side problem? `OK` here means it did not.
- **`outcome`** — did the service's terminal exchange succeed? **No.** No session was established.
- **`execution`** — did svcdoctor's own run finish? Yes.

**`status OK` is not "the service works."** This run exits `0` and established nothing. That is
the single most important thing to internalise, and [`CI.md`](CI.md#three-things-exit-codes-do-not-mean)
says why.

## 4. Add a credential, safely

There is no `--password` flag. An argument is visible to every process on the host.

```sh
svcdoctor diagnose postgres --host db.internal.example.com --user app \
  --password-file /run/secrets/orders-db
```

Or from a pipe, for a secret-provider command:

```sh
vault kv get -field=password secret/orders-db | \
  svcdoctor diagnose postgres --host db.internal.example.com --user app --password-stdin
```

The credential is bound to the endpoint you named, crosses only a verified-TLS channel, and never
appears in the report.

## 5. Diagnose several at once

One command per service does not scale past about three. Describe them in a file instead:

```yaml
# services.yaml
version: 1

targets:
  - id: orders-db
    type: postgres
    host: orders-db.internal.example.com
    credentials:
      username: svcdoctor
      password:
        env: ORDERS_DB_PASSWORD

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

```sh
export ORDERS_DB_PASSWORD='…'
svcdoctor run --config services.yaml
```

`diagnose` is one endpoint you name on the command line. `run` is many endpoints a file names for
you. They perform exactly the same measurement.

**The password is not in the file.** `env:` names a variable and `file:` names a path — a
plaintext value there is refused before anything is dialled. Copy
[`examples/minimal.yaml`](../examples/minimal.yaml) to start, or
[`examples/services.yaml`](../examples/services.yaml) for one target per service.

## 6. Get JSON

```sh
svcdoctor run --config services.yaml --output json > report.json
```

```sh
# which targets have a problem?
jq -r '.targets[] | select(.report.summary.status == "PROBLEMS_FOUND") | .targetId' report.json

# which could not be measured at all?
jq -r '.targets[] | select(.executionState != "COMPLETED") | .targetId' report.json
```

JSON is canonical; the terminal form is derived from it. Parse the JSON, never the text.

## 7. Share it

```sh
svcdoctor run --config services.yaml --output json --shareable > report.shareable.json
```

Hostnames, addresses, identities and evidence identifiers become stable pseudonyms —
`host-001`, `ip-001`, `identity-001` — applied consistently, so the relationships stay readable
while the names are gone. Findings, durations, ports and every conclusion are preserved, and the
exit code is unchanged.

It is pseudonymized, **not anonymized**. Review it against your own disclosure requirements
before sending it anywhere. [`OUTPUT.md`](OUTPUT.md#shareable-reports) states exactly what is
replaced and what is not.

## Next

| | |
|---|---|
| Every configuration field | [`CONFIGURATION.md`](CONFIGURATION.md) |
| Terminal, JSON and shareable contracts | [`OUTPUT.md`](OUTPUT.md) |
| Exit codes and pipelines | [`CI.md`](CI.md) |
| What has actually been tested | [`COMPATIBILITY.md`](COMPATIBILITY.md) |

### If you need something to point at

The integration fixtures start real servers in Docker and are the fastest way to see svcdoctor
work end to end:

```sh
make integration-postgres     # PostgreSQL 18
make integration-rabbitmq     # RabbitMQ 3.13.7, 4.0.9, 4.2.0
```

Run them one at a time. **Their credentials are test values in a throwaway container** — they are
not a recommended configuration for anything.
