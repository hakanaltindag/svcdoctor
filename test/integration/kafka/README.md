# Kafka integration validation

Runs svcdoctor against a **real** three-broker Apache Kafka cluster. This is the
Phase 3 acceptance gate; the hermetic tests elsewhere prove each layer against a
fake peer, and these prove the layers compose correctly against a broker that
does not know it is being tested.

Excluded from `go test ./...` by the `integration` build tag. Nothing in the
ordinary quality gate needs Docker.

## Run it

```sh
make integration-kafka          # up, wait, test, down
```

or, step by step:

```sh
make kafka-up                   # 3 brokers, KRaft, SASL_SSL, ~15s
make kafka-test                 # the suite
make kafka-down                 # stop and delete volumes
```

Certificates are generated on demand into `env/certs/` by `env/gen-certs.sh` and
are git-ignored. They are throwaway test material with a hardcoded password; no
production secret exists in this tree.

## Why the cluster is SASL_SSL rather than PLAINTEXT

Not for coverage. `kafka.Metadata` takes an `*AuthenticatedSession`, and the only
constructor of that type is a successful SASL authentication; the default
credential-transport policy then requires verified TLS. So SASL_SSL is the only
listener shape that reaches topology discovery at all.

That restriction is svcdoctor's, not Kafka's — a real broker serves Metadata
happily on a PLAINTEXT listener — and it is recorded as such in
`internal/adapter/kafka/metadata.go` and ADR 0031. A PLAINTEXT cluster is still
useful for the transport layers, and `env/compose.yaml` keeps one.

## Topology

```text
                    EXTERNAL (SASL_SSL/PLAIN)        INTERNAL (PLAINTEXT)
broker-1  node 1    localhost:19192                  broker-1:9094
broker-2  node 2    localhost:29192                  broker-2:9094
broker-3  node 3    localhost:39192                  broker-3:9094
```

The listener split is what makes the failure scenarios possible. Inter-broker
traffic uses INTERNAL, so a broker advertising an unreachable address **to
clients** stays a healthy cluster member — which is exactly the production
failure mode, and why the bootstrap keeps working while the advertised endpoint
does not.

## Scenarios

Failures are injected by reconfiguring the broker, never by changing svcdoctor.
Each is a compose variable, so the change is visible in `env/compose-sasl.yaml`.

| Test | Injection | Expected |
|---|---|---|
| `TestHealthyCluster` | none | 3 brokers, no findings |
| `TestAdvertisedDNSFailure` | `ADV_2=…invalid:9092` | one CONFIRMED finding, DNS causal ref |
| `TestAdvertisedTCPRefused` | `ADV_2=localhost:29999` | one finding, TCP refs, skips not cited |
| `TestAdvertisedTLSFailure` | `KS_2=/certs/wrongname.p12` | one finding, TLS causal refs |
| `TestPartialAddressSuccess…` | `PORTS_2=127.0.0.1:…` | **no** finding, failure still in evidence |
| `TestOneBadBrokerProduces…` | `ADV_2=localhost:29999` | exactly one broker-scoped finding |
| `TestAllBadBrokersProduce…` | all three bad | three findings, no cluster aggregate |
| `TestWrongCredentialIsRejected…` | wrong password | `AUTH_CREDENTIALS_REJECTED`, no leak |
| `TestOneConnectionCarries…` | none | one socket per address, four exchanges |

Set `SVCDOCTOR_ARTIFACTS=<dir>` to write each scenario's `LOCAL_FULL` and
`SHAREABLE_REDACTED` report as JSON.

## Known environment quirks

- `localhost` is dual-stack here, so every sweep measures `127.0.0.1` **and**
  `[::1]`. That is real behaviour and it is what makes the partial-address
  scenario reproducible.
- Colima's userspace port forwarder occasionally drops a connection under load,
  and both kcat and svcdoctor see it. It is not a cluster or a svcdoctor fault;
  re-run if a scenario fails with a transport error on the bootstrap path.
- Colima can leak host port bindings after `compose down`. The ports here
  (`19192`/`29192`/`39192`) were chosen to avoid a leaked set; if binding fails,
  `colima restart` clears them.
