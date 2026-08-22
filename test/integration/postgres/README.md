# PostgreSQL integration validation

Drives the real PostgreSQL adapter against a real PostgreSQL 18 server: the real
resolver, the real dialer, the real TLS probe, the real protocol, the real graph.
Nothing here hand-authors evidence and nothing simulates the credential path — the
server really receives a client proof and really verifies it.

**Not part of `make check`.** It needs Docker and it is not hermetic, while the
ordinary gate must stay fast and offline.

```sh
make postgres-up      # generate a throwaway certificate and start the server
make postgres-test    # run the suite against it
make postgres-down    # stop it and delete its volume

make integration-postgres   # all three
```

## What the environment provides

`env/pg_hba.conf` gives one role per authentication method, so each row of ADR
0038's mechanism table has something real to run against:

| Role | `pg_hba` method | What it validates |
|---|---|---|
| `scramuser` | `scram-sha-256` | the supported path, over TLS and plaintext |
| `md5user` | `md5` | observed and declined |
| `clearuser` | `password` | observed and declined |
| `trustuser` | `trust` | no credential, no authentication node |

| `norights` | `scram-sha-256` | authenticates, then `42501` on `closeddb` |
| `rejectuser` | `reject` | refused by `pg_hba` before authentication: the `28000` producer |
| `svcdcanaryrole` | `scram-sha-256` | the redaction canary, with `svcdcanarydb` |

**Two listeners.** `svcd-pg` on 55432 has TLS on; `svcd-pg-plaintext` on 55433 has it off and
exists to answer one `SSLRequest` with `N`. Measuring `POSTGRES_TLS_DECLINED` needs a server
that really declines, and simulating the byte would prove nothing about the negotiation.

**The host is `127.0.0.1`, not `localhost`.** `localhost` resolves to both `127.0.0.1` and
`::1`, so the transport chain returns two completed paths and every caller must then choose —
which ADR 0024 §3 refuses to let any layer do implicitly. This suite removes the choice
instead of making it, and `requireSingleContinuation` asserts the count rather than assuming
it. Production selection is deferred to ADR 0041.

`scramuser`'s password contains a space and a tilde — the two ends of the
printable-ASCII range svcdoctor supports — so the boundary is exercised against a
real SCRAM verifier rather than only against a unit test.

## The certificate is generated, never committed

`env/gen-certs.sh` writes a two-day self-signed certificate into `env/certs/`,
which is gitignored. A repository that ships a private key teaches the wrong habit
even when the key is worthless.
