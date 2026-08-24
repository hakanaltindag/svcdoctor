# Redis BASIC validation environment

`make integration-redis` brings up eight pinned Redis servers, runs the suite against them
through `app.DiagnoseRedis`, and tears them down. It needs Docker and is deliberately **not**
part of `make check`, which stays fast and hermetic.

Pinned image: **`redis:8.2.1-alpine`**. Never `latest` — a suite that passes against a moving
tag means nothing a week later, and `docs/COMPATIBILITY.md` names this exact version.

## Fresh checkout

Nothing needs preparing. `redis-up` runs `env/gen-certs.sh` first, which generates the throwaway
TLS material into `env/certs/` — gitignored, regenerated every run, never committed.

## The servers, and why each exists

| Container | Port | Exists for |
|---|---|---|
| `svcd-redis` | 56379 | R-00 baseline, R-11 IPv4 literal, R-12 IPv6 literal |
| `svcd-redis-pw` | 56380 | R-13, the plaintext credential refusal, with its own AUTH accounting |
| `svcd-redis-acl` | 56381 | R-02 to R-07, the ACL matrix. See `env/users.acl.md` |
| `svcd-redis-tls` | 56382 | R-01, R-08, R-09, R-10, R-14 — TLS with `tls-auth-clients no` |
| `svcd-redis-mtls` | 56383 | R-20 — the Redis **default**, `tls-auth-clients yes` |
| `svcd-redis-replica` | 56384 | R-15 role observation |
| `svcd-redis-cluster` | 56385 | R-16 cluster-mode node |
| `svcd-redis-sentinel` | 56386 | R-17 Sentinel detection |

R-18 and R-19 need no container: both are **INJECTED** conditions built in-process — a listener
that accepts and never answers, and a port nothing listens on. They are labelled injected in the
test names and comments, and neither is described as an organic failure.

## Ground truth comes first

Every scenario that asserts something about a server establishes it independently with
`redis-cli` before svcdoctor is asked. A suite that only compared svcdoctor against itself would
pass just as happily against a server that had changed underneath it.

Three upstream behaviours the ADRs rest on are re-measured here rather than read from a source
file: `nopass` accepting any password through the two-argument `AUTH`, the two `AUTH` forms
differing on the same server, and the three authentication failures producing byte-identical
`WRONGPASS` replies.

## What this environment does not validate

Redis Cluster as a cluster, Sentinel as a service, mutual TLS, any managed provider, and any
version other than the pinned one. `docs/COMPATIBILITY.md` says so per row.
