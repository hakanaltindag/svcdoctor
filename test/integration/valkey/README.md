# Valkey BASIC validation environment

`make integration-valkey` brings up six pinned Valkey servers, runs the suite against them
through `app.DiagnoseRedis`, and tears them down. It needs Docker and is deliberately **not**
part of `make check`, which stays fast and hermetic.

Pinned image: **`valkey/valkey:8.1.1-alpine`**. Never `latest` — a suite that passes against a moving
tag means nothing a week later, and `docs/COMPATIBILITY.md` names this exact version.

## Fresh checkout

Nothing needs preparing. `valkey-up` runs `env/gen-certs.sh` first, which generates the throwaway
TLS material into `env/certs/` — gitignored, regenerated every run, never committed.

## The servers, and why each exists

| Container | Port | Exists for |
|---|---|---|
| `svcd-valkey` | 56479 | V-00 baseline, V-01 identity, V-04 PING |
| `svcd-valkey-pw` | 56480 | V-08 plaintext credential refusal |
| `svcd-valkey-acl` | 56481 | V-02, V-03 ACL authentication |
| `svcd-valkey-tls` | 56482 | V-02 over TLS, V-05 verified TLS |
| `svcd-valkey-replica` | 56484 | V-06 role observation |
| `svcd-valkey-cluster` | 56485 | V-07 cluster-mode node |

**The production code under test is the Redis adapter.** There is no Valkey adapter, no Valkey
vocabulary and no Valkey rule, and `TestNoProductionCodeBranchesOnImplementationName` fails the
build if one appears. This environment exists to prove that is honest rather than convenient:
V-01 asserts the report says `valkey` even though the operator typed `diagnose redis`.

## Ground truth comes first

Every scenario that asserts something about a server establishes it independently with
`valkey-cli` before svcdoctor is asked. A suite that only compared svcdoctor against itself would
pass just as happily against a server that had changed underneath it.

Three upstream behaviours the ADRs rest on are re-measured here rather than read from a source
file: `nopass` accepting any password through the two-argument `AUTH`, the two `AUTH` forms
differing on the same server, and the three authentication failures producing byte-identical
`WRONGPASS` replies.

## What this environment does not validate

Valkey Cluster as a cluster, Sentinel as a service, mutual TLS, any managed provider, and any
version other than the pinned one. `docs/COMPATIBILITY.md` says so per row.
