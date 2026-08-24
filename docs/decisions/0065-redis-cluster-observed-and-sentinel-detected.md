# ADR 0065: Redis Cluster is observed and not traversed, and a Sentinel is detected and not diagnosed

## Status

**Accepted in Phase 7.4. Not implemented.**

It decides what Redis/Valkey BASIC does when the endpoint an operator named turns out to be a
cluster node or a Sentinel. Both are `mode` values from the same `HELLO` reply
([ADR 0063](0063-redis-basic-journey-and-usability-boundary.md) §8), which is why one record
decides both.

It authorizes **no** topology producer, **no** redirect handling and **no** `CLUSTER` command.
It authorizes **one** finding, for the Sentinel case, and names the contract that makes it
legitimate.

`SchemaVersion` stays **1**. No `FailureClass`, no dependency.

## 1. Context

The obvious reading of "defer Redis Cluster" is that it is complicated and can wait. That reading
is wrong in an important way, and the correction is the substance of this record: **most of Redis
Cluster is not deferred from BASIC, it is unobservable by it.**

`redis/src/server.c:4609`-`4616`:

```c
    /* If cluster is enabled perform the cluster redirection here.
     * However we don't perform the redirection if:
     * 1) The sender of this command is our master.
     * 2) The command has no key arguments. */
    if (server.cluster_enabled &&
        !mustObeyClient(c) &&
        !(!(c->cmd->flags&CMD_MOVABLE_KEYS) && c->cmd->key_specs_num == 0 &&
          c->cmd->proc != execCommand))
```

And `-MOVED`, `-ASK`, `-CLUSTERDOWN`, `-TRYAGAIN` and `-CROSSSLOT` are emitted from exactly one
place, `clusterRedirectClient` (`src/cluster.c:1515`-`1537`), reached only through that gate.

`HELLO`, `AUTH` and `PING` all have `key_specs_num == 0` and no `CMD_MOVABLE_KEYS`. So under
ADR 0063 §11's zero-keyspace-access contract, **svcdoctor cannot receive a redirect at all** —
not rarely, not in practice, but structurally. It also cannot receive `CLUSTERDOWN`: a keyless
command is served locally by whichever node answered, regardless of slot ownership and regardless
of whether the cluster state is `fail`.

The Sentinel case is the mirror image. `src/server.c:3501`-`3503` hides a command in sentinel
mode unless it carries `CMD_SENTINEL`, and `ping.json`, `hello.json` and `auth.json` all carry
it. **A Sentinel completes the entire BASIC journey and answers `PONG`.** It stores no data
whatsoever.

## 2. Decision

### Cluster

**Option A: treat a `mode=cluster` endpoint exactly as a direct endpoint, record the mode, and
report that topology was not measured.**

- No `CLUSTER SHARDS`, no `CLUSTER SLOTS`, no `CLUSTER INFO`.
- No topology node, and therefore no topology producer.
- `MOVED`/`ASK`/`CLUSTERDOWN` get **no `FindingCode`, no `FailureClass` and no parser special
  case**.
- `mode=cluster` is an observation and never a finding.
- Cluster health is **not measured**, and the renderer must say so.
- Discovered endpoints do not exist, and would not receive a credential if they did.

### Sentinel

**Detection is BASIC and mandatory. Diagnosis is deferred to a separate target type.**

- Identified by `HELLO`'s `mode` field equal to `sentinel`.
- It is a **stop condition that produces a finding**. The run stops before `AUTH`, so the
  data-endpoint credential is never presented to a Sentinel.
- If `HELLO` is unavailable, `mode` is UNKNOWN and svcdoctor claims neither that the endpoint is
  a Redis data server nor that it is a Sentinel.

## 3. Why the redirect codes get no owner

ADR 0054 is usually applied in one direction: a production-reachable FAIL-producing stage does not
land unless its outcomes have an owner. This record applies it in the other direction, which has
not been recorded before:

> **An unreachable producer must not have an owner.** A finding code for evidence that no run can
> produce is policy nobody can test, and it will read to every later reader as a natural
> completion of the table.

This is structurally the same move ADR 0059 made for DNS: a run given an address literal has no
`dns.lookup` node **at all**, which is what makes a DNS finding structurally unreachable for one
rather than suppressed. `MOVED` is the same shape. The absence is the decision.

A parser that encountered `-MOVED` on a keyless command would be looking at a peer that is not
behaving as Redis does, so it lands where any unrecognized prefix lands:
`PROTOCOL_UNEXPECTED_RESPONSE`, prefix recorded as unrecognized
([ADR 0066](0066-redis-error-prefix-classification-and-observed-identity.md)). There is no
MOVED-specific handling, because there is no MOVED-specific evidence.

## 4. What excluding cluster actually costs

Less than it looks like, and the reason is worth stating because it is the argument that made
option A defensible rather than merely convenient:

**Because the journey is keyless, v1 behaves identically against a cluster-mode node and a
standalone one.** DNS, TCP, TLS, `HELLO`, `AUTH` and `PING` all execute and mean the same thing.
Excluding cluster excludes cluster *diagnosis*, not cluster *users*.

What is genuinely lost is the class of finding an operator most wants from a cluster — "this
cluster advertises addresses my pods cannot reach" — and that is L6 topology work with its own
model, its own completeness rules and its own credential-authority question. It is deferred whole
rather than approximated.

## 5. What the renderer must not do

`mode=cluster` with no topology measurement is the exact shape ADR 0052 was written about. The
rule binds here without amendment:

> **"not measured" is never collapsed into "not reached", and neither is ever collapsed into
> "healthy".**

A report on a cluster-mode endpoint says that the endpoint served `PING` and that topology was
not measured. It does not say the cluster is healthy, does not say it is unhealthy, and does not
imply that the absence of topology findings is the absence of topology problems.

## 6. When cluster traversal arrives, these bind

Recorded now so that a later phase inherits them rather than re-deriving them:

- **Discovery creates no credential authority.** ADR 0050's Kafka reasoning transfers, and the
  case is stronger for Redis: `cluster-announce-ip` and `cluster-announce-hostname` make the
  advertised destination a single line of server configuration. The counter-argument — that Redis
  credentials are usually cluster-wide anyway, so propagation is harmless — confuses *whether the
  credential would work* with *who chose the destination*.
- **Advertised endpoints get credential-free DNS, TCP and TLS, or nothing.**
- **The topology model must represent the documented abnormal endpoint forms**: `""` (the node
  does not know its own IP), `"?"` (announced-hostname mode with no hostname configured), and the
  empty-endpoint redirect `:6380` (same host as the current connection, different port). A model
  that cannot express "unknown endpoint, relative to the connection I am on" is wrong before it
  is written.
- **`CLUSTER SHARDS` is `@slow`**, and therefore *less* privileged than `ROLE`
  (`@admin @dangerous`). A credential that cannot run `ROLE` may well be able to run
  `CLUSTER SHARDS`.
- **A node's `health: online|failed|loading` is that node's gossiped opinion**, not svcdoctor's
  measurement, and must never be rendered as one.
- **One unreachable advertised node justifies exactly "one advertised endpoint was unreachable
  from this vantage."** ADR 0051's existential/universal split applies unchanged.
- **If the credential cannot run the cluster commands, the report says topology could not be
  inspected** — `SKIPPED`/`UNKNOWN` with the denial recorded. Never "cluster failure".

## 7. The Sentinel guard is the cheapest correctness win in the phase

A journey of `TCP → AUTH → PING` against a Sentinel returns `+PONG`. Without a guard, svcdoctor
reports a healthy Redis endpoint for a process that holds no keys — while the operator's actual
problem is the wrong port in their configuration, which is exactly what they came to diagnose.
It is a confident, specific, wrong answer, which is the worst kind this product can give.

The guard costs one branch over evidence already collected.

| Question | Decision |
|---|---|
| How is a Sentinel identified? | `HELLO`'s `mode == "sentinel"` |
| Is `mode` enough? | **Yes.** It is the server's own self-description, from an ACL-exempt command. It is corroborated by the **omission of the `role` field** (`src/networking.c:5122` emits `role` only when `!server.sentinel_mode`), which the parser must tolerate regardless |
| If `HELLO` is unavailable? | `mode` is **UNKNOWN**. svcdoctor claims neither outcome, and the report states that mode was not measured |
| Is a `ROLE` fallback acceptable, solely for Sentinel detection? | **No** — though the argument for it is real and is recorded in §9 |
| Finding, stop condition, or different outcome? | **A stop condition that produces a finding**, and the run stops before `AUTH` |
| A future CLI target? | **Yes**, later: `diagnose redis-sentinel` |

### Why this finding is legitimate without an external expectation contract

Every other Redis observation is barred from becoming a finding for want of a contract:
`role=replica` needs an expected-role contract, `mode=cluster` needs an expected-topology
contract, a version needs an expected-version policy.

The Sentinel case is different, and the difference is precise: **the contract is the operator's
own invocation.** They typed `diagnose redis`, which names a Redis data endpoint, and this
endpoint provably is not one. No external policy is required, because the expectation was stated
by the command that was run.

### Why Sentinel is a separate target and not a mode of this one

- A different port by convention (26379).
- A different command set — most data commands do not exist in sentinel mode at all.
- **Independent credential domains**: `requirepass` on the Sentinel itself, versus
  `sentinel auth-pass` / `sentinel auth-user` which the Sentinel uses toward the primary it
  monitors. Three domains, not one.
- Its useful questions — is quorum met, did a failover happen — are assurance questions needing a
  quorum model svcdoctor does not have.

## 8. Consequences

- A cluster user gets a truthful BASIC run today, and no cluster diagnosis.
- A Sentinel target gets an ERROR finding, exit 1, and no credential transmitted.
- No `CLUSTER` command appears in the allowlist, so ADR 0063 §11's contract needs no exception.
- `MOVED`, `ASK` and `CLUSTERDOWN` are absent from the vocabulary entirely — a later reader adding
  them must first make them reachable.

## 9. Rejected alternatives

| Option | Rejected because |
|---|---|
| **B — run `CLUSTER SHARDS` in v1** | L6 topology work. It needs an endpoint model, completeness rules and a credential-authority decision, none of which BASIC has. Also: gathering topology invites reading health into it |
| **C — transport-probe discovered endpoints in v1** | Coherent and genuinely useful, and still needs the topology model in B plus an owner for its outcomes under ADR 0054 |
| **D — follow `MOVED`/`ASK`** | Requires naming a key, which breaks zero keyspace access for evidence obtainable keylessly later |
| Name a synthetic key to provoke a redirect | Same, plus it needs a key-pattern ACL a scoped user will not have, and it turns a clean authorization answer into `NOPERM ... one of the keys used as arguments` |
| A `FindingCode` for `MOVED` now, "ready for later" | §3. An unreachable producer with an owner is untestable policy that reads as a completed table |
| A `ROLE` fallback when `HELLO` is unknown, for Sentinel detection only | Tempting, and the supporting argument is real: an endpoint without `HELLO` predates Redis 6.0 and therefore predates ACLs, so `ROLE` could not be ACL-denied *on that same server*. Rejected because the argument fails for a proxy fronting a modern Redis, it puts an `@admin @dangerous` command into a three-command allowlist, and the outcome it avoids is **UNKNOWN, not a false positive** |
| Treat Sentinel as an ordinary Redis endpoint | §7. It answers `PONG` |
| A `--sentinel` or `--cluster` flag | Service behaviour is discovered from `HELLO.mode`, never declared. A flag would let an operator assert a mode svcdoctor can measure |

## 10. Reopen conditions

- **A Redis topology phase** with an owner for advertised-endpoint outcomes, at which point §6's
  list becomes its input and `CLUSTER SHARDS` gets a producer.
- **A `diagnose redis-sentinel` target**, which needs its own credential model for the three
  domains in §7 and its own claim discipline for quorum.
- **Validation shows pre-`HELLO` endpoints are common enough that Sentinel detection fails
  materially often**, which would reopen the `ROLE` fallback on measured grounds rather than
  speculative ones.
- **A keyless command that can be redirected** — an upstream change to the gate at
  `server.c:4609` — which would make `MOVED` reachable and require an owner in the same
  change-set, per ADR 0054.
