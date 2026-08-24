# ADR 0066: A Redis error is classified by its prefix, and an implementation is what the endpoint says it is

## Status

**Accepted in Phase 7.4. Not implemented.**

It decides two things that turn out to be one thing seen twice: how a Redis error reply is
normalized, and how Redis and Valkey are told apart. Both are questions about a peer-supplied
string, and both get the same answer — **it is a fact about what the peer said, never about what
is true.**

It also freezes the adapter and CLI shape that follow from it: one adapter, one command, identity
observed rather than declared.

`SchemaVersion` stays **1**. No `FindingCode`, no `FailureClass`, no dependency.

## 1. Context

### Error text is peer-controlled, twice over

`redis/src/server.c:4386` interpolates the caller's own command arguments into the error string:

```c
    args = sdscatprintf(args, "'%.*s' ", 128 - (int)sdslen(args), (char *)c->argv[i]->ptr);
```

`redis/src/acl.c:2871`-`2876` interpolates the **username** into every `NOPERM`:

```c
    case ACL_DENIED_CMD:
        return sdscatfmt(sdsempty(), "User %S has no permissions to run "
                                     "the '%S' command", user->name, cmd->fullname);
```

So a Redis error message can contain bytes svcdoctor sent, bytes the operator supplied, or — from
a hostile or merely unusual peer — anything at all.

### Error text is also implementation-specific, where the prefix is not

`valkey/src/server.c:2138` parameterizes the shared error strings by server name:

```c
    createSharedStringFromSds(sdscatfmt(sdsempty(), "-LOADING %s is loading the dataset in memory\r\n", name));
```

Redis hardcodes `"Redis"` at `src/server.c:2243`. The **prefixes** — `LOADING`, `NOAUTH`,
`WRONGPASS`, `NOPERM`, `DENIED`, `MASTERDOWN`, `BUSY` — are byte-identical across both.

The RESP specification is explicit that even the prefix "is a convention used by Redis rather
than part of the RESP error type", which is why an unrecognized prefix must degrade rather than
be trusted.

### Identity is configurable

`valkey/src/networking.c:5936`-`5940`:

```c
    addReplyBulkCString(c, "server");
    addReplyBulkCString(c, server.extended_redis_compat ? "redis" : SERVER_NAME);

    addReplyBulkCString(c, "version");
    addReplyBulkCString(c, server.extended_redis_compat ? REDIS_VERSION : VALKEY_VERSION);
```

`extended_redis_compat` defaults to off (`valkey/src/server.c:2390`), so Valkey normally says
`valkey` — but an operator can configure it to say `redis`, with a Redis version number.

## 2. Decision

1. **Only an allowlisted, normalized error prefix crosses the wire-package boundary.** Raw error
   text never enters evidence, a renderer, a log line or an error value. An unrecognized prefix is
   recorded as a fixed sentinel, never passed through.
2. **Implementation and version are observed from `HELLO` and recorded as what the endpoint
   reported.** Never inferred from the CLI verb, never treated as proof.
3. **Cross-implementation version arithmetic is prohibited.** No comparison, no ordering, no
   capability inference from a version string.
4. **One adapter, one CLI command**, with compatibility graded separately.

## 3. Prefix-only, and what it costs

The prefix is the first whitespace-delimited token of a `-` reply. It is matched against a closed
set and recorded as a normalized value; anything outside the set becomes an `UNRECOGNIZED`
sentinel. Nothing peer-supplied is copied.

This is ADR 0027's boundary reasoning applied to a different payload, and it is the same rule
Kafka already lives under: the broker's SASL error message never leaves the wire package.

### Reachable prefixes in v1

Reachability is decided by the three-command allowlist
([ADR 0063](0063-redis-basic-journey-and-usability-boundary.md) §11), not by what Redis can emit
in general.

| Prefix | Reachable | Where | Protocol fact | Safe conclusion | Unsafe conclusion |
|---|---|---|---|---|---|
| `NOAUTH` | yes | first `HELLO`, `PING` | the connection is unauthenticated | this endpoint requires authentication | "the credential is wrong" |
| `WRONGPASS` | yes | `AUTH` | authentication rejected | the endpoint rejected the presented credential | "wrong password" / "no such user" / "user disabled" — merged at `acl.c:1511` |
| `NOPERM` | yes | `PING` | ACL denial after authentication | authenticated; not authorized for this command | "the service is broken"; "the app will fail" |
| `ERR` | yes | unknown `HELLO`; `AUTH` against a `nopass` default user | generic | only what the surrounding context justifies | anything read from the message text |
| `DENIED` | yes | any point, then the peer closes | protected mode, non-loopback, no password configured | reachable Redis, no password set, not exposed deliberately | "firewall problem" |
| `LOADING` | yes | `PING` only — `HELLO` and `AUTH` carry `CMD_LOADING` | the endpoint is loading its dataset | the endpoint named `LOADING` and refused | "the server is down"; "data was lost" |
| `MASTERDOWN` | yes | `PING` only — the other two carry `CMD_STALE` | a replica with a broken link, refusing stale reads | the endpoint named `MASTERDOWN` and refused | "the primary is down" — svcdoctor never observed the primary |
| `BUSY` | yes, rare | `PING` | the server is blocked in a script or module | the endpoint named `BUSY` and refused | "the server is overloaded" |
| `NOPROTO` | **no** | — | a zero-argument `HELLO` requests no version | — | — |
| `MOVED` / `ASK` / `CLUSTERDOWN` / `TRYAGAIN` / `CROSSSLOT` | **no** | — | require a key argument (`server.c:4609`) | — | — |
| `READONLY` | **no** | — | requires a write | — | — |
| `OOM` / `MISCONF` | **effectively no** | — | require a `denyoom` or write command | — | — |

Client-limit exhaustion (`ERR max number of clients reached`, `networking.c:1754`) is reachable
at connect time and carries a bare `ERR` prefix, so v1 records it as generic `ERR`. That is a
real loss of specificity and it is accepted: inventing a distinction the prefix does not carry is
the error this record exists to prevent.

### Where a failing reply lands

`NOPERM` maps to `FailureAuthzDenied`, whose definition is "the identity authenticated but was
denied the operation" — an exact fit, and the direct analogue of PostgreSQL's `42501`.

Every other reachable non-success prefix maps to `FailureProtocolUnexpectedResponse` with the
normalized prefix recorded as an attribute. This follows
`internal/adapter/postgres/establish.go:420`-`441` exactly, where `53300` and `57P03` — both real
operational facts, both with a different remedy from anything else in the window — land on the
honest weak class with the SQLSTATE recorded beside them, because *one producer and no
authorizing record is not enough to grow a service-neutral vocabulary*.

That precedent is why this phase adds **no `FailureClass`**, and why Phase 7.5 is not expected to
need one either. `LOADING` and `MASTERDOWN` were the two most likely to force one, and they do
not.

### The one thing prefix-only loses, and where it is recovered

`AUTH <password> called without any password configured for the default user` carries its meaning
entirely in text, and its prefix is a bare `ERR`.

The underlying fact — *this endpoint requires no authentication* — is already established by the
credential-free first `HELLO`, which answered with a map instead of `-NOAUTH`. The journey shape
recovers what the classification rule discards, which is why **no message-fragment allowlist is
needed and none is authorized.**

That is the whole of the loss. It was looked for specifically, and it is not general.

### One classifier per step, never a shared dictionary

`internal/adapter/postgres` keeps a separate SQLSTATE classifier for each of startup,
authentication and session establishment, on the stated ground that a shared table would answer
*what does this code mean* when the only answerable question is *what does this code prove here*.
Redis inherits that: `WRONGPASS` at `AUTH` and a hypothetical `WRONGPASS` elsewhere are not the
same evidence, and a single Redis error dictionary is forbidden for the same reason.

## 4. Identity is observed, and it is not proof

The retained `HELLO` fields, and their disposition:

| Field | Decision | Reason |
|---|---|---|
| `server` | **retain**, observation only | Implementation identity, configurable via `extended-redis-compat` |
| `version` | **retain** as an opaque string | Never parsed, never compared — see §5 |
| `proto` | **retain** | The connection's actual protocol version; always 2 in v1 |
| `mode` | **retain — BASIC and load-bearing** | It drives the Sentinel guard (ADR 0065) |
| `role` | **retain**, observation only | `master` / `replica`; never a finding |
| `id` | **ignore — not collected** | A server-internal correlation handle with no BASIC use. Collecting it would need an `AttrKind` decision under ADR 0037 for no benefit |
| `modules` | **ignore — not collected** | The only unbounded field in the reply; it names third-party extensions and invites "is this module healthy" |
| `availability_zone` (Valkey) | **defer** | Valkey-only, location-revealing, and no BASIC rule reads it |
| any unknown future field | **ignore** | Parsed and discarded within the reply budget. The parser must not fail on an unknown key |

Retained peer strings are bounded, charset-validated and redaction-classified before they are
recorded, exactly as any other identity-bearing value under ADR 0037.

**Implementation identity can never be a finding in v1.** It would need an expected-implementation
contract, which is real in a migration project and is still a contract svcdoctor does not have.
The wording in every surface is *the endpoint reported*, never *the endpoint is*.

## 5. No version arithmetic

Prohibited: comparing, ordering, or inferring a capability from a version string, in any
direction, for either implementation.

The reason is not fastidiousness. Valkey's version numbers are on an unrelated line from Redis's,
and `extended_redis_compat` can make either report the other's. A rule like "version < 6.0 means
no `HELLO`" is simply false for Valkey, and would be false for Redis under a compat-configured
peer.

Capability is established by **asking** — the `HELLO` outcome is the capability evidence — which
is the same discipline Kafka already applies through ApiVersions rather than through broker
version strings.

A guard should assert that no production file parses or compares a Redis version string.

## 6. One adapter, one command

| Decision | Result |
|---|---|
| Adapters | **One**, `internal/adapter/redis` |
| CLI commands | **One**, `svcdoctor diagnose redis` |
| Report identity | Observed from `HELLO`; an operator who typed `diagnose redis` against Valkey must see `valkey` in the report |
| Compatibility | **Graded separately** in `docs/COMPATIBILITY.md`, enforced by the existing `internal/cli/docsclaims_test.go` |

Every command in the frozen journey behaves identically on both implementations. The divergence
is confined to two places — the `HELLO` identity fields and the error message text — and both are
handled by §3 and §4 rather than by branching.

Two separate commands were rejected: they would duplicate a CLI surface for a protocol difference
that does not exist, and they would encode implementation identity in the verb, which §4 forbids.
`diagnose redis-compatible` was rejected as accurate and unusable — no operator types it. A thin
registry alias for `valkey` remains available later if discoverability turns out to be a real
complaint; it is a CLI decision, not an architecture one.

The compatibility grading machinery already handles "same protocol, different implementation,
different validation level" — it is how Apache Kafka and Redpanda are graded today — so nothing
new is required to keep the two honest.

## 7. Consequences

- A Valkey-specific error message can never change a classification, because no classification
  reads a message.
- A hostile peer cannot inject bytes into the canonical report through an error reply.
- A `NOPERM` reply containing the operator's username is moot: the text is never read.
- svcdoctor cannot distinguish client-limit exhaustion from any other bare `ERR` in v1, and says
  so rather than guessing.
- Adding an eleventh recognized prefix later is additive and testable; adding a message-fragment
  rule is not, and is forbidden.

## 8. Rejected alternatives

| Option | Rejected because |
|---|---|
| Pass the raw error text through and redact later | A security property that depends on a renderer hiding something already in the canonical report is not a security property |
| A message-fragment allowlist | §3. The one fact it would recover is already recovered by the credential-free first `HELLO` |
| A shared Redis error dictionary | Answers "what does this code mean" instead of "what does this code prove here" — the shape ADR 0039 §7.1 already rejected for SQLSTATE |
| Trusting the prefix without an allowlist | The RESP specification calls the prefix a convention, not part of the type. An unrecognized prefix must degrade |
| A new `FailureClass` for `LOADING`/`MASTERDOWN` | The PostgreSQL `53300`/`57P03` precedent: one producer and no authorizing record is not enough to grow a service-neutral vocabulary |
| Two adapters, or two CLI commands | Protocol-identical journey; separate commands would encode identity in the verb |
| `diagnose redis-compatible` | Honest and unusable |
| Version-based capability inference | §5. Unrelated numbering lines, and a configurable identity |
| Retaining `modules` | Unbounded, names third-party extensions, and creates an assurance expectation |
| Retaining the connection `id` | Server-internal correlation handle; no BASIC rule reads it |

## 9. Reopen conditions

- **A prefix arrives that is genuinely ambiguous without its text**, and the ambiguity is measured
  rather than argued. That would justify a narrow, enumerated fragment allowlist — and nothing
  wider.
- **A second implementation family diverges in prefixes rather than only in text**, which would
  end the assumption that one allowlist serves both.
- **A `FailureClass` for "the peer is not ready to serve"** gains a second service producer,
  meeting the bar the PostgreSQL precedent sets for growing service-neutral vocabulary. Redis
  alone is one producer.
- **An expected-implementation contract** — a migration mode where an operator declares "this
  should be Valkey" — which is the only thing that would let identity become a finding.
- **Discoverability complaints about `diagnose redis` for Valkey users**, which reopens the
  registry-alias question as a CLI decision.
