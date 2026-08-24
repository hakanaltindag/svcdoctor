# ADR 0064: Capability discovery precedes Redis authentication, and it carries no credential

## Status

**Accepted in Phase 7.4. Not implemented.**

It decides the credential contract for Redis/Valkey BASIC: where a credential may appear, how
many times it may be transmitted, over which channel, and what a success reply is allowed to
claim. [ADR 0063](0063-redis-basic-journey-and-usability-boundary.md) decides the journey this
contract sits inside.

It **adds no policy member** to `security.CredentialTransportPolicy` and changes nothing about
Kafka or PostgreSQL credential handling. It authorizes exactly one new production
`security.Reveal` call site, taking the module count from 2 to 3.

`SchemaVersion` stays **1**. No `FindingCode`, `FailureClass` or dependency.

## 1. Context — the upstream behaviour that forces the ordering

ADR 0007 puts protocol and capability discovery before authentication because that is the wire
order of both existing services. Redis supplies a second, independent and much harder reason.

`redis/src/server.c:4378`-`4389`, on the unknown-command path:

```c
    *err = sdscatprintf(*err, "unknown command '%.128s'", (char *)c->argv[0]->ptr);

    if (c->argc >= 2) {
        sds args = sdsempty();
        for (int i = 1; i < c->argc && sdslen(args) < 128; i++)
            args = sdscatprintf(args, "'%.*s' ", 128 - (int)sdslen(args), (char *)c->argv[i]->ptr);
        *err = sdscatprintf(*err, ", with args beginning with: %s", args);
        sdsfree(args);
    }
```

The arguments of an unknown command are echoed back to the caller, up to a 128-byte budget, and
the same string is logged. `HELLO 3 AUTH <user> <password>` fits inside that budget comfortably.

Redis does redact the AUTH arguments of `HELLO` — `networking.c:5055`-`5056` calls
`redactClientCommandArgument` on them — but that call is **inside `helloCommand`**, so it runs
only when `HELLO` is a command the server knows. On the unknown path there is no redaction,
because there is no `helloCommand`.

`HELLO` is unknown on Redis before 6.0, on implementations that have not adopted it, on
deployments that rename commands, and — the case that matters operationally — on **proxies**.
Azure Managed Redis returns `ERR unknown command` for commands it disables; Envoy `redis_proxy`
and twemproxy implement a subset.

So the combined form `HELLO <ver> AUTH <user> <pass>` can write an operator's password into a
server log and into svcdoctor's own evidence, at exactly the endpoints an operator is most likely
to be diagnosing.

Three more upstream facts shape the rest of this record:

| Fact | Source |
|---|---|
| `-WRONGPASS invalid username-password pair or user is disabled.` is the **single** reply site for *unknown user*, *wrong password* and *disabled user* | `src/acl.c:1511`; the distinction exists internally at `acl.c:3384`-`3392` as `ENOENT` vs `EINVAL` and is discarded |
| For a `nopass` user, `ACLCheckUserCredentials` returns `C_OK` **before examining the password** | `src/acl.c:1485` |
| The one-argument `AUTH <password>` form **errors** against a `nopass` default user, where the two-argument form returns `+OK` | `src/acl.c:3369`-`3378` |

## 2. Decision

1. **`HELLO` carries zero arguments, always.** No `protover`, no `AUTH`, no `SETNAME`.
2. **A credential may appear in exactly one command: `AUTH`.**
3. **At most one credential-bearing command per run.**
4. **The credential crosses only a channel `security.CredentialTransportPolicy` permits**, which
   today means verified TLS and nothing else.
5. **The operator's `AUTH` form is transmitted verbatim.** `default` is never synthesized.
6. **`AUTH` `+OK` is reported as "the endpoint accepted this credential"**, never as "the
   credential is valid".

## 3. Zero arguments makes the defect impossible, not forbidden

A rule saying "do not put the credential in `HELLO`" is enforced by review. A rule saying
"`HELLO` has no arguments" is enforced by a byte comparison against `*1\r\n$5\r\nHELLO\r\n`.

The second is worth more, and it costs one thing: `SETNAME`. That is decided in ADR 0063 §7 and
is deferred rather than rejected, with the consequence recorded there — reopening `SETNAME`
reopens this enforcement mechanism too, and the invariant would have to be re-expressed as the
weaker "no credential in `HELLO`".

The unknown-`HELLO` echo still happens under this decision. It echoes the literal string
`HELLO`, and nothing else, because there is nothing else.

## 4. The invariant's scope: per run

Three scopes were considered. All three are satisfiable by the frozen journey, and they are not
equivalent in general, so the strictest is frozen and the generalization is recorded:

> **At most one credential-bearing command per run.**
>
> In v1 this coincides with one per explicitly authorized endpoint and one per connection,
> because a run has exactly one authorized endpoint and establishes exactly one authenticated
> connection. When topology arrives, the form that generalizes is **per explicitly authorized
> endpoint**, and per-run remains strictly stronger. Relaxing per-run to per-endpoint requires a
> new record.

Explicitly:

| Question | Answer |
|---|---|
| May a credential appear inside `HELLO`? | **No.** Structurally impossible |
| May a credential be retried? | **No** |
| May a credential be propagated to a discovered node? | **No**, and v1 discovers none — see [ADR 0065](0065-redis-cluster-observed-and-sentinel-detected.md) |
| May a credential be sent after a redirect? | **No.** v1 cannot receive one, and would not follow it |
| May a credential be sent on a re-dial after transport failure? | **No.** There is no re-dial |
| May `RESET` be used to re-authenticate? | **No.** `RESET` is excluded from the allowlist permanently |

One `AUTH` suffices for the whole journey: the connection stays authenticated, and every
subsequent command in the allowlist runs on it. So the strict form costs nothing operationally,
which is why it is the frozen one.

## 5. The `AUTH` form is the operator's, verbatim

If the operator supplied only a password, svcdoctor sends `AUTH <password>`. If they supplied a
username, svcdoctor sends `AUTH <username> <password>`. It never normalizes the first into
`AUTH default <password>`.

The documentation says the one-argument form "assumes the implicit username is `default`", and
that is true of the *authentication target*. It is **not** true of the observable behaviour:
`acl.c:3369`-`3378` makes the one-argument form return

```text
ERR AUTH <password> called without any password configured for the default user.
    Are you sure your configuration is correct?
```

against a `nopass` default user, where `AUTH default <anything>` returns `+OK`.

Normalizing would therefore convert a true configuration finding into a false success. The
operator's input is the thing being diagnosed, and rewriting it destroys the measurement.

### Password bytes

Any bytes within the existing 4 KiB input bound (ADR 0049). Redis hashes the raw bytes
(`ACLHashPassword`); there is no SASLprep and no normalization. **PostgreSQL's printable-ASCII
restriction is a PostgreSQL constraint and must not be generalized to Redis** — it exists because
PostgreSQL applies SASLprep and svcdoctor implements only the range over which SASLprep provably
changes nothing.

### Username

An ordinary flag value. It is not a secret; it is identity, and it is redacted structurally like
any identity value under ADR 0037.

## 6. What each reply is allowed to claim

| Reply | Safe claim | Forbidden claim |
|---|---|---|
| `+OK` | the endpoint accepted this credential | **"the credential is valid"** — `acl.c:1485` accepts every password for a `nopass` user |
| `-WRONGPASS` | the endpoint rejected the presented credential | "wrong password", "no such user", "the user is disabled" — the three are merged upstream by design |
| `-NOAUTH` (first `HELLO`) | this endpoint requires authentication | "the credential is wrong" — none was sent |
| `-NOPERM` (`PING`) | authenticated; this identity is not authorized for this command | "the service failed", "the service is unusable" |
| `-ERR` | only what the surrounding context justifies | anything read out of the message text — see [ADR 0066](0066-redis-error-prefix-classification-and-observed-identity.md) |

### The evidence prefix-only classification would have lost, and where it is recovered

Under ADR 0066 svcdoctor reads no error message text. The `AUTH <password> called without any
password configured` reply carries its meaning entirely in that text, and its prefix is a bare
`ERR`.

That fact is not lost, because the **credential-free first `HELLO` already established it**: an
endpoint that answers `HELLO` with a map rather than `-NOAUTH` requires no authentication. The
journey shape recovers the evidence the classification rule discards. No message-fragment
allowlist is needed and none is authorized.

## 7. Plaintext: `RequireVerifiedTLS` stands, unchanged

`security.CredentialTransportPolicy` has exactly one member, `RequireVerifiedTLS`
(`internal/security/credentialtransport.go`), and `PermitsCredentials` returns false for
`ChannelPlaintext`, `ChannelTLSUnverified` and `ChannelUnknown`. Redis inherits that without an
exception.

Four options were evaluated.

| Option | Verdict |
|---|---|
| **A — plaintext `AUTH` forbidden entirely** | **Frozen.** It is the shipped behaviour of both existing services |
| **B — allowed by default** | Rejected. Silently weakens a guarantee two services depend on |
| **C — refused by default with an explicit per-run acknowledgement** | **Rejected for v1** — see below |
| **D — allowed on loopback or private addresses** | **Rejected outright.** A loopback address proves nothing about the path: `127.0.0.1:6379` is routinely a `kubectl port-forward` into a remote production cluster, and an RFC1918 address is a routing fact rather than a security one. `security.Channel` deliberately has no "private network" member, and adding one would record a fact nobody established. It would also make svcdoctor's security depend on the topology of the network it is diagnosing |

### Why C is rejected here rather than adopted

ADR 0029 §7 states the reopen condition precisely: the override, the second policy member and the
`ReportSecurity` field "arrive together, because each is useless without the others." Two of the
three now exist. The condition is therefore **technically satisfied**, and acting on it inside a
Redis phase would still be wrong:

1. It is a **product-wide** decision. A second policy member applies to Kafka and PostgreSQL the
   instant it exists, so landing it here means a shared security primitive is widened by whichever
   service happened to want it, without cross-service review.
2. A Redis-only exception would be conditional sprawl at a security boundary.
3. It needs its own security review, its own record and its own mutation matrix.

### What v1 therefore does, with the cost stated rather than minimized

| Deployment | Outcome |
|---|---|
| Plaintext, no auth (`nopass`) | **Full journey.** `HELLO` and `PING` both succeed; no credential is involved |
| Plaintext, password required | `HELLO` proves the requirement; `AUTH` and `PING` are **SKIPPED** with `EXEC_SKIPPED_BY_POLICY`, **zero credential bytes written**, and a WARN-level withheld-credential finding. `SummaryStatus` OK, complete, exit 0 |
| TLS verified, password required | **Full journey** |
| TLS with verification disabled | `AUTH` **SKIPPED** — `Channel.IdentityVerified()` is false |

Plaintext-plus-password is a large share of self-hosted Redis, and in that segment v1 cannot
reach its terminal proof. That is Redis inheriting a product-wide policy, not Redis creating a
problem, and it is the strongest available argument for scheduling the transport-opt-in work as
its own phase. It is recorded in `docs/BACKLOG.md` rather than resolved here.

The acknowledgement itself is **not a finding** and there is no CLI concept for it in v1, because
there is nothing to acknowledge.

## 8. The channel, and the mTLS gap

Redis TLS is out-of-band and port-based — `tls-port` listens *in addition to* `port`, and there
is no in-band negotiation. So the generic chain performs the handshake exactly as it does for
Kafka, and **no TLS semantic changes for Redis**. ADRs 0053, 0058, 0059 and 0060 apply unmodified:
trust and peer identity stay distinct, the custom CA replaces the system roots rather than
extending them, the server name is never derived from a resolved address, and the three TLS-only
flags are refused under `--tls disable`.

**Client certificates do not exist in svcdoctor.** `internal/probe/tls.Params` has no such field;
the CLI exposes four TLS flags and none of them is a certificate; and
`FailureTLSClientCertificateRequired` and `FailureTLSClientCertificateRejected` are declared with
no producer and are **banned from production code** by
`internal/diagnosis/transport/boundary_test.go`.

This matters more for Redis than for the existing services, because `tls-auth-clients` defaults
to **yes** (`src/config.c:3514`): a self-hosted Redis with `tls-port` and no explicit
`tls-auth-clients no` demands a client certificate. Redis also has
`tls-auth-clients-user CN`, which authenticates a client *as a Redis user* from its certificate —
a certificate-as-credential path with no analogue in svcdoctor today.

**mTLS is DEFERRED from Redis BASIC v1**, and it is not a stop condition:

- A Redis endpoint demanding a client certificate produces a handshake alert that
  `internal/probe/tls/handshake.go:257` classifies as `TLS_HANDSHAKE_FAILURE`. That is truthful
  and imprecise. Imprecision is not an overclaim.
- The case is **already reachable in production** for Kafka (`ssl.client.auth=required`) and
  PostgreSQL (`clientcert=verify-full`), and both already land there. Redis raises the frequency,
  not the reachability, so ADR 0054's owner-before-producer rule does not fire on this change-set.
- Adding it means a new field on two transport types, two CLI flags, a **new class of secret
  material** (a private key, which is not a `security.Secret` and has no redaction owner), and
  owners for two currently-banned failure classes. That is a generic-transport phase, not a Redis
  one.

## 9. The `Reveal` boundary

Redis adds the **third and only new** production `security.Reveal` call site, in
`internal/adapter/redis/wire`. ADR 0027's confinement is unchanged: `forbidigo` fails the build on
a call site outside a wire package, and the module count moves from 2 to 3 and to nothing else.

`credential.SecretFor(endpoint)` is called with the logical `Host:Port` the operator named, never
with a resolved address. ADR 0028 §2's reasoning transfers without modification: resolution is a
runtime fact that changes, differs per vantage, and can be attacker-influenced.

## 10. Threat model, frozen

| Vector | Invariant |
|---|---|
| Password in `argv` | No `--password` value flag. ADR 0049 unchanged |
| Password in the environment | Not a supported source in v1 |
| Password file / stdin | The only two sources, mutually exclusive, 4 KiB bound |
| **`HELLO` argument echo** | `HELLO` carries zero arguments, asserted on the exact frame bytes |
| Raw server errors | Only an allowlisted, normalized prefix crosses the wire boundary (ADR 0066) |
| Failed `AUTH` in the ACL LOG | Documented, unavoidable, bounded by the one-attempt invariant |
| Retries | Zero |
| Multiple connections | One authenticated connection per run |
| Redirects / discovered endpoints | Unreachable in v1; never credential-bearing (ADR 0065) |
| DNS rebinding | Resolution is never identity authority (ADR 0058); `SecretFor` refuses any endpoint but the named one |
| TLS verification disabled | `PermitsCredentials` is false; `AUTH` is SKIPPED |
| Plaintext | Same |
| mTLS private keys | **No private key material enters svcdoctor in v1** — the strongest available form of this invariant, and a consequence of §8 |
| Peer-controlled `HELLO` metadata | Bounded, charset-validated, redaction-classified, reported as what the endpoint said (ADR 0066) |

> No security property may depend on a renderer hiding something after it has entered the
> canonical report. Every invariant above stops the value at or before the wire-package boundary.

## 11. Rejected alternatives

| Option | Rejected because |
|---|---|
| `HELLO <ver> AUTH <user> <pass>` | §1. The server echoes up to 128 bytes of arguments when `HELLO` is unknown, and its redaction runs only when it is known |
| `AUTH` before any capability probe | Sends the credential to an unprobed endpoint, inverts ADR 0007's layer order, and discards the free "authentication is required" fact — which is also the fact that rescues prefix-only classification (§6) |
| Normalizing a bare password to `AUTH default <password>` | The two forms behave differently against a `nopass` server; normalizing converts a true finding into a false success |
| Reporting `+OK` as "the credential is valid" | `acl.c:1485` accepts every password for a `nopass` user |
| Distinguishing wrong-password from unknown-user | `acl.c:1511` is a single reply site; the distinction is discarded upstream on purpose |
| A second `CredentialTransportPolicy` member for Redis | §7. Product-wide decision, needs its own review, and a service-local exception would be sprawl at a security boundary |
| Loopback or RFC1918 as implicit trust | §7 option D |
| Client certificates in v1 | §8. A generic-transport phase, with a new secret class and two banned failure classes to own |
| Reusing PostgreSQL's printable-ASCII password restriction | It exists for SASLprep, which Redis does not apply |

## 12. Reopen conditions

- **A product-wide unsafe-transport opt-in phase** satisfying ADR 0029 §7 in full — the second
  policy member, the per-run input surface and the report projection, landing together for all
  three services. Recorded in `docs/BACKLOG.md`.
- **A generic mTLS phase**, which would give the two banned TLS client-certificate classes an
  owner, decide the private-key redaction owner, and make §8's deferral moot.
- **Topology arrives for Redis**, at which point the per-run invariant must be argued down to
  per-explicitly-authorized-endpoint in a new record, not silently relaxed.
- **Upstream removes argument echo from unknown-command errors** *and* a validated
  Redis-compatible endpoint is found that requires the combined `HELLO ... AUTH` form. Both
  conditions, not either.
- **A Redis authentication mechanism that is not a single round trip** — a SASL-style or
  token-refresh mechanism — which would test whether "one credential-bearing command" is still
  the right unit.
