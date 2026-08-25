# ADR 0068: RabbitMQ authentication is one PLAIN frame, and its authority is the endpoint

## Status

**Accepted in Phase 8.1. Not implemented.**

It decides which mechanism svcdoctor selects, how many credential-bearing frames a run
may send, which endpoint authorizes the credential, and over which channels a credential
may cross. It changes no existing credential rule for Kafka, PostgreSQL or Redis, and it
weakens none.

`SchemaVersion` stays **1**. No `FailureClass`, no `FindingCode`, no dependency.

Companion records: [0067](0067-rabbitmq-basic-journey-and-terminal-boundary.md) is the
journey this sits inside, [0069](0069-rabbitmq-vhost-authorization-and-close-normalization.md)
decides how a refusal is classified.

It applies ADR 0028's credential contract and ADR 0029's channel-security rule to a
third service, and ADR 0049's credential input unchanged.

## 1. Decision summary

1. **SASL PLAIN only.** `AMQPLAIN`, `EXTERNAL` and `ANONYMOUS` are observed and never
   selected.
2. **`authentication_failure_close` is mandatory** in svcdoctor's client-properties.
3. **At most one credential-bearing frame per run**, and the protocol makes that exact
   rather than aspirational.
4. **Credential authority is the operator-named `host:port`**, never the vhost.
5. **A password crosses only a channel whose peer identity was verified.** No plaintext
   opt-in, no loopback exception, no private-address exception, no `--tls-insecure`
   exception.
6. **A malformed PLAIN response must be structurally impossible**, not merely avoided.

## 2. PLAIN only

`Connection.Start` carries the offered mechanism list, so mechanism discovery and
mechanism selection are one credential-free round trip. This is strictly better than
Kafka, where discovery needs its own request.

| Mechanism | Decision | Reason |
|---|---|---|
| **PLAIN** | **selected** | one frame, no challenge, universally offered, byte-testable |
| `AMQPLAIN` | never selected | it encodes the credential inside an AMQP field table, which means a second serializer on the credential path — for zero diagnostic gain. Every RabbitMQ and LavinMQ build measured in Phase 8.0C that offered `AMQPLAIN` also offered `PLAIN`. |
| `EXTERNAL` | never selected | requires a plugin the operator may not have, requires client-certificate transport svcdoctor does not have, and takes its identity from a certificate rather than from a credential. Deferred, not rejected. |
| `ANONYMOUS` | **never selected; presence recorded** | selecting it would authenticate svcdoctor as RabbitMQ's `anonymous_login_user` — `guest` by default — without the operator asking. That is synthesizing a credential, and it would sometimes *work*, which is worse. |

**Mechanism ordering is ignored.** The AMQP specification says the server lists
mechanisms in decreasing preference, and Phase 8.0C measured that the order is not even
stable across RabbitMQ releases with identical configuration: 3.13.7 offered
`AMQPLAIN PLAIN`, 4.0.9 offered `ANONYMOUS AMQPLAIN PLAIN`, and 4.2.0 offered
`PLAIN AMQPLAIN ANONYMOUS`. Selecting by preference would let an untrusted peer steer
svcdoctor's choice; selection is by name.

**There is no fallback ladder**, and the reason is not that a second attempt would cost
a connection — mechanism choice happens before any credential is sent, so it would not.
It is ADR 0063 §6.3's reason: a fallback ladder is the mechanism by which an
incompatibility gets hidden. With no ladder, *"svcdoctor silently downgraded my
authentication"* is not a bug that can be written.

### 2.1 When PLAIN is not offered

The run stops with `UNKNOWN`, failure class `AUTH_MECHANISM_NOT_OFFERED`, and **zero
credential bytes sent**. It is not a FAIL: the broker is behaving correctly and
svcdoctor is the limited party.

Claimable: *this endpoint offers `<list>`; svcdoctor implements PLAIN only.*
Not claimable: anything about whether the credential is valid.

## 3. `authentication_failure_close` is a precondition, not a courtesy

svcdoctor's `Connection.Start-Ok` client-properties **must** contain
`capabilities → authentication_failure_close: bool true`.

Phase 8.0C measured both branches, on RabbitMQ 3.13.7 and 4.2.0:

| Client-properties | What the client observes |
|---|---|
| capability advertised | `Connection.Close`, `reply_code` **403**, `class_id`/`method_id` **0/0**, `reply_text` **108 bytes**: `ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN. For details see the broker logfile.` — byte-identical on both versions |
| capability absent | **no AMQP frame whatsoever**; the socket is closed after about three seconds |

Without it, *"the credential was refused"* and *"the peer closed the connection"* are
the same observation, and svcdoctor would have to report the weaker of the two on every
failed login. This one table entry is the difference between a diagnosis and a shrug.

LavinMQ 2.3.0 gates on the same capability name, which is corroboration rather than
coincidence.

**svcdoctor advertises nothing else in `capabilities`.** In particular not
`connection.blocked`: it changes broker behaviour on a running connection, and BASIC has
no running connection.

## 4. What a 403 may be said to mean

`AUTH_CREDENTIALS_REJECTED`, and nothing narrower. **svcdoctor never says "wrong
password."**

RabbitMQ's internal backend returns the identical refusal for an unknown user and a bad
password, and equalises the timing deliberately to prevent username enumeration. Phase
8.0C measured that an unknown user and a wrong password produce **byte-identical**
`Connection.Close` frames.

The same 403 is also what a user refused by a host-based restriction receives. So four
conditions share one wire response:

- the password is wrong
- the user does not exist
- the user exists and is refused from this source address
- an authentication backend refused for a reason it did not disclose

This is exactly the boundary `FailureAuthCredentialsRejected` already documents: *"It
does not state that the secret was wrong, that the principal does not exist, that an
account is disabled or locked, or that the peer's own authentication backend was working
when it answered."*

### 4.1 The `guest` case gets a sentence, not a finding

RabbitMQ ships `loopback_users = [guest]`, under which `guest` is refused from any
non-loopback source. It is plausibly the most common RabbitMQ connection question, and
Phase 8.0A proposed a `HYPOTHESIS` finding for it.

**Phase 8.0B rejected it and this record follows that, for a categorical reason rather
than a precision one.** RabbitMQ evaluates the restriction against *the broker's view of
the client's source address*. svcdoctor can only observe *its own destination address*.
Those are different ends of the connection, and the two disagree in both directions in
common topologies — a port-forward makes a remote broker look like loopback to the
client while the broker sees a remote source, and an SSH tunnel does the reverse.

So the finding is dropped. What survives is a detail sentence on the existing
`RABBITMQ_CREDENTIALS_REJECTED` finding:

- **always**: RabbitMQ returns an identical refusal for an unknown user, an invalid
  password and a user refused by a host-based restriction, and does not tell the client
  which applies; the broker's own log records the reason.
- **only when the configured username is exactly `guest`**: RabbitMQ ships with `guest`
  in its `loopback_users` list, so `guest` is refused from any non-loopback source under
  default configuration — and svcdoctor cannot see which source address this broker
  observed, so it cannot tell whether that policy applied here.

The second sentence is gated on the username and on **nothing else**. It must not be
gated on any address observation, because that is the observation svcdoctor does not
have. It states a documented default and disclaims applicability to this run, so it is
not a diagnosis.

## 5. Exactly one credential-bearing frame

PLAIN is single-shot: `Connection.Start-Ok.response` carries `\0username\0password` and
RabbitMQ never challenges it. So the invariant is *exact* rather than aspirational, and
it is easier to hold than PostgreSQL SCRAM's two credential-derived messages.

> **Credentials are transmitted at most once per run, in exactly one
> `Connection.Start-Ok` frame, on one connection, to the operator-named endpoint. There
> is no reconnect, no redial and no second attempt for any reason.**

Three consequences are part of the decision:

1. **If `Connection.Secure` arrives after svcdoctor's `Start-Ok`, svcdoctor does not
   answer it.** It records `PROTOCOL_UNEXPECTED_RESPONSE`, closes, and never sends the
   credential again. This is unreachable against RabbitMQ's PLAIN, which is why it must
   be written down rather than assumed.
2. **A peer close after a credential was sent is never retried.** That is the state in
   which a retry is most dangerous and least informative.
3. **A refusal is not a reason to try a different mechanism.** §2.

## 6. Credential authority is the endpoint, and the protocol forces it

Authentication happens in frame 2. The vhost is named in frame 5. By the time svcdoctor
learns whether the vhost exists or is permitted, the password has already been
transmitted.

**Therefore `host:port + vhost` is not merely undesirable as an authority tuple; it is
unimplementable.** A vhost-scoped authority would have to gate a transmission that has
already happened.

The corollary is the shape ADR 0069 builds on: **vhost authorization is a separate
resource-authorization step that consumes an already-established identity.** Same
endpoint, same credential, different vhost yields a different outcome at
`rabbitmq.connection_open` and never at `rabbitmq.authentication`. The graph carries the
distinction structurally, so no wording has to.

`security.Credential.SecretFor` is called with the operator-named endpoint and nothing
else, exactly as the three existing adapters call it.

## 7. Transport policy: verified TLS or no credential

A password crosses only a channel whose peer identity was verified. **A plaintext
connection and a connection with `--tls-insecure` are both refused, and neither a
loopback nor a private address changes that.**

This is not a new rule and it is not softened for RabbitMQ. It is the sentence
`svcdoctor diagnose redis --help` already prints, and `internal/cli` already has a test
asserting that `--allow-plaintext-credential`, `--credential-policy any` and
`--insecure-credential` do not exist. Adding an escape hatch for RabbitMQ would weaken an
existing credential-authority rule.

Plaintext AMQP on a private network is genuinely the common RabbitMQ deployment, so the
cost is real and is accepted with one mitigation that is part of this decision:
**a refused run must still be useful.** Because mechanism discovery is credential-free,
a policy refusal still delivers DNS, TCP, the TLS state, the peer's product and version,
the full advertised mechanism list and the Tune parameters. The report says: *this
endpoint speaks AMQP 0-9-1, is `<product> <version>`, offers `<mechanisms>`, and
svcdoctor refused to put a password on an unverified channel.* That is an answer, not a
dead end.

The outcome is `SKIPPED` + `EXEC_SKIPPED_BY_POLICY` with **zero bytes sent**, mirroring
`KAFKA_CREDENTIAL_WITHHELD` and `POSTGRES_CREDENTIAL_WITHHELD` exactly.

A `--tls-insecure` run is additionally refused because the identity of the peer that
would receive the password was never established — the distinction ADR 0058 draws
between trust and identity, unchanged.

## 8. The PLAIN encoder is security-critical, and the reason was read out of the source

`rabbit_auth_mechanism_plain:handle_response/2` formats **the entire SASL response** —
password included — into an error when it cannot parse it:

```erlang
        error ->
            {protocol_error, "response ~tp invalid", [Response]}
```

Phase 8.0C established the blast radius. That path produces `502 SYNTAX_ERROR`, which at
the `starting` state takes RabbitMQ's silent-close branch, so **the bytes are not sent
back to the client**. They do reach the broker log and the `user_authentication_failure`
event. Phase 8.0C measured **zero** occurrences of either the real or a deliberately
wrong password in any broker log across four brokers, because a well-formed response
never takes that branch.

The consequence is a requirement on svcdoctor, not a defence against RabbitMQ:

> **The PLAIN response is exactly `0x00 || username || 0x00 || password`, with no other
> byte, and the frame must be pinned by a byte-literal test.**

An off-by-one that appends a trailing NUL writes the operator's password into the
target's log file. This is the RabbitMQ analogue of the Redis `HELLO` credential echo,
and it gets ADR 0063 §7's treatment: a literal comparison in a test, so a mutation fails
on comparison rather than on a reviewer's attention.

`security.Reveal` is called at exactly one site in the RabbitMQ wire package, matching
the one-per-service pattern the three existing adapters hold.

## 9. Client-properties are a fixed literal

svcdoctor's `Connection.Start-Ok` client-properties are exactly `product`, `version`,
`platform` and `capabilities: {authentication_failure_close: true}`. Nothing derived
from the target, nothing derived from the environment, nothing operator-supplied.

Two reasons. It keeps the only variable bytes in the frame confined to the credential,
which is what makes §8's byte-literal test possible. And LavinMQ 2.3.0 **silently drops**
a `Connection.Start-Ok` above 4096 bytes — measured — so a client-properties table that
grew with its inputs would be a compatibility cliff nobody would find. svcdoctor's
measured `Start-Ok` is 165–202 bytes.

No local cap is imposed on the frame. Inventing a limit for a peer svcdoctor may not be
talking to would be worse than recording LavinMQ's as a compatibility note.

## 10. Reopen conditions

1. **`EXTERNAL` and client certificates.** Two separate decisions. Presenting a client
   certificate is generic TLS work owned by ADR 0053/0058, not RabbitMQ work; naming a
   broker's *demand* for one requires `TLS_CLIENT_CERTIFICATE_REQUIRED` — which exists in
   `internal/domain` today with **no production producer** — to acquire a producer and an
   owner under ADR 0054 first.
2. **A second credential-bearing attempt.** Would need a threat model this record does
   not have.
3. **`ANONYMOUS` becoming a finding.** An endpoint advertising it lets any remote client
   attempt a `guest` login. That is a hardening judgement about configuration, and BASIC
   diagnoses reachability rather than posture. Reopen with a stated posture contract.
