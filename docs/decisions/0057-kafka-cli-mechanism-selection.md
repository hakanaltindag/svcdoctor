# ADR 0057: the operator names one Kafka SASL mechanism, and svcdoctor never picks one

## Status

**Accepted.** Implemented in Phase 6.4C, in the same change-set that exposes
`svcdoctor diagnose kafka`.

It fixes how a Kafka run learns which SASL mechanism to propose, and it is a
security decision rather than a UX one: the mechanism decides the framing the
operator's password travels in.

## Problem

`app.KafkaParams.Mechanism` is a required string, and nothing in the repository
says where it comes from. Phase 6.1c introduced it with the protocol reason
recorded on the field — the Kafka protocol has no *"list your mechanisms"*
request, so a client proposes one and the broker's answer carries the list — and
deliberately left the operator-facing question open, because no CLI existed.

Phase 6.4C exposes the command. The question has to be answered first, because
three of the available answers are ways to send a credential the operator did not
choose to send:

- default to `PLAIN`, and an operator who supplies a password file and forgets
  the flag authenticates with RFC 4616 framing against any broker that offers it
- probe the broker's mechanism list first, then pick one, which makes svcdoctor
  choose whose framing carries the secret
- try one and fall back to another, which spends a second attempt against
  whatever counts them and is a second step towards lockout in a
  directory-backed deployment

## External facts

- **A SASL mechanism name is a public protocol parameter.** RFC 4422 §3.1 fixes
  the grammar as 1–20 characters from `A-Z`, `0-9`, `-` and `_` — uppercase, with
  no lowercase form defined — and the names are drawn from an IANA registry.
- **A `SaslHandshakeRequest` carries a mechanism name and nothing else.** No
  identity, no password, no token. Proposing one costs the broker a request and
  **not** an authentication attempt (ADR 0026).
- **A broker's `SaslHandshakeResponse` carries its full mechanism list** whether
  or not it accepted the proposal, so one handshake answers *"what does this
  listener offer"* without any credential existing in the run.

## Decision

### 1. `--sasl-mechanism` is required, and has no default

Not `PLAIN`, not "whatever the broker offers first", not inferred from the
credential's shape, and not inferred from the port.

A default would be a silent decision about how the operator's password is
framed, taken by the tool, on the run where the operator was already distracted
enough to forget the flag. It is the same reasoning ADR 0049 used to refuse a
literal `--password`, and the same reasoning `--user` uses to refuse a fallback
to the operating-system user: the value that identifies or authorizes has to be
stated.

A credential-free run needs it too. The handshake runs on every completed path
whether or not a secret exists, and its answer is one of the more useful things
a Kafka BASIC run produces.

### 2. Exactly one mechanism, presented at most once

The CLI passes one value. There is no list, no comma-separated set, no ordering
and no second flag.

**No auto-probe.** svcdoctor does not read the broker's mechanism list and then
decide. The list is recorded as evidence and reported; it never becomes an input
to this run.

**No fallback in either direction.** Not PLAIN after SCRAM, not SCRAM after
PLAIN, not a retry of the same mechanism. ADR 0028 already fixed the cardinality
at the composition root — one credential-bearing attempt, no loop, no second
candidate in scope — and this record adds no way to reach it twice from the
command line.

### 3. Names are taken verbatim, in uppercase, and are never folded

`--sasl-mechanism plain` is refused with a usage error naming `PLAIN`. It is not
silently uppercased.

Folding at the CLI would be harmless on its own, and it would put a second,
looser matching rule beside the one that actually gates the credential:
`internal/adapter/kafka`'s `supportedMechanism` is an exact-match whitelist with
no folding, chosen so that a mechanism svcdoctor cannot perform can never be
mistaken for one it can (Phase 6.1a). Two matching rules that disagree is how
that guard fails quietly. Refusing teaches the operator the registry spelling and
costs one re-run.

### 4. The CLI does not restrict the value to the two svcdoctor can perform

`PLAIN` and `SCRAM-SHA-256` are what the adapter can carry out. Any other
well-formed name is accepted by the command and proposed to the broker.

This is deliberate, and it is the one place where accepting more is safer than
accepting less. Naming a mechanism sends no secret. What comes back is either
*"this listener does not offer it"* — `KAFKA_AUTH_MECHANISM_NOT_OFFERED` — or
*"it does, and svcdoctor cannot perform it"* — `UNKNOWN` +
`AUTH_MECHANISM_UNSUPPORTED` + `KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR`,
at exit 0, with **zero `SecretFor`, zero `Reveal` and zero bytes written**.

Refusing `GSSAPI` at the command line would remove the only way to ask *"what
does this broker want, and can this tool do it?"*, which is a question an
operator diagnosing a failed connection genuinely has. Answering it truthfully is
what svcdoctor is for.

### 5. `--user` is required with a credential source, and refused without one

Kafka's identity travels only inside the SASL exchange. A run with no credential
sends no identity at all, so `--user` without `--password-file` or
`--password-stdin` would be a flag with no effect — and a flag that is silently
ignored is worse than one that is refused, because the operator believes it did
something.

Both directions are usage errors:

```text
--password-file without --user   the credential has no identity to authenticate as
--user without a password source  --user has no effect without a credential source
```

PostgreSQL differs and correctly so: its role travels in the `StartupMessage`,
which every run sends, so `--user` is unconditionally required there.

## Rejected alternatives

| Alternative | Why rejected | Reopen condition |
|---|---|---|
| Default to `PLAIN` | A silent decision about the framing that carries the password | Never |
| Default to `SCRAM-SHA-256` | Safer framing, same defect: the tool chose | Never |
| Probe the mechanism list, then pick | Makes svcdoctor choose whose framing carries the secret, from peer-supplied data | Never |
| Try SCRAM, fall back to PLAIN | A second credential-bearing attempt; a second step towards lockout | Never |
| Infer from the credential's shape | A password does not know its mechanism; the inference is fiction | Never |
| Infer from the port | ADR 0011 refuses to infer a service from a port; this is the same mistake one layer down | Never |
| Accept a comma-separated list | The only honest way to use it is to try several, which §2 forbids | An accepted multi-attempt authentication model exists |
| Fold case at the CLI | A second, looser matching rule beside the guard that gates the credential | Never |
| Restrict to `PLAIN` and `SCRAM-SHA-256` | Removes the only way to ask what a broker offers, and the refusal path is already truthful and free | Never |
| Reuse `--tls-*` style `--kafka-` prefixes | The flag set is per command already; a prefix adds noise | Never |

## Consequences

- One new flag, `--sasl-mechanism`, on `svcdoctor diagnose kafka` only.
- Maximum credential-bearing authentication attempts per run stays **1**.
- `security.Reveal` production call sites stay **2**.
- No new finding code, no new failure class, no schema change, no dependency.
- A mistyped mechanism is a usage error when the case is wrong and a truthful
  `INFO` at exit 0 when the name is well-formed and unsupported. Neither sends a
  byte derived from the secret.

## Reopen conditions

- svcdoctor gains a mechanism whose selection genuinely depends on a broker's
  answer — channel binding, for instance, where `SCRAM-SHA-256-PLUS` is only
  usable when the channel supports it.
- An accepted decision authorizes more than one credential-bearing attempt.
- A managed provider requires a mechanism name outside RFC 4422's grammar.
