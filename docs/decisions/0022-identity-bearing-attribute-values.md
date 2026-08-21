# ADR 0022: A producer declares which attribute values carry identity

## Status

Accepted.

## Decision

`domain.AttrValue` gains two kinds to the closed union:

```go
domain.HostAttr("broker.internal")                 // AttrKindHost
domain.HostListAttr("broker.internal", "alt.internal")  // AttrKindHostList
```

A **host value** is anything that identifies a network peer: a DNS name, an IP
literal or a `host:port` reference. A producer records identity through these
constructors, and structural redaction replaces every such value with a stable
pseudonym — whatever it looks like, and wherever it appears.

Redaction keeps its existing opportunistic check on plain strings, which
recognizes a value that parses as an IP address or a `host:port` reference. That
is now a **safety net for a producer that forgot to declare**, not the mechanism.

One identity per value or per list entry. Redaction replaces whole values, so two
names joined into one string would survive together.

## Context

ADR 0018 recorded a known limit: an attribute value carrying identity in a shape
the transformation cannot recognize structurally, appearing nowhere else in the
report, is preserved. Phase 2.1 and 2.2 never hit it — DNS records addresses,
which parse, and TCP records no attributes at all.

Phase 2.3 hit it immediately and unavoidably. A TLS handshake observes the names
on the peer's certificate, and a certificate name is a **bare hostname**. Worse,
the interesting case is precisely the one where that name appears nowhere else in
the report: a hostname mismatch means the certificate carries names the run never
asked for. The first `test/security` run leaked `broker-canary.tls.internal` and
`alt-canary.tls.internal` into a report labelled `SHAREABLE_REDACTED`.

So the choice was not theoretical: either TLS records no certificate names —
losing the fact that makes a mismatch actionable — or the model learns to carry
identity honestly.

## Why the type and not a heuristic

The obvious alternative is to teach redaction to recognize hostnames by shape.
It cannot be done safely:

```text
broker.internal    identity
TLS1.3             not identity
alt-canary.test    identity
0x0399             not identity
```

Any rule that catches the first and third also catches the second, or misses the
third. A redactor that guessed would either leak a hostname or destroy the
negotiated version — and the version is exactly what a shared report is for.

The producer, on the other hand, *knows*. The DNS probe knows its answers are
addresses; the TLS probe knows a certificate's SANs are names and its cipher
suite is not. Recording that knowledge in the value's type moves the question
from "can this be recognized?" to "was this declared?", which is decidable.

This is the same argument that made the union closed in the first place: ADR 0010
excluded `map[string]any` so that what evidence can hold is a structural property
rather than a convention. Identity is now structural in the same way.

## Why not per-key sensitivity

`docs/BACKLOG.md` framed the eventual fix as per-key sensitivity classification,
tied to the open question of where service attribute keys live. That framing was
wrong in one respect, and this record supersedes it on that point.

Per-key classification needs a table mapping keys to sensitivity, and both the
producer and the redactor must agree on it. Redaction cannot import a probe —
depguard forbids it — so the table would have to live in `internal/domain`, which
would make it exactly the central registry of service attribute keys the
architecture rejects: every new service would edit shared core code to declare
its own keys.

Per-**value** classification needs no table at all. The declaration travels with
the value, so no package has to know another package's keys.

**This does not settle where attribute keys live.** Keys stay with their
producers, `dns.answers` and `tls.server_name` included. What changed is that
redaction no longer needs to know them, which removes redaction from that open
question entirely. Diagnosis's inability to import probe key constants is
untouched and still open.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Teach redaction to recognize hostnames by shape | Cannot separate "broker.internal" from "TLS1.3"; would leak identity or destroy diagnostic values | Never; the ambiguity is inherent |
| A per-key sensitivity table in `internal/domain` | Becomes the central registry of service keys the architecture rejects, and every service would edit core code | Never in that form |
| Record no certificate names | Removes the fact that makes a hostname mismatch actionable, which is one of the main reasons to run a TLS check | Never |
| A `Sensitive bool` field on every attribute | Same information as a kind, but optional, so forgetting it is silent — and the zero value would be "not sensitive", which fails open | Never; fail-closed matters more here |
| Encoding identity in the key name, e.g. a `_host` suffix | A naming convention no compiler checks, and a typo would silently leak | Never |
| Redact every string attribute | Destroys versions, cipher suites, states and every other diagnostic value; a shareable report would say nothing | Never |

## Consequences

- A shareable report no longer preserves a declared identity, whatever its shape
  and wherever it appears. ADR 0018's known limit now applies only to identity a
  producer recorded as a plain string and that appears nowhere else.
- The wire format gains two kind tags, `host` and `hostList`. The change is
  additive for readers that switch on the tag; `dns.answers` moved from
  `stringList` to `hostList`, which is a semantic clarification of a field
  nothing consumes yet.
- A producer that records identity as a plain string is still caught by the
  opportunistic check when the value is an address or has a port, and is still
  missed when it is a bare name. That is a mistake a review should catch, and
  `test/security` is where it becomes visible.
- Adding an identity-bearing attribute is now a decision a producer makes
  explicitly, in one line, at the point where the fact is known.
