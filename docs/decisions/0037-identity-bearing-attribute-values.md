# ADR 0037: A principal or named resource is identity, and redaction must pseudonymize it

## Status

Accepted, and **implemented in Phase 4.1**, before any PostgreSQL evidence node exists.

Implementation notes, appended after the fact and changing no decision above:

- `AttrKindIdentity` is appended to the kind enumeration, so no existing kind is renumbered
  and no existing tag renamed. `TestExistingAttrKindTagsAreUnchanged` pins that.
- The empty-value question §1 did not reach is settled by the precedent `HostAttr("")` had
  already set: the value is representable, redaction collects nothing from it, and no
  pseudonym is manufactured. Inventing one would report a removal that did not happen.
- Pseudonym namespaces are **separate**, matching the existing host and IP namespaces. One
  raw value declared as both a host and an identity receives one pseudonym in each.
- Propagation is **global once declared**, inherited rather than chosen: an ordinary string
  attribute equal to a collected hostname was already rewritten before this phase, and
  identity joins that rule. The peer categories are checked first, so no rewrite that
  happened before Phase 4.1 changed.
- The residual scan gained the identity namespace and was **not** otherwise altered. Identity
  inherits the substring ambiguity the host namespace already has — a role named `PASS` or
  `host-001` fails closed, exactly as a hostname with that text does at HEAD — and no special
  case was added for it.
- `schemaVersion` stays `1`. Adding `redactions.identity` is additive under
  `docs/REPORT_SCHEMA.md` section 1, and a `LOCAL_FULL` report carries no `redactions` object
  at all, so every local report serializes byte-identically before and after.

Refines ADR 0022, which introduced declared identity for network peers. This adds the
second identity category and closes a gap ADR 0030 predicted by name.

## Problem

PostgreSQL cannot produce a single useful evidence node without recording a role name and a
database name. `internal/security/redaction` has no safe way to carry either.

The mechanism today, established by ADR 0022, is that a producer *declares* an
identity-bearing value by its kind:

```go
domain.HostAttr("db.internal")        // AttrKindHost     -> host-001
domain.HostListAttr("a", "b")         // AttrKindHostList -> host-001, host-002
```

A role name is not a network peer. Recording `HostAttr("payments-svc")` would be false —
the value does not identify a host — and it would render in a shareable report as
`host-004`, actively misleading a reader into looking for a machine. The opportunistic
safety net does not help either: it recognizes a value only when it parses as an IP address
or a `host:port` reference, and a bare role name is the same shape as a version string. ADR
0022 already established why no heuristic can separate those.

So the choices for a role name today are: record it and leak it, or do not record it. Both
are wrong. Not recording it means a report cannot say which role or which database a
finding is about; recording it means a report labelled `SHAREABLE_REDACTED` publishes the
tenant, service and dataset names of the environment it came from.

The repository predicted this precisely. ADR 0030's reopen conditions already name **"an
identity-bearing attribute kind for principals"** as one of the five things that would
extend it, and `domain.RedactionCounts` documents the absence in its own comment:

> There is no separate identity or username category. Schema v1 has no structural carrier
> for a username: the report holds no credential, and a username can only reach it inside an
> attribute value or a prose field, where it is counted under those categories.

That was true and safe while no producer recorded one. PostgreSQL is the producer that
makes it false.

## Decision

`domain.AttrValue` gains one kind and one constructor:

```go
domain.IdentityAttr("payments-svc")   // AttrKindIdentity -> identity-001
```

**An identity value is one that names a principal, a tenant, or a named resource whose
disclosure identifies the environment, and that is not a network peer.** A role, a user, a
database, a schema, a namespace, a service account, a topic, a cluster name.

Structural redaction assigns it a stable pseudonym in the same way it already does for
hosts: all values are collected, sorted, then numbered, so numbering never depends on
traversal order. `identity-001` appears everywhere the original did, including inside prose,
so correlation survives and identity does not.

`domain.RedactionCounts` gains an `Identity` field, and the comment quoted above is
replaced by the carrier it says does not exist. That is a report schema change and is
recorded as one.

### 1. One kind, not two

A role and a database are different categories of thing, and the obvious alternative is two
kinds — `PrincipalAttr` and `ResourceAttr` — so a reader can tell them apart after
redaction.

Rejected, because **the attribute key already says which**, and the key survives redaction
untouched:

```json
"postgres.role":     { "kind": "identity", "value": "identity-001" },
"postgres.database": { "kind": "identity", "value": "identity-002" }
```

A reader learns that one is a role and one is a database from the keys, and learns nothing
about *which* role or *which* database from the values. That is exactly the split redaction
exists to produce. A second kind would add a second thing for a producer to get wrong while
adding no information a reader does not already have.

The same argument applies to the `Identity` count: it counts distinct values, and the
reader who needs to know what kind of thing was removed reads the keys.

### 2. Why the kind and not a per-key sensitivity table

The same argument ADR 0022 made, unchanged and still decisive. A table mapping attribute
keys to sensitivity would have to live in `internal/domain`, because redaction cannot
import a probe or an adapter, which would make it the central registry of service attribute
keys `docs/ARCHITECTURE.md` refuses — every new service editing shared core code to declare
its own keys.

Per-value classification needs no table. The declaration travels with the value.

### 3. The declaration is the producer's, and forgetting fails open

This is the honest weakness and it is unchanged from ADR 0022. A producer that records a
role as `StringAttr` leaks it, and no compiler catches that. The safety net recognizes
addresses and `host:port` references, and a bare name is neither.

What limits the damage is where the mistake becomes visible: `test/security` runs a real
report through redaction with canary values and asserts that none survives. Phase 4 adds
canaries for a role name and a database name to that suite, which is the same place the
TLS certificate-name leak was caught in Phase 2.3.

A `Sensitive bool` on every attribute was rejected by ADR 0022 for a reason that still
holds: it is optional, so forgetting it is silent, and its zero value would be "not
sensitive", which fails open in the worst direction.

### 4. What is still not covered

**Free text in `Target.Requested()`.** A PostgreSQL connection string carries the role and
the database inside one string, and `Target` is a plain string that redaction rewrites only
where it recognizes a collected value. This change helps, and does not fully solve it: once
the role and database are collected as identity values from evidence, prose replacement
rewrites them inside the target too — but only if the same evidence recorded them. A target
naming a database that no evidence node mentions is still preserved.

The real fix is at L0: whatever normalizes a connection string hands `Target` a form with
the credential already removed, and should hand it a form with the role and database
declared separately rather than embedded. That belongs to the phase that builds input
normalization and is recorded in `docs/BACKLOG.md`, not solved here.

**Identity that arrives only inside a server's prose.** A message from the peer can name a
value the report has never otherwise seen — including svcdoctor's own source address as the
server observed it, which
`docs/validation/POSTGRES_PHASE4_PROTOCOL_STUDY.md` §4.2 records happening in a real
`ErrorResponse`. Collect-and-replace cannot catch what it never collected. ADR 0036 §6
handles this by refusing to store server prose at all, which is the only reliable answer
and is a producer-side rule rather than a redaction capability.

## Consequences

- `internal/domain` gains `AttrKindIdentity`, `IdentityAttr` and the `identity` wire tag.
  The change is additive for a reader that switches on the tag.
- `domain.RedactionCounts` gains `Identity int`, and `docs/REPORT_SCHEMA.md` records it.
  This is the first schema field added since v1 and is deliberately not a silent one.
- `internal/security/redaction` collects, pseudonymizes and prose-replaces identity values.
  The prose table is already built from every pseudonymized category, so identity joins it
  with no structural change.
- `test/security` gains role and database canaries.
- The known limit ADR 0018 recorded and ADR 0022 narrowed narrows again: what remains is
  identity a producer recorded as a plain string, in a shape that is neither an address nor
  a `host:port` reference, and that appears nowhere else in the report.
- ADR 0030's reopen condition "an identity-bearing attribute kind for principals" is met.
- No existing producer changes. Kafka records no principal today: `security.Credential`
  holds the identity and the report holds no credential.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Record roles and databases as `HostAttr` | False — the value is not a network peer — and renders as `host-00N`, sending a reader to look for a machine | Never |
| Record them as `StringAttr` and rely on the safety net | A bare name is the same shape as a version string; ADR 0022 established that no heuristic separates them | Never |
| Do not record them at all | A finding could not say which role or which database it is about, which is most of the diagnostic value | Never |
| Two kinds, principal and resource | The attribute key already distinguishes them and survives redaction; a second kind adds a way to be wrong and no information | A category needs a genuinely different transformation, not a different label |
| A per-key sensitivity table in `internal/domain` | Becomes the central registry of service attribute keys the architecture rejects | Never in that form |
| A `Sensitive bool` on every attribute | Optional, so forgetting is silent, and the zero value fails open | Never |
| Redact every string attribute | Destroys versions, SQLSTATEs, cipher suites and states; a shareable report would say nothing | Never |
| Leave it to the PostgreSQL adapter to decide | Redaction is a core guarantee, not a per-service convention | Never |

## Reopen conditions

- **A category that needs a different transformation rather than a different label** — one
  that must be truncated, bucketed or hashed rather than replaced by a counter — reopens
  §1's single-kind decision.
- **A producer that leaks an identity through a plain string in a real report** reopens §3
  and would be evidence that declaration-by-producer is not enough on its own.
- **L0 input normalization** reopens §4's target question, in the layer that owns it.
