# ADR 0027: security.Reveal is confined to adapter wire packages, mechanically

## Status

Accepted.

## Decision

`security.Reveal` — the single function that turns a masked `Secret` into
plaintext — may be called **only from a service adapter's wire package**:

```text
internal/adapter/<service>/wire/
```

The confinement is enforced by `forbidigo` in `.golangci.yml`, which fails the
build rather than a review. Two supporting `depguard` rules deny
`internal/security` outright to the layers that must never hold secret material
at all: diagnosis, renderers and platform collectors.

Phase 3.2 adds **zero** call sites. The guard lands before the first credential
byte, not after it.

## Context

Phase 1 built `Reveal` as a deliberate escape hatch and documented the rules for
using it: call it as late as possible, never store the result, obtain the
`Secret` through `Credential.SecretFor` so the endpoint binding is checked first.
It also recorded, in `docs/BACKLOG.md`, that nothing enforced *where* it may be
called, and named the condition to revisit that: **"Kafka wire packages exist, in
Phase 3."**

They now exist, and Phase 3.2 is the phase in which SASL made a future caller
concrete. That is the reopening condition, met.

The reason to act now rather than when the first credential is actually sent is
ordering. A guard added after the first `Reveal` call has to be argued against
working code, in the phase where the author has the most reason to want an
exception. A guard added before it is just the shape of the code.

## Observed evidence

- There are currently **zero** call sites outside `internal/security` and its own
  tests. Confinement costs nothing today and constrains only future code.
- `internal/adapter/kafka/wire` already has the properties that make it the right
  home: it is the only package that touches the protocol library, it holds no
  state between exchanges, it never closes or owns a connection, and everything
  it returns upward is plain values. `docs/SECURITY.md` said so in Phase 3.1,
  before there was anything to confine.
- The Phase 3.2 handshake needs no reveal at all, which is what made it possible
  to install the rule and verify it against a deliberate violation rather than
  against real credential code.

## Why depguard cannot express this

The obvious mechanism is the one already used for every other boundary here: deny
the import. It does not work.

`Reveal` is reachable by any package that imports `internal/security`. But an
adapter **must** import `internal/security` to hold a `security.Credential` and
to call `SecretFor`, which is the endpoint-binding check that makes credential
use auditable in the first place. Denying the import to adapters would ban the
safety check along with the escape hatch, and the natural workaround — passing a
bare string down from somewhere else — is strictly worse than what the rule was
meant to prevent.

So the boundary is not "which package may import secrets" but "which package may
turn one into bytes", and only a call-level rule can say that.

`forbidigo` matches the call expression `security.Reveal`, with a path exclusion
for `internal/adapter/[^/]+/wire/`. Verified empirically both ways: the same file
is rejected in `internal/adapter/kafka` and accepted in
`internal/adapter/kafka/wire`.

## Amendment, Phase 3.2b decision pass: the guard failed open on one line

Re-verifying this boundary before authentication was designed found a real hole,
which is recorded here rather than quietly fixed.

golangci-lint deduplicates issues **by line** by default. A `security.Reveal`
call that shared a line with any other reported issue therefore lost the race and
its message never appeared. It was reproduced with a one-line function, where
`unused` was reported first and the forbidigo finding vanished:

```go
func wouldSendCredential(s security.Secret) string { return security.Reveal(s) }
// unused: reported.  forbidigo: silently dropped.
```

A guard that holds except when it does not is the failure mode this record exists
to prevent, so `issues.uniq-by-line` is now `false`. The tree still reports zero
issues, so nothing was traded for it, and the same deliberate violation is now
caught whichever way it is written.

The lesson generalizes past this rule: a security lint has to be verified against
the shape an author would actually write, not only against the shape that is
convenient to test.

## What this does and does not guarantee

**It does** guarantee that plaintext extraction happens in a package that is one
function call away from the socket, that has no report model in scope, and whose
entire surface is reviewed as a protocol boundary.

**It does not** guarantee that a revealed value stays there. A wire package can
still put plaintext into an error, and Go cannot erase a string from memory —
`internal/security/doc.go` has said so since Phase 1, and this ADR does not
weaken that statement. What the rule buys is that the number of places where such
a mistake is *possible* is one per service, and that adding a new one requires
editing a lint configuration with this record attached to it.

The complementary guards are unchanged and still carry their share: `Secret`
masks every fmt, JSON and text path; `Credential` has no plain accessor;
canonical evidence is a closed union of normalized values with no field a secret
could occupy; and the `test/security` leak matrices assert exact canary absence
rather than masked-looking output.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Leave it to review and the greppable call form | The Phase 1 note was already that, and it is exactly the "developers must remember" contract this repository refuses elsewhere | Never |
| depguard-deny `internal/security` to all adapters | Bans `Credential.SecretFor` with it, and pushes callers towards passing bare strings | Never |
| A capability token — an unexported type only wire can mint | Real, but it needs a type, a constructor, a threading path and a story for tests, to enforce something one lint rule already enforces exactly. Speculative machinery of the kind ADR 0002 forbids | The lint proves insufficient in practice, for example if a wire package legitimately grows sub-packages |
| Make `Reveal` return `[]byte` and document zeroization | Go cannot guarantee erasure; a `Zero` method would imply a guarantee that does not hold, which Phase 1 rejected for the same reason | Never, absent a language-level guarantee |
| Wait until the first credential is actually sent | The guard would then have to be argued against working code, in the phase least willing to hear it | Never |
| Confine to `internal/adapter/**` rather than the wire subpackage | The adapter is where connections, evidence and the graph builder are in scope; the wire package is where none of them are | Never |

## Consequences

- A `security.Reveal` call outside a wire package fails `make check` and CI, with
  a message naming this record.
- Diagnosis, renderers and platform collectors cannot import `internal/security`
  at all, which is a stronger statement than they had before and costs them
  nothing: none of them has a legitimate use for a secret type.
- PostgreSQL inherits the boundary for free, because the exclusion is written
  against `internal/adapter/*/wire/` rather than against Kafka.
- Adding a second reveal site is a visible, reviewable configuration change
  rather than a line of code in a large diff.

## Reopen condition

If a legitimate caller appears that cannot live in a wire package — a mechanism
whose credential computation genuinely cannot be expressed at the framing layer,
for instance an external token exchange — this record is reopened rather than the
exclusion quietly widened. The alternative that would then be on the table is the
capability token rejected above, which becomes justified exactly when the number
of legitimate sites stops being "one per service".
