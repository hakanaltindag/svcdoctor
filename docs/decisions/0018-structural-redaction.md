# ADR 0018: Structural redaction produces the shareable report

## Status

Accepted.

## Decision

A shareable report is produced by transforming a local one:

```text
LOCAL_FULL Report -> Redact -> SHAREABLE_REDACTED Report
```

The transformation lives in `internal/security/redaction`. It reads an
already-valid report and builds another one through the ordinary domain
constructors. It never mutates its input, creates no findings, changes no
judgement, and performs no I/O.

### Package ownership

`docs/SECURITY.md` gives the security package ownership of redaction, and this is
a subpackage of it rather than part of it.

`internal/security` stays a leaf with no internal dependencies; the subpackage
imports `internal/domain`. Putting the transformation directly in
`internal/security` would have made that package depend on `domain`, which
forecloses the `domain -> security` direction the architecture allows for masked
value types. As separate packages, `redaction -> domain -> security` is a chain,
not a cycle.

The report holds no `security.Secret` and no `security.Credential`, so this
package needs nothing from `internal/security` and never calls `security.Reveal`.

### Preserve correlation, remove identity

Replacing every identifier with a fixed marker would make a shareable report
useless: a reader could no longer see that one host appears in the target, in
three evidence subjects and in a finding. Each distinct value therefore maps to
one stable pseudonym everywhere it occurs:

```text
kafka.prod.internal -> host-001
10.20.30.40         -> ip-001
```

Ports are preserved. Knowing a check targeted 9092 says which protocol was
expected, not who was running it.

### Deterministic assignment

Values are collected first, sorted, then numbered. Numbering on first encounter
would tie a pseudonym to traversal order, so adding a rule or reordering a graph
walk would silently renumber an existing report.

Pseudonyms are per-report. Nothing persists between transformations, and the same
host may receive a different pseudonym in a different report. That is deliberate:
a stable cross-report pseudonym would let someone correlate two reports shared
from one environment.

Plain numbering was chosen over hashing. An unsalted hash is a stable identifier
across reports and re-introduces exactly that correlation; a salted hash destroys
byte stability unless the salt is stored, which is machinery this needs no part
of. `host-001` is also simply easier to read.

### Evidence identifiers are rewritten

The evidence identifier grammar accepts any printable text, and the identifiers
this project uses embed endpoints:

```text
target/ep:broker-2.internal:9092/dns
```

An identifier is therefore not safe to share, and pseudonymizing the subject
while leaving the hostname inside the identifier would leak it.

Identifiers are remapped to opaque `evidence-001` values, assigned in sorted
order of the originals. Every reference is rewritten with them: node identity,
parent edges, blocked-by references and finding evidence references. The
rebuilt report passes the ADR 0014 membership check like any other, which is what
proves no reference was missed.

Structurally rewriting the identity portion of a path was rejected. It would
require parsing an identifier whose format the domain deliberately leaves opaque,
and a parser that is wrong for one future scheme leaks a hostname. Losing the
human-readable path is the cost; the graph relationships carry the same
information.

### Prose

Finding summaries, details, discriminators and recommendation actions are free
text that can repeat identifiers from evidence.

Every value the report was found to contain structurally is replaced inside prose
by exact substitution, longest value first so a longer value is never partly
rewritten by a shorter one it contains. The sentence keeps its shape, which is
what keeps a shareable report readable.

Blanket-replacing prose was rejected: a shareable report with no summaries is not
worth sharing, and the requirement is to preserve usefulness while removing
identity.

### Attributes

Only string-shaped attribute values are touched. An integer, boolean, duration or
timestamp cannot carry identity, which the closed `AttrValue` union makes
checkable rather than assumed, so `dns.latency` and `dns.answers` pass through
untouched.

A string value is replaced when it matches a known identifying value, parses as an
IP address, or parses as a `host:port` reference whose host is known. These are
structural tests, not pattern matching, so `NOERROR` and `TLSv1.3` survive intact.

**Known limit.** An attribute whose value carries identity in some other shape,
and which appears nowhere else in the report, is preserved. The evidence model has
no per-key sensitivity classification. Adding one is tied to the open question of
where service attribute keys live, and that decision is not closed here. The gap
is recorded in `docs/BACKLOG.md` and `docs/SECURITY.md`.

### Regex is a safety net, not the mechanism

Redaction transforms domain values before serialization. No regex is used, and the
package is forbidden from importing `regexp`.

After rebuilding, the finished report is re-encoded and scanned for the exact
values the transformation knew to be identifying. That check cannot raise a false
alarm and cannot be satisfied by output that merely looks clean. It exists so a
field added later without a matching transformation fails loudly rather than
shipping an identifier.

### Idempotence

A report that is already `SHAREABLE_REDACTED` is returned unchanged.

That makes `Redact` idempotent in the ordinary sense, so calling it defensively is
safe, and it removes any possibility of `host-001` becoming `host-002`. Rejecting
an already-redacted report was considered and rejected: returning it unchanged is
the correct answer to the question, not an error.

### Metadata is derived

The shareable report reports how many distinct values were replaced, by category.
The counts come from the transformation, and they are absent entirely on a local
report, where a zero would read as "nothing sensitive was present" rather than
"nothing was removed".

Counts are of distinct values rather than occurrences. "Two hostnames were
removed" is what a reader can act on, and an occurrence count would describe how
often each host appeared, which is structural information about the environment.

The mode stays honest at the type level: the ordinary constructor still refuses to
produce `SHAREABLE_REDACTED`, and the derivation used here requires a real
`LOCAL_FULL` value to derive from.

### Fail closed

There is no partial result. Any failure returns no report at all, because a caller
holding a half-transformed report would share it. Error messages never name the
value they were protecting.

## Consequences

- A shareable report is a valid report: same invariants, same schema, re-derived
  summary.
- Diagnostic content is unchanged. Layers, states, failure classes, steps, graph
  topology, finding codes, judgements, timings and summary figures all survive.
- The transformation is deterministic and independent of insertion order, so the
  same content always produces the same bytes.
- Redaction cannot be bypassed by adding a report field without a matching
  transformation: the residual scan fails the transformation instead.
