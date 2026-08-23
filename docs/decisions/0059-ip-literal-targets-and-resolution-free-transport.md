# ADR 0059: An address is not a name, so a run that was given one resolves nothing and says so

## Status

**Accepted and implemented in Phase 6.7.**

Unlike ADR 0058, which ratified behaviour that already existed, this one changed
production Go in seven packages: `internal/probe`, `internal/probe/transport`,
`internal/diagnosis/transport`, `internal/diagnosis/kafka`, `internal/app`,
`internal/render/terminal` and `internal/cli`.

It supersedes nothing. It closes the standing *IP literal target semantics*
backlog item and the Phase 6.5 documentation guard that held `--host` to names
while the question was open. It does **not** close ADR 0058 §14's three product
gaps, which Phase 6.7 measured and found to be one coupled defect; see §14.

`SchemaVersion` stays `1`.

## Context

PostgreSQL and Kafka must accept literal IPv4 and IPv6 targets as first-class
input. Operators diagnose by address routinely — a broker that only advertises an
IP, a database behind a load-balancer VIP, a Kubernetes Service address, a host
with no DNS entry at all.

They already could. That was the problem.

Measured against the shipped binary before this phase:

```text
$ svcdoctor diagnose kafka --host 127.0.0.1 --port 1 --sasl-mechanism PLAIN --tls disable

  ✓ PASS  DNS  78µs                     ← nothing was resolved
  ...
  ✗ ERROR  TCP_CONNECTION_NOT_ESTABLISHED  127.0.0.1:1
    Every address the hostname resolved to was tried and none accepted a connection.
                     ^^^^^^^^ there was no hostname
```

and in the canonical JSON:

```json
{ "id": "dns.lookup/127.0.0.1", "layer": "L1", "step": "dns.lookup", "state": "PASS",
  "attributes": { "dns.answers": { "kind": "hostList", "value": ["127.0.0.1"] } },
  "duration": "4.958µs" }
```

`net.Resolver` returns a literal unchanged, so the chain recorded a **passing L1
measurement, with a duration, of an operation that never happened**, and a
downstream rule read it as the denominator of a claim about resolution.

Two further defects were measured in the same pass and are fixed here:

- **A non-canonical spelling produced two endpoints in one report.** `--host
  2001:0db8:0:0:0:0:0:1` yielded an anchor reading `[2001:0db8:0:0:0:0:0:1]:1`
  and a connection subject reading `[2001:db8::1]:1` — two spellings of one
  address, inside a single evidence identifier.
- **An IPv6 zone identifier was silently dropped.** `--host fe80::1%lo0` named
  `[fe80::1%lo0]:1` and measured `[fe80::1]:1`, because Go's resolver strips the
  zone from a literal it is handed. svcdoctor reported one endpoint and measured
  another.

ADR 0058 §6 had already settled the TLS half by measurement against the standard
library: an IP literal verifies against a certificate's IP SANs with no flag, Go
sends no SNI for one, and `--host <address> --tls-server-name <name>` connects by
address and verifies the name. **TLS was never what blocked this.** What remained
was DNS, graph shape, canonicalization, rendering, redaction and completeness.

## Decision

### 1. What a host is, decided once, in `internal/probe`

`probe.ParseHost` is the single classification. `netip.ParseAddr` is the whole
detection rule, and anything it rejects is a name.

`net/netip` was chosen over `net.ParseIP` because it yields a canonical *value*
rather than a byte slice: `netip.Addr.String` emits dotted decimal for IPv4 and
the RFC 5952 form for IPv6, so the function that detected the address is also the
function that canonicalizes it and the two cannot drift. It is also the type the
DNS probe, the TCP probe and `security.Endpoint` already speak, so one literal
keeps one representation from input to socket.

The rule lives in `internal/probe` rather than in each caller because three
layers need the same answer — input normalization mints the requested target from
it, the transport chain decides whether to resolve, and the credential binding
key is built from the same spelling. Three implementations of "is this an IP"
produce the two-endpoint report quoted above.

**Diagnosis has no access to it and needs none.** `depguard` denies
`internal/diagnosis` both `net` and `internal/probe`, which is a forcing function
rather than an obstacle: a rule must answer "did resolution happen here?"
structurally, and the structural answer is the truthful one.

### 2. Canonicalization

- IPv4: dotted decimal.
- IPv6: the RFC 5952 form `netip.Addr.String` produces. `2001:0db8:0:0:0:0:0:1`,
  `2001:DB8::1` and `2001:0db8::0001` all become `2001:db8::1`.
- **IPv4-mapped IPv6 is unmapped**: `::ffff:192.0.2.1` becomes `192.0.2.1`. It is
  the same peer, it is the rule the DNS probe already applies to resolver
  answers, and keeping the mapped form would render an IPv4 address inside IPv6
  brackets.
- A **name is returned verbatim**. Lowercasing, trailing-dot removal and IDNA
  conversion each change the question the resolver is asked, and evidence must
  record the question actually asked. Only a literal has a canonical form this
  layer may impose, because for a literal there is no question to change.

Canonicalization happens at **L0, in `internal/app`, before validation**, and in
the CLI before the credential is constructed. Both call the same function, so the
requested-target anchor, the report envelope's target, the endpoint every
transport node is scoped by and the credential binding key are built from one
string and have no opportunity to disagree.

`security.Endpoint` is deliberately **unchanged**. It is the credential-binding
key, it canonicalizes literals of its own accord, and it now only ever receives
an already-canonical host from svcdoctor's own CLI. Teaching it to unmap would
merge two spellings into one credential key — a widening of authority, in the
package where widening is least acceptable.

### 3. Scoped IPv6 is refused, and the refusal is the decision

`fe80::1%en0` parses. svcdoctor declines it, with an invocation error naming the
limitation and exit code 2.

The zone is a vantage-local interface name, and four layers would each have to
carry it truthfully: the evidence subject, the credential binding key, the TLS
identity presented for verification, and the pseudonym namespace a shareable
report puts it in. None of those has a decision recorded, and inventing four at
once inside a phase about address literals is how a half-supported form ships.

It is refused rather than left alone because leaving it alone was measured and is
worse: before this rule, svcdoctor named one endpoint and measured another.

**Deferred, not rejected.** Reopen when there is a use case that needs it and a
decision for each of the four representations above.

### 4. The graph shape: MODEL A — no node for an operation that did not happen

```text
a name                              an address
  target.requested                    target.requested
    └── dns.lookup                      └── tcp.connect
          └── tcp.connect                     └── tls.handshake
                └── tls.handshake
```

A literal sweep records **no L1 node at all**. The connection attempts derive
directly from whatever caused the sweep.

`dns.lookup` names an operation, and every state it can carry describes how that
operation went: PASS says it answered, FAIL says it did not, SKIPPED says
something stopped it being attempted. **None of them means "there was nothing to
attempt."** Absence does, exactly, and it needs no new state, no new step and no
new attribute.

#### Rejected alternatives

**Model B — keep `dns.lookup` with a new state or attribute meaning "resolution
not required".** Rejected. The node *is* the claim: an L1 node in the graph says
an L1 operation was performed, and every consumer that walks the graph
structurally would read it that way. It would also need either a new `State` or a
new `FailureClass`, both of which are serialized vocabulary, for the sole purpose
of preserving a tree shape nothing requires. Graph-shape convenience is not a
reason to record work that did not occur.

**Model C — a new L1 step such as `address.literal` or `target.address`.**
Rejected. It buys nothing the L0 anchor does not already state: the anchor
records the requested target, and for a literal the target *is* the address. It
would cost a new entry in the step vocabulary, in the renderer's label table, and
in every ownership walk in two diagnosis packages — all to represent "no
measurement happened" as a measurement.

**Model D — resolve the literal anyway and mark the node.** Rejected outright. It
costs a round trip, and the resolver can return something other than what the
operator typed, which is how the zone came to be dropped.

#### What Model A costs, and why it is the right cost

Four consumers had to learn a second shape: requested-target sweep collection,
Kafka advertised sweep collection, the Kafka completeness predicate, and the
terminal renderer's advertisement collection. Each already walked the graph
structurally, so each learned it by adding one branch on a step or a layer the
producer had written — none needed a host string, an identifier parse or a
service switch.

That is the shape of the cost this repository is willing to pay: a rule that has
to be told about a new graph shape is a rule that is reading the graph.

### 5. Ownership: owner before producer, in one change

ADR 0054 is a hard gate, and this phase made two FAIL-producing stages reachable
in a new shape. Both were measured unowned in the intermediate state — a literal
TCP refusal produced `findings none` and `status OK` — and both owners landed in
the same change as the producer.

- **DNS.** No owner is needed, because no producer exists. The claim is
  unreachable for a literal by two independent mechanisms: `collectSweep` records
  no lookup, and the rule's own `FAIL`-only check cannot be satisfied by a zero
  `Evidence`, whose `State` is `UNKNOWN`. Suppression by hostname heuristic,
  identifier parsing or renderer hiding was never considered and does not exist.
- **TCP.** `transport.TCP` no longer requires a lookup. When a name was resolved
  the lookup is the denominator and is cited; when an address was supplied the
  set is closed by the input itself and the connection nodes beneath the anchor
  are exhaustively what was attempted. The aggregation rule is otherwise
  unchanged, in both shapes.
- **Generic TLS.** `transport.TLS` needed no change at all. Its ownership
  predicate is "a handshake directly under a connection under this anchor", a
  sentence that never mentioned DNS. Collection learned the shape; the rule
  inherited it.
- **Kafka advertised endpoints.** `collectSweep` in `internal/diagnosis/kafka`
  reads a `LayerTCP` root as a resolution-free sweep and produces the same
  reachability verdict, the same causal owner and the same evidence references as
  a resolved name.

A **mixed shape** — a lookup *and* a direct connection under one anchor or one
advertisement — is refused in all four consumers rather than partially read. An
endpoint is either a name or an address, never both, and a rule that reads half
of an unrecognized shape eventually publishes the half it guessed.

### 6. `firstBrokenLayer` is unchanged, because layer is data

A literal TCP failure is **L2**; a literal TLS failure is **L3**. Nothing had to
be done to achieve this: `Layer` is a field the producer sets on the node, not a
function of tree depth, so removing a node above the connection cannot promote
it. Pinned by test in both directions.

### 7. TLS identity

Wholly ADR 0058, restated for the literal case and pinned here:

| requested target | connect to | verify | SNI |
|---|---|---|---|
| `broker.internal` | each resolved address | `broker.internal` | `broker.internal` |
| `10.20.30.40` | `10.20.30.40` | `10.20.30.40`, against IP SANs | none |
| `10.20.30.40` + `--tls-server-name kafka.internal` | `10.20.30.40` | `kafka.internal` | `kafka.internal` |

The identity a bare address verifies is the **bare literal, never the bracketed
endpoint form**: `[2001:db8::1]` is a rendering of a host and a port together, and
sending it as a server name would ask for an identity no certificate can carry
and turn every IPv6 literal run into a verification failure that looks like the
peer's fault.

A DNS SAN does not satisfy a raw address, and verification is **never relaxed**
for one — that mutation survived the first pass of the matrix and is now closed
by a real handshake against a DNS-only certificate.

`--tls-server-name` does not propagate to Kafka advertised brokers. ADR 0058
already said so; nothing here changes it.

### 8. Kafka advertised literals

A cluster that advertises `10.20.30.41:9093` gets a first-class advertised
endpoint: TCP, then TLS if the plan required one, counted in the topology line
like any other, with `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` available and
truthful — and no sentence saying a hostname did not resolve.

**Credential authority is unchanged and unchangeable.** `MeasureAdvertised` takes
a graph builder, a list of advertisements and a transport plan; none of them can
hold a credential, a secret, an identity, a mechanism or a session. An advertised
literal receives zero `SecretFor` calls, zero `Reveal` calls and zero SASL bytes,
for the same structural reason a named one does (ADR 0050).

Reading "no lookup" as "not measured" would have counted every reachable literal
broker as unmeasured and made the topology line understate a working cluster.
`not measured` and `not reached` remain distinct (ADR 0052), and a literal
advertisement the budget cut short is still `not measured`.

### 9. Endpoint formatting

`net.JoinHostPort` everywhere a host and a port are joined, which was already
true and is now pinned: `10.20.30.41:9093`, `[2001:db8::1]:9093`. No double
brackets, no missing brackets, no `strings.Split(":")`.

`internal/security` and `internal/security/redaction` keep their own bracketing
rules and deliberately do not import `net` — the first because it holds secrets
and must not link the DNS resolver, the second because it needs only the
bracketing rule. Both are pinned by test against `net.SplitHostPort`.

### 10. Redaction

**No new code was needed, and that was verified rather than assumed.** The
pseudonym table already routed a value through `netip.ParseAddr` into a separate
`ip-NNN` namespace, and `endpointParts` already handled brackets and ports.

What this phase added is the proof: canaries `10.88.77.66` and
`2001:db8:feed:beef::42` are shown present in the local report and absent from the
shareable one, one literal keeps one pseudonym across every node, two literals do
not collapse, an IPv6 pseudonym leaves no stray bracket and keeps its port, and
the counts land in `ipAddress` rather than `hostname`. Four mutations against the
redaction path — skipping addresses, skipping IPv6 only, bypassing bracketed
refs, and a naive colon split — are all caught.

### 11. Schema

`SchemaVersion` stays `1`, and the versioning policy in `docs/REPORT_SCHEMA.md` §1
is why: no field was removed and no existing field changed meaning. The evidence
graph's step vocabulary is open by contract, and a graph that contains one fewer
node instance is not a schema change — a report has never guaranteed that any
particular step is present.

The canonical JSON of a literal run contains no `dns.lookup` node, no
`dns.answers` attribute and no `L1` layer. It invents no `"resolved": [...]`.

### 12. Completeness

Both predicates were audited. PostgreSQL's never mentioned DNS. Kafka's did, and
now reads both shapes.

ADR 0051's asymmetry is intact for literals: a measured literal advertisement —
reached, refused, or rejected at TLS — settles, and an unmeasured one leaves the
run incomplete. The Phase 6.7 mutation matrix found a real defect here that the
implementation had introduced and the tests then caught: the lookup branch
ignored a stray sibling connection, partially reading a mixed shape. It now
returns unresolved, because unrecognized must always err towards "the run is not
finished".

### 13. What did not change

No new `FindingCode` (40, unchanged). No new `FailureClass` (41, unchanged). No
new `State`, `Step` or `Layer`. No new dependency. `SchemaVersion` 1. Two
production `security.Reveal` call sites. One credential-bearing Kafka
authentication attempt per run. SCRAM untouched. PostgreSQL BASIC's product
invariants untouched.

The generic TCP finding gained a **second detail string, not a second code**. The
claim is identical — no measured connection completed — and `docs/FINDINGS.md`
§3.1 item 11 makes "the first move differs" the test for splitting a code. It does
not: an operator checks the same listener either way.

### 14. ADR 0058 §14's three gaps: one coupled defect, deferred together

Phase 6.7 was asked to decide whether the insecure-mode terminal gap must be
fixed here, on the theory that IP literals increase the chance of
`--tls-insecure` being used as a workaround. It was measured, and the three gaps
turned out to be one defect with one fix order:

1. **PostgreSQL accepts `--tls-insecure` alongside `--tls disable`**, where Kafka
   refuses the pair with a usage error. This is the cause.
2. **So a plaintext PostgreSQL run reports `tlsVerificationDisabled: true`** — a
   TLS fact about a run with no TLS. Measured, still reproducible.
3. **So the terminal cannot yet safely surface that fact.** Adding the row today
   would print a TLS security warning on plaintext runs, making gap 2 visible to
   every operator. That is worse than the gap it fixes.

**All three are deferred to the pre-release gate, as one item, in that order.**
Fixing gap 1 is a released-CLI behaviour change on a path that has nothing to do
with address literals, and this phase's own stop conditions forbid making it
here. All three are pinned by test exactly as they stand, so none can drift
without a decision.

The mitigation that *is* in scope, and is now documented: an operator hitting an
address whose certificate carries a name does not need `--tls-insecure` at all.
`--tls-server-name` names the identity explicitly and keeps verification on.

## Consequences

**Good.** A literal target is first-class and truthful in both services and both
families. No report claims resolution that did not happen. One address has one
spelling, so an operator's typing cannot split one endpoint into two. Four
consumers now read graph shape rather than assuming it, which is a smaller
assumption than the one they held. The Phase 6.5 documentation guard inverted
cleanly: it kept its shape and changed sides.

**Costs.** Two graph shapes exist where there was one, and every future consumer
of a requested-target or advertised sweep must handle both. The mixed shape is
refused in four places rather than one, which is duplication in exchange for each
consumer failing safe on its own terms. A zoned IPv6 literal that used to
"work" — wrongly — is now an invocation error.

**Unresolved.** Scoped IPv6 (§3). ADR 0058's three coupled gaps (§14).
Managed-service compatibility is untouched and remains separate: this phase
implemented no provider-specific behaviour and makes no compatibility claim,
though first-class address support is a prerequisite for private MSK bootstrap
endpoints, internal Redpanda, Kubernetes Service and load-balancer addresses,
split-horizon DNS and private PostgreSQL deployments — none of which is validated
here.

## Reopen conditions

- A use case needs scoped IPv6, and each of §3's four representations has a
  decision.
- A producer legitimately emits a mixed name-and-address sweep, which would make
  four consumers' refusal wrong rather than safe.
- A second literal-like host form appears — a UNIX socket path, a service
  discovery URI — at which point `probe.Host` becomes a three-way classification
  and the "either a name or an address" premise behind the mixed-shape refusal
  has to be re-derived.
- The report schema gains a way to state "this stage was not applicable", which
  would make Model B expressible without a false claim and is worth re-testing
  Model A against.
