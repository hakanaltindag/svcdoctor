# Security

Security is an architecture invariant, not a feature to bolt on later.

## Mandatory requirements

1. Bare CLI secret flags are not considered safe. Design stdin, askpass, strict-permission file, or secret-reference inputs.
2. Resolved runtime secret references are never written to disk.
3. Secrets use typed wrappers whose string/debug/JSON representations remain masked.
4. Structural redaction happens before serialization. Regex/token detection is a secondary safety net.
5. Local/full and shareable/redacted outputs are separate concepts; shareable reports are safe by default.
6. `--insecure` is explicit, per-run, warned about, and recorded in output.
7. The system trust store is the default; the trust source used is recorded.
8. Credentials are bound to the intended endpoint. Do not automatically forward credentials to topology-discovered hosts.
9. Do not use SSH agent forwarding or silently copy cloud/Kubernetes tokens.
10. Release design includes signing, SBOM, provenance, and telemetry-off-by-default expectations.
11. Panic/debug paths must not dump secrets or argv; release hardening must account for core-dump exposure.

## Credential binding and topology discovery

Credentials are endpoint-bound. Credentials resolved for the original target are not
automatically forwarded to endpoints discovered through topology discovery.

Default policy for discovered endpoints:

```text
deny
```

Initial verification of a discovered endpoint uses credential-free checks:

- DNS
- TCP
- TLS
- protocol capability discovery where safe

This is sufficient for the primary topology finding class, because proving that an
advertised endpoint is unreachable from the current vantage point does not require
authentication. Authenticated follow-up against discovered endpoints requires an explicit
policy decision and is recorded in the report.

## TLS verification

Full verification against the system trust store is the default, and the trust source used
is recorded in the report.

`--insecure`:

- is an explicit, per-run opt-in
- is warned about on stderr
- is recorded in the report
- is **never** an automatic fallback after a verification failure

### Per-attempt verification, in the evidence

The CLI flag does not exist yet, but the underlying contract does. `internal/probe/tls`
takes verification settings per attempt and records what actually happened on the node:

- `tls.verified` — true only when the handshake completed **and** verification was enabled.
  A handshake with verification disabled proves the channel is encrypted and proves nothing
  about who is on the other end, so the two never read the same.
- `tls.trust_source` — `system` or `custom`; absent when verification was disabled, because
  no trust source was consulted. It never records a filesystem path, which would be identity
  a shareable report cannot redact.

This is not a duplicate of the report's `tlsVerificationDisabled`, which records how the run
was configured. The per-attempt fact has to be on the node because **diagnosis receives only
the evidence graph** (ADR 0017): a rule can never see report security metadata, so a fact
recorded only there would be invisible to the layer that must reason about it.

The probe never retries an unverified handshake after a verified one fails; see ADR 0023.

Automatically retrying with verification disabled would silently turn a safety failure into
a successful-looking result. When disabling verification would produce useful additional
evidence, that belongs in a recommendation for the operator to act on deliberately.

Credentials are not automatically sent over an unverified TLS channel.

## Protocol wire boundaries

A service adapter's wire package is where credentials are written to a socket.
`internal/adapter/kafka/wire` was built for that two phases before it needed to
be: it is the only package that touches the protocol library, it holds no state
between exchanges, and everything it returns upward is plain values that a report
can carry.

As of Phase 3.2c it does write one. The boundary keeps four things out of
evidence: raw protocol objects, buffers, the socket's own error text, and the
broker's SASL error message. Secret handling stays inside that one package rather
than spreading through the adapter.

### Reveal is confined to that boundary, and the compiler says so

As of Phase 3.2 the rule above is a lint rather than an intention (**ADR 0027**):

```text
security.Reveal may be called only from internal/adapter/<service>/wire/
```

`forbidigo` enforces it and `make check` fails otherwise. Two `depguard` rules go
with it: diagnosis, renderers and platform collectors may not import
`internal/security` at all, because none of them has a legitimate use for a secret
type and a platform collector harvesting cloud tokens is already forbidden by item
9 above.

depguard alone could not express the reveal rule. An adapter must import
`internal/security` to hold a `Credential` and call `SecretFor` — the endpoint
check that makes credential use auditable — so denying the import would ban the
safety check along with the escape hatch. The boundary is "which package may turn
a secret into bytes", and that is a call-level rule.

**There are exactly two call sites, one per service:**

| Service | Call site |
|---|---|
| Kafka | `internal/adapter/kafka/wire/saslauthenticate.go`, in `plainAuthBytes` |
| PostgreSQL | `internal/adapter/postgres/wire/scram.go`, in `authenticateSCRAM` |

Two is the number ADR 0027 sized the rule for. A third fails `make check` and CI.

The guard was installed in the phase *before* the first credential byte,
deliberately: a rule added afterwards has to be argued against working code. It
was re-verified against deliberate violations in an adapter package and a probe
package before that byte was written, and both were rejected.

**Two blanket grants were narrowed in Phase 4.4b**, both found by re-verifying the
boundary in every direction rather than only in the two that were expected. The
wire-package exclusion named no message text, so it exempted wire packages from
*every* `forbidigo` rule — including the channel-authority rules ADR 0029 reserves
to `internal/probe/tls`. And the Phase 4.3 plaintext grant to
`internal/adapter/postgres/` was a path prefix, so it also covered the `wire/`
subpackage, which decides nothing about encryption. Neither was exploited; both
are now matched by message text and by a path that stops at the directory.

Re-verified before authentication was designed, and the re-verification found a
hole worth knowing about: golangci-lint deduplicates issues by line, so a
`security.Reveal` call sharing a line with any other finding was silently
dropped. `issues.uniq-by-line` is now `false` and the violation is caught however
it is written. See the amendment in ADR 0027.

### Kafka SASL: what each step sends

`kafka.sasl_handshake` (L5) asks a broker whether it offers a named mechanism. The
request carries **a mechanism name and nothing else** — no identity, no password,
no token — which is a property of the Kafka protocol, not a choice made here. That
is what makes it safe to run on every measured path.

Mechanism names such as `PLAIN` or `SCRAM-SHA-512` are protocol facts drawn from a
public registry. They are neither secrets nor identity, so they are recorded as
ordinary string values and survive redaction intact; a shared report that turned
`PLAIN` into `host-001` would have destroyed the only thing the node is for.

`kafka.sasl_authenticate` (L5) is the step that does send one. What it sends, and
what has to be true first, is the whole of the next section.

### When a credential may be sent

Three statements, kept separate on purpose:

| | |
|---|---|
| **Capability** | The Kafka protocol permits SASL/PLAIN on a plaintext listener |
| **Policy** | svcdoctor sends a password only over a channel whose peer identity was verified. Anything weaker is an explicit, per-run, recorded opt-in — never automatic |
| **Diagnosis** | "This cluster accepts PLAIN without verified TLS" is a finding a rule states, not a sentence an adapter writes |

So, concretely: **not over plaintext TCP, not over TLS with verification
disabled, and yes over verified TLS.** This is the same shape item 6 already fixes
for `--insecure` and that `ForwardingPolicy` already implements for credential
forwarding; it is applied, not invented.

### The connection says what it proved

As of Phase 3.2b the rule above is enforceable rather than merely written
(**ADR 0029**). A live connection carries one fact describing itself:

```text
security.Channel   unknown | plaintext | tls-unverified | tls-verified
```

It travels beside the connection from the handshake that established it, through
the transport chain and both Kafka steps, to the session a future authentication
step would consume:

```text
tls.Result.Channel() -> transport.Continuation.Channel()
                     -> kafka.Session.Channel()
                     -> kafka.HandshakeSession.Channel()
                     -> kafka.AuthenticatedSession.Channel()
```

**Authority follows the observation boundary** (Phase 4.2, amending ADR 0029).
The component that directly performed and observed a fact is the one entitled to
state it; every other layer propagates the value it was given:

| Fact | Authority | Because |
|---|---|---|
| `tls-verified`, `tls-unverified` | `internal/probe/tls` | it performs the handshake |
| `plaintext` | `internal/probe/transport` | it decides to leave the connection in the clear |
| `unknown` | anyone | it is the absence of a claim, and every policy refuses it |

That is narrower than the rule it replaces. The transport chain used to be the
sole authority, and now cannot name a TLS constant at all — it copies
`tls.Result.Channel()` after taking the connection, and has nothing to add. The
correction was forced by PostgreSQL, which negotiates TLS from inside its own
protocol flow (`SSLRequest`, then a handshake on the same socket) and so reaches
the TLS probe without the chain. A protocol reaching the probe directly still gets
an authoritative answer, because authority never depended on the call path.

A failed handshake reports `unknown`, not `tls-unverified`. `Channel` governs what
may be written to a **live** connection, and a rejected certificate produced none;
the diagnostic fact is recorded in the evidence instead.

The policy reads it and nothing else:

```go
var policy security.CredentialTransportPolicy      // zero value: require verified TLS
if !policy.PermitsCredentials(session.Channel()) {
    // nothing is sent, and the channel is why
}
```

Four properties make this worth relying on:

- **The zero value of the channel is `unknown`, not `plaintext`.** A connection
  nobody classified and a connection known to be in the clear are different
  facts. Both are refused; only one is a claim.
- **The zero value of the policy is the strictest one.** A policy never set,
  never parsed or never threaded through a call chain requires verified TLS —
  the same choice `ForwardingPolicy` makes, for the same reason.
- **Every unknown denies**, in both directions: an unclassified channel, an
  undefined channel value and an undefined policy value all return false.
- **The transport ownership path produces the fact; every other layer propagates
  it unchanged and must not manufacture a stronger value.** That is the contract,
  and it is enforced at three levels rather than claimed at one. No package
  outside the one defining a carrier can forge a channel: the fields are
  unexported, there is no setter, and the zero value it *can* construct is
  `unknown`, which is refused. Inside a defining package the type system cannot
  help — a package owns its own fields — so the adapter's constructors copy the
  fact from the object being continued instead of accepting it as a parameter,
  `forbidigo` forbids naming each `security.Channel` constant outside the one
  package authoritative for it, `depguard` denies adapters `crypto/tls` so a
  connection cannot be interrogated to re-derive one, and mutation-checked tests
  fail when a channel is forged or downgraded. See ADR 0029 for what each level
  does and does not guarantee.
- **The graph is never consulted to decide credential safety.** The runtime fact
  travels with the connection; `PermitsCredentials` takes a `Channel` and nothing
  else, so there is no parameter through which a `domain.Graph` could arrive.
  Evidence is the recorded proof a report and a diagnosis rule read afterwards,
  and the two share a source of truth rather than querying one another.

### PostgreSQL negotiates encryption in band, and that changes two things

The PostgreSQL adapter reaches the TLS probe directly rather than through the transport
chain: TCP, then an 8-byte `SSLRequest`, then a handshake on the same socket. Two security
properties follow, both mechanical rather than conventional.

**The adapter authors `plaintext`, and only `plaintext`.** When the run chose no
encryption, this adapter is the component that decided not to ask and knows the socket was
left in the clear, so ADR 0029's amended rule makes it authoritative for that one fact. It
still cannot name a TLS constant — those come only from the probe that handshakes — and it
still cannot call `security.Reveal`. Verified against deliberate violations in every
direction.

**A plaintext channel can finally name the node that proves it.** The negotiation is
recorded whether or not TLS was attempted: `PASS`/`FAIL` when svcdoctor asked, `SKIPPED`
with `EXEC_SKIPPED_BY_POLICY` when the run chose plaintext and did not. Either way there is
a node stating what happened, so a credential refusal in a later phase points at a fact
rather than at nothing. That is the gap ADR 0030 recorded and ADR 0036 promised to close.

### An unauthenticated peer's prose never enters svcdoctor

Two rules, both structural rather than remembered.

**The `SSLRequest` error response is not read.** A server may answer the negotiation with
`E`. At that moment no certificate has been verified and anything able to answer the socket
can produce those bytes, so svcdoctor records that an error-shaped answer arrived and
closes the connection without reading the message (CVE-2024-10977).

**A decoded `ErrorResponse` has no field for prose.** `wire.ErrorFields` holds a SQLSTATE,
a non-localized severity, and whether that severity was present. There is no field for the
message, detail, hint, context, schema, table, column, constraint, or the server's source
file and routine — so a caller cannot leak what it is never handed, and adding one is a
visible change to a struct whose shape is pinned by test. The Phase 4.0 study measured a
real `ErrorResponse` message carrying, in one string, the role, the database and
svcdoctor's own NAT-translated source address as the server saw it; that last value appears
nowhere else in a report, so structural redaction could never have pseudonymized it.

Classification therefore reads **SQLSTATE and protocol position, never text**. A source
scan fails the build if a file that interprets a peer's reply calls `strings.Contains` or
imports `regexp`.

### Nothing is buffered before a TLS handshake

The negotiation byte is read straight from the connection into a local array. No
`bufio.Reader` exists anywhere on that path, so no byte can be read out of the socket and
stranded in a buffer the handshake never sees — which is the CVE-2021-23222 class, and it
is absent structurally rather than detected. A surplus byte that has already arrived is
refused outright, because a server willing to encrypt sends one byte and then waits.

**Encryption is not identity.** A completed handshake with verification disabled
is `tls-unverified`, and it is refused. Encryption to an unidentified peer is
encryption to whoever answered.

The channel is deliberately **not** recorded as evidence. `tls.verified` already
states what a handshake proved, on the node that observed it; a second copy would
be one fact with two representations that can disagree. When a refusal needs to
appear in a report it appears as a `SKIPPED` node with `EXEC_SKIPPED_BY_POLICY`,
which is a different statement from the channel itself.

**There is no unsafe override, and that is deliberate.** An explicit per-run
opt-in needs an input surface, run configuration and a place in the report to be
recorded, and none exists. A weaker policy value added now would be a bypass with
no owner. See ADR 0029 for the condition that reopens it.

**A refusal is recorded, not silent.** When policy forbids the attempt, the
authentication node is `SKIPPED` with `EXEC_SKIPPED_BY_POLICY`, and **zero bytes
reach the peer** — which the tests assert by measuring what the peer's protocol
layer consumed, not by observing that authentication failed. A reader can then
tell "not attempted, by policy" from "not attempted, nobody asked".

The node points at the fact that caused it, when one exists:

| Channel | `blockedBy` |
|---|---|
| `tls-unverified` | the L3 TLS node for this path, whose `tls.verified` is `false` |
| `plaintext` | **none** |
| `unknown` | **none** |

A plaintext channel is recorded because the caller asked for no TLS, so **no node
anywhere in the graph states that TLS is absent**. A refusal there carries no
blocker rather than pointing at the TCP node, which passed and says nothing about
encryption. The identifier travels for the same reason the channel does — declared
by the layer that recorded it, never re-derived — and reports its own absence:

```text
transport.Continuation.ChannelEvidence() (domain.EvidenceID, bool)
  -> kafka.Session -> kafka.HandshakeSession -> kafka.AuthenticatedSession
```

See ADR 0030 section 9.

### One credential, one broker, one call

Authentication is **singular by construction**: the API takes exactly one session,
never a list. Discovery asks every path because it costs the broker nothing; an
authentication attempt is logged, counted and, against a directory-backed store, a
step towards lockout.

A list parameter would have made "authenticate everything" the convenient default
and `sessions[0]` the next one — and `sessions[0]` is IPv4, by canonical address
ordering. Selecting which broker receives a credential is the caller's decision,
and the signature is what makes it impossible for the adapter to make one
accidentally. See ADR 0028.

### Credential authority is name-based, and DNS cannot widen it

`security.Endpoint.Equal` compares normalized names, never resolved addresses, and
this is load-bearing rather than incidental: resolution changes over time, differs
per vantage point, and can be influenced by an attacker.

> A credential is authorized by the logical endpoint the operator named, never by
> an address it resolved to.

One lookup producing five addresses therefore produces five paths that are all the
same authorized endpoint, and no answer in a DNS response ever becomes an
authority of its own. `kafka.Session.Endpoint()` carries that logical name through
the adapter chain unchanged, so the value `SecretFor` will eventually be given is
the one the operator asked about. See ADR 0026 section 9.

Recovering it is mechanical and never touches the resolved address:

```text
HandshakeSession.Endpoint()  "primary.internal:9092"   the name the operator gave
  -> net.SplitHostPort       ("primary.internal", 9092)
  -> security.NewEndpoint    normalized: ASCII case, trailing dot, IPv6 form
  -> credential.SecretFor(endpoint)
```

A mismatch is a **programming error, not a diagnostic result**. It returns an
error, records no evidence and sends nothing — an evidence node saying "the wrong
credential was offered" would be svcdoctor reporting on its own caller.

### The order in which a credential becomes bytes

This is the sequence every credentialed step follows, and each step is a
precondition for the next:

```text
session.Channel()                        what this connection proved
  -> policy.PermitsCredentials(channel)  may a secret cross it at all
  -> security.NewEndpoint(session)       the logical name, never the address
  -> credential.SecretFor(endpoint)      is this credential authorized here
  -> wire.ExchangePLAIN                  the only layer that may reveal
  -> security.Reveal                     one call, immediately before the write
```

PostgreSQL follows the same order with **two mechanism checks in front of it**,
because it has no separate handshake step to settle the mechanism first:

```text
result.AuthMethod() == "sasl"            did the peer ask for a family we do
  -> "SCRAM-SHA-256" is advertised       … and the one mechanism we implement
  -> result.Channel()                    what this connection proved
  -> policy.PermitsCredentials(channel)  may a secret cross it
  -> security.NewEndpoint(result)        the logical name, never the address
  -> credential.SecretFor(endpoint)      is this credential authorized here
  -> wire.AuthenticateSCRAM              the only layer that may reveal
  -> security.Reveal                     first statement inside, then the
                                         printable-ASCII check
```

The mechanism checks come first on purpose. A peer demanding md5 cannot be
authenticated to whatever the channel is, so reporting a policy refusal there
would imply that fixing TLS would help — and putting them first means
`security.Reveal` is never reached, and `SecretFor` never called, for an endpoint
svcdoctor cannot authenticate to at all.

A refused channel never reaches the code that parses an endpoint. A credential
bound elsewhere never reaches the wire package. **Nothing is revealed in either
path, because nothing reaches the only function that can reveal.**

The order is asserted from the outside rather than trusted: for a policy refusal,
an endpoint mismatch, an unclassified channel and an undefined policy value alike,
the tests prove the peer received **zero protocol bytes** after the handshake.

### SASL/PLAIN specifics

The payload is RFC 4616, built inside the wire package immediately before the
write:

```text
authzid NUL authcid NUL passwd
```

The authorization identity is **empty and present** — a leading NUL with nothing
before it, which means "act as the authenticating identity". `security.Credential`
has no authorization identity, and one is not synthesized: overloading `Identity`
to mean both would give one field two meanings. See ADR 0030 section 2.

**No erasure is claimed or performed.** By the time the payload reaches the socket
the protocol library has copied it into the frame it builds, and the string
`Reveal` returns cannot be erased at all. A `Zero` call would imply a guarantee
item 11 explicitly refuses. Lifecycle handling is best-effort; memory exposure is
addressed by process hardening.

### PostgreSQL SCRAM-SHA-256 specifics

Success is a **conjunction**, and neither half alone is enough:

```text
authentication PASS  <=>  server signature verified  AND  AuthenticationOk received
```

A verifying signature followed by an `ErrorResponse` and no `AuthenticationOk` is
a measured sequence, not a hypothetical: it is what a pooler returns for an
unknown database. And nothing in the protocol obliges a peer to prove itself
before sending `AuthenticationOk`, so a client that accepted one without a
verified signature would have proved *itself* to the peer and learned nothing
about the peer. RFC 5802 makes the client's verification a MUST.

**A password must be printable ASCII (`U+0020`–`U+007E`) in this phase.**
PostgreSQL applies SASLprep to passwords on both sides, and a client that skips it
computes a different key — so the server answers `28P01` for a *correct* password.
Measured on PostgreSQL 14.24 and 18.6. Over printable ASCII, SASLprep provably
changes nothing; outside it svcdoctor refuses rather than guessing, as `UNKNOWN` +
`EXEC_UNSUPPORTED_BY_SVCDOCTOR`, with zero bytes sent. That is a truthful
"svcdoctor cannot do this", never a false "PostgreSQL rejected your credential".
svcdoctor implements no SASLprep and adds no Unicode dependency; ADR 0038 §11.3
gates any widening on adopting *and* differentially validating an implementation
against `pg_saslprep`.

**The server chooses the work factor, so svcdoctor bounds it.** PostgreSQL's
`scram_iterations` maximum is 2147483647 — about eight minutes of PBKDF2 — and
libpq imposes no ceiling at all. svcdoctor refuses above 1048576, *before* any
derivation runs, as `UNKNOWN` + `EXEC_UNSUPPORTED_BY_SVCDOCTOR`. Counts below RFC
7677's recommended 4096 are accepted and recorded rather than refused: that is a
weak server configuration worth reporting, not a reason to go blind.

**`08P01` is never read as a credential rejection.** A pooler collapses every
failure into it — pgBouncer's own source says it "used to report SQLSTATE 08P01
(protocol_violation) for all cases", and `disconnect_client()` still substitutes
it whenever no specific code is supplied. Measured against pgBouncer 1.25.2, the
same wrong password arrives in two different protocol positions depending on
whether the pooler had the role's verifier cached, and a *correct* credential
arrives in one of them when the pooler cannot serve the role. No arrangement of
svcdoctor's own protocol state isolates the credential case, so svcdoctor states
the weaker true claim — `PROTOCOL_UNEXPECTED_RESPONSE` — and records the SQLSTATE
and the missing `V` field for a rule to reason over later.
`AUTH_CREDENTIALS_REJECTED` comes only from `28P01`, where PostgreSQL itself
asserted the refusal, or from a SCRAM signature svcdoctor refused.

**MD5, cleartext and SCRAM-SHA-256-PLUS are observed and declined**, each as
`UNKNOWN` + `AUTH_MECHANISM_UNSUPPORTED` with zero bytes sent. There is no
fallback from any of them, on any channel. Cleartext is declined even over
verified TLS: TLS protects against the network, not against the peer, and a
`PasswordMessage` hands the peer the password itself — a different threat model
from the one the transport policy covers.

### The broker's error message never leaves the wire package

`SASLAuthenticateResponse` carries an `ErrorMessage` written by the deployment
rather than by the protocol. In practice it names principals, realms, listeners
and internal hostnames.

It is dropped where it arrives. The value the wire package returns has two
fields — an error code and a session lifetime — so there is **no field an error
message could occupy** and no filtering step anybody can forget. The error code is
the normalized fact. A canary test gives a fake broker a message naming a
principal and an internal host, proves it is really sent, and proves that neither
the message nor any fragment of it reaches evidence, a report, an error, a
`String()` or any `fmt` verb.

**The authenticating identity is not recorded either.** A username is real
deployment identity, and redaction's declared kinds cover hosts and addresses; a
bare principal name is not structurally recognizable, so it would survive into a
shareable report unpseudonymized. Reopen when a rule needs to tell two identities
apart — which needs a declared identity-bearing kind first.

### What happens to the socket

| Outcome | Evidence | Connection |
|---|---|---|
| Authenticated | `PASS` | **kept** — becomes an `AuthenticatedSession` |
| Credentials rejected | `FAIL` | closed |
| Exchange broke, peer closed, malformed | `FAIL` | closed |
| Budget expired or cancelled | `UNKNOWN` | closed |
| Policy refused to send | `SKIPPED` | closed |
| Credential bound elsewhere | none | closed |

**The rows do not all close for the same reason.** The first three are the
protocol's doing: Kafka fails the connection itself after a rejected credential,
a broken exchange leaves a socket whose protocol state nobody knows, and an
expired budget may leave a request in flight and a response unread, so the next
reader would decode the wrong bytes. The criterion there is *does this socket have
a defined next message?*

**The last two are svcdoctor's own decision, and the distinction is worth being
exact about.** Both are caught before any SaslAuthenticate byte is written, so the
broker is still waiting for one and Kafka neither requires nor expects a close.
For a policy refusal the one message the socket accepts is the one the policy
forbids, and the channel cannot change, so nothing usable is discarded. For an
endpoint mismatch a corrected credential *would* be a legal next message on that
same socket:

> Endpoint mismatch occurs before authentication I/O. The connection is not closed
> because Kafka made it unusable; svcdoctor deliberately discards it because
> `Authenticate` is a consuming ownership boundary, and returning the
> pre-authenticated session would complicate ownership and retry semantics — and
> would make trying several credentials against one broker the cheapest thing to
> write. Retrying means re-running the chain, which re-measures what is about to
> be authenticated over. See ADR 0030 §10.


## Discovered endpoints

Metadata is the first step that puts endpoints into a report that nobody typed.
Three properties keep that safe, and none of them is a promise (**ADR 0031**).

**A credential does not follow a discovery.** A credential authorized for
`bootstrap.internal:9093` is not authorized for `broker-2.internal:9093` merely
because the cluster advertised it. "Same cluster" is not credential authority,
and `ForwardingPolicy`'s zero value still denies. The guarantee is structural:
the discovery API has no parameter a credential could occupy, and a discovered
broker exposes neither a credential nor a `security.Endpoint`.

**A discovered endpoint is deliberately not the credential-binding type.** It is
normalized by the same rules `security.Endpoint` uses — ASCII lowercasing, one
trailing dot removed, IP literals canonicalized — and is a plain string. Handing
out a `security.Endpoint` would put forwarding one function call away from a
caller who merely wanted somewhere to connect. Same rules, different type, no
conversion offered.

**Discovery records; reachability measures, credential-free.** The Metadata step
probes nothing it discovers. Phase 3.4 measures the advertised endpoints with the
generic transport chain — DNS, TCP and TLS — which is exactly the credential-free
initial verification the section above requires, and it stops there: no protocol
request, no authentication, no recursion, and no parameter its API could put a
credential into. `reachability.go` does not import `internal/security`, and the
production `security.Reveal` call-site count is unchanged at one (**ADR 0033**).

Authenticated follow-up against a discovered endpoint still requires the explicit
policy decision this document has always demanded, and no layer takes it yet.

**An advertised hostname is declared identity.** It is recorded through the
`host` attribute kind rather than as a plain string, so redaction pseudonymizes
it structurally rather than by guessing (ADR 0022) — and an advertised broker
name is exactly the internal name a shared report must not carry. What survives
redaction is the cluster's shape: node identifiers, the controller relationship,
the counts, and the parent edges. What does not is every name and address.

**No cluster identifier can appear in any report.** svcdoctor sends Metadata v1,
where the field is not on the wire. It is structurally absent rather than
received and filtered, which is a stronger property than a filter and one no
future edit can weaken.

## Report output mode

A report is produced unredacted for local use. The shareable, redacted form is a separate
report produced by transforming a local one, in `internal/security/redaction`.

The mode stays honest at the type level: the ordinary report-security constructor still
refuses to produce `SHAREABLE_REDACTED`, so only a real transformation can label a report
that way, and the redaction counts it carries come from that transformation rather than from
a caller.

### What a shareable report removes

Identity is removed and correlation is preserved. Each distinct value maps to one stable
pseudonym everywhere it appears, so a reader can still see that one host occurs in the
target, in several evidence subjects and in a finding:

```text
kafka.prod.internal -> host-001
10.20.30.40         -> ip-001
```

Covered structurally: the target, the vantage host, evidence and finding subjects, evidence
identifiers, identifying attribute values, and any of those values repeated inside finding
prose. Ports are kept — a port says which protocol was expected, not who was running it.

Pseudonyms are per-report. Two reports shared from the same environment cannot be
correlated through them.

Diagnostic content is untouched: layers, states, failure classes, steps, graph topology,
finding codes, kinds, severities, confidences, timings and the summary figures all survive.

### Known limit

Identity that a producer recorded as a **plain string**, in a shape that is neither an IP
address nor a `host:port` reference, and that appears nowhere else in the report, is
**preserved**.

That limit used to be wider. Until Phase 2.3 it covered every unrecognizable shape, including
the bare hostnames on a certificate, because redaction had to infer identity from shape.
ADR 0022 replaced inference with declaration: a producer records identity through
`domain.HostAttr` or `domain.HostListAttr`, and a declared value is always replaced.
ADR 0037 extended the same mechanism to `domain.IdentityAttr` for identity that is not a
network peer. What remains is a producer forgetting to declare — a mistake code review and
the contract tests below are there to catch, rather than a property of the model.

Treat a shareable report as safe for identity svcdoctor declared, which is all of it today.
See ADR 0018, ADR 0022, ADR 0037 and `docs/BACKLOG.md`.

### The residual scan, and what it is allowed to call an identity

After the transformation, redaction re-reads the finished report and fails if any value it
knew to be identifying still appears. This is a safety net rather than the mechanism: the
values were already replaced structurally, and the check exists so that **a field added later
without a matching transformation fails loudly instead of shipping an identifier**.

Two properties, both load-bearing:

- **It searches string positions, not the serialized bytes.** Every value redaction protects
  is string-typed in the canonical schema, so an identity that genuinely survived is
  necessarily inside a JSON string. Searching the raw encoding instead meant a value whose
  text occurred in the document's own punctuation or numbers — `"info":0` in the severity
  counts, a timestamp, a negative integer attribute — was reported as surviving.
- **Only the identity-bearing part of a reference is an identity.** An endpoint reference is
  host, punctuation and port; the host is identity and the rest is not. Reading a port that is
  out of range as "this reference has no port" made the whole display string an identity, and
  that is what produced the failure above: a cluster advertising `host="" port=0` yields the
  subject `:0`, which was then hunted for in every report and found in `"info":0`.

**Fail-closed is unchanged.** A real hostname, IP address, declared host attribute, evidence
identifier, target, vantage or prose identity that survives still fails the whole redaction,
and `internal/security/redaction/residual_test.go` plants each of those in turn to prove it.
There is no partially redacted result and no way to relabel a `LOCAL_FULL` report as shareable
without transforming it.

**Remaining limit, recorded rather than papered over.** The scan asks whether an identity's
text appears in any string the report contains, so an identity that is a substring of ordinary
report text — a host named `kafka`, matching the service identifier, or `host`, matching an
attribute key and the pseudonym `host-001` — is still reported as surviving when it has not.
**The `identity` namespace inherits this exactly, and inherits nothing worse**: a role named
`PASS`, `error` or `host-001` fails closed, and so does a hostname with the same text, at
HEAD and after ADR 0037. `TestPseudonymShapedIdentityFailsClosedExactlyAsAHostnameDoes`
pins both halves side by side so the property is visibly shared rather than newly introduced.
No special case was carved out for identity, because an exception in a security verifier for
a value nobody records is a weakening with no user.
Such a run cannot produce a shareable report. It fails **closed**, and it is far narrower than
what it replaced, which broke every endpoint whose port was out of range. No shape-based rule
can settle it: whether an occurrence of `host` is the hostname or part of `probe.host` is a
question about provenance, not about text. Settling it needs verification that checks
identity-bearing surfaces structurally instead of searching the serialized document. Pinned by
`TestKnownLimitationIdentityTextOccurringInOtherReportText`; see `docs/BACKLOG.md`.

### Producer obligation: declare identity-bearing values

A producer that records identity **declares** it, using the value's type:

```go
domain.HostAttr("broker.prod.internal")                 // one network peer
domain.HostListAttr("broker.internal", "alt.internal")  // one peer per entry
domain.IdentityAttr("payments_writer")                  // one logical identity
```

Every declared value is replaced with a stable pseudonym, whatever its shape and wherever it
appears. That is what makes a certificate's subject alternative names safe to record: a bare
hostname cannot be recognized by shape — `broker.internal` and `TLS1.3` are the same shape —
so declaration, not inference, is the mechanism. See **ADR 0022** and **ADR 0037**.

### Three categories, and the boundaries between them

| Category | Example | May be in `LOCAL_FULL` | In `SHAREABLE_REDACTED` |
|---|---|---|---|
| **Secret** | password, private key, SCRAM proof, session nonce | **no** — it has no path into evidence at all | never, in any form |
| **Identity** | role, database, tenant, namespace | yes | `identity-NNN` |
| **Host / IP** | DNS name, address, `host:port` | yes | `host-NNN` / `ip-NNN` |
| **Ordinary** | SQLSTATE, TLS version, cipher suite, state | yes | unchanged |

**An identity is not a secret, and the distinction is structural rather than a convention.**
A secret is a `security.Secret`, it is revealed only inside an adapter's wire package, and no
`AttrValue` constructor accepts one — so a password cannot reach a report even locally. An
identity is an ordinary string the model is willing to hold, that a reader may see on their
own machine, and that must not be published. Adding `AttrKindIdentity` therefore changes
nothing about the credential boundary: it introduced no `security.Reveal` call site, and the
production count is unchanged at one.

**An identity is not a host.** They carry separate pseudonym namespaces, so a principal is
never numbered as a machine. One raw value declared under both kinds — a database and a
hostname that happen to share a name — receives one pseudonym in each namespace, because each
attribute is rewritten according to what its own producer declared it held.

**Declaring a value once makes that exact token sensitive everywhere in the report.** An
ordinary string attribute, a list entry or a prose field carrying the same text is rewritten
too. The reverse does not hold and is not claimed: a value nobody ever declared is preserved.
That is the known limit above, and it is a producer obligation. **A future adapter that
records a user or a database as an ordinary `StringAttr` will leak it, and redaction cannot
detect that mistake** — a bare role name and a version string are the same shape. No key-name
heuristic is added to compensate; `TestRedactionPerformsNoKeyNameInference` and
`TestRedactionContainsNoServiceSpecificPolicy` in `test/security` keep it that way, because a
heuristic would silently miss every service whose key spelling differs while creating the
appearance of protection.

Two rules go with it:

```text
good    tls.peer_dns_names = HostList("broker.internal", "alt.internal")
bad     tls.peer_dns_names = HostList("broker.internal, alt.internal")   # two in one value
bad     tls.summary        = String("broker.internal offered alt.internal")
```

Redaction replaces whole values, so two identities in one value survive together, and
identity inside prose is not recognized at all.

Plain string attributes are still checked opportunistically — a value that parses as an IP
address or a `host:port` reference is replaced — but that is a safety net for a producer that
forgot to declare, not the contract.

Non-identifying values are untouched and stay readable, which is what keeps a shareable
report diagnostically useful: a shared TLS report still says which version was negotiated,
which cipher was chosen, whether identity was verified, and when the certificate expires.

The guard is executable. `test/security/` builds reports from real probe evidence, redacts
them, and asserts every canary identity is gone: `dns_evidence_redaction_test.go`,
`tcp_evidence_redaction_test.go` and `tls_evidence_redaction_test.go`. A new probe or adapter
that records identity extends that set rather than assuming it is covered.

### Identity inside evidence identifiers

Evidence identifiers embed the things they identify — a hostname for a DNS lookup, an endpoint
and an address for a TCP attempt (ADR 0019). That is safe, but for a different reason than
everything else: identifiers are **replaced wholesale** with `evidence-NNN` rather than
rewritten in place, so a hostname reachable only through an identifier still disappears.

The distinction matters because the two mechanisms have different failure modes. A value in a
subject or attribute is removed only if redaction recognizes its shape; a value inside an
identifier is removed because the entire string is discarded. A probe therefore may put
identity in an identifier freely, and must still keep any identity it puts in an *attribute*
in a recognizable shape.

`test/security/tcp_evidence_redaction_test.go` proves the identifier path with a hostname that
appears in no subject, no attribute and no prose.

## Redaction boundary

Redaction is:

- applied before serialization
- structural rather than pattern-matched
- deterministic where determinism preserves useful correlation
- complete before any renderer runs

Sensitive values must be removed or tokenized before they reach renderers. Renderers are not responsible for discovering secrets.

Service adapters may identify service-specific sensitive fields, but the security package owns common masking/redaction primitives.

The canonical evidence model supports this structurally: it carries normalized values
rather than raw protocol objects or uncontrolled payloads, so credential material has no
path into a report by accident. See `docs/ARCHITECTURE.md` section 10.

## Testing

Security-sensitive changes require tests covering:

- secret wrapper string/debug behavior
- JSON serialization
- known DSN/URL credential patterns
- tokens and passwords embedded in fixtures
- report generation
- logs and error wrapping
- discovered endpoints and credential forwarding policy

Leak tests assert that a known secret value does not appear in any output path, rather than
asserting that output merely looks masked.

A release is blocked by a reproducible secret leak.
