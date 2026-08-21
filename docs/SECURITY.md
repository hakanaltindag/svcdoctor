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

A service adapter's wire package is where credentials will eventually be written to
a socket. `internal/adapter/kafka/wire` is built for that before it needs to be:
it is the only package that touches the protocol library, it holds no state
between exchanges, and everything it returns upward is plain values that a report
can carry.

Phase 3.1 sends no credentials — ApiVersions is unauthenticated — but the boundary
already keeps three things out of evidence: raw protocol objects, buffers, and the
socket's own error text. When SASL arrives, secret handling stays inside that one
package rather than spreading through the adapter.

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

**There are still zero call sites.** The guard was installed in the phase before
the first credential byte, deliberately: a rule added afterwards has to be argued
against working code.

### Kafka SASL: what Phase 3.2 does and does not send

`kafka.sasl_handshake` (L5) asks a broker whether it offers a named mechanism. The
request carries **a mechanism name and nothing else** — no identity, no password,
no token — which is a property of the Kafka protocol, not a choice made here. That
is what makes it safe to run on every measured path.

Mechanism names such as `PLAIN` or `SCRAM-SHA-512` are protocol facts drawn from a
public registry. They are neither secrets nor identity, so they are recorded as
ordinary string values and survive redaction intact; a shared report that turned
`PLAIN` into `host-001` would have destroyed the only thing the node is for.

Authentication is deferred, and `docs/BACKLOG.md` carries the four questions that
block it. Two of them are security questions in their own right: which paths may
receive credentials, and whether a credential may cross an unverified channel. See
ADR 0026.

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
`domain.HostAttr` or `domain.HostListAttr`, and a declared value is always replaced. What
remains is a producer forgetting to declare — a mistake code review and the contract tests
below are there to catch, rather than a property of the model.

Treat a shareable report as safe for identity svcdoctor declared, which is all of it today.
See ADR 0018, ADR 0022 and `docs/BACKLOG.md`.

### Producer obligation: declare identity-bearing values

A producer that records identity **declares** it, using the value's type:

```go
domain.HostAttr("broker.prod.internal")            // one identity
domain.HostListAttr("broker.internal", "alt.internal")  // one identity per entry
```

Every declared value is replaced with a stable pseudonym, whatever its shape and wherever it
appears. That is what makes a certificate's subject alternative names safe to record: a bare
hostname cannot be recognized by shape — `broker.internal` and `TLS1.3` are the same shape —
so declaration, not inference, is the mechanism. See **ADR 0022**.

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
