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

Automatically retrying with verification disabled would silently turn a safety failure into
a successful-looking result. When disabling verification would produce useful additional
evidence, that belongs in a recommendation for the operator to act on deliberately.

Credentials are not automatically sent over an unverified TLS channel.

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

An attribute value that carries identity in a shape the transformation cannot recognize
structurally, and that appears nowhere else in the report, is **preserved**. The evidence
model has no per-key sensitivity classification, and adding one is tied to the open question
of where service attribute keys live.

Until that is resolved, treat a shareable report as safe for the identifiers svcdoctor knows
it collected, not as a guarantee about attribute values a future adapter may add. See
ADR 0018 and `docs/BACKLOG.md`.

### Producer obligation: identity-bearing attribute shapes

The limit above is a requirement on every probe and adapter, not only a caveat for readers.

Redaction recognizes an identifying attribute value when it parses as an IP address or as a
`host[:port]` reference. So a producer that records identity must record it as **one value
per attribute or per list entry, in canonical form**:

```text
good    dns.answers = ["10.11.12.13", "2001:db8::1"]
bad     dns.summary = "resolved kafka.prod.internal to 10.11.12.13"
```

The second shape survives redaction into a shareable report. Nothing rejects it at compile
time, so the guard is a test: `test/security/dns_evidence_redaction_test.go` builds a report
from real probe evidence, redacts it, and asserts that every canary identity is gone. A new
probe or adapter that records identity should extend that contract test rather than assume it
is covered.

Non-identifying values are untouched by redaction and stay readable, which is what keeps a
shareable report diagnostically useful. See ADR 0020.

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
