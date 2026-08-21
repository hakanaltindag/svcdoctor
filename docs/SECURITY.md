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
