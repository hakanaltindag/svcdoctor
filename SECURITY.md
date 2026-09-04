# Security policy

svcdoctor authenticates to databases and message brokers on an operator's behalf, and it
produces a report that is meant to be shared. Both of those make it a program where a defect
can disclose something. Please report one privately.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting for this repository:**

> [github.com/hakanaltindag/svcdoctor/security/advisories/new](https://github.com/hakanaltindag/svcdoctor/security/advisories/new)

That channel is private between you and the maintainers until an advisory is published. It is
the only reporting channel this project has, and it is deliberately the only one: an email
address published in a repository is an address nobody can rotate, and a project this size
cannot promise a monitored inbox.

**Please do not open a public issue, pull request or discussion for an undisclosed
vulnerability.** svcdoctor is a diagnostic tool that handles credentials; a public report is a
working description of how to misuse one before anybody can fix it.

## What is in scope

Anything that could disclose a credential, disclose something a report promised to remove, or
cause svcdoctor to trust a peer it should not. Concretely:

- **Credential exposure.** A password reaching a report, a log line, an error message, an
  argument list, an environment variable svcdoctor set, or the wire in a form svcdoctor's own
  policy forbids.
- **Redaction failure.** A hostname, address, logical identity, evidence identifier or local
  filesystem path surviving into a `SHAREABLE_REDACTED` report. So is redaction *failing open* —
  emitting a document it could not verify instead of refusing to emit one.
- **Credential transport policy.** A credential leaving over a channel whose peer identity was
  not verified, or reaching an endpoint the operator did not name — in particular an endpoint
  svcdoctor learned from a peer, such as a Kafka advertised broker.
- **TLS trust and identity.** A chain accepted that should not verify, an identity mismatch
  reported as a verified peer, or `--tls-ca-file` failing to replace the system trust store.
- **Supply chain.** A published container image whose digest does not match its signature,
  provenance or SBOM.

Reports about the four services svcdoctor diagnoses belong to those projects, not here, unless
svcdoctor's own handling is what makes them exploitable.

## What is not a vulnerability

These are documented behaviours. Please open an ordinary issue if you disagree with one — that
is a design conversation, not a disclosure.

- **A shareable report is pseudonymized, not anonymized.** Pseudonyms are stable within a
  report so that relationships stay readable, and ports, durations, timestamps, service names,
  finding codes and severities are preserved unchanged. `docs/OUTPUT.md` states exactly what is
  replaced and what is not.
- **`--tls-insecure` disables identity verification.** It is explicit, per-run, recorded in the
  report, and never an automatic fallback. A credential is withheld over such a channel rather
  than sent.
- **Exit code 0 does not mean the service is healthy.** It means no error-level target-side
  problem was proven. `docs/CI.md` is authoritative.
- **A local error message names a local path or reference.** An operator has to be able to fix
  the problem. The shareable projection is where those are withheld.

## What to include

As much as you can share safely:

- what you observed, and what you expected instead;
- the invocation or configuration shape that produced it, **with real hostnames and credentials
  removed** — a `--shareable` report is a good way to send one;
- the svcdoctor version (`svcdoctor --version`), your OS and architecture;
- whether it reproduces against a fixture in `test/integration/`, which is the fastest way for
  a maintainer to see it too.

**Never include a real password, private key or certificate private key in a report**, in any
channel, including the private one.

## What to expect

svcdoctor is maintained by one person. The honest commitments are these and no more:

- Reports are read, and you will get a human reply.
- A confirmed vulnerability is fixed in a new release. **A published tag is never moved or
  rebuilt** — a defect ships as the next version, never as a re-point of an existing one.
- You will be credited in the advisory unless you ask not to be.

No response-time guarantee is offered, because none could be kept.

## Supported versions

**The most recent release only.** Fixes land in a new version; earlier tags are not patched,
and there is no backport branch. That follows from the rule above: a tag is immutable, so
"patching v0.4.0" would mean publishing v0.4.1.

`svcdoctor --version` reports what you are running, and the same value is recorded in every
report as `run.svcdoctorVersion`. A build from a working checkout reports `dev` and corresponds
to no release.

## Security properties this project asserts

They are enforced by tests rather than by convention, and each is a fair thing to attack:

- **Exactly one `security.Reveal` call site per service**, inside that service's wire package,
  with a linter failing the build on a second one elsewhere.
- **A password is never a command-line argument.** There is no `--password` flag, in any
  command, because an argument is visible to every process on the host.
- **A plaintext password is refused by the configuration decoder's type**, not by a check, so
  `password: hunter2` cannot be parsed at all.
- **No secret is cached.** Two targets naming the same reference resolve it independently.
- **Redaction fails closed.** When the residual check cannot confirm that a covered value was
  replaced, svcdoctor emits no report and exits 3 rather than writing a partially redacted one.

The design records behind them are `docs/SECURITY.md` and `docs/decisions/`.
