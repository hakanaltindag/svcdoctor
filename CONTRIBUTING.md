# Contributing to svcdoctor

Thank you for looking. This is a small project with strong opinions, and most of them are
written down — so the fastest way to get a change merged is to know which ones apply.

## Before you write code

**Open an issue first** for anything that is not a bug fix or a documentation correction. The
architecture has boundaries that are enforced by tests, and it is much cheaper to find out
which one your idea crosses before you have written it.

**Report a security issue privately.** See [`SECURITY.md`](SECURITY.md). Please do not open a
public issue for an undisclosed vulnerability.

## The quality gate

```sh
make check
```

That is `gofmt`, `go test ./...`, `go vet`, `golangci-lint` and a `CGO_ENABLED=0` build. **It
mirrors CI exactly**, it is hermetic, and it takes seconds. A change that passes it locally
passes CI.

The integration suites are excluded because they need Docker. Each starts a real server, runs
against it and tears it down. **Run them one at a time** — the clusters compete for cores:

```sh
make integration-postgres  make integration-kafka     make integration-redpanda
make integration-redis     make integration-valkey
make integration-rabbitmq  make integration-lavinmq   make integration-multitarget
```

Run the ones your change could affect. If you cannot run Docker, say so in the pull request and
a maintainer will.

Linting uses [golangci-lint](https://golangci-lint.run) `v2.13.1`, which uses the v2 config
format. An older major version will not read `.golangci.yml`.

## What a change has to respect

### The architecture rule

> **Probes collect facts. Adapters understand protocols. Diagnosis correlates evidence.
> Renderers explain results.**

Concretely, and each of these is enforced by a test in `test/security/`:

- A probe knows no service. A generic DNS, TCP or TLS probe that mentioned PostgreSQL would be
  a boundary violation, not a shortcut.
- An adapter never dials. Generic transport owns DNS, TCP and TLS and hands a live connection
  over; an adapter calling `net.Dial` or performing its own handshake is a violation.
- **Diagnosis performs no I/O.** It runs on a frozen evidence graph. When evidence is missing it
  emits `UNKNOWN` or `SKIPPED` — it never goes and looks.
- **A renderer creates nothing.** No finding, no severity, no interpretation. If output needs a
  fact the report does not carry, the fix is upstream of the renderer.

### Claim discipline

This is the product, so it is the thing most likely to be broken accidentally:

- `UNKNOWN` is not `FAIL`. A capability svcdoctor does not implement is a gap in the tool.
- A local timeout is not a remote failure.
- No credential is not a rejected credential.
- A finding names the exact evidence identifiers that produced it.

If a change makes svcdoctor claim something it did not measure, it will be sent back even if the
code is otherwise good.

### A decision that changes a contract needs an ADR

`docs/decisions/` holds them. Write one when a change alters the report schema, the exit codes,
the CLI surface, a credential rule, a TLS rule, an evidence vocabulary, or what svcdoctor is
willing to claim.

An ADR states **Context, Decision, Consequences, Rejected alternatives and Verification**.
Rejected alternatives are not a formality: they are how the next person learns why the obvious
approach was not taken. No `TBD` in an accepted decision.

A bug fix, a test or a documentation correction needs no ADR.

### Frozen numbers

Several counts are pinned by test because moving them is a decision rather than an
implementation detail: the report schema version, the number of finding codes, the number of
failure classes, the number of `security.Reveal` call sites, and the number of external module
dependencies. If your change moves one, the failing test will tell you which — and the answer is
an ADR, not a new number.

**Adding a dependency is a decision.** svcdoctor has two, each confined to one package and each
with no transitive dependencies of its own. A third needs a written justification.

## Tests

Every change carries the test that would have caught its absence.

- **Package-level fixtures** live in a package-adjacent `testdata/`.
- **Cross-package and environment-dependent tests** live in `test/`.
- **A structural guard needs a non-vacuity proof.** A test that scans an empty list passes
  forever and looks exactly like one that passes correctly, so guards in this repository come
  with a companion test proving they can still fail. Follow the pattern in
  `test/security/fleet_boundary_test.go`.

Golden files exist for the terminal renderer and for all seven help surfaces. Regenerate with
`-update` and **read the diff** — a golden updated without reading it is worse than no golden.

## Documentation

The six public documents each have one owner, and a concept is documented in exactly one of
them (ADR 0075 §2.4):

| Document | Authoritative for |
|---|---|
| `README.md` | positioning, install, one example of each shape |
| `docs/QUICKSTART.md` | the first successful journey |
| `docs/CONFIGURATION.md` | the `run --config` schema and credential references |
| `docs/OUTPUT.md` | terminal, JSON and shareable contracts |
| `docs/CI.md` | exit codes and pipelines |
| `docs/COMPATIBILITY.md` | what has actually been tested |

Documentation is checked by tests. Every YAML example in `examples/` and in a public document is
parsed by the real configuration loader, help text is snapshotted, and a set of guards fails the
build on a claim the repository does not support — in **both** directions: claiming a platform
nobody ran against, and omitting a capability that exists.

**A compatibility claim needs evidence.** `docs/COMPATIBILITY.md` grades by what was actually
done — a real instance with a committed fixture, or documentation only — and a row cannot move up
without the run that justifies it.

## Language

Everything in the repository is written in English: code, comments, documentation, commit
messages, tests, fixtures, help text, error messages and ADRs.

## Commits and pull requests

- One logical change per pull request.
- Commit messages in the imperative: `fix(fleet): reject a zoned host before execution`.
- Say what you ran. If you could not run the integration suites, say that too.
- `make check` green.

## Releasing

Contributors do not need this, but it is not a secret:
[`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) is the ceremony, and its one rule is
that **a published tag is never moved**. A broken release is succeeded, never repaired.

## Licence

svcdoctor is Apache-2.0. By contributing you agree that your contribution is licensed under it.
