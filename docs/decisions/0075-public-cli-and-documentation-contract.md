# ADR 0075 — Public CLI and documentation contract

**Status:** Accepted
**Date:** 2026-09-01
**Phase:** 9.2A
**Supersedes:** nothing. Extends ADR 0041 (CLI shape) and ADR 0048 (leaf-command boundary).

---

## 1. Context

Phase 9.1 is frozen and five commands exist: `diagnose postgres`, `diagnose kafka`,
`diagnose redis`, `diagnose rabbitmq` and `run --config`. Every one works. Phase 9.2A audited
them as an external Senior SRE would meet them, and the measured result is recorded in
`docs/validation/PHASE92A_RELEASE_UX_AUDIT.md`.

The audit found that the product's *behaviour* is in better condition than its *explanation*.
The configuration error corpus — 21 black-box failures — answers what failed, where, why, how
to fix it and frequently why the design refuses to guess. The help surfaces are precise and
honest. But the README's second sentence names two of four services, its credential section
states a rule that a later section contradicts, and its container section asserts a security
property ("svcdoctor's production code reads no environment variable at all") that stopped
being true in Phase 9.1A.

The cause is structural rather than careless. `internal/cli/docsclaims_test.go` guards the
documentation mechanically and guards it in **one direction**: it forbids claiming a platform
that was never run against, an unimplemented mechanism, or health the product cannot observe.
Nothing can fire when a document *omits* something that exists. A capability added in Phase 7,
8 or 9 therefore lands in the code, in `--help` and in `docs/COMPATIBILITY.md` while the
README's opening paragraph keeps describing Phase 6.

Two further facts shape this decision. There is no CI documentation at all, for a tool whose
exit codes are its primary machine interface. And there is no configuration example anywhere
except one fenced block in the README that no test parses.

The question this ADR answers is: **what is the public surface of svcdoctor, who owns each
statement about it, and what mechanically prevents that statement from drifting?**

---

## 2. Decision

### 2.1 The command surface is frozen as it stands

Five commands. Four leaf `diagnose` commands and one `run`. No command is renamed, no flag is
renamed, no flag is added or removed, and `inspect` stays a reserved namespace with no
implementation.

This is a decision, not an omission. The audit found one genuine wart — `--user` on
postgres/kafka against `--username` on redis/rabbitmq for the same concept — and declines to
fix it by renaming, because `--user` has been in a published release since `v0.2.0` and a
rename breaks every existing invocation for a cosmetic gain. It is documented instead, in one
table, in the one document that owns configuration.

### 2.2 One sentence is the canonical mental model

> **`diagnose` is one endpoint you name on the command line. `run` is many endpoints a file
> names for you. They perform exactly the same measurement — `run` schedules the diagnoses that
> `diagnose` performs, one per target — and the only reason both exist is that a password
> belongs to one endpoint, so N endpoints need N credential references and a file is where
> those live.**

It appears in root help and in the README, in those words. It is true of the implementation:
`internal/fleet/run` imports no adapter, no wire package, no diagnosis rule and no probe, and
contains no service name.

### 2.3 Every help surface carries the same seven elements

Purpose in one sentence; usage; required arguments; important optional arguments; credential
safety; TLS; and the identical five-line exit-code block. Where a service's semantics differ,
the help says so — `--step-timeout` must exceed 3s for RabbitMQ because RabbitMQ delays
refusals by exactly that long, and that sentence stays. Where they do not differ, the wording
does not differ either.

`run --help` carries the exit-code block too. It is the command written for CI; it is the one
that most needs it, and today it is one of the two that lack it.

No help surface contains a Go type name, a package path, an ADR number, or a single-dash
rendering of a flag the user types with two dashes.

### 2.4 Six public documents, each with exactly one owner

| Document | Owns | Authoritative for |
|---|---|---|
| `README.md` | what it is, what it is not, install, one example of each shape, links | positioning |
| `docs/QUICKSTART.md` | the five-minute first success | onboarding |
| `docs/CONFIGURATION.md` | the whole `run` schema, every field, every credential reference | the configuration schema |
| `docs/OUTPUT.md` | terminal anatomy, the JSON contract, shareable semantics, `jq` recipes | the output contract |
| `docs/CI.md` | exit codes, the three policies, four platform examples, artifacts | CI and exit codes |
| `docs/COMPATIBILITY.md` | unchanged | what has actually been tested |

`docs/REPORT_SCHEMA.md`, `docs/SECURITY.md`, `docs/ARCHITECTURE.md`, `docs/decisions/` and
`docs/validation/` are **engineering evidence**. They are linked from the six and are never
required reading for normal operation. A root `SECURITY.md` is a vulnerability-reporting
policy (ADR 0076 §2.5) and is not a user document.

When two documents disagree, the owner in this table wins and the other is corrected.

### 2.5 The example-configuration strategy is one canonical file plus two focused ones

- `examples/services.yaml` — canonical. One target per registered service, TLS on, credentials
  by reference, comments only where a comment earns its place.
- `examples/minimal.yaml` — the smallest thing that runs.
- `examples/production.yaml` — verified TLS with a private CA, `env:` for CI and `file:` for a
  Kubernetes-mounted secret, explicit budgets and concurrency.

All three: no plaintext credential, no secret value, no invented syntax, valid against the real
decoder, representative rather than exhaustive.

### 2.6 Documentation drift is prevented mechanically, in three ways and no more

1. **Every YAML fence is parsed.** One test extracts every ` ```yaml ` block from `README.md`,
   `docs/*.md` and `examples/`, and decodes each through the real `internal/fleet/config`
   loader. A block that must fail — the plaintext-password counter-example — is marked as such
   and asserted to fail with the documented error.
2. **Every help surface has a golden snapshot.** Seven files. A help change becomes a reviewed
   diff instead of silent drift. This extends the existing `internal/cli/testdata/` pattern.
3. **The claim guard gains its missing direction.** `docsclaims_test.go` currently forbids
   claiming what does not exist. It also comes to forbid *omitting what does*: every service
   registered in the CLI must appear in the README's supported-services statement, and every
   credential source the product implements must appear in its credential section.

Shell examples are **not** executed. One guard instead asserts that no documented shell example
contains `| tee`, `|| true`, or a flag the CLI does not define.

---

## 3. Consequences

**A capability cannot be added without the README noticing.** Registering a fifth service or a
third credential source fails `make check` until the README names it. That is the property the
audit found missing, and it is what turns §2.4's ownership table from an intention into a rule.

**`make check` stays hermetic.** The three mechanisms are in-tree: an importable config loader,
golden files, and text guards. Nothing opens a socket, starts a container or calls `gh`.

**Help text becomes harder to change casually and easier to change correctly.** A golden
snapshot means every wording change is visible in review. That is the intent: help text is the
document most users read and the one least often reviewed.

**Documentation grows to six files from one.** The README shrinks. A reader looking for the
config schema stops scrolling a 956-line document and opens the one named for it.

**The `--user`/`--username` split is now a documented decision rather than an accident.** It
will read as a wart forever, and a future major version may reconcile it. Until then nobody has
to rediscover which service uses which.

**Nothing here changes behaviour**, with one exception carried by ADR 0077: the two help
surfaces that lack an exit-code block gain one. That is added text, not changed semantics.

---

## 4. Rejected alternatives

**Rename `--user` to `--username` everywhere, with `--user` as a hidden alias.** Rejected. It
is the tidier CLI and it is not worth it: `--user` shipped in `v0.2.0`, an alias is a second
name for one thing forever, and a hidden flag is a flag nobody can discover but everybody must
maintain. The audit's job was to find this, not to trade a real compatibility break for visual
symmetry.

**Put configuration and CI into the README.** Rejected. It is already 956 lines, and every one
of the six stale passages the audit found is in the half a reader reaches last. Length is what
made the drift invisible.

**Split help text into a man page or a docs site.** Rejected. `--help` must be complete on its
own — an operator debugging connectivity may have no browser and no network. That is the whole
premise of the tool.

**Execute README shell examples in CI.** Rejected. It makes `make check` non-hermetic and
network-dependent, which is the property that makes it worth running. The guard against
`| tee`, `|| true` and undefined flags catches the failure modes that actually occurred without
running anything.

**A full literate-documentation harness.** Rejected as disproportionate. Three targeted
mechanisms cover the three ways this project's documentation has actually drifted: an unparsed
example, an unreviewed help change, and an omitted capability.

**Adopt a CLI framework to unify help generation.** Rejected. It adds a dependency to a project
with two, to solve a formatting problem that seven golden files solve with none.

**Add terminal color.** Rejected, and recorded here because it is the change most likely to be
proposed as a UX improvement. There is no color anywhere today, output is byte-identical on a
TTY and redirected, and that is exactly why the golden tests are stable. State is already
carried twice — by glyph and by word — so nothing depends on a visual channel. Color would cost
TTY detection, `NO_COLOR`, `CLICOLOR_FORCE`, a dumb-terminal path and a determinism guard on
every golden test. The measured readability defect is **width** — a 246-column line with no
wrapping — and that is where the effort goes.

---

## 5. Verification

| Claim | Verified by |
|---|---|
| Five commands, no rename, no flag change | UX-01; the golden help snapshots |
| The mental model appears in root help and README | UX-01 |
| Every leaf help carries all seven elements | UX-02 |
| `run --help` carries the exit-code block | UX-03 |
| No help surface carries a Go name, package path or single-dash flag | UX-17 |
| Six public documents exist and each concept has one owner | UX-15, UX-18 |
| `examples/minimal.yaml` decodes | UX-04 |
| `examples/services.yaml` decodes and covers every registered service | UX-05 |
| The plaintext counter-example fails as documented | UX-06 |
| Every YAML fence in README, `docs/` and `examples/` decodes | UX-18 |
| Every registered service appears in the README's service statement | UX-15 |
| Every implemented credential source appears in the README's credential section | UX-15 |
| No documented shell example uses `\| tee`, `\|\| true` or an undefined flag | UX-14 |
| No escape sequence is ever emitted | UX-20 |

Every one is a named executable test in the Phase 9.2A acceptance matrix
(`docs/validation/PHASE92A_RELEASE_UX_AUDIT.md` §11). None is a prose claim.
