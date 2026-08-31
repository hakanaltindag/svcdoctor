# ADR 0072: Configuration references credentials; it never contains them

## Status

**Accepted in Phase 9.0. Not implemented.**

It decides which credential sources a multi-target configuration may name, what happens to
a plaintext secret written into the file, when a reference is resolved, who owns each step
of the resolution, and how credential authority survives the introduction of many targets
in one process.

`SchemaVersion` stays **1**. No `FailureClass`, no `FindingCode`, no dependency. It adds
**no `security.Reveal` call site and no `Credential.SecretFor` call site**: both stay at
**4**, one per service, where ADR 0038 put them.

Companion records: [0071](0071-multi-target-configuration-schema.md) is the schema this
sits inside, [0073](0073-multi-target-execution-and-budgets.md) decides when a target runs.

It applies ADR 0028's credential contract, ADR 0029's channel-security rule and ADR 0049's
credential-input decision to a fourth caller, and it weakens none of them.

## 1. Decision summary

1. **Two sources, `env` and `file`.** Exactly one per password, and a password is an object
   rather than a scalar.
2. **A plaintext secret in the file is refused by the decoder's type**, before validation
   runs and long before any network execution.
3. **Preflight proves every reference is resolvable without retaining any secret value.**
   Resolution happens per target, immediately before that target executes.
4. **There is no secret cache.** Two targets naming the same reference resolve it twice and
   receive two independently bound credentials.
5. **A credential reference is never serialized into a report**, in either output mode. It
   may appear on stderr.
6. **The username is identity-classed, not secret-classed**, which is the classification the
   repository already made.
7. **`internal/fleet/config` cannot construct a secret**, because it does not import
   `internal/security`.

## 2. The reference

```yaml
credentials:
  username: svcdoctor
  password:
    env: ORDERS_DB_PASSWORD
```

```yaml
credentials:
  username: svcdoctor
  password:
    file: /run/secrets/orders-db
```

| Form | Meaning |
|---|---|
| `password: {env: NAME}` | Read the process environment variable `NAME` |
| `password: {file: PATH}` | Read the file at `PATH` |
| `password: {env: A, file: B}` | **Configuration error.** No precedence |
| `password: {}` | **Configuration error.** A reference that names nothing |
| `password:` absent | **Valid.** The run carries no credential |
| `password: hunter2` | **Configuration error**, §3 |

**`password:` absent is a supported run, not a degraded one.** It reaches the endpoint,
discovers that authentication is demanded, and produces `<SERVICE>_CREDENTIAL_NOT_CONFIGURED`
— CONFIRMED / WARN / HIGH, summary status `OK`, no session, exit 0. That is one of the three
load-bearing product invariants in `CLAUDE.md`, and multi-target mode inherits it unchanged
rather than restating it. A target may also carry `credentials.username` with no password,
which is exactly today's `--user u` with no `--password-file`.

**Two sources is an error rather than a resolution.** This is ADR 0049 §2 applied verbatim:
*"A precedence rule is one more thing to remember under pressure, and the failure it hides —
svcdoctor used the other credential — is exactly the one that costs an hour during an
incident."*

## 3. A plaintext secret is refused by the type system

```yaml
    password: hunter2
```

is rejected by the decoder itself:

```
line 4: cannot unmarshal !!str `hunter2` into config.CredentialRef
```

This is measured, and it is the reason the reference is modelled as an object rather than
as a string with an optional prefix scheme such as `env:NAME`. A scheme-prefixed string
would make `password: hunter2` a *syntactically valid* value that a hand-written check has
to catch — and a hand-written check is one someone can move, reorder or forget. Modelling
the reference as an object makes the refusal a property of the schema.

**It is a configuration error, not an accept-and-redact.** Redacting it would mean svcdoctor
read a plaintext password out of a file, used it, and then hid it in the output — leaving
the operator with a working invocation, a clean report, and a secret committed to whatever
holds that file. The refusal happens before any target is dialled, so nothing is on the wire
to redact.

**File permissions are not a defence and are not consulted.** `0600` says who can read the
file; it says nothing about whether the file is in a git repository, a container image
layer, a backup, or a support bundle. svcdoctor does not inspect the config file's mode and
does not vary its behaviour on it, because a mode check would imply that a stricter mode
makes a plaintext secret acceptable.

## 4. Why `env` is allowed here when ADR 0049 §5 refused it

ADR 0049 §5 rejected environment variables as a credential source **for a leaf command**,
and Phase 8.2-R3 removed a `--password-env` flag that had contradicted it.

That decision is not weakened, and this is not an exception to it. The two are different
objects:

| | Leaf command | Fleet configuration |
|---|---|---|
| Credentials per invocation | one | many |
| The reference is | an ambient process value with no written form | a written line, bound to one target ID, in a reviewable file |
| Which endpoint it authorizes | implied by the flags | stated beside it |
| `--password-file` covers it | yes | no — one flag cannot carry N distinct secrets |
| Container/K8s injection (ADR 0062) | one file suffices | env and file are both the documented mechanisms |

The decisive point is the third row. `--password-env DB_PASS` was an unnamed binding: the
variable and the endpoint met only inside svcdoctor. `password: {env: DB_PASS}` sits inside
the target it authorizes, in a file that goes through review, and cannot be read as
authorizing anything else.

**The structural consequence is preserved by construction.** `internal/cli` still contains
**zero** environment-read call sites. The `run` command reads no environment variable; the
fleet credential resolver does, and it lives in `internal/fleet/secret`. The existing guards
in `internal/cli/cli_test.go` and `test/integration/postgres/guards_test.go`, which fail the
build on `os.Getenv`, `os.LookupEnv` and `os.Environ` in `internal/cli`, keep passing
unchanged and are not relaxed.

## 5. Resolution: what happens when

```
  parse the config file                     internal/fleet/config
        |                                   holds a CredentialRef; cannot build a Secret
        v
  validate the whole config                 zero network execution past here on any error
        |
        v
  PREFLIGHT every reference                 internal/fleet/secret
        |                                   proves resolvable; retains no value
        v
  ---------------- no target has been dialled yet ----------------
        |
        v
  for each target, when its worker picks it up:
        resolve the reference       -> security.Secret
        bind to this target's host:port -> security.Credential
        call app.DiagnoseX
        release the credential
```

### 5.1 Preflight proves resolvability and retains nothing

| Source | Preflight check | Value retained |
|---|---|---|
| `env: NAME` | present, and non-empty | **no** — read and discarded |
| `file: PATH` | resolves to a regular file, non-empty, within the size bound | **no** — contents not read |

`os.LookupEnv` returns the value in order to report presence; there is no API that reports
only presence. So the environment preflight does hold one value transiently, one at a time,
and drops it. That is stated plainly rather than glossed: the alternative is not checking
env references at all, which means a fleet run with one typo'd variable name executes 49
targets before failing on the 50th.

The file preflight is stronger — `os.Stat` proves type, existence and size without reading
a byte.

### 5.2 Why not resolve everything upfront, and why not resolve lazily

Three options were weighed.

**A — resolve every secret before any network activity.** Deterministic preflight, nothing
starts if anything is missing. But N secrets are resident for the whole run: with 512
targets that is 512 live secrets for the duration, and residency is exactly what a core
dump, a `%+v` and a heap profile expose.

**B — resolve each secret lazily, immediately before its target runs.** Minimal residency,
at most `concurrency` secrets alive. But target 1 executes before target 18's missing
variable is discovered, which is the partial execution ADR 0071 and §6 below exist to
prevent.

**C — validate resolvability without reading the value.** Achieves A's determinism at B's
residency, and is only partially possible: complete for a file, and for env only by reading
and discarding.

**The decision is C for preflight and B for resolution.** Nothing starts if a reference
cannot be resolved, and at most `concurrency` secrets are alive at once — a 128-fold
reduction against A at the maximum target count.

### 5.3 The residual gap, stated

A file can be deleted, replaced or made unreadable between preflight and execution.
Preflight is therefore not a guarantee, and a per-target credential resolution failure
remains reachable at runtime.

That is not a security hole — the file is the operator's own, and a changed file yields a
resolution failure rather than a wrong credential being sent — but it is a real outcome, so
the execution-state vocabulary in ADR 0074 §4 can express it and does not have to be widened
later to accommodate it.

## 6. Ownership, frozen

| Step | Owner | May not |
|---|---|---|
| Read the config file | `internal/fleet/config` | import `internal/security`; read env; open a secret file |
| Hold a `CredentialRef` | `internal/fleet/config` | hold a value |
| Read env / read a secret file | `internal/fleet/secret` | know any protocol |
| Build `security.Secret` | `internal/fleet/secret` | — |
| Bind `security.Credential` to `host:port` | `internal/fleet/secret` | bind to anything but the target's own endpoint |
| Pass the credential into `app.DiagnoseX` | the registered service runner | rebind it — the composition root already refuses |
| Verify the binding | `app.*Params.validate`, then `Credential.SecretFor` | — |
| Call `security.Reveal` | the adapter's wire package, unchanged | — |

**`internal/fleet/config` does not import `internal/security`.** That is the structural form
of "the parser must not reveal secrets": it is not that the parser declines to build a
secret, it is that the type is not in scope. A `CredentialRef` carries a source kind and a
name or path, and nothing else.

**The orchestrator never calls `Reveal`.** The count stays 4, and `forbidigo` already fails
the build on a call site outside a wire package, so this needs no new mechanism — only the
absence of an exemption.

**The orchestrator never calls `SecretFor` either.** It hands a bound `Credential` to a
composition root, whose `validate` refuses a credential bound to any other endpoint, and
whose adapter then calls `SecretFor`. Both existing checks run unchanged; neither is
duplicated in the fleet layer.

## 7. Credential authority across many targets

Multi-target execution creates one genuinely new hazard: a secret resolved for target A
reaching target B. Every invariant below exists to make that unreachable rather than
unlikely.

1. **A resolved secret is bound before it is usable.** `security.Credential` has no plain
   secret accessor; `SecretFor(endpoint)` requires naming the endpoint it is about to be used
   against. A credential built for target A cannot yield its secret at target B's endpoint
   without a visible mismatch that returns an error.
2. **The authority is the target's own `host:port`**, exactly as it is for each leaf command.
   Nothing about multi-target mode widens it.
3. **A target ID is not credential authority.** It identifies a logical execution. It is not
   an endpoint, it never reaches `security.Endpoint`, and no code path binds a credential to
   one.
4. **A shared reference is not shared authority.** §8.
5. **No secret cache exists** — §8 again, and it is the mechanism that makes 4 true.
6. **Kafka's discovered-broker rule is untouched.** ADR 0050 stands: an advertised broker
   receives credential-free DNS, TCP and TLS and nothing else. Multi-target mode adds no path
   by which a credential reaches one.
7. **RabbitMQ's virtual host does not become authority.** ADR 0068 §6 stands: the credential
   crosses in `Connection.Start-Ok` and the vhost is named in `Connection.Open`, in that
   order, so a vhost-scoped authority would gate a transmission that already happened.
   `config.vhost` is a service configuration field and never an authority component.
8. **A failed target leaves no secret state.** Its credential goes out of scope when its
   execution returns; there is nothing global for it to have written to.
9. **No secret reaches any report**, and no target's report can carry another target's
   material, because no target's report is ever assembled from anything but its own frozen
   graph.

## 8. The same reference in two targets

```yaml
  - id: orders-db
    credentials: {username: svcdoctor, password: {env: SHARED_PASSWORD}}
  - id: billing-db
    credentials: {username: svcdoctor, password: {env: SHARED_PASSWORD}}
```

This is supported, and it produces **two independent resolutions**: two `security.Secret`
values and two `security.Credential` values, each bound to its own target's `host:port`.

The references are identical. The authorities are not, and the sameness of the text is a
coincidence of the file rather than a fact about either endpoint.

**There is no cache, and adding one was rejected.** A cache would have to be keyed by the
reference — and a reference is not an authority. Handing target B a `Credential` object
built for target A's endpoint would produce a `SecretFor` mismatch: an error, caught, at the
wire boundary, in the one code path where being wrong is most expensive. Today that
situation is not caught late; it is unconstructable.

The cost is reading the same environment variable twice. That is free, and it buys an
invariant that holds by construction.

## 9. Concurrent secret handling

With concurrency above 1, several secrets are resident at once — at most `concurrency` of
them, by §5.2.

Frozen:

- **No global secret registry**, no package-level secret variable, no process-wide store.
- **A credential's lifetime is one target execution.** It is created by the worker that runs
  the target and goes out of scope when that execution returns.
- **No structure that can hold a resolved secret is logged, printed or formatted.**
  `security.Secret` and `security.Credential` already implement `String`, `GoString` and
  `Format` so that `%v`, `%+v`, `%#v` and `%s` all mask; the fleet layer adds no type that
  embeds one without inheriting that.
- **No debug dump of in-flight targets**, in any build, behind any flag.
- **The config struct is never formatted**, because a formatted config would print
  reference names — see §10 for why that is a report concern and a stderr allowance.

## 10. What may be serialized, and where

| Value | stderr | canonical report (either mode) |
|---|---|---|
| A secret value | **never** | **never** |
| An environment variable name | yes | **never** |
| A credential file path | yes | **never** |
| The config file path | yes | **never** |
| The raw config, in any form | **never** | **never** |
| The username | yes | yes — verbatim in `LOCAL_FULL`, pseudonymized in `SHAREABLE_REDACTED` |

**The split between the two columns is deliberate and it is ADR 0049 §3's.** stderr is
ephemeral, local and read by the operator who owns the file; a report is attached to a
ticket, pasted into a chat and kept. A file svcdoctor cannot read must be nameable *to the
person fixing it*, and that person is at the terminal.

So a credential resolution failure reads:

```
svcdoctor: services.yaml: targets[3] "payments-rabbit": credentials.password.file
  /run/secrets/rabbit cannot be read: no such file
```

and the aggregate report records that the target's execution failed, naming the target and
nothing about where its credential was supposed to come from.

**The aggregate report carries no credential surface at all** — not a source kind, not a
boolean, not a count. Whether a credential was configured is already visible where it
matters, in that target's own report, as the presence or absence of a
`<SERVICE>_CREDENTIAL_NOT_CONFIGURED` finding. Restating it at run level would be a second
copy of a fact the report already owns.

## 11. Username is identity, not secret

The repository already classified this, twice, and this record inherits both rather than
re-deciding:

- `security.Credential.String` includes the endpoint and the identity and masks only the
  secret, because *"both already appear in the report's target model; the secret is the only
  value that must not"*.
- ADR 0037 added `AttrKindIdentity` specifically so that an identity can be **pseudonymized**
  under redaction — preserved as a correlatable value, stripped of its real text — rather
  than withheld.

So `credentials.username` is an ordinary configuration scalar. It is written in the file, it
appears in a `LOCAL_FULL` report, and it is pseudonymized in a `SHAREABLE_REDACTED` one. It
is **not** a `CredentialRef`, cannot be sourced from `env` or `file`, and there is no
`username: {env: ...}` form — a username is not a secret, and giving it a secret's
indirection would suggest it is.

## 12. Secret file semantics are inherited, not reinterpreted

A `file:` reference uses **exactly** the semantics `--password-file` already has, from ADR
0049 §3 and `internal/cli/secret.go`:

| Question | Answer | Source |
|---|---|---|
| Maximum input | 4 KiB, measured on the **input** and not the trimmed secret | `maxCredentialInput` |
| Reading one byte past the bound | yes, so "at the bound" and "over it" are distinguishable | `readBoundedSecret` |
| Trailing newline | exactly one `\n` or `\r\n` removed | `trimOneLineEnding` |
| A second newline | the operator's data, kept | same |
| Leading or trailing spaces | **kept** — legal password material | same |
| `strings.TrimSpace` | forbidden | same |
| A directory | named as a directory, not as "unreadable" | `readSecretFile` |
| An empty file, or one holding only a newline | yields no credential at all, same as no reference | `credentialFor` |
| The contents, or their length, in an error | never | ADR 0049 §3 |

Two questions ADR 0049 left implicit are **documented here and not changed**, because
Phase 9.0 may record existing behaviour but must not alter it:

- **An embedded NUL is not rejected today.** It is read as an ordinary byte. PostgreSQL
  additionally restricts a password to printable ASCII and refuses it later with
  `UNKNOWN` + a capability failure class; the other three do not. Whether a NUL should be
  refused at the input boundary for every service is recorded in `docs/BACKLOG.md` and is
  **not** decided here.
- **Multiple lines are accepted**, and everything after the first line is part of the
  secret. This follows from "exactly one trailing line ending, and nothing else" and is not
  a separate rule.

**Nothing in this record creates a second interpretation of a secret file.** If Phase 9.1
finds it needs one, that is a change to ADR 0049 and must be argued there, for all four leaf
commands as well.

## 13. Sources that are not in v1

| Source | Why not now | Reopen condition |
|---|---|---|
| `stdin` | ADR 0074 §8: stdin cannot be both the config and a credential, and in fleet mode there are N credentials and one stdin | None foreseen |
| A literal value | §3 | None |
| Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager | Each is a network client with its own TLS, auth, retry and failure semantics, executing before any diagnosis. Each is also a dependency | A concrete need, with its own ADR and its own security review |
| Kubernetes Secret, read from the API | Same, plus an in-cluster identity | Phase 5 platform work, if ever |
| `exec:` / command provider | Arbitrary code execution driven by a config file. It is the single largest surface any of these would add | None. This is a decision, not a deferral |
| A per-run keyring or agent | No stated need | A concrete need |

The v1 set is `env` and `file` because those are what a container runtime and a Kubernetes
pod already provide (ADR 0062), and because between them they need no network, no
credential of their own and no dependency.

## 14. Reopen conditions

1. **A fifth service whose credential is not a username and a password** — a token, a
   client certificate, or a mechanism with two secrets — reopens §2's shape.
2. **A measured need for a secret provider that performs I/O of its own** reopens §13, with
   its own security review, and would be the first time svcdoctor authenticates to something
   in order to diagnose something else.
3. **A measured case where per-target resolution is too late** — a fleet where reading a
   secret is expensive or rate-limited — reopens §5.2's B-for-resolution half, but not the
   preflight half.
4. **Evidence that transient environment residency during preflight is unacceptable**
   reopens §5.1, in the direction of dropping env preflight rather than of caching.

None of these reopens §3, §7 or §8. A plaintext secret in a config file, a widened
authority, and a shared credential object are refused permanently.
