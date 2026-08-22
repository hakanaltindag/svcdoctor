# ADR 0049: A secret arrives by file or by pipe, and never by argument

## Status

**Accepted, and implemented in Phase 5.2.**

`internal/cli` reads `--password-file` and `--password-stdin`, builds a
`security.Secret`, binds it to the logical endpoint and hands it to
`internal/app`. `security.Reveal` stays at **two** call sites, both in wire
packages, and `internal/cli` cannot reach either — a depguard rule denies the
wire import and forbidigo denies the call.

**One edge the record implied rather than stated, now settled.** The 4 KiB bound
applies to *the input as read*, not to the trimmed secret: §3 says "Read the file
whole, subject to a bounded maximum" and "Reject **input** above the bound", and
nothing here bounds the result. So a 4096-byte password followed by a newline is
4097 bytes of input and is refused. The distinction is only visible within one
byte of a limit no real password approaches, and refusing is the safe direction.

**One consequence of the security API worth recording**, because it is not
obvious and getting it wrong sends an empty password to a real server:
`security.NewSecret("")` is the zero `Secret`, but `security.Credential.IsZero`
reads only the **endpoint**. A credential built around an empty secret is
therefore *not* zero, and `internal/adapter/postgres` would walk past its
"nothing to present" branch and attempt SCRAM with an empty password. So an empty
source builds **no credential at all**, which is the honest mapping: an empty
file, a file holding one newline, and no flag at all all mean the run was given
nothing to present, and all reach `POSTGRES_CREDENTIAL_NOT_CONFIGURED`.

It decides how `svcdoctor diagnose postgres` accepts a password, which sources
are refused and why, and what the CLI may do with the value once it holds one.

No `FindingCode`, no `FailureClass`, no schema field and no dependency. It adds
no `security.Reveal` call site: the count stays **two**, both in wire packages.

## 1. Context, and why this is its own record

ADR 0048 decides the CLI's output and process boundary. This is a different kind
of decision with a different failure mode: getting the output boundary wrong
produces a misleading report, and getting this wrong leaks a production
credential into a shell history file, a process table or a CI log. Splitting them
means this one can be reviewed on its own terms.

Everything below sits on top of authority the repository already has.
`security.Secret` masks `String`, `GoString`, `Format`, `MarshalJSON` and
`MarshalText`; `security.Credential` binds a secret to a logical endpoint;
`security.Reveal` is confined by `forbidigo` to wire packages. This ADR consumes
all three and widens none of them.

## 2. Decision

v0.1 accepts a password from exactly two sources:

```text
--password-file <path>
--password-stdin
```

They are **mutually exclusive, with no precedence**. Supplying both is an invalid
invocation: exit 2, on stderr, no report.

Precedence rules were considered and rejected outright. A precedence order is a
rule an operator has to remember under pressure, and the failure it hides —
"svcdoctor used the other credential" — is exactly the one that costs an hour
during an incident. Refusing ambiguity is stronger than resolving it.

**Supplying no credential is valid input**, and this is the part that makes the
whole design simpler. An endpoint that demands authentication produces
`POSTGRES_CREDENTIAL_NOT_CONFIGURED` — CONFIRMED, WARN, with `SummaryStatus` `OK`
and exit 0 (ADR 0046). That is a truthful, useful diagnosis rather than a usage
error, so the CLI never has to acquire a credential it was not given, and needs
no prompt.

## 3. `--password-file`

- Read the file whole, subject to a bounded maximum.
- Trim **exactly one** trailing line ending — `\n` or `\r\n` — if present, and
  nothing else. `strings.TrimSpace` is forbidden: a leading or trailing space is
  legal PostgreSQL password material, and silently removing it would turn a
  correct credential into `POSTGRES_CREDENTIALS_REJECTED`, which is the single
  most misleading outcome this tool can produce. One trailing newline is trimmed
  because every editor and `echo` adds one; anything more is the operator's data.
- Reject input above the bound with a usage error rather than truncating it. A
  truncated secret authenticates as a wrong one.
- Convert directly into `security.Secret`; the plaintext is not retained
  elsewhere, logged, or echoed.
- The **path** may appear in a CLI error — a missing or unreadable file has to be
  nameable. The **contents** never appear anywhere.

**The bound is 4 KiB** for v0.1. It is far above any password a SCRAM exchange
can carry (svcdoctor already restricts passwords to printable ASCII, ADR 0038
§11) and far below a size that indicates the operator pointed at the wrong file.
A file larger than this is much more likely to be a certificate, a key or a
config than a password, and failing loudly is the safer answer.

## 4. `--password-stdin`

- Read stdin once, to EOF, under the same bound and the same one-trailing-newline
  rule.
- **No prompt, no echo, no `Password:` line.** stdin is an input channel, not a
  conversation, and printing a prompt would put non-artifact bytes on a stream
  ADR 0048 keeps clean.
- The intended automation shape is the ordinary one:

```sh
printf '%s' "$PW" | svcdoctor diagnose postgres --host db --user app --password-stdin
```

There is no conflict with terminal or JSON output: those go to stdout, this
reads stdin.

## 5. Rejected sources

| Source | Why | Reopen when |
|---|---|---|
| `--password <literal>` | Lands in shell history and in the process table, where every other user on the host can read it. No mitigation exists at the CLI layer | never |
| Environment variable | Inherited by every child process, visible through `/proc` on some systems, and nothing in this repository contracts a variable name. Adding one also re-opens the precedence question §2 closed | A contracted variable and a precedence decision both exist |
| Interactive prompt | Needs terminal control to suppress echo, which means `golang.org/x/term` — a dependency — and it is unnecessary, because no credential is a valid, well-diagnosed input (§2) | Operators ask for it and the dependency is decided |
| DSN / connection URI | Combines the secret, the target and TLS semantics in one string, and pulls libpq compatibility — `sslmode`, `prefer` — that ADR 0036 §4 deliberately does not implement | — |
| Keychain, Vault, cloud secret managers | Real future capability, each with its own authentication and failure modes; none belongs in the first CLI | A concrete deployment demands one |

**There is no hidden fallback source.** If neither flag is given, svcdoctor holds
no credential — it does not consult a file, a variable or an agent on its own
initiative.

## 6. Secret authority is unchanged

The CLI constructs a `security.Secret` and a `security.Credential` bound to the
logical endpoint, and hands the credential to `internal/app` through the existing
`PostgresParams.Credential` field.

- The **CLI must not call `security.Reveal`**, and `forbidigo` already fails the
  build if it does.
- The **renderer never receives the secret**, in any form. `render.Input` carries
  a report and a boolean.
- The credential is authorized by the logical endpoint the operator named, never
  by a resolved address (ADR 0028 §2). That check already happens inside
  `Authenticate`; the CLI does not duplicate it.

No secret may appear in stdout, stderr, the report, a `Finding`, an `Evidence`
node, an `EvidenceID`, an error string, or panic formatting. The masking on
`security.Secret` makes the common accidents — `%v`, `%+v`, `json.Marshal` — safe
by construction rather than by review.

## 7. Interaction with the transport policy

`security.CredentialTransportPolicy` has one member, `RequireVerifiedTLS`, so a
credential crosses only a verified-TLS channel. A run that supplies a password
alongside `--tls-insecure` or `--tls disable` therefore sends nothing and records
`POSTGRES_CREDENTIAL_WITHHELD`.

That is existing committed policy surfacing at the CLI, not a new rule, and
ADR 0048 §15 requires the flag help to say so. The CLI does not warn, override or
second-guess it: the report already states it, with the channel evidence attached.

## 8. Test obligations for Phase 5.2

- Both flags together → exit 2, stderr, no report.
- Neither flag against a SCRAM endpoint → `POSTGRES_CREDENTIAL_NOT_CONFIGURED`,
  WARN, exit 0.
- A file whose last byte is `\n` and one without produce the **same** secret.
- A password with a leading and a trailing space survives byte-identically.
- Oversized input → exit 2, not a truncated authentication attempt.
- A missing or unreadable file names the path and never its contents.
- The password appears in no stream, no report, no error, in either output mode
  and in both security modes.

## 9. What would falsify this

- An operator's correct password rejected because svcdoctor trimmed it.
- A credential recovered from a shell history, a process table or a CI log after
  a documented invocation.
- A prompt turning out to be genuinely necessary because no-credential runs are
  unusable in practice.
