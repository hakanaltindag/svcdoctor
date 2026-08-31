# ADR 0071: A multi-target run is described by one strict YAML document

## Status

**Accepted in Phase 9.0. Not implemented.**

It decides the configuration format, its version, its identity model, which fields the
generic envelope owns and which each service owns, and the resource bounds a
configuration file is parsed under.

`SchemaVersion` stays **1**. No `FailureClass`, no `FindingCode`. It **authorizes one new
dependency in Phase 9.1**, named in section 3, taking the module count from 1 to 2.

Companion records: [0072](0072-multi-target-credential-references.md) decides how a
credential is referenced and resolved, [0073](0073-multi-target-execution-and-budgets.md)
decides how targets are scheduled and bounded, and
[0074](0074-multi-target-report-and-exit-semantics.md) decides what the run reports and
what the process returns.

It applies ADR 0009's explicit-registration rule to a fourth composition point, and it
changes nothing about the four existing leaf commands.

## 1. Decision summary

1. **One format: YAML 1.2, one document, decoded strictly.** JSON is accepted because it
   is a YAML subset, not because a second parser exists.
2. **The configuration carries its own `version: 1`**, independent of the report's
   `SchemaVersion`. A missing or unknown version is a configuration error.
3. **Unknown fields, duplicate keys, anchors, aliases, merge keys and non-core tags are
   all refused.** Four of those six are refused by the parser at no cost; the other two
   need an explicit pre-pass.
4. **Every target carries an explicit `id`.** It is never derived from list position,
   never derived from `host:port`, and a duplicate is an error rather than a last-wins.
5. **A target is an envelope with a typed discriminator and a service-owned `config`
   node.** The generic core never holds a `map[string]any`.
6. **A field is generic only when its semantics are identical across all four services.**
   Where the semantics match but the valid range does not, the field is generic and its
   validation is service-owned.
7. **No templating, no `${VAR}` interpolation, no remote config, no default config path.**

## 2. What a configuration file looks like

```yaml
version: 1

run:
  concurrency: 4
  timeout: 10m

targets:
  - id: orders-db
    type: postgres
    host: orders-db.internal.example.com
    port: 5432
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: require
      ca_file: /etc/ssl/internal-ca.pem
      server_name: orders-db.internal.example.com
    credentials:
      username: svcdoctor
      password:
        env: ORDERS_DB_PASSWORD
    config:
      database: orders

  - id: events-bootstrap
    type: kafka
    host: kafka-1.internal.example.com
    port: 9093
    credentials:
      username: svcdoctor
      password:
        file: /run/secrets/kafka
    config:
      sasl_mechanism: SCRAM-SHA-256

  - id: session-cache
    type: redis
    host: redis.internal.example.com
    port: 6379
    credentials:
      username: svcdoctor
      password:
        env: REDIS_PASSWORD

  - id: task-queue
    type: rabbitmq
    host: rabbit.internal.example.com
    port: 5671
    credentials:
      username: svcdoctor
      password:
        env: RABBITMQ_PASSWORD
    config:
      vhost: /production
```

Every field above already exists as a flag on one of the four leaf commands. Nothing here
is a new capability, and section 7 holds the mapping.

## 3. YAML, and the dependency it costs

### 3.1 The alternatives, and what decided between them

Three were considered. The decision rests on measurements taken in Phase 9.0 against real
libraries, recorded in `docs/validation/MULTI_TARGET_PHASE90_CONTRACT_STUDY.md` §2.

| Option | Dependency | Comments | Duplicate keys | Verdict |
|---|---|---|---|---|
| **JSON only** (`encoding/json`) | none | **no** | **silently last-wins** | Rejected |
| **YAML only** | one | yes | **rejected, with both line numbers** | **Accepted** |
| YAML + JSON as two formats | one | yes | differs by format | Rejected |

The duplicate-key row is the decisive one, and it is measured rather than argued.
`encoding/json` accepts

```json
{"password": {"env": "A"}, "password": {"env": "B"}}
```

and silently takes the second. In a file whose entire purpose is to name which credential
authorizes which endpoint, a silently-discarded credential reference is precisely the
class of defect this project refuses everywhere else — it is the config-file form of the
truncated secret ADR 0049 §3 declines to produce. A YAML decoder rejects it:

```
line 2: mapping key "password" already defined at line 1
```

The comment column is the second reason and the ordinary one. A fleet file is maintained
by hand over years, and `# decommission after the Q3 migration` beside a target is the
only place that sentence can live. A format that cannot hold it is a format operators
work around by keeping a second, unversioned file.

**YAML + JSON as two supported formats was rejected outright.** It buys nothing — a YAML
parser already accepts JSON, measured — and costs two error vocabularies, two sets of
strictness semantics and a "which format am I in" branch in the one package that must be
boring.

### 3.2 Writing a YAML subset parser was considered and rejected

It is the option this repository's history would predict: svcdoctor implemented
SCRAM-SHA-256 rather than take a dependency, and wrote its own AMQP 0-9-1 encoder.

It is wrong here, and the asymmetry is worth stating. A protocol encoder is written
against a specification and validated against real servers, and a divergence shows up as
a failed exchange. A configuration parser is written against a specification and validated
against **what operators believe YAML means** — and a divergence shows up as a file that
parses to something other than what it says. A hand-rolled subset that accepts most of
YAML and quietly misreads the rest is worse than either alternative, because the failure
is silent and lands on the operator's own data.

### 3.3 The module

**`go.yaml.in/yaml/v3`, v3.0.5.** Measured properties:

- **Zero requirements in its own `go.mod`** — not even a test-only one. This is strictly
  better than `gopkg.in/yaml.v3`, whose `go.mod` names `gopkg.in/check.v1`.
- `gopkg.in/yaml.v3` is frozen at v3.0.1 (June 2022) and `go.yaml.in/yaml/v3` is its
  maintained continuation, which retracts `[v3.0.0, v3.0.1]` as belonging to the old path.
- `Decoder.KnownFields(true)` rejects unknown fields with a line number.
- Duplicate mapping keys are rejected by the parser, at every nesting depth, naming both
  lines.
- Alias expansion is bounded: a nine-way seven-deep alias bomb returns
  `document contains excessive aliasing` in 1 ms rather than expanding.
- `!!merge`, `!!binary`, `!!timestamp`, `!!float` and arbitrary `!tags` are each visible
  as a distinct tag on a parsed node, so an allow-list pre-pass can refuse them.

`internal/fleet/config` is the **only** package that may import it. This mirrors ADR 0025's
containment of `kmsg` to a wire package, for the same reason: a dependency that only one
package can name cannot spread by convenience.

The dependency count becomes **2**. `test/security/dependency_test.go`'s `allowedModules`
gains one entry in Phase 9.1, with its licence and this ADR as its reason, which is the
mechanism that test exists to force.

## 4. Versioning

### 4.1 `version: 1`, and not `apiVersion` / `kind`

`apiVersion: svcdoctor.io/v1` plus `kind: DiagnosticRun` exists in Kubernetes to
disambiguate many resource kinds, from many API groups, appearing in one stream. svcdoctor
has one kind in one document. Adopting the ceremony would import a shape whose entire
justification is absent, and the smallest stable model is the one that stays honest as the
project grows.

### 4.2 It is not the report's `SchemaVersion`

Two numbers, two lifecycles. `domain.SchemaVersion` describes what svcdoctor **emits**;
`version` describes what an operator **writes**. Coupling them would force a configuration
bump every time a report field was added, and would tell operators their files were
obsolete when nothing they wrote had changed.

### 4.3 Version behaviour, frozen

| Case | Behaviour |
|---|---|
| `version` absent | **Configuration error.** Not defaulted to 1 |
| `version: 1` | Accepted |
| `version: 2`, or any other value | **Configuration error** naming the supported version |
| A future svcdoctor meeting `version: 1` | Accepts it, or supersedes this record explicitly |
| Unknown field, anywhere | **Configuration error** |
| Deprecated field | None exist in v1. A field is never silently ignored: deprecation means still honoured with a stated meaning, and removal requires a version bump |

**`version` is not defaulted, and that is deliberate.** A versionless file treated as
version 1 becomes a file that silently changes meaning the day version 2 exists. Requiring
it costs one line and removes the entire class.

The version is read by a **lax first pass** before the strict decode — measured to work in
§2 of the study. That ordering is what makes `version: 2` produce *"configuration version 2
is not supported; this build supports version 1"* rather than an avalanche of unknown-field
errors about fields that version 2 legitimately defines.

## 5. Target identity

### 5.1 `id` is required and explicit

An identity that is derived is an identity that moves. Derived from list position, it
changes when a target is inserted above it, so two runs of "the same" file disagree about
which target `targets[3]` was. Derived from `host:port`, it collapses exactly the cases
§32 requires be kept apart: the same PostgreSQL endpoint under two databases, the same
RabbitMQ endpoint under two virtual hosts, the same Kafka bootstrap under two identities.

So it is written down.

### 5.2 The grammar

```
1*63( lowercase letter / digit / "-" / "_" ), starting and ending with a letter or digit
```

- **63 bytes** is the DNS label limit. It is a derivation rather than a round number: it
  guarantees a target ID can be used as a filename component, a label value and a JSON key
  with no escaping, in every consumer this project can foresee.
- **Lowercase is required, not folded.** `Orders-DB` is an error, not a synonym for
  `orders-db`. This is `domain.ServiceID`'s decision applied unchanged — *"case is fixed so
  that `Kafka` and `kafka` cannot both appear and split what should be one service in every
  report and every dashboard query"* — and folding would create two spellings of one thing,
  which is the failure `internal/app`'s host normalization exists to prevent.
- Comparison is byte equality after that. There is no Unicode normalization to disagree
  about, because the grammar admits no non-ASCII byte.

### 5.3 What is not identity

- **The endpoint is not identity.** Duplicate endpoints across targets are supported, never
  deduplicated, and never share a result. See ADR 0073 §9.
- **The service kind is not part of identity.** `orders-db` is unique across the whole
  file, not per type, so `--target orders-db` can never need a type to disambiguate it and
  an aggregate report can never hold two rows a reader must tell apart by a second column.
- **There is no separate display name in v1.** A second human-facing string would have to
  be ordered, redacted and rendered for no diagnostic value. The ID is already
  human-chosen; that is enough.

### 5.4 Duplicates

A repeated `id` is a configuration error naming both occurrences. It is not last-wins, not
first-wins, and not silently suffixed. This is the same refusal-over-resolution posture
ADR 0049 §2 took for two credential sources, for the same reason: the failure a precedence
rule hides is *svcdoctor diagnosed the other one*.

## 6. Service configuration ownership

### 6.1 The shape

```
Target {
  id            generic
  type          generic, the discriminator
  host, port    generic
  timeout       generic
  step_timeout  generic
  tls           generic block
  credentials   generic block           (ADR 0072)
  config        service-owned, opaque to the core
}
```

`config` is held by the generic core as an **unparsed node**, never as
`map[string]any`, and is handed to the registered service decoder, which decodes it into
its own concrete typed struct with unknown-field rejection enabled.

Holding it as a typed node rather than a generic map is not a style preference. Decoding
YAML into `any` re-enables implicit typing, which is how `id: no` becomes the boolean
`false` and `vhost: 1.10` becomes the float `1.1`. Decoding into a struct with string
fields does not: measured, `id: no` yields the string `"no"`. The core never decodes into
`any`, so the whole class is absent rather than defended against.

### 6.2 The two alternatives, and why they lost

**`postgres: {...}` with no `type` key.** Elegant, and it makes the discriminator and the
payload one thing. Rejected because "exactly one service key is present" becomes a
hand-written runtime invariant rather than a type-level one — zero keys and two keys are
both syntactically fine — and because the service is unknown until the keys have been
inspected, so every error raised before that point cannot name it.

**`type: postgres` with the service's fields flat on the target.** Rejected because it
forces the single global struct §6 of the phase brief names as the bad direction: one
struct carrying `database`, `vhost`, `sasl_mechanism` and every future service's fields,
which makes per-service unknown-field rejection impossible. `vhost` on a PostgreSQL target
would have to be accepted.

### 6.3 The registry boundary

Adding a fifth service requires:

1. a config struct and its strict decoder, in that service's own package;
2. its validation, including any range its generic fields need narrowed;
3. its default port;
4. a call into the existing `app.DiagnoseX` composition root;
5. **one line at the single composition point** where the four are wired.

It requires no edit to the runner, the config decoder, the aggregate report, the renderer
or the exit-code mapping. That is the property ADR 0009 asked for, and Phase 9.1's test
matrix proves it by construction rather than by inspection.

Registration is explicit and happens at one place, exactly as `cli.New` wires the four
`diagnose*` function values today. **No `init()` registration, no reflection, no plugin
discovery.**

## 7. Generic versus service-owned fields

### 7.1 The rule

> A field belongs in the generic envelope only when its semantics are identical across
> every supported service. Where the semantics are identical but the valid range is not,
> the field is generic and its **validation** is service-owned.

The second clause is the one that earns its place, and it has a measured instance: §7.4.

### 7.2 The mapping, derived from the four flag sets

| Config field | Owner | Derivation |
|---|---|---|
| `id`, `type` | generic | Exist only in multi-target mode |
| `host`, `port` | **generic** | All four `app.*Params` document this pair in near-identical words as *"the logical endpoint the operator asked about"* and as the credential authority boundary. The binding must be constructed once or it can drift per service |
| default port | **service** | 5432 / 9092 / 6379 / 5672. Supplied by the registered factory; nothing infers a service from a port (ADR 0011) |
| `timeout` | generic | The whole-run bound `--timeout` on all four commands, now the per-target bound |
| `step_timeout` | generic field, **service-owned range** | §7.4 |
| `tls` | generic block, **service-owned interpretation** | §7.3 |
| `credentials.username` | generic field, **service-owned requiredness** | All four map it to `credentialFor(host, port, <identity>, secret)`. PostgreSQL additionally requires it as the startup role; the other three accept its absence |
| `credentials.password` | generic | ADR 0072 |
| `config.database` | postgres | `--database` |
| `config.sasl_mechanism` | kafka | `--sasl-mechanism`, required |
| `config.vhost` | rabbitmq | `--vhost`, default `/` |
| — | redis | Redis adds no service field |
| `output`, `shareable` | **neither** | Run-level, not target-level. They describe the artifact, not a target |

### 7.3 TLS is generic, and that is a finding rather than an assumption

The phase brief warns that TLS may look generic without being it, naming PostgreSQL's
in-band `SSLRequest` against everyone else's direct handshake.

The repository already answered this. `internal/cli/tls.go` is a single file holding the
whole TLS-flag contract for all four services, and it says so: *"The four are identical
across services on purpose, and grouping them makes that a fact of the type rather than a
coincidence of two flag sets."* ADR 0060 forced that unification after finding the contract
in two places where the two disagreed.

So the split is already made, and this record inherits it rather than re-deriving it:

- the **block** — `mode`, `ca_file`, `server_name`, `insecure` — is generic, and so is the
  ADR 0060 refusal of the last three under `mode: disable`;
- what `require` **means on the wire** is service-owned, and stays where it already is:
  `tlsPlan` for PostgreSQL, the direct-handshake options for the other three.

Adopting a different split here would put the contract back in two places, which is the
defect ADR 0060 closed.

### 7.4 `step_timeout` proves the second clause

The semantics are identical in all four `app.*Params`: *"optionally bounds each probe call
and each protocol exchange"*.

The valid range is not. `internal/cli/rabbitmq.go` refuses a `--step-timeout` of 3 s or
less, because several RabbitMQ refusal paths hold the socket open for exactly that long on
purpose (ADR 0070 §8) and a shorter budget reports the broker's deliberate delay as
svcdoctor's own deadline expiring. The other three have no such floor.

Making the field service-owned would repeat it four times. Making its range generic would
either impose RabbitMQ's floor on services that do not need it, or drop it for the service
that does. Generic field, service-owned validation is the only split that is true.

## 8. Parsing bounds and file security

Every bound below has a derivation. The measurements are in the study; the arithmetic is
here.

| Bound | Value | Derivation |
|---|---|---|
| Config file size | **1 MiB** | max targets × a generous 2 KiB per fully-specified, commented target block. Coincides with the existing `maxCAFileSize` |
| Targets per file | **512** | ADR 0073 §11 derives it from measured report sizes and a memory budget |
| Documents | **1** | A second document is a second run nobody asked for. Measured: the second `Decode` must return `io.EOF` |
| File type | **regular file, after symlink resolution** | Below |
| Anchors / aliases / merge keys | **refused** | §8.2 |
| YAML tags | **allow-list**: `!!str !!int !!bool !!null !!map !!seq` | §8.2 |
| Duplicate keys | **refused** | Free; the parser does it |
| Unknown fields | **refused** | Free; `KnownFields(true)` |
| Env interpolation, templating | **absent** | §8.3 |

### 8.1 Symlinks are followed; the final file must be regular

Refusing symlinks would break ADR 0062's own Kubernetes execution model: a projected
ConfigMap or Secret volume is a symlink farm through `..data/`, so a config file mounted
the documented way is always reached through one.

The final target must be a regular file. A directory, FIFO, device or socket is a
configuration error naming what was found. This is the same posture `--password-file` and
`--tls-ca-file` already take, and consistency across the three file inputs is worth more
than a bespoke rule for one of them.

### 8.2 Anchors, aliases, merge keys and tags

Four of the six refusals in the table are free. These two are not, and the study measured
exactly why.

**Anchors and aliases expand silently.** A document using `&t` / `*t` decodes without
error into two identical targets. They are refused rather than bounded: an alias is a way
of writing the same target twice, the duplicate-ID rule already forbids that outcome, and
a file where the same bytes appear in two places is a file where a reader cannot tell what
a target actually says without executing the aliasing in their head. The alias-expansion
budget the library already enforces is a backstop, not the policy.

**A merge key needs its own refusal.** Measured: `<<: {id: a}` merges into a struct
*without* an alias and *without* tripping `KnownFields(true)`. So refusing aliases does not
refuse merges, and the pre-pass must reject the `!!merge` tag by name. This is recorded
because it is the one hazard in this section that a careful implementer would reasonably
expect to be covered by the refusal above it, and it is not.

**Tags are an allow-list, not a deny-list.** `!!binary`, `!!timestamp` and `!!float` are
each unnecessary for this schema and each carries a decoding behaviour nobody needs; a
deny-list would have to be extended every time the library gains a tag. Fail closed.

### 8.3 No interpolation, no templating, ever

`host: ${DB_HOST}` is not supported, and support is not deferred — it is refused.

The moment any string can name an environment variable, the file stops describing the run.
Reading it no longer tells an operator what svcdoctor will do, and reproducing an incident
requires the environment as well as the file. It is also a templating language, and a
templating language grows conditionals.

Environment access exists at exactly one place in the whole configuration: the
`password.env` reference of ADR 0072. That is a typed field with one meaning, not a string
substitution, and it is the only reason the runner reads the environment at all.

**There is no default config path.** `--config` is required. A searched default is ambient
configuration in the same way `${VAR}` is ambient: it makes the run depend on the working
directory.

## 9. Error reporting

A configuration error names the file, the target ID when one has been read, the field path,
and the reason:

```
svcdoctor: services.yaml: targets[3] "payments-rabbit": credentials.password:
  exactly one of "env" or "file" is required, and both were given
```

It never contains a secret value, a resolved environment value or the contents of a
credential file. It **may** contain an environment variable name or a file path, on stderr
only — that is ADR 0049 §3's existing decision, *"the path appears in errors, because a file
svcdoctor cannot use has to be nameable or the operator cannot fix it"*, and ADR 0072 §8
carries the split between what stderr may say and what the report may serialize.

Line and column reporting comes free from the decoder — measured, every strictness error
carries a line — so it is used where the decoder supplies it and never synthesized where it
does not.

## 10. Rejected alternatives

| Alternative | Reason | Reopen condition |
|---|---|---|
| TOML | Named as unwanted in the brief, and it buys nothing over YAML that is not already free | None foreseen |
| HCL, Jsonnet, CUE, Starlark | Each is a language, and a configuration language grows conditionals until the file no longer states what will happen | None |
| JSON only | Section 3.1: no comments, and silently last-wins duplicate keys | If the YAML module becomes unmaintained and no successor exists |
| Auto-detect format by extension | Two vocabularies, and the branch is reachable by a rename | None |
| Default config path search | Ambient configuration; the run depends on the working directory | None |
| Remote config over HTTP, or from git | Fetching config is a network operation before any diagnosis, with its own TLS, auth and failure semantics | A concrete fleet-management need, decided separately |
| Optional `labels: {}` | Cardinality, sensitivity, ordering and future selector semantics, for a use case nobody has stated. The ID is already human-chosen | A concrete filtering or grouping requirement |
| A separate `name:` beside `id:` | A second human string to order, redact and render, for no diagnostic value | If IDs prove too constrained to be readable |
| Deriving `id` from `host:port` | Collapses the duplicate-endpoint cases §5.3 requires be kept apart | None |
| Folding `Orders-DB` to `orders-db` | Two spellings of one thing, which `domain.ServiceID` already refuses | None |

## 11. Reopen conditions

This record is reopened by:

1. **The YAML module becoming unmaintained with no successor.** The format decision and the
   library decision are separable, and §3.1's comparison would be re-run.
2. **A fifth service whose configuration cannot be expressed** in the envelope of §6.1
   without a generic field that fails §7.1's test.
3. **A measured need for more than 512 targets or a file above 1 MiB**, which reopens
   ADR 0073 §11's derivation first.
4. **A second document kind** — a config file that must describe something other than a
   diagnostic run — which is the only circumstance under which `apiVersion` / `kind` earns
   its ceremony.

Nothing here is reopened by an operator finding the format inconvenient. Inconvenience is
an argument for better defaults and better errors, not for a parser that guesses.
