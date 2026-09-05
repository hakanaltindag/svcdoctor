# Reading svcdoctor output

**This document is authoritative for the output contract**: what the terminal shows, what the
JSON guarantees, and exactly what a shareable report replaces.

Two output forms, selected with `--output`:

| `--output` | Result |
|---|---|
| `text` | The human-readable terminal report (**default**) |
| `json` | The canonical document |

**JSON is canonical.** The terminal form is derived from it. Parse the JSON; do not parse the
terminal text, whose layout is a presentation detail and will change.

## The terminal report

```text
svcdoctor · postgres · orders-db.internal:5432

  ✓ PASS  DNS  2.3ms

  Path 10.0.4.17:5432 · continued
    ✓ PASS  TCP             1.8ms
    ✓ PASS  SSLRequest      0.9ms
    ✓ PASS  TLS             4.1ms
    ✓ PASS  Startup         1.2ms
    ✓ PASS  Authentication  2.8ms
    ✓ PASS  Session         0.4ms

Findings
  none

Result
  status     OK                   no target-side error was proven
  outcome    session established
  execution  complete
  duration   13.5ms
```

**The header** names the service and the endpoint you asked for.

**The stage rows** are one line per attempted exchange, with the state, the elapsed time, and —
when something went wrong — a failure class such as `TCP_CONNECTION_REFUSED`. Rows are grouped
into a `Path` per resolved address, because a hostname with three addresses is three journeys and
they can differ.

Five states appear:

| | Meaning |
|---|---|
| `✓ PASS` | The exchange completed and did what it was supposed to |
| `✗ FAIL` | The exchange completed and the answer was a failure |
| `? UNKNOWN` | svcdoctor could not learn the answer — a local budget expired, or the capability is one it does not implement. **Not a failure of the target** |
| `· SKIPPED` | Deliberately not attempted, with the reason recorded — a policy refusal, or a prerequisite that failed |
| `· not reached` | The journey stopped before this stage |

**Findings** are the conclusions. Each carries a code, a severity, the subject it is about, a
one-line summary, the detail, what the finding does *not* establish, and a `→` recommendation.

A recommendation may carry a classification, shown in brackets after the action:

```text
    → Identify the connection limits applicable to this attempted session …  [NEXT_EVIDENCE / COMPARE / you must collect]
      The endpoint stated that a connection limit applying to this session had been reached …
```

| Part | Meaning |
|---|---|
| `NEXT_EVIDENCE` | an **observation** that would separate the remaining explanations. It changes nothing |
| `REMEDIATION` | a **change** to make. svcdoctor emits one only from a CONFIRMED finding at HIGH confidence |
| `OBSERVE` / `VERIFY` / `COMPARE` / `CONFIG_CHANGE` | what taking it would cost, by blast radius |
| `svcdoctor can collect` | a differently configured run — a larger budget, for instance — could take this observation. **It does not mean svcdoctor took it, or will** |
| `you must collect` | svcdoctor cannot take it from where it stands. This is the common case and is said plainly rather than implied away |

The indented line beneath is the **rationale**: why that observation discriminates.

A recommendation with no brackets is one svcdoctor has not classified. That is normal — most of
the advice in the product predates the classification — and it means *nobody said*, never *this is
safe*.

**The `Result` block** is the summary. `status` is the whole report's verdict, `outcome` is the
service's terminal question — a session, Kafka metadata, a PING, a virtual host — and `execution`
says whether svcdoctor's own run finished.

A multi-target run wraps one of these per target and ends with a `Run` block.

## The vocabulary

Six words do most of the work, and the differences between them are the product.

| Term | What it is |
|---|---|
| **Evidence** | One recorded fact about one exchange: what was attempted, what state it reached, how long it took, and its normalized attributes. Evidence is never a conclusion |
| **Finding** | A conclusion drawn from evidence. It names the exact evidence identifiers that produced it |
| **Confirmed** | A finding whose evidence establishes it directly |
| **Hypothesis** | A finding the evidence supports but does not establish. It says so |
| **Confidence** | `HIGH`, `MEDIUM` or `LOW`. **Separate from severity**, never fused into one score, never a percentage |
| **Recommendation** | What to inspect next. Never an action svcdoctor took, and never an action it will take |

Severity is `INFO`, `WARN`, `ERROR` or `CRITICAL`. Severity and confidence are independent: a
`CRITICAL` finding held with `LOW` confidence is a real and useful thing to report, and averaging
them would destroy it.

### Claim discipline

The rules the whole output obeys:

- **`UNKNOWN` is not `FAIL`.** A capability svcdoctor does not implement, or a stage it could not
  complete, is a gap in the tool — not a defect in the target.
- **A local timeout is not a remote failure.** The budget expired. Nothing was learned.
- **No credential is not a rejected credential.** Nothing was sent, so nothing was refused.
- **A finding is valid from the vantage it was recorded at**, unless the evidence proves
  otherwise. `vantageDependent` says which.

### Observations are not findings

The Result block also prints **endpoint-reported observations** — what the endpoint said about
itself. They are not findings: they carry no severity, no confidence and no recommendation, they
move no exit code, and no rule reads them. They are shown because an operator wants the fact, and
they stop there because svcdoctor holds no expectation to compare any of them against.

PostgreSQL prints two, both describing **the session svcdoctor established** and nothing else:

| Line | Values | What it means |
|---|---|---|
| `recovery` | `in recovery` / `not in recovery` | the session was reported as attached to a server in recovery, or not |
| `default transaction read-only` | `on` / `off` | the session reported that its transactions default to read-only, or that they do not |

**The second line prints the parameter's own value, deliberately.** `off` is *not* rendered as
"read write", "writable" or anything else positive: the parameter says one default is not set,
and every positive phrasing of that would be a claim about what the session can do. `on` is not
rendered as "writes will fail" for the mirror-image reason.

**They are independent and neither follows from the other.** A standby can report `in recovery`
while `default transaction read-only` is `off`; a primary can report `not in recovery` while it is
`on`, which is what `ALTER ROLE … SET default_transaction_read_only = on` does. Neither
combination is a contradiction and svcdoctor does not present one as such.

**Neither line answers "will my writes work."** That depends on the session-local
`transaction_read_only`, on object, database and row-level privileges, on what the application
does next, and — behind a pooler — on which backend serves the next transaction. svcdoctor runs
no query and measures none of it. A line is printed only when the endpoint sent the parameter; a
server that sent none produces no line, and never a default.

### A finding's explanation is as specific as its evidence, and no more

`detail` is canonical: it is a field of the finding, it is in the JSON, and the terminal prints
it verbatim. So its specificity is a claim like any other, and it moves only when the evidence
already earned it.

**RabbitMQ capacity ceilings are the worked example.** A broker enforces three separate connection
limits — one for the node, one for a virtual host, one for a user — and refuses with a sentence
naming which. svcdoctor classifies that sentence into a closed value it owns, and
`RABBITMQ_CONNECTION_NOT_PERMITTED` now says which ceiling the endpoint named:

```text
The endpoint named a connection limit scoped to the node.
The endpoint named a connection limit scoped to the virtual host.
The endpoint named a connection limit scoped to the user.
```

The three lead to different places: a node ceiling affects every client on that broker, a virtual
host ceiling affects one tenant, and a user ceiling most often means one application's own
connections. Before this, all three read *"Where the endpoint named a capacity ceiling…"* and
recommended reviewing all three.

**What the sentence does not say, and never will.** That the limit is reached everywhere, that it
is too low, that demand is abnormal, that anything is leaking, that the broker is unhealthy, or
what to change. The finding still ends with *"it proves nothing about why, for how long, or what
to change, and a second run a moment later may succeed."* The recommendation is unchanged.

**Absence of a scope proves nothing.** A broker whose reply text was truncated — which happens
with long virtual host and user names — produces no recognizable value, and the finding keeps its
general wording. A capacity ceiling was still reached; svcdoctor simply could not read which.

**It is the outcome that earns the sentence, not the product.** LavinMQ reaches the same
virtual-host value through its own reply wording and gets the same sentence. Nothing in svcdoctor
branches on which implementation answered.

## Execution state versus diagnosis

**This is the distinction to understand before automating anything.** They are two axes and
neither implies the other.

| Axis | Question | Where |
|---|---|---|
| **Execution state** | Did svcdoctor manage to measure this target? | `targets[].executionState` |
| **Diagnosis** | What did the measurement find? | `targets[].report.summary.status` |

Execution has four states:

| | Meaning |
|---|---|
| `COMPLETED` | svcdoctor measured this target and produced a report |
| `NOT_STARTED` | The run ended before this target began. **No report** |
| `CANCELLED` | The run ended this target while it was in flight. A partial report survives |
| `EXECUTION_FAILED` | svcdoctor could not run this target locally. **No report** |

**`COMPLETED` does not mean the service is healthy.** It means svcdoctor finished the journey it
set out to make. A rejected password is:

```text
executionState  COMPLETED          svcdoctor did its job
summary.status  PROBLEMS_FOUND     and the job found a problem
```

And the converse is just as real. `EXECUTION_FAILED` carries **no report at all**, because
nothing was measured — so it makes no claim about the endpoint, in either direction. A target
svcdoctor could not run is not a target that is down.

`incomplete` is a third, orthogonal flag: `OK` **and** incomplete is a valid, common combination
meaning svcdoctor's own budget stopped the measurement before anything was proven.

## JSON

### One target

```json
{
  "schemaVersion": 1,
  "run": {
    "svcdoctorVersion": "v0.4.0",
    "startedAt": "2026-09-01T12:00:00Z",
    "duration": "13.5ms",
    "service": "postgres",
    "tlsVerificationDisabled": false,
    "outputMode": "LOCAL_FULL"
  },
  "target":   { "requested": "orders-db.internal:5432" },
  "vantage":  { "source": "LOCAL_HOST", "host": "runner-7" },
  "evidence": { "nodes": [ … ], "relationships": [ … ] },
  "findings": [ … ],
  "summary": {
    "status": "OK",
    "findingCountsBySeverity": { "info": 0, "warn": 0, "error": 0, "critical": 0 },
    "skippedEvidenceCount": 0,
    "unknownEvidenceCount": 0
  },
  "security": { "outputMode": "LOCAL_FULL", "tlsVerificationDisabled": false, "credentialForwardingEnabled": false }
}
```

`schemaVersion` is `1`. The evidence is a **graph**, not a list: `relationships` carry the parent
edges, because topology discovery can create additional endpoint chains.

### A run

```json
{
  "schemaVersion": 1,
  "kind": "run",
  "run": { "svcdoctorVersion": "v0.4.0", "concurrency": 4, "outputMode": "LOCAL_FULL", … },
  "targets": [
    { "targetId": "orders-db", "service": "postgres", "executionState": "COMPLETED",
      "report": { … }, "incomplete": false },
    { "targetId": "cache", "service": "redis", "executionState": "EXECUTION_FAILED",
      "executionError": { "class": "INTERNAL", "message": "…" } }
  ],
  "summary": {
    "targets": 2, "completed": 1, "notStarted": 0, "cancelled": 0, "executionFailed": 1,
    "withProblems": 0, "incompleteReports": 0, "status": "OK", "incomplete": true
  }
}
```

The aggregate has its **own** `schemaVersion`, and `kind: "run"` distinguishes it from a
single-target document. It **wraps** reports and never merges them: an embedded report is
byte-identical to the same single-target invocation.

`executionError.class` is a closed vocabulary — `CREDENTIAL_RESOLUTION` or `INTERNAL`. Its
`message` is prose meant for the operator, so read the class, not the message.

### What the JSON guarantees

- `schemaVersion` is `1` for both documents and changes only for a breaking change.
- Exit codes `0`, `1` and `4` write exactly one document to stdout and nothing to stderr.
- Exit codes `2` and `3` write nothing to stdout.
- Every decision a machine needs is a typed field. **Nothing important requires parsing prose.**
- The CLI injects nothing into the document: no process exit code, no session flag. Those are
  process- and presentation-level facts and the schema does not carry them.

`jq` recipes for the common questions are in [`CI.md`](CI.md#reading-the-artifact). The full model
is [`REPORT_SCHEMA.md`](REPORT_SCHEMA.md).

### One known limit, stated rather than worked around

**A single-target JSON document carries no completeness flag.** Whether svcdoctor's own execution
finished is reported by the **exit code** — `4` rather than `0` or `1` — and an artifact file does
not carry the exit code with it.

So a consumer that stores only `svcdoctor diagnose … --output json` cannot later tell a complete
run from one that was cut short. If you need completeness *in the file*, use
`svcdoctor run --config` — even for a single target — whose aggregate carries
`summary.incomplete` and `targets[].incomplete`.

This is a real asymmetry. It is documented rather than fixed because `schemaVersion` is frozen at
1 and a supported route already exists.

## Shareable reports

```sh
svcdoctor diagnose postgres --host db.internal --user app --shareable --output json
svcdoctor run --config services.yaml --shareable --output json
```

`--shareable` emits the `SHAREABLE_REDACTED` projection of the same report instead of the local
one. The diagnosis is identical and **the exit code is unchanged**: redaction changes what a
shared copy reveals, never what was concluded.

### What is replaced

| Category | Becomes |
|---|---|
| Hostnames | `host-001`, `host-002`, … |
| IP addresses | `ip-001`, `ip-002`, … |
| Logical identities — role, database, virtual host, username | `identity-001`, … |
| Evidence identifiers | `evidence-001`, … |
| Target identifiers, in a run | `target-001`, … |
| The local vantage host | `host-001` |
| An execution failure's message | A sentence naming its class, with the local detail withheld |

Pseudonyms are **stable within a document**, so a host appearing in two targets gets one
pseudonym and the relationships between target, evidence and findings stay readable. The number
of substitutions of each kind is reported in `security.redactions`, so you can see that the
transformation ran and how much it did.

### What is preserved, deliberately

**Ports, durations, timestamps, service names, finding codes, severities, confidences,
recommendations, evidence structure and every diagnostic conclusion.** A report with those removed
would not be worth sharing.

### What it is, in exact words

It is **pseudonymization**, not anonymization. Say that, and not more:

- It is **not anonymous.** A consistent pseudonym is a correlation handle: a reader can tell that
  two targets share a host, and that is information the document exists to convey.
- It is **not a compliance control** for any named regime.
- It is **not unconditionally safe to publish.** The preserved set above — a port, a duration, a
  timestamp, a topology shape — is information about your infrastructure.

Review a shared report against your own disclosure requirements before sending it.

### It fails closed

After redaction, svcdoctor re-reads the finished document and checks that no value it knew to be
identifying is still present. If that check cannot confirm a covered value was replaced,
**svcdoctor emits no report at all and exits 3** rather than writing a partially redacted artifact
to stdout.

The check covers the categories in the table above. A value in none of those categories is not
covered by it — which is why an execution failure's message is *replaced* rather than filtered:
prose cannot be verified the way a known value can.

The redaction policy is recorded in [`SECURITY.md`](SECURITY.md).
