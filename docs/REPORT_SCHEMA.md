# Canonical Report Model

This document specifies the **concepts** the canonical report must carry. It is an
architecture-level specification, not a final JSON Schema and not an implementation plan.

Phase 1 implements these concepts. Field names below are conceptual; exact Go types and
serialization details are decided during implementation.

## Core principle

JSON is the canonical representation. Terminal, Markdown, and HTML are derived renderers.

The report model is independent of renderer formatting. A renderer selects, orders, and
presents what the model already contains. It does not add fields, compute severity, derive
new conclusions, or discover secrets.

If a renderer needs a value, that value belongs in the canonical model.

## Top-level structure

```text
schemaVersion
run
target
vantage
evidence
findings
summary
security
```

---

## 1. schemaVersion

Initial value: `1`.

Versioning policy:

- v0.1 development prefers additive changes.
- Removing a field, or changing the semantic meaning of an existing field, requires an
  explicit schema decision recorded as an ADR.
- Renderers consume the canonical report model. A renderer must not invent its own fields to
  compensate for a gap in the model.

This is an early v0.x project. The policy above states an intent to avoid gratuitous
breakage during v0.1; it is not a long-term compatibility guarantee.

---

## 2. run

Execution metadata for the run that produced this report.

Minimum concepts:

- svcdoctor version
- timestamp of the run
- execution duration
- selected service
- execution mode
- whether TLS verification was disabled
- whether the report is local/full or shareable/redacted

The last two also appear in the `security` section, which is the authoritative place for
report-interpretation warnings. `run` carries them as basic run facts; `security` carries
their consequences. They are stored once, in the security metadata, and written into both
sections from that one value, so the two can never disagree.

**Execution mode is deliberately not implemented.** No document defines its vocabulary, and
the two things it could mean already have owners: where a run executed from is `vantage`
(ADR 0012), and whether it completed fully is incompleteness, which
`docs/ARCHITECTURE.md` section 13 assigns to the summary and the exit code. It can be added
when a real execution mode exists that neither of those already expresses.

---

## 3. target

What the user asked svcdoctor to inspect, after L0 normalization.

Conceptually:

- Kafka: the bootstrap endpoint or endpoints
- PostgreSQL: the DSN or multi-host target

The target records what was requested and how it was normalized, so a reader can tell the
difference between what the user typed and what svcdoctor actually inspected.

> **Security rule: the canonical report must never contain plaintext credentials.**

A DSN-shaped target is recorded in a form with credential material removed, not merely
visually masked at render time.

---

## 4. vantage

Vantage is a first-class concept, not metadata.

A vantage identifies **where the probes were executed from**.

Conceptual fields:

- host
- environment
- network context
- source type, such as local host or in-cluster execution
- Kubernetes context/namespace, only when that becomes relevant in a later phase

Kubernetes vantage detail is deliberately under-specified at this stage.

> **Semantic rule: a connectivity finding is only valid from the recorded vantage point, unless the evidence explicitly proves otherwise.**

This is the most easily misread part of a shared report. "broker-2 is unreachable" is a claim
about a network position, not about the cluster. Every connectivity and topology finding
retains its vantage context, and renderers surface the vantage prominently rather than
burying it in run metadata.

See ADR 0012.

---

## 5. evidence

Normalized, deterministic diagnostic data.

### Forbidden content

The canonical evidence model must not contain raw runtime or protocol-library objects.
Examples that are explicitly forbidden:

```text
*kmsg.MetadataResponse
*tls.ConnectionState
*net.OpError
map[string]any
```

Normalization happens at the probe or adapter boundary. See ADR 0010.

### Conceptual fields

```text
id
parent / parents
subject
layer
step
state
failureClass
attributes
startedAt
duration
origin
```

Not every field is mandatory on every node. `failureClass` is meaningless on a `PASS` node;
`parents` is empty at the root.

- `id` is stable and deterministic within a run, so findings can reference it.
- `subject` is the endpoint or target the node describes.
- `layer` is one of L0-L6 (see `docs/ARCHITECTURE.md` section 2).
- `step` names the concrete operation, for example a DNS lookup or an ApiVersions exchange.
- `origin` distinguishes an endpoint the user supplied from one discovered through topology.

### States

```text
PASS | FAIL | DEGRADED | UNKNOWN | SKIPPED
```

Semantics:

- `PASS` — the step succeeded from this vantage.
- `FAIL` — failure is **positively evidenced**.
- `DEGRADED` — the step succeeded but with a defect worth reporting.
- `UNKNOWN` — the result could not be determined.
- `SKIPPED` — the step was intentionally not executed.

Claim rules:

- Unsupported by svcdoctor is not target failure. A capability gap in svcdoctor is `UNKNOWN`.
- Insufficient privilege is not healthy and not necessarily target failure. It is `SKIPPED`
  or `UNKNOWN`, with the required privilege recorded.
- A local execution timeout must not automatically become a remote failure. An exhausted
  local budget means nothing was learned about the target.

A `SKIPPED` node records why it was skipped and which evidence blocked it. Without that, a
report cannot answer "why was TLS never checked?".

### Graph shape

Topology expansion allows evidence to form a DAG: each discovered endpoint opens its own
probe chain beneath the node that discovered it.

A complex graph serialization format is not designed here. Parent references plus
deterministic ordering are sufficient for v0.1.

### Encoded shape (schema v1)

The conceptual field list above includes `parent / parents`, which reads as though
relationships belong on each node. ADR 0013 subsequently made relationships graph-owned
rather than properties of a fact, and the encoding follows the architecture:

```json
"evidence": {
  "nodes": [ { "id": "...", "layer": "L1", "state": "PASS", ... } ],
  "relationships": [
    { "id": "...", "parents": ["..."], "blockedBy": ["..."] }
  ]
}
```

Nodes carry their own fields; relationships are listed separately, in the graph's canonical
`EvidenceID` order, and only for nodes that have any. The information content is the same
exact identifiers plus deterministic ordering this section requires. See ADR 0016.

The report owns this shape. The in-memory graph type has no standalone JSON encoding.

---

## 6. attributes

Attributes use a controlled, normalized value model. Implementation types are not defined here.

Allowed conceptual value categories:

- string
- integer
- boolean
- duration
- timestamp
- list of simple values

Avoid arbitrary nested dynamic objects unless Phase 1 demonstrates a real need.

> **`map[string]any` is not part of the canonical evidence contract.**

Complex service-specific information should prefer:

- normalized scalar or list attributes, or
- additional evidence nodes

rather than opaque blobs.

This constraint protects schema stability, deterministic serialization, and structural
redaction at the same time. An uncontrolled payload defeats all three.

---

## 7. findings

Conceptual finding model:

```text
code
kind
severity
confidence
layer
subject
summary
detail
evidenceRefs
recommendations
vantageDependent
```

Finding codes are service-namespaced strings, for example:

```text
KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE
POSTGRES_TLS_POLICY_MISMATCH
```

There is no centralized enumeration listing every service's codes. See `docs/FINDINGS.md`
for the code convention and lifecycle rules.

### 7.1 kind

```text
CONFIRMED | HYPOTHESIS
```

A finding may be a hypothesis when evidence is suggestive but not conclusive. There are no
separate parallel `Hypothesis` and `Finding` report types; a hypothesis is a finding with a
different `kind`.

For `HYPOTHESIS`, the model allows a **discriminator**: what additional evidence would
confirm or reject the hypothesis. Final field syntax is decided during implementation.

The discriminator is what makes a hypothesis actionable rather than a hedge.

### 7.2 severity

```text
INFO | WARN | ERROR | CRITICAL
```

Do not add levels without evidence from implementation.

### 7.3 confidence

```text
HIGH | MEDIUM | LOW
```

Ordinal only. Never percentages.

- `HIGH` — direct and strongly matching evidence.
- `MEDIUM` — multiple consistent indirect signals.
- `LOW` — plausible, but alternative explanations remain.

Confidence is not a probability and must not be rendered as one.

### 7.4 evidence references

> **Findings must reference exact evidence IDs.**

A renderer must be able to answer "why was this finding produced?" from the report alone,
without rerunning probes. A finding that cannot point at its evidence is not reportable.

A finding carries identifiers, never embedded evidence values, and validates only that each
identifier is well formed. The cross-object invariant — every reference resolves to a node in
the report's evidence graph — is validated when the report is assembled, because the report is
the first thing that owns both sets. See ADR 0014.

---

## 8. summary

Summary is derived from findings and evidence. It introduces no new diagnosis logic.

Conceptually it may contain:

- overall status
- first broken layer
- finding counts by severity
- number of skipped and unknown checks

Aggregation algorithms are not over-specified here. The last item matters: a report where
half the checks were skipped is not the same as a clean report, and the summary must make
that visible.

The overall status is also the basis of the exit code contract in `docs/SCOPE.md`.

### Derivation (schema v1)

The summary is computed by the report from its graph and findings. A caller cannot supply
one, so it can never contradict the report that contains it. See ADR 0015.

- `status` is `PROBLEMS_FOUND` when any finding is `ERROR` or `CRITICAL`, otherwise `OK`.
  This is exactly the exit-code 0/1 boundary. **`OK` means "no ERROR or CRITICAL finding",
  not "healthy"** — read it together with the skipped and unknown counts.
- `firstBrokenLayer` is the lowest layer holding evidence in state `FAIL`. `UNKNOWN` and
  `SKIPPED` are not failures, and a blocked-by reference is not one either. Omitted when
  nothing failed.
- `findingCountsBySeverity` counts findings; the four levels are always present.
- `skippedEvidenceCount` and `unknownEvidenceCount` count evidence nodes.

Exit codes 2, 3 and 4 stay outside the summary: they describe usage errors, internal
failures and partial runs, none of which a report can observe about itself.

---

## 9. security

Report security metadata, for interpretation rather than for diagnosis.

Conceptually:

- output mode: local/full vs shareable/redacted
- whether TLS verification was disabled
- number and categories of redacted fields
- whether credential forwarding to discovered endpoints was enabled
- warnings relevant to interpreting the report

> **Never include secret values.**

Recording the count and category of redacted fields lets a reader know that redaction
happened, and roughly what was removed, without exposing anything.

See `docs/SECURITY.md`.

### Implemented in schema v1

`outputMode`, `tlsVerificationDisabled`, `credentialForwardingEnabled`, and — on a shareable
report only — `redactions`.

```json
"security": {
  "outputMode": "SHAREABLE_REDACTED",
  "tlsVerificationDisabled": false,
  "credentialForwardingEnabled": false,
  "redactions": {"hostname": 3, "ipAddress": 1, "evidenceId": 3, "prose": 4}
}
```

The counts are of **distinct values** replaced, not occurrences: "three hostnames were
removed" is what a reader can act on, and an occurrence count would describe how often each
host appeared, which is structural information about the environment. `prose` counts fields
in which at least one value was replaced.

`redactions` is **absent on a local report**. Nothing was transformed there, and a zero would
read as "nothing sensitive was present" rather than "nothing was removed".

The counts come from the transformation, never from a caller: the ordinary constructor still
refuses to produce `SHAREABLE_REDACTED`, so only a real redaction can label a report that
way. There is no separate identity or username category — schema v1 has no structural
carrier for a username, so one can only reach a report through an attribute value or prose
and is counted there. See ADR 0018 and `docs/SECURITY.md`.
