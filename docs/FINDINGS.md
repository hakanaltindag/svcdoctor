# Finding Catalog and Conventions

This document defines the conventions findings must follow. It is deliberately **not** an
enumeration of every future svcdoctor finding.

The goal is to fix the conventions before coding, so that finding identifiers stay stable
once they are exposed to users and automation.

See `docs/REPORT_SCHEMA.md` for the finding model itself.

## 1. Finding code convention

Finding codes are uppercase, underscore-separated, stable identifiers:

```text
<NAMESPACE>_<DESCRIPTION>
```

### Service findings

Service findings use the service name as the namespace:

```text
KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE
KAFKA_SECURITY_PROTOCOL_MISMATCH
POSTGRES_TLS_POLICY_MISMATCH
```

### Generic transport findings

Generic transport findings use the layer as the namespace:

```text
DNS_RESOLUTION_FAILED
TCP_CONNECTION_REFUSED
TLS_CERTIFICATE_EXPIRED
```

This is the chosen convention: **the namespace names the owner of the rule.** A rule owned by
`internal/diagnosis/transport/` is namespaced by its transport layer; a rule owned by
`internal/diagnosis/<service>/` is namespaced by its service.

The layer namespaces (`DNS`, `TCP`, `TLS`) are unambiguous and read naturally, so no extra
generic prefix is introduced.

### Ownership

Code constants live with the rules that produce them. The core knows only that a code is a
namespaced string.

> There is no central enumeration listing every service's codes.

A central enum would recreate the coupling that central service branching creates, in a
different shape: every new service would have to edit shared core code.

## 2. Finding lifecycle

Finding identifiers are machine-consumed contracts. Automation, dashboards, and alert rules
will match on them.

- Avoid renaming a code without a real reason.
- Once exposed, a code's semantics must remain stable. If the meaning must change, introduce
  a new code rather than redefining the old one.
- Message text may improve freely without changing the code.
- Renderer formatting must never affect code identity.

A code is the stable part. Everything a human reads around it is not.

## 3. Finding properties

Every finding should eventually provide:

```text
code
kind
severity
confidence
layer
summary
evidenceRefs
vantageDependent
```

Recommended when relevant:

```text
detail
recommendations
discriminator
affectedResources
help / reference
```

None of these are being introduced as mandatory implementation fields yet. Phase 1 decides
which are required at the type level and which are optional.

## 4. Claim discipline

These rules exist to keep svcdoctor from producing confident, wrong answers.

- Never claim an absolute root cause unless the evidence truly proves it.
- Prefer `kind: HYPOTHESIS` when alternative explanations remain, and state the discriminator.
- An unsupported diagnostic capability must not be converted into a service failure. If
  svcdoctor cannot check something, that is a gap in svcdoctor.
- Privilege-related missing evidence must not be interpreted as healthy.
- Downstream findings must not be generated when their prerequisite layer failed.
- Findings that depend on network location must be marked `vantageDependent`.

The shared theme: **"I could not measure it" and "it is broken" are different claims.**
Collapsing them is the fastest way to make a diagnostic tool untrustworthy.

## 5. First-broken-layer behavior

The report must make the earliest evidenced failing layer obvious.

```text
DNS       FAIL
  |
TCP       SKIPPED
  |
TLS       SKIPPED
  |
PROTOCOL  SKIPPED
```

This must not produce separate, misleading TCP/TLS/auth failure findings. One evidenced
failure plus explicit skips is correct. Four failures is noise that hides the real cause.

Layer order is defined in `docs/ARCHITECTURE.md` section 2:

```text
L0 config -> L1 DNS -> L2 TCP -> L3 TLS -> L4 protocol -> L5 auth -> L6 topology
```

## 6. Initial known finding

### `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`

The flagship finding for the Kafka vertical slice, described conceptually only.

**Condition**

- The bootstrap path succeeds far enough to obtain Kafka Metadata.
- Metadata returns one or more broker endpoints.
- One or more discovered broker endpoints fail connectivity verification from the current
  vantage point.

**Expected characteristics**

| Property | Value |
|---|---|
| `kind` | `CONFIRMED` or `HYPOTHESIS`, depending on the strength of the evidence |
| `severity` | typically `ERROR` |
| `confidence` | `HIGH` when the discovered-endpoint failure is directly evidenced |
| `vantageDependent` | `true` |

**Evidence references**

The finding must reference both:

- the evidence showing successful bootstrap and Metadata discovery, and
- the evidence showing the discovered endpoint failing

Both halves are required. The finding's entire meaning is the contrast between them: the
cluster answered, and then advertised an address this client cannot reach.

**Why vantage matters here**

This finding is a statement about the network position of the client, not about the health of
the cluster. The same cluster may be perfectly reachable from another vantage. Reports
carrying this finding must make that unmistakable.

No code structures are defined here. Verification of discovered endpoints uses credential-free
probes by default, per `docs/SECURITY.md`.
