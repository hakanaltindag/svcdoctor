# Diagnosis Examples

What svcdoctor's findings actually look like.

`docs/REPORT_SCHEMA.md` defines the shape and `docs/FINDINGS.md` defines the conventions.
Neither shows the product, and until Phase 3.6.5 nobody could see one without writing a
harness. This document closes that gap.

**Scope, so this does not rot into fiction.** The examples are finding-level JSON, taken from
real output of `internal/diagnosis/kafka.AdvertisedEndpointUnreachable` over real graphs. They
are illustrative, not normative: **the tests are authoritative**, and where this file and
`internal/diagnosis/kafka/*_test.go` disagree, the tests are right and this file is stale. Full
reports are deliberately not reproduced — they are large, they are mostly evidence, and a
pasted copy would drift within a phase.

Only one finding exists today. This file grows one section per finding code.

---

## `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`

The flagship Kafka finding: the cluster answered, and then advertised an address this client
cannot reach. See ADR 0034 for the policy and `docs/FINDINGS.md` section 6 for the contract.

### Confirmed — every resolved address refused the connection

A bootstrap connection succeeded, Metadata returned three brokers, and both addresses of
broker 2 failed.

```json
{
  "code": "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE",
  "kind": "CONFIRMED",
  "severity": "ERROR",
  "confidence": "HIGH",
  "layer": "L6",
  "subject": { "kind": "ENDPOINT", "ref": "broker-2.prod.internal:9092" },
  "summary": "Kafka advertised endpoint for broker node 2 could not be reached from this vantage point; earliest evidenced failure L2 TCP_CONNECTION_REFUSED, TCP_CONNECTION_TIMEOUT",
  "detail": "The Kafka Metadata exchange succeeded and advertised this endpoint, and no measured path to it completed L2 (tcp).\nReachability is relative to network position: this states what this vantage point observed, not the health of the cluster.",
  "evidenceRefs": [
    "kafka.broker_advertised/kafka-bootstrap.prod.internal:9092/10.4.1.10/2/broker-2.prod.internal:9092",
    "kafka.metadata/kafka-bootstrap.prod.internal:9092/10.4.1.10",
    "tcp.connect/advertised.77f2936e…bd27/broker-2.prod.internal:9092/10.4.2.21",
    "tcp.connect/advertised.77f2936e…bd27/broker-2.prod.internal:9092/10.4.2.22"
  ],
  "recommendations": [
    { "action": "Check routing, firewall rules and security group policy between this vantage point and the advertised address and port" }
  ],
  "vantageDependent": true
}
```

The sweep-scope digests are abbreviated here with `…` for width. They are full SHA-256 in real
output, deliberately (ADR 0032), and nothing may parse them.

Two references are the successful half of the contrast and two are the causal half. Which is
which is not encoded in the list — a consumer resolves each reference against the graph and
reads its `state`. See `docs/REPORT_SCHEMA.md` section 7.4.

The report summary that accompanies it:

```json
{ "status": "PROBLEMS_FOUND", "firstBrokenLayer": "L2",
  "findingCountsBySeverity": { "info": 0, "warn": 0, "error": 1, "critical": 0 },
  "skippedEvidenceCount": 0, "unknownEvidenceCount": 0 }
```

`layer: "L6"` on the finding and `firstBrokenLayer: "L2"` on the summary are **not** a
contradiction. The first is the layer of the claim, the second is where the run first broke.
`docs/REPORT_SCHEMA.md` section 7.5 defines both.

### Hypothesis — one path failed, another was never finished

Same cluster, but the execution budget expired before the second address was attempted.

```json
{
  "code": "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE",
  "kind": "HYPOTHESIS",
  "severity": "WARN",
  "confidence": "LOW",
  "layer": "L6",
  "subject": { "kind": "ENDPOINT", "ref": "broker-2.prod.internal:9092" },
  "summary": "Kafka advertised endpoint for broker node 2 may be unreachable from this vantage point; at least one path failed with L2 TCP_CONNECTION_REFUSED and the remaining paths were not measured",
  "detail": "The Kafka Metadata exchange succeeded and advertised this endpoint, and no measured path to it completed L2 (tcp). At least one of those outcomes is a positively observed failure and the rest were never finished, so unreachability is not proven.\nReachability is relative to network position: this states what this vantage point observed, not the health of the cluster.",
  "evidenceRefs": ["…metadata", "…advertisement", "…tcp FAIL", "…tcp UNKNOWN"],
  "recommendations": [
    { "action": "Check routing, firewall rules and security group policy between this vantage point and the advertised address and port" }
  ],
  "vantageDependent": true,
  "discriminator": "re-run with a larger execution budget so the unmeasured paths are attempted"
}
```

It is a **different claim**, not a hedged version of the confirmed one, which is why the
severity is different and why that is not severity tracking confidence: *"at least one path
failed and the rest were unmeasured"* is a real problem that is not currently breaking use.

`status` stays `OK` and `unknownEvidenceCount` becomes `1`, so an incomplete measurement never
fails a pipeline on svcdoctor's own timeout — and never disappears either.

### No finding — one address worked

```text
broker-2.prod.internal -> 10.4.2.21        TCP_NETWORK_UNREACHABLE
                       -> 2001:db8:4:2::22 connected
```

```json
"findings": [],
"summary": { "status": "OK", "firstBrokenLayer": "L2",
             "findingCountsBySeverity": { "info": 0, "warn": 0, "error": 0, "critical": 0 },
             "skippedEvidenceCount": 0, "unknownEvidenceCount": 0 }
```

No `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`, because a client that selects the working address
succeeds and the claim would be false. No partial-reachability finding either — its
actionability depends on which address a real client picks, which svcdoctor does not observe
(ADR 0034 section 6).

**`firstBrokenLayer: "L2"` in an `OK` report is the signal that matters here.** `OK` means "no
`ERROR` or `CRITICAL` finding", not "healthy". The failing address is fully recorded in the
evidence graph; what was withheld is a conclusion, not the data. A consumer that gates only on
`status` will not see this, by design — it is not a problem svcdoctor can prove.

---

## Shareable output

Redaction transforms the same finding. Only the identity-bearing parts change:

| Field | `LOCAL_FULL` | `SHAREABLE_REDACTED` |
|---|---|---|
| `subject.ref` | `broker-2.prod.internal:9092` | `host-001:9092` |
| `evidenceRefs[]` | `tcp.connect/advertised.77f2…/…/10.4.2.21` | `evidence-004` |
| `summary`, `detail`, `recommendations` | — | **byte-identical** |
| `severity`, `kind`, `confidence`, `layer`, `vantageDependent` | — | **unchanged** |

The prose is untouched because it never carried identity in the first place: the hostname lives
on the subject and on the evidence, where structural redaction reaches it. That is a design
rule rather than a happy accident — see `docs/FINDINGS.md` section 3.1, item 15 — and
`test/security/kafka_finding_redaction_test.go` fails if prose ever starts needing rewriting.

The broker node identifier survives redaction, deliberately. It names a position in a cluster
rather than a host or a network address, and after pseudonymization it is the only thing left
that tells a reader *which* broker a shared finding is about.

**The cost of redaction is legibility of the references.** `evidence-004` says nothing on its
own, so a reader of a shareable report must resolve it against the graph in the same report —
which still carries every node's `layer`, `step`, `state` and `failureClass`. Renderers already
have to traverse; a human reading raw shareable JSON does not, and that is the case this
project has not yet built a renderer for.

---

## What a renderer can derive

No renderer exists yet. This is what one would have to work with, and the point of showing it
is the rule in `docs/FINDINGS.md` section 3.1, item 13: **a renderer must never parse
`summary`.**

Everything below is reachable from structured fields plus graph traversal:

```text
ERROR  KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE
       kind=CONFIRMED  confidence=HIGH  vantageDependent=true

  Subject:          broker-2.prod.internal:9092  (ENDPOINT)
  Observed from:    ci-runner-7.build.internal (LOCAL_HOST)

  Earliest failure: L2  TCP_CONNECTION_REFUSED, TCP_CONNECTION_TIMEOUT   (2 paths)
      L2  tcp.connect   10.4.2.21:9092   TCP_CONNECTION_REFUSED
      L2  tcp.connect   10.4.2.22:9092   TCP_CONNECTION_TIMEOUT

  Established by:
      L6  kafka.metadata            PASS
      L6  kafka.broker_advertised   PASS

  Next:             Check routing, firewall rules and security group policy …
```

| Line | Where it comes from |
|---|---|
| severity, code, kind, confidence, vantage flag | finding fields |
| subject | `finding.subject` |
| vantage host | `report.vantage` |
| earliest failing layer | lowest `layer` among cited nodes in state `FAIL` |
| failure classes | `failureClass` on those nodes |
| per-path rows | cited nodes, resolved against the graph |
| "established by" | cited nodes in state `PASS` |
| unmeasured paths | cited nodes in state `UNKNOWN` or `SKIPPED` with an `EXEC_` class |
| resolved addresses, timings, TLS facts | graph traversal from the cited nodes |

Nothing in that view requires reading a sentence. The summary is for a human skimming a list;
it is not the transport for any of it.
