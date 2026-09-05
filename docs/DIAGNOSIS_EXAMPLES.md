# Diagnosis Examples

What svcdoctor's findings actually look like.

`docs/REPORT_SCHEMA.md` defines the shape and `docs/FINDINGS.md` defines the conventions.
Neither shows the product, and until Phase 3.6.5 nobody could see one without writing a
harness. This document closes that gap.

**Scope, so this does not rot into fiction.** The examples are finding-level JSON, taken from
real output of the rules in `internal/diagnosis/kafka` over real graphs. They
are illustrative, not normative: **the tests are authoritative**, and where this file and
`internal/diagnosis/kafka/*_test.go` disagree, the tests are right and this file is stale. Full
reports are deliberately not reproduced — they are large, they are mostly evidence, and a
pasted copy would drift within a phase.

This file grows one section per finding code.

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

## `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE`

The counterpart: Metadata answered, and the endpoint it reported for a broker cannot be used at
all. See ADR 0035.

### Confirmed — the cluster advertised a broker with no host

```json
{
  "code": "KAFKA_ADVERTISED_ENDPOINT_UNUSABLE",
  "kind": "CONFIRMED",
  "severity": "ERROR",
  "confidence": "HIGH",
  "layer": "L6",
  "subject": { "kind": "ENDPOINT", "ref": ":9093" },
  "summary": "Kafka advertised broker node 9 without a usable network endpoint",
  "detail": "The Kafka Metadata exchange succeeded, and the host and port it reported for this broker do not name somewhere a client could connect. Both values are recorded on the referenced advertisement exactly as they arrived.\nThis is a property of what the cluster reported rather than of this vantage point: any client reading the same Metadata response receives the same endpoint.",
  "evidenceRefs": [
    "kafka.broker_advertised/kafka-bootstrap.prod.internal:9092/10.4.1.10/9/:9093",
    "kafka.metadata/kafka-bootstrap.prod.internal:9092/10.4.1.10"
  ],
  "recommendations": [
    { "action": "Check how this broker's advertised host and port are configured, and whether anything rewrites Kafka Metadata responses between the broker and this client" }
  ],
  "vantageDependent": false
}
```

Three things are worth reading closely.

**`vantageDependent` is `false`, and it is the only finding so far where it is.** The defect is
in the values the cluster reported, so no other network position sees anything different.
`false` is encoded rather than omitted precisely so that a reader is told this positively —
it is the difference between "try from somewhere else" and "there is nothing to try".

**The subject is `:9093`, and it is not repaired.** That is what the cluster advertised: a port
with no host. Substituting a plausible hostname would invent the target the cluster failed to
name. It also means the subject is an `ENDPOINT` that is not a usable endpoint, which is
correct — the producer chose that kind and diagnosis does not overrule it.

**Two references, and neither is transport.** Phase 3.4 runs no sweep for an advertisement it
cannot turn into a target, so there is no DNS, TCP or TLS node to cite and none is invented.

The subcase — missing host versus impossible port — is deliberately absent from the prose. A
machine reads it from the cited advertisement's `kafka.broker.advertised_host` and
`kafka.broker.advertised_port` attributes; a human reads it off the subject at a glance.

The accompanying summary block:

```json
{ "status": "PROBLEMS_FOUND", "firstBrokenLayer": "L6",
  "findingCountsBySeverity": { "info": 0, "warn": 0, "error": 1, "critical": 0 },
  "skippedEvidenceCount": 0, "unknownEvidenceCount": 0 }
```

Here `firstBrokenLayer` is **L6, the same as the finding's `layer`** — because the advertisement
node is the only `FAIL` in the run and it is an L6 node. Compare the reachability example above,
where the finding is `L6` and the first broken layer is `L2`. Both reports are consistent;
`docs/REPORT_SCHEMA.md` section 7.5 says why.

### The two Kafka findings never both fire

```text
advertisement PASS  ->  a usable endpoint existed, transport ran   ->  UNREACHABLE (or nothing)
advertisement FAIL  ->  no endpoint could be formed, nothing ran   ->  UNUSABLE
```

The reachability rule requires `PASS` and the usability rule requires `FAIL`, so one
advertisement can never carry both codes. Nothing suppresses anything; the predicates are
complementary on a single field.

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

---

## `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY`

Phase 10.2's observation: the measured **scope** of advertised-endpoint reachability, once per
Metadata exchange. See ADR 0084 and `docs/FINDINGS.md` section 6.

It fires only when at least one advertised endpoint positively failed, so a healthy run carries
none. It is `INFO` because a count is never a cluster verdict, which means it can never move an
exit code.

### One of three unreachable, and the set is complete

Taken from `TestOneBadBrokerProducesOneFinding` against the real three-broker KRaft cluster,
with broker 2 reconfigured to advertise an address nothing listens on.

```json
{
  "code": "KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY",
  "kind": "CONFIRMED",
  "severity": "INFO",
  "confidence": "HIGH",
  "layer": "L6",
  "subject": { "kind": "ENDPOINT", "ref": "127.0.0.1:19192" },
  "summary": "1 of the 3 broker endpoints this cluster advertised could not be reached from this vantage point; the other 2 were reached",
  "vantageDependent": true
}
```

The second clause is the whole reason the finding exists. Three separate per-endpoint findings
state nowhere that the other two *were* reached, and that is the fact ruling against this client
having no path to the cluster's broker plane at all.

The subject is the endpoint the Metadata question was asked at — never an advertised endpoint.
That is what keeps it from colliding with `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`, whose subject
*is* the advertised endpoint.

### None of three reachable, and the set is complete

```json
{
  "code": "KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY",
  "summary": "None of the 3 broker endpoints this cluster advertised could be reached from this vantage point",
  "severity": "INFO"
}
```

Still `INFO`. Three failures rather than one is not a reason to escalate a count — the impact is
already reported at `ERROR`, once per endpoint, by the finding that has carried it since Phase
3.6.

### Anything unmeasured, and every total disappears

```json
{
  "code": "KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY",
  "summary": "1 of the 3 broker endpoints this cluster advertised could not be reached from this vantage point; 1 was reached and 1 was not measured",
  "recommendations": [
    { "action": "Re-run with a larger execution budget so the advertised endpoints that were not measured are attempted" }
  ]
}
```

On a partial set both *"none of them"* and *"only that one"* would assert a total nobody
established — they fail in opposite directions and need the same missing fact. The detail adds
*"an endpoint that was not measured is not an endpoint that refused"*.

---

## `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE`

Phase 10.2's hypothesis, and the one the phase is most careful about.

### Every advertised endpoint unreachable, after a bootstrap that worked

Taken from `TestAllBadBrokersProduceOneFindingEach` against the real cluster, with all three
brokers advertising addresses nothing listens on.

```json
{
  "code": "KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE",
  "kind": "HYPOTHESIS",
  "severity": "WARN",
  "confidence": "MEDIUM",
  "layer": "L6",
  "subject": { "kind": "ENDPOINT", "ref": "127.0.0.1:19192" },
  "summary": "The broker endpoints this cluster advertised may not be usable from this client's network position",
  "discriminator": "whether the advertised addresses are the ones a client on this network is expected to use to reach these brokers",
  "recommendations": [
    { "action": "Compare the addresses this cluster advertised with the addresses a client on this network is expected to use to reach its brokers" }
  ],
  "vantageDependent": true
}
```

**`MEDIUM` is a ceiling, not a setting.** The rule declares `AuthorityNone`, and the ladder
admits `HIGH` only when the peer stated the condition in its own protocol or when every
distinguishable alternative was measured and excluded. No Kafka field says *"my advertised
address is unreachable from where you are"*, and routing, packet filtering, a bootstrap-side
proxy and a broker-side outage are all unexcluded. The bootstrap contrast excludes exactly one
alternative — *this client has no path to the cluster* — and one exclusion is `MEDIUM`.

The detail says the rest out loud, including *"svcdoctor read no broker setting and holds
none"*, because the sentence a reader is most likely to write for themselves is the one about
`advertised.listeners` and it is a claim about a value nobody observed.

### The same evidence with one reachable peer — and no hypothesis at all

```text
1 of the 3 broker endpoints this cluster advertised could not be reached from this
vantage point; the other 2 were reached
```

No `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE`. A reachable peer is not a weaker case for the
hypothesis; it **contradicts** it, because two advertised addresses in the same plane
demonstrably worked from this client. Observed evidence inconsistent with a claim suppresses it
rather than qualifying it, and that is why there is no per-endpoint version of this hypothesis.

### The refusal, which is the point

One advertised endpoint, unreachable, after a reachable bootstrap. svcdoctor emits the confirmed
unreachability, the failure boundary, the topology count and this hypothesis at `MEDIUM` — and
it does **not** choose between *a network path that is unavailable* and *an advertisement
unsuitable for this client*. It cannot, and saying so is the honest output. Golden incident
fixture K14 forbids "the cause", "therefore", "this proves" and "the only explanation" so that a
future edit cannot quietly make the choice.
