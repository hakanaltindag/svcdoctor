# ADR 0053: A certificate is presented by an endpoint, so a generic TLS finding names one

## Status

**Accepted.** Not implemented, and no code changes with this record.

It closes the gap ADR 0043 §14 deferred, whose reopen condition it satisfies:
*"Reopen when a production run produces a `tls.handshake` node whose direct
parent is a requested-target `tcp.connect` node. Kafka bootstrap composition is
the likely first."* It is.

**Revised before acceptance.** The first draft proposed `TLS_PEER_NOT_TLS` and
`TLS_HANDSHAKE_FAILED` as finding codes. A naming review rejected both — §5
records why — and required the claim-discipline rule in §6.

## Problem

PostgreSQL negotiates encryption in band, so its handshake hangs off
`postgres.ssl_request` and ADR 0044 owns it. `internal/app` calls `transport.Run`
with `TLS` unset, so **no production run has ever produced a generic
requested-target `tls.handshake` node.**

Kafka bootstrap TLS is ordinary transport TLS. A `DiagnoseKafka` that offers
`--tls` will call `transport.Run` with a TLS plan and produce:

```text
target.requested
  └── dns.lookup
        └── tcp.connect
              └── tls.handshake      ← owned by nobody today
```

The Kafka integration harness already builds this shape, and it produces no
finding because no rule claims it.

**The silent-failure mode is specific.** `collectSweep` in
`internal/diagnosis/transport` validates that a lookup's children are
`tcp.connect` and **does not inspect their children**. A `tls.handshake` beneath
a requested connect therefore leaves the sweep well-formed. The node is not
rejected; it is invisible. `status: OK` beside a broken L3 becomes reachable
again — the exact condition ADR 0044 closed for PostgreSQL, and the reason
ADR 0054 makes owner-before-producer an invariant.

## Repository facts, verified at `ca0dae1`

`internal/probe/tls/handshake.go` produces exactly **six** FAIL classes and two
UNKNOWN classes:

| Produced | Line |
|---|---|
| `FailureTLSPeerNotTLS` | 281 |
| `FailureTLSHostnameMismatch` | 291 |
| `FailureTLSCertificateNotYetValid` | 300 |
| `FailureTLSCertificateExpired` | 302 |
| `FailureTLSUnknownAuthority` | 305 |
| `FailureTLSHandshakeFailure` (floor) | 252 |
| `FailureExecCancelled` / `FailureExecLocalTimeout` (UNKNOWN) | 241, 243, 250 |

Three declared classes have **no producer anywhere**:
`FailureTLSVersionMismatch`, `FailureTLSClientCertificateRequired`,
`FailureTLSClientCertificateRejected`.

## Decision

### 1. Generic TLS findings are endpoint-scoped, not target-scoped

The subject is the **concrete endpoint** whose handshake failed — the
`tls.handshake` node's own subject — not the logical requested target.

This deliberately does **not** follow ADR 0043's target-level aggregation, and
the reason is a difference in what the evidence is about:

- **DNS and TCP claims answer:** *can the logical target be reached through its
  address set?* That is a property of the set, and one PASS falsifies the
  negative. Target-level with withholding is correct.
- **TLS claims answer:** *what did this concrete endpoint present during this
  attempt?* A sibling endpoint succeeding does not falsify *this endpoint
  presented a name mismatch*, *this endpoint presented an untrusted chain*,
  *this endpoint's certificate was outside its validity window*, or *this
  endpoint did not complete TLS*.

Restating a per-peer fact at target level would require an aggregation rule false
in both directions: *"the target's TLS is broken"* overclaims when a path works,
and *"the target's TLS is fine"* hides a defect a client may select. Endpoint
scope avoids the choice.

Re-tested against real client behaviour before acceptance: address selection
varies with resolver order and Happy-Eyeballs, DNS rotation and load balancers
change which endpoint a client reaches between runs, and managed Kafka commonly
serves distinct certificates per broker endpoint. Each makes *which endpoint
presented which certificate* the actionable unit.

### 2. This resolves the tension rather than copying either precedent

ADR 0044 anticipated this question. Its rejected-alternatives table lists
*"Withholding when another path's TLS passes — the claim is per-endpoint;
withholding would hide a real defect"*, with the reopen condition *"the claim is
ever restated at target level."* This record declines to restate it, so that
condition stays closed and the two TLS surfaces agree.

The alternative would be incoherent: the same certificate defect would be
reported at endpoint scope when a service negotiates TLS in band and at target
scope when it does not. Scope would become a property of the service's handshake
style rather than of the fact.

### 3. Therefore: no partial-success withholding

One address failing TLS while another succeeds produces a finding for the failing
address. Evidence for both is in the graph, and the finding names which endpoint
it is about.

### 4. Five codes

| Code | Classes | Operator-facing claim |
|---|---|---|
| `TLS_ENDPOINT_DOES_NOT_SPEAK_TLS` | `TLS_PEER_NOT_TLS` | this endpoint answered, and what it answered with was not TLS |
| `TLS_IDENTITY_MISMATCH` | `TLS_HOSTNAME_MISMATCH` | the certificate presented carries no name matching the identity this run asked for |
| `TLS_CHAIN_NOT_TRUSTED` | `TLS_UNKNOWN_AUTHORITY` | the chain presented did not verify against this run's trust context |
| `TLS_CERTIFICATE_NOT_VALID_NOW` | `TLS_CERTIFICATE_EXPIRED`, `TLS_CERTIFICATE_NOT_YET_VALID` | the certificate presented is outside its validity window as measured against this host's clock |
| `TLS_HANDSHAKE_NOT_COMPLETED` | `TLS_HANDSHAKE_FAILURE` | no TLS handshake completed here, and svcdoctor could not attribute why |

They are **not** merged into one code because the first move differs for each:
"this port is not TLS" sends an operator to the listener configuration, "chain not
trusted" to this run's trust material, "identity mismatch" to the certificate's
names or `--tls-server-name`, "not valid now" to renewal or clock.
`docs/FINDINGS.md` §11 forbids merging distinct first moves.

Expired and not-yet-valid merge because they pose one question — *is this
certificate valid now, and whose clock says so?* — and `tls.peer_not_before` /
`tls.peer_not_after` preserve the distinction where a machine reads it.

The codes carry **no service prefix**, because the evidence is service-neutral.
PostgreSQL's five `POSTGRES_TLS_*` codes are untouched and not renamed: they
describe the same failures observed through a different negotiation and are
already released.

### 5. Two names were rejected, and the reason is a namespace collision

Every existing FindingCode in this repository is claim-oriented and none mirrors
its `FailureClass`:

| FindingCode | Triggering class | Mirror? |
|---|---|---|
| `TCP_CONNECTION_NOT_ESTABLISHED` | `TCP_CONNECTION_REFUSED` and five others | no |
| `DNS_NAME_NOT_RESOLVED` | `DNS_NO_ADDRESS`, `DNS_NXDOMAIN` | no |
| `POSTGRES_TLS_UPGRADE_NOT_HONORED` | `TLS_PEER_NOT_TLS` | no |
| `POSTGRES_TLS_CHAIN_NOT_TRUSTED` | `TLS_UNKNOWN_AUTHORITY` | no |

**`TLS_PEER_NOT_TLS` was rejected** because it mirrors its class exactly.
Generic codes carry no service prefix, so a report would contain
`failureClass: "TLS_PEER_NOT_TLS"` on the evidence node and
`code: "TLS_PEER_NOT_TLS"` on the finding — two namespaces, one string, and a
consumer matching on strings could conflate them. PostgreSQL's `POSTGRES_` prefix
hides that hazard; generic codes cannot. A code should express a claim rather
than repeat the observation vocabulary.

**`TLS_HANDSHAKE_FAILED` was rejected** as too close to `TLS_HANDSHAKE_FAILURE` —
one word apart, and confusable in exactly the same way.
`TLS_HANDSHAKE_NOT_COMPLETED` follows the established `<THING>_NOT_<PARTICIPLE>`
convention, states what was not achieved, and stays non-causal.

`TLS_SESSION_NOT_ESTABLISHED` was considered and rejected for the floor:
ADR 0052 is removing "session" from the Kafka vocabulary, and reintroducing it as
a TLS code invites the confusion that record resolves.

### 6. Claim discipline: the prose is scoped to this endpoint and this attempt

**Mandatory, and it binds the finding text rather than the code.**

For `TLS_ENDPOINT_DOES_NOT_SPEAK_TLS` the prose must **not** imply:

- that this endpoint never supports TLS;
- that the service is not TLS-capable;
- that the operator used the wrong port;
- that a proxy, firewall or load balancer caused it;
- that a future attempt will behave the same way.

The claim is scoped to **this endpoint, this attempt, this vantage**. Preferred
direction:

> *This endpoint did not speak TLS during this attempt.*

**Never** *"This endpoint does not support TLS."* The code is stable and concise;
the human-readable claim carries the observation scope. `docs/FINDINGS.md` §11's
no-cause rule applies to all five.

### 7. Semantic fields

| Code | Kind | Severity | Confidence | vantageDependent |
|---|---|---|---|---|
| `TLS_ENDPOINT_DOES_NOT_SPEAK_TLS` | CONFIRMED | ERROR | HIGH | **true** |
| `TLS_IDENTITY_MISMATCH` | CONFIRMED | ERROR | HIGH | **true** |
| `TLS_CHAIN_NOT_TRUSTED` | CONFIRMED | ERROR | HIGH | **true** |
| `TLS_CERTIFICATE_NOT_VALID_NOW` | CONFIRMED | ERROR | HIGH | **true** |
| `TLS_HANDSHAKE_NOT_COMPLETED` | CONFIRMED | ERROR | HIGH | **true** |

Subject: the concrete endpoint. Evidence refs: the `tls.handshake` node and its
`tcp.connect` parent — the handshake carries the certificate facts, the connect
establishes that a connection existed to hand to it. The `dns.lookup` node is
**not** referenced: DNS has its own owner and these findings make no resolution
claim.

Every value is reasoned, not copied:

- **All five are CONFIRMED** because each restates a measured node state. None
  infers a cause.
- **The floor is CONFIRMED at HIGH confidence, not a hypothesis.** *"No handshake
  completed"* is positively evidenced; its non-causality lives in the wording.
  A hedged floor would misrepresent a certain fact as an uncertain one.
- **`vantageDependent` is true for all five**, for four different reasons:
  peer-not-TLS, because what answers this address from here may differ elsewhere;
  identity mismatch, because interception and path-dependent routing change which
  certificate arrives; chain-not-trusted, because the trust context is this run's;
  validity, because *both* which certificate is presented and the clock it is
  measured against are local.

Three detail-text requirements are normative:

- **`TLS_CHAIN_NOT_TRUSTED`** proves *this run's trust context did not trust the
  presented chain*. It must **not** claim the certificate is objectively invalid,
  and the detail must name local CA and trust configuration as a possible
  explanation — frequently it is the actual one.
- **`TLS_CERTIFICATE_NOT_VALID_NOW`** depends on the presented certificate **and
  this host's clock**. The detail must not imply a globally correct wall clock.
- **`TLS_HANDSHAKE_NOT_COMPLETED`** may say that no handshake completed. It must
  not say why.

### 8. Ownership predicate

A `tls.handshake` node is generic requested-target TLS **iff all of**:

1. `Step == tls.handshake`;
2. `Layer == LayerTLS` (L3);
3. `State == FAIL`;
4. exactly one parent, whose `Step == tcp.connect`;
5. that parent has exactly one parent, whose `Step == dns.lookup`;
6. that lookup has exactly one parent, whose `Step == target.requested`;
7. that anchor has `Layer == LayerInput` and `Subject().Kind() == SubjectKindTarget`.

Graph accessors only — `Node`, `Parents`, `Step`, `Layer`, `State`, `Subject`.
No `Origin`, no EvidenceID parsing, no service-name switch, no transitive
ancestry inference, no `SweepScope`.

Conditions 5–7 make ownership **direct**, and are what prevent every overlap:

| Shape | Fails at | Owner |
|---|---|---|
| `target.requested → dns.lookup → tcp.connect → tls.handshake` | — | **generic (this record)** |
| `tcp.connect → postgres.ssl_request → tls.handshake` | (4) parent is `postgres.ssl_request` | ADR 0044 |
| `kafka.broker_advertised → dns.lookup → tcp.connect → tls.handshake` | (6) lookup's parent is `kafka.broker_advertised` | ADR 0034 |
| SKIPPED handshake (prerequisite failed) | (3) | the blocking layer |

Condition 3 also excludes the SKIPPED node the chain mints with
`EXEC_SKIPPED_PREREQUISITE_FAILED`, as in ADR 0044 §3, because `docs/FINDINGS.md`
§11 forbids citing a blocked step as a cause.

### 9. Three FailureClasses stay deferred

`FailureTLSVersionMismatch`, `FailureTLSClientCertificateRequired` and
`FailureTLSClientCertificateRejected` have no producer. **No code is created for
them.** Publishing a finding for evidence no run can emit would make unproduced
behaviour public policy, testable only against hand-built graphs — the failure
ADR 0043 §14 refused. A version mismatch is recorded as the floor today, which is
why the floor is not a rare case.

## Acceptance matrix

| Scenario | Evidence | Finding | Status | Incomplete | Owner |
|---|---|---|---|---|---|
| TLS PASS | handshake PASS | none | OK | false | — |
| Identity mismatch | FAIL `TLS_HOSTNAME_MISMATCH` | `TLS_IDENTITY_MISMATCH` @ endpoint | PROBLEMS FOUND | false | generic |
| Unknown authority | FAIL `TLS_UNKNOWN_AUTHORITY` | `TLS_CHAIN_NOT_TRUSTED` @ endpoint | PROBLEMS FOUND | false | generic |
| Expired | FAIL `TLS_CERTIFICATE_EXPIRED` | `TLS_CERTIFICATE_NOT_VALID_NOW` | PROBLEMS FOUND | false | generic |
| Not yet valid | FAIL `TLS_CERTIFICATE_NOT_YET_VALID` | `TLS_CERTIFICATE_NOT_VALID_NOW` | PROBLEMS FOUND | false | generic |
| Peer not TLS | FAIL `TLS_PEER_NOT_TLS` | `TLS_ENDPOINT_DOES_NOT_SPEAK_TLS` | PROBLEMS FOUND | false | generic |
| Unclassified handshake failure | FAIL `TLS_HANDSHAKE_FAILURE` | `TLS_HANDSHAKE_NOT_COMPLETED` | PROBLEMS FOUND | false | generic |
| Local timeout | UNKNOWN `EXEC_LOCAL_TIMEOUT` | **none** | OK | **true** | — |
| Cancellation | UNKNOWN `EXEC_CANCELLED` | **none** | OK | **true** | — |
| One address FAIL, one PASS | one FAIL, one PASS | **one** finding, failing endpoint | PROBLEMS FOUND | false | generic |
| One address FAIL, one UNKNOWN-local | FAIL + UNKNOWN | **finding fires** for the FAIL endpoint | PROBLEMS FOUND | **true** | generic |
| All addresses FAIL, same class | N FAIL | N findings, one per endpoint | PROBLEMS FOUND | false | generic |
| All addresses FAIL, mixed classes | N FAIL | N findings, each its own code | PROBLEMS FOUND | false | generic |
| SKIPPED handshake | SKIPPED | none | — | — | the blocking layer |
| PostgreSQL in-band TLS FAIL | parent is `postgres.ssl_request` | `POSTGRES_TLS_*` | PROBLEMS FOUND | false | **ADR 0044** |
| Kafka advertised TLS FAIL | lookup's parent is `kafka.broker_advertised` | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` | PROBLEMS FOUND | false | **ADR 0034** |

The FAIL + UNKNOWN-local row is the ADR 0051 interaction: the finding is a
complete claim about the endpoint that failed, and the run is incomplete because
a selectable sibling was never measured. The two are orthogonal, and both appear.

## Rejected alternatives

| Alternative | Why rejected | Reopen condition |
|---|---|---|
| **Target-scoped with withholding** (ADR 0043's shape) | A certificate is presented by an endpoint, not by a name-set. Withholding hides a defect a client may select; asserting overclaims when a path works | An aggregate reachability claim about TLS is ever specified |
| **`TLS_PEER_NOT_TLS` as a code** | Exact `FailureClass` mirror; generic codes have no prefix, so evidence and finding namespaces would collide on one string | Never |
| **`TLS_HANDSHAKE_FAILED` as a code** | One word from `TLS_HANDSHAKE_FAILURE`; same collision hazard | Never |
| `TLS_SESSION_NOT_ESTABLISHED` for the floor | ADR 0052 removes "session" from the Kafka vocabulary | Never |
| One generic TLS code | Five distinct first moves. FINDINGS.md §11 forbids the merge | A remediation study shows operators act identically |
| Separate expired / not-yet-valid codes | One question; the evidence says which end | A consumer needs it and cannot read attributes |
| Reusing `POSTGRES_TLS_*` codes | Service-prefixed codes on service-neutral evidence, and they are released | Never |
| Codes for the three unproduced classes | Public policy for evidence no run emits | The TLS probe gains version bounds or client certificates |
| Also emitting a target-level TLS finding | Two findings for one fact; the endpoint finding already names where | An aggregate claim is specified |
| Referencing the `dns.lookup` node | The finding makes no resolution claim | Never |
| Marking the validity finding non-vantage-dependent | Which certificate is presented is path-dependent, and the clock is local | Never |

## Consequences

- Repository finding codes: **24 → 29** when implemented. No `FailureClass` is
  added.
- The last transport-layer silence closes for any service using out-of-band TLS.
- PostgreSQL is untouched: no code renamed, no output changed; ownership is
  decided structurally by parent step.
- Redis, MySQL and any future out-of-band-TLS service inherit this rule with no
  new mechanism, which is the generalization ADR 0044 predicted.
- `schemaVersion`, `Reveal`, `diagnosis.Rule` and the dependency set are unchanged.
- ADR 0054's invariant is satisfied for Kafka bootstrap TLS by implementing this
  record in Phase 6.1b, **before** the producer lands in 6.1c.

## Reopen conditions

- The TLS probe gains version bounds or client-certificate support, making three
  deferred classes reachable.
- An aggregate target-level TLS claim is specified, which would reopen §1 and
  ADR 0044's matching row together.
