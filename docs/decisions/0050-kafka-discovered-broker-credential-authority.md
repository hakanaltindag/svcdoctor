# ADR 0050: A credential is authorized for the endpoint the operator named, and a cluster cannot widen that

## Status

**Accepted, and implemented in Phase 6.1c.**

`internal/app.DiagnoseKafka` is the `DiagnoseKafka` this record was written to
constrain, and it is constrained in four independent ways rather than by review:

- `KafkaParams.validate` refuses a credential bound to anything but the logical
  target, before any socket opens, as `ErrInvalidInput` and never as evidence
  (§4);
- the composition calls `security.NewCredential`, `security.NewSecret`,
  `security.Reveal` and `Credential.SecretFor` **nowhere**, asserted statically
  in `test/security/kafka_production_reachability_test.go`;
- `kafka.TransportPlan` has no field that can hold credential material, asserted
  by reflection over the real struct;
- a behavioural test drives §5's scenario exactly — a bootstrap broker that
  advertises `attacker.…` holding a **valid certificate signed by the CA the run
  trusts** — and counts zero application bytes at the attacker above its TLS
  layer.

`MeasureAdvertised` is unchanged, which is what §1 predicted: this record made
its existing shape a policy rather than an implementation detail, and
composition had to add nothing to comply.

Nothing in `internal/adapter/kafka` changed with the implementation either.

The governing invariant, stated once so that later records can cite it:

> **Discovery may create evidence; discovery must not create secret authority.**

Four consequences of that sentence are normative, and each is argued in the
decision below:

- A Metadata response is **evidence obtained from the authenticated bootstrap
  peer**. It is not authorization to send a credential anywhere.
- A verified TLS channel to the bootstrap endpoint establishes **endpoint
  identity**, not transferable cluster-wide credential authority.
- `MeasureAdvertised` remaining transport-only is **intentional policy**, not an
  unfinished implementation.
- Any future authentication of a discovered broker requires a **new, explicit
  authority decision**; it may not arrive as a side effect of another phase.

## Problem

An operator runs:

```text
svcdoctor diagnose kafka --host kafka-bootstrap.internal --port 9093 --password-file …
```

The credential is bound to `kafka-bootstrap.internal:9093`. The bootstrap broker
authenticates it and answers Metadata with three brokers:

```text
broker-1.internal:9093
broker-2.internal:9093
broker-3.internal:9093
```

**Does authorization to present the credential to the bootstrap endpoint
authorize presenting it to those three?**

The question is forced by Kafka's topology and does not arise for PostgreSQL,
which has one endpoint and no discovery. It has to be answered before
`DiagnoseKafka` exists, because a composition root is exactly the layer that
could construct a second `security.Credential` and hand it to a discovered
broker — and nothing in the type system stops it.

### Repository facts, verified at `ca0dae1`

- `security.Credential.SecretFor(endpoint)` requires **exact endpoint equality**
  (`credential.go:69`). A mismatch returns `ErrEndpointMismatch`, documented as
  *"a programming error, not a diagnostic result. It must not be normalized into
  evidence."*
- `security.NewCredential(endpoint, identity, secret)` is **unrestricted**: any
  package holding a `Secret` can mint a credential bound to any endpoint. The
  binding is a check the adapter performs, not a capability the type withholds.
- `kafka.Authenticate` derives its endpoint from `session.Endpoint()` — the
  **logical** bootstrap label the operator gave, never the resolved address
  (`saslauthenticate.go:272`, ADR 0028 §2).
- `kafka.MeasureAdvertised` returns **no `transport.Continuation` and no socket**;
  it closes every sweep (`reachability.go:262`). There is no type path from an
  advertised sweep to `Authenticate`.
- ADR 0033 §1 already gave the reason the advertised sweep stops at L3:
  *"L5 needs credential authority for an endpoint no credential was authorized
  for."*
- `docs/SECURITY.md` and `CLAUDE.md` both state the standing rule: *"Do not
  forward credentials to topology-discovered hosts. Default policy is `deny`."*

So the repository has already refused this twice, on the record. This ADR does
not invent a policy; it **confirms one and states why it is not a temporary
limitation.**

### External Kafka facts

- `bootstrap.servers` is *"used to establish the initial connection to the Kafka
  cluster … since these servers are just used for the initial connection to
  discover the full cluster membership (which may change dynamically), this list
  need not contain the full set of servers"*
  ([Producer Configs](https://kafka.apache.org/41/configuration/producer-configs/)).
  **The advertised set is data returned by a peer, not configuration the operator
  supplied.**
- A Metadata response is an ordinary authenticated API response. It carries no
  signature, no attestation and no cluster-identity proof beyond the TLS identity
  of the *one* broker that answered.

## Decision

### 1. Bootstrap-only credential authority (Model A)

**A credential is presented on exactly one connection: the selected bootstrap
path.** No credential material is presented to any endpoint learned from a
Metadata response, in Kafka BASIC or by default in any later phase.

Advertised broker measurement stays what ADR 0033 made it: credential-free
DNS, TCP and TLS.

### 2. What "advertised broker usable" therefore means

The claim an advertised sweep supports, in full:

> *The endpoint this cluster published for broker N was reachable at the
> transport layer from this vantage point.*

It does **not** state that the broker speaks Kafka, that it would accept this
credential, that it would authorize this principal, or that a client could
produce or consume through it. Those require L4 and L5 exchanges that this
policy declines to perform.

The existing findings already word it this way, and no wording changes.

### 3. Authority does not travel down a derivation edge

A run's credential authority comes from **the operator's input**, and from
nowhere else. It is not extended by:

- a verified TLS channel to the bootstrap endpoint;
- a successful SASL authentication;
- a successful Metadata exchange;
- a graph edge from an authenticated node to an advertised one.

The graph records what caused what. It is not a capability chain, and reading it
as one would make evidence into authority — which is precisely the direction
`Origin` was deferred to avoid.

### 4. The composition root may not rebind

`DiagnoseKafka` constructs **one** `security.Credential`, bound to the logical
endpoint the operator named, and passes it only to the single selected bootstrap
continuation. It must not call `security.NewCredential` a second time with an
address or a discovered host.

This is a rule about the composition root because that is the only layer that
*could* do it: `NewCredential` is unrestricted by design, and ADR 0028 §1 already
makes the adapter incapable of choosing which session receives a credential.

### 5. Why the alternative models are refused

The decisive argument is **scenario A of the threat model**: a compromised or
misconfigured bootstrap broker chooses the contents of its own Metadata response.
Under any model that authorizes discovered endpoints, a broker that answers

```text
broker-1: attacker.example:9093
```

causes svcdoctor to open a TLS connection to `attacker.example` and present the
operator's SASL credential to it. The credential is exfiltrated by a single
protocol field.

Verified TLS does not prevent it: `attacker.example` may hold a perfectly valid
certificate **for itself**. TLS proves *"you are talking to attacker.example"*;
it does not prove *"attacker.example is a broker of the cluster you asked
about."* SASL_SSL establishes **endpoint identity, not cluster identity** — there
is no cluster-level assertion anywhere in the protocol for a client to verify.

That is the whole argument, and it is not a corner case: it is the ordinary
consequence of treating peer-supplied data as an authorization source.

## Acceptance matrix

| Scenario | Credential presented? | Advertised sweep | Finding |
|---|---|---|---|
| Advertisement equals the bootstrap endpoint | Once, on bootstrap only | transport-only | existing reachability rules |
| Different hostname, same certificate | **No** | transport-only | reachability only |
| Different hostname, different certificate | **No** | transport-only | reachability only |
| Broker advertises `attacker.example:9093` | **No** | transport-only | reachability only; **no exfiltration** |
| Broker advertises `localhost:9093` | **No** | transport-only | likely unreachable, reported as such |
| No credential configured | None anywhere | transport-only | credential-not-configured (Phase 6.3) |
| PLAIN over verified TLS | Bootstrap only | transport-only | — |
| SCRAM over verified TLS | Bootstrap only | transport-only | — |
| Credential + unverified channel | **Withheld** by ADR 0029 policy | transport-only | withheld (Phase 6.3) |

Every row's advertised column is identical, which is the point: **the advertised
sweep does not vary with the credential, so no credential decision can leak into
topology measurement.**

## Rejected alternatives

| Alternative | Why rejected | Reopen condition |
|---|---|---|
| **Model B — cluster-wide authority** | Metadata is peer-supplied data over a channel that proves endpoint identity only. A single broker field would redirect the credential. No cluster-identity assertion exists in the protocol to verify against | A Kafka mechanism appears that lets a client verify cluster membership independently of the responding broker |
| **Model C — operator allow-list** (suffix, list, service identity) | Genuinely safer than B and defensible, but it is CLI and configuration surface for a capability nothing yet needs: no finding requires authenticating a discovered broker. Adding the flag before the finding is the speculative-API failure this architecture refuses | A Kafka BASIC or DEEP finding is specified that provably requires per-broker authentication, and an operator can state the authorization |
| **Model D — defer to DEEP** | Not actually distinct from A for BASIC; it is A plus a promise. Recorded here as the reopen path rather than as a separate model | — |
| Deriving authority from a verified TLS channel | Proves endpoint identity, not cluster membership. §5 | Never |
| Deriving authority from a successful authentication | Proves the bootstrap broker accepted the principal, which says nothing about who else may receive the secret | Never |

## Consequences

- Kafka BASIC can never report *"authentication succeeded on every broker."*
  That capability is out of scope, and the findings must not imply it.
- `security.Credential` is reused **unchanged**. No new authority type, no
  delegation concept, no cluster identity, no `Origin`.
- `MeasureAdvertised`'s existing shape is confirmed rather than constrained: it
  already returns no socket, and this record makes that a policy rather than an
  implementation detail.
- Shareable reports are unaffected: no new identity-bearing field is introduced,
  because no new endpoint is authorized.
- Managed Kafka is unaffected in the direction that matters. MSK and Confluent
  Cloud publish bootstrap endpoints that differ from broker endpoints and hold
  per-broker certificates; under this model svcdoctor never needs to reason about
  either, because it authenticates only where the operator pointed it.

## Reopen conditions

- A BASIC or DEEP finding is specified that cannot be produced without
  authenticating a discovered broker, **and** an operator-supplied authorization
  model exists to permit it (Model C).
- Kafka gains a verifiable cluster-identity assertion.
