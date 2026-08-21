// Package kafka turns Kafka protocol exchanges into normalized evidence.
//
// It is the first service adapter. It understands the Kafka protocol; it does
// not understand DNS, TCP or TLS, and it never opens a connection. The transport
// chain establishes and measures the paths, and this package speaks over the
// exact connections that were measured (ADR 0021).
//
//	transport.Continuation -> ApiVersions   -> Session          -> domain.Evidence (L4)
//	Session                -> SaslHandshake -> HandshakeSession -> domain.Evidence (L5)
//
// Two steps exist: ApiVersions (Phase 3.1) and SASL mechanism discovery
// (Phase 3.2a). There is no Metadata, no topology and no finding.
//
// # No credential is sent, and that is a boundary rather than a gap
//
// A SaslHandshake request carries a mechanism name and nothing else — no
// identity, no password, no token. That is a property of the Kafka protocol, and
// it is what makes discovery safe to run on every measured path: it costs the
// broker nothing and appears in no audit log as an authentication attempt.
//
// Authentication is a different kind of act. A failed attempt is logged, counted
// and, in directory-backed deployments, a step towards lockout. So it may not run
// anywhere until a layer exists that can say *where* and record why — and that
// layer does not exist yet. Three more questions block it: where a credential
// comes from, whether it may cross an unverified channel, and how SCRAM is
// implemented without importing the production client. See ADR 0026 section 7.
//
// This package therefore has no parameter a credential could be put into, and
// security.Reveal is confined by lint to the wire package below it (ADR 0027).
//
// # Every transport path is asked, and no path is chosen
//
// The chain returns every path that completed and picks none of them (ADR 0024).
// This package does not pick one either, and the reason is stronger than
// symmetry: **ApiVersions is a per-connection fact by protocol definition.** A
// Kafka client sends it on every new connection because the answer describes the
// broker at the other end of *that* connection.
//
// One bootstrap name routinely resolves to several brokers, or to a load
// balancer with several backends. Those brokers can genuinely differ — a rolling
// upgrade, one node with a different listener configuration, one backend that is
// not Kafka at all. Asking only one path would hide exactly the inconsistency
// somebody is running a diagnostic tool to find.
//
// So each path gets its own exchange and its own evidence node, and nothing is
// aggregated. A production client would stop at the first broker that answers,
// because it wants service; svcdoctor wants an explanation.
//
// ApiVersions is also the cheapest thing to ask: unauthenticated, side-effect
// free, and the first request every Kafka client sends anyway.
//
// # Connections stay live
//
// A successful exchange leaves the connection open and owned by the returned
// Result, because the next phases — SASL, then Metadata — must continue on the
// same measured socket rather than dial a new one. A failed exchange closes its
// connection: after a protocol error the socket's state is unknown, and only
// this package is in a position to know that.
//
// # What it refuses to decide
//
// It records what the broker advertised. It does not decide that a version is
// too old, that a cluster is incompatible, or that an endpoint is unhealthy.
// Those need policy, and policy is diagnosis work over frozen evidence.
//
// A broker's own error code is recorded as a fact and normalized only when the
// response proves a generic one by itself: UNSUPPORTED_VERSION says the broker
// does not support the version it was sent, and nothing else an ApiVersions
// response can carry says anything as portable. See protocolFailure.
//
// # What it never sees
//
// This package is handed the transport paths that completed, so a path whose
// TCP or TLS step failed does not reach it and produces no protocol node. That
// is a consequence of the input contract, not a decision that such a node would
// be wrong: its subject — the address — is perfectly nameable, and
// docs/ARCHITECTURE.md section 12 would permit it. Nothing here knows that a
// Kafka exchange was *requested* for an address it was never handed, and the
// layer that would know is the orchestration boundary Phase 3.1 did not build.
// Recorded as an open question, with its reopen condition, in ADR 0025 section
// 9 — so this API shape does not become the policy by default.
package kafka
