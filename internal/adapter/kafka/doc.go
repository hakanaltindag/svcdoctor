// Package kafka turns Kafka protocol exchanges into normalized evidence.
//
// It is the first service adapter. It understands the Kafka protocol; it does
// not understand DNS, TCP or TLS, and it never dials or performs a handshake
// itself. The transport chain establishes and measures every path — including
// the ones this package asks for when it measures an advertised endpoint — and
// the protocol steps speak over the exact connections that were measured
// (ADR 0021).
//
//	transport.Continuation -> ApiVersions      -> Session              -> domain.Evidence (L4)
//	Session                -> SaslHandshake    -> HandshakeSession     -> domain.Evidence (L5)
//	HandshakeSession       -> SaslAuthenticate -> AuthenticatedSession -> domain.Evidence (L5)
//	AuthenticatedSession   -> Metadata         -> MetadataResult       -> domain.Evidence (L6)
//	[]DiscoveredBroker     -> MeasureAdvertised -> MeasurementResult   -> domain.Evidence (L1-L3)
//
// Five steps exist: ApiVersions (Phase 3.1), SASL mechanism discovery
// (Phase 3.2a), SASL/PLAIN authentication (Phase 3.2c), Metadata topology
// discovery (Phase 3.3) and advertised endpoint reachability (Phase 3.4). There
// is no finding and no diagnosis.
//
// The last one is the odd one out, and deliberately so: it is the only step here
// that speaks no Kafka. It drives the generic transport chain over endpoints the
// cluster advertised, which is why its evidence is DNS, TCP and TLS rather than
// anything protocol-shaped.
//
// # Discovery records; it probes nothing
//
// Metadata is where this package first learns of endpoints the operator never
// named. Each advertisement becomes its own evidence node, parented to the
// exchange that carried it, and that edge records **derivation**: which response
// produced this fact. It is not provenance and must not be read as one — how an
// endpoint entered the run is a separate question the graph does not answer, and
// `Origin` stays deferred (ADR 0031 section 6).
//
// Nothing advertised is resolved, dialled, or spoken to by that step, and no
// credential goes anywhere near it. A credential authorized for the bootstrap
// endpoint is not authorized for a broker merely because the cluster advertised
// one — "same cluster" is not credential authority. See ADR 0031.
//
// # Reachability measures those endpoints, and speaks no protocol to them
//
// MeasureAdvertised is the consumer discovery was built to feed. For each usable
// advertisement it runs one generic DNS -> TCP -> TLS sweep whose root node
// derives from that advertisement, and it closes every connection it opened.
// Then it stops (ADR 0033):
//
//   - **The transport plan is the caller's.** A Metadata response says nothing
//     about whether a listener is plaintext or TLS, so nothing is inferred from
//     the port, from the bootstrap connection, or from convention.
//   - **One advertisement, one sweep.** Two advertisements naming one endpoint
//     are two measurements. Deduplicating them would mean choosing one of them
//     as the cause of a single sweep by a tiebreak, leaving the other with no
//     measurement attached to it.
//   - **No credential can reach it.** The API has no parameter one could occupy,
//     and this phase's file imports neither internal/security nor the wire
//     package below.
//   - **No protocol byte leaves.** Transport is established and released; a
//     fixture peer counts what arrives, and the count is zero.
//   - **It judges nothing.** Generic failure classes, per-layer latency, no
//     aggregate verdict, no finding, no severity.
//
// # Two of the three steps send no credential, and the third is why that matters
//
// A SaslHandshake request carries a mechanism name and nothing else — no
// identity, no password, no token. That is a property of the Kafka protocol, and
// it is what makes discovery safe to run on every measured path: it costs the
// broker nothing and appears in no audit log as an authentication attempt.
//
// Authentication is a different kind of act. A failed attempt is logged, counted
// and, in directory-backed deployments, a step towards lockout. So the two
// discovery steps take a slice of sessions and ask all of them, and Authenticate
// takes exactly one session and asks nobody else. The asymmetry is in the types.
//
// Before any byte derived from a credential is written, four things are checked,
// in this order and no other:
//
//	session.Channel()                        what this connection proved
//	  -> policy.PermitsCredentials(channel)  may a secret cross it at all
//	  -> security.NewEndpoint(session)       the logical name, never the address
//	  -> credential.SecretFor(endpoint)      is this credential authorized here
//	  -> wire.ExchangePLAIN                  the only layer that may reveal
//
// A channel the policy refuses ends the call before an endpoint is parsed; a
// credential bound elsewhere ends it before the wire package is reached. Neither
// path reaches the only function that can turn a Secret into plaintext, and
// security.Reveal stays confined by lint to the wire package below (ADR 0027).
//
// A refusal is evidence rather than silence: a SKIPPED node with
// EXEC_SKIPPED_BY_POLICY, blocked by the TLS node that proves the channel
// insufficient when one exists. See ADR 0028 and ADR 0030.
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
// # Connections stay live, when the protocol defines a next message
//
// A successful exchange leaves the connection open and owned by the returned
// Result, because the next phases — SASL, then Metadata — must continue on the
// same measured socket rather than dial a new one. A failed exchange closes its
// connection: after a protocol error the socket's state is unknown, and only
// this package is in a position to know that.
//
// The criterion is the protocol's rather than the recorded state's, and the
// three steps differ because the protocol does. ApiVersions keeps a connection
// whose broker answered with an error code, since any request may still follow
// it. A handshake keeps one only when the mechanism was accepted, since the
// broker will then accept that mechanism's continuation and nothing else. An
// authentication keeps one only when the credential was accepted — at which
// point the socket is more usable than the one it consumed, which is why
// success produces a distinct AuthenticatedSession.
//
// Two outcomes close a socket the protocol left perfectly usable, and they are
// ownership decisions rather than protocol facts: a policy refusal, and a
// credential whose endpoint binding failed. Both are caught before any
// authentication byte is written, so the broker is still waiting for the
// SaslAuthenticate it was promised. svcdoctor discards the connection because
// Authenticate consumes what it is given, not because Kafka made it unusable.
// See ADR 0030 section 10.
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
