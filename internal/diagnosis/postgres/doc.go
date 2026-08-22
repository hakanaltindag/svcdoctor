// Package postgres holds the diagnosis rules that read PostgreSQL evidence.
//
// A rule here is a pure function of a frozen domain.Graph, exactly like every
// other rule: the package is PostgreSQL-specific because of what it reads and
// what it claims, not because the engine treats it differently. The engine never
// branches on a service name (ADR 0009), and a service rule is simply a rule
// that is only wired in for that service.
//
// It imports internal/domain and internal/service/postgres, and nothing else.
// depguard denies it the adapter, the probes, security, render and platform, and
// denies it net, crypto/tls, os and the random-number generators — the mechanism
// that makes "diagnosis performs no I/O" a build failure rather than a habit.
//
// Everything here implements ADR 0040 and invents nothing. Where a comment
// explains a choice, the choice was made there.
//
// # Four rules, one per anchor step
//
//	SSLRequest      postgres.ssl_request      L3
//	Startup         postgres.startup          L4
//	Authentication  postgres.authentication   L5
//	Session         postgres.session          L5
//
// This is a deliberate departure from internal/diagnosis/kafka's shape of one
// exported rule per finding code. Twelve codes across four anchors would
// otherwise need twelve pairwise disjointness arguments; grouping by anchor buys
// the property structurally, because a rule evaluates one node once and returns
// at most one finding for it (ADR 0040 section 3).
//
// # At most one primary diagnosis per node, and that is a scope
//
// Each non-passing PostgreSQL node yields at most one finding **from the twelve
// this package owns**, and a failed one yields exactly one. That is not a
// repository-wide invariant and must never be implemented as one: an independent
// claim resting on the same node — a security-posture or certificate-posture
// finding — is *complementary* under ADR 0034 section 3 rather than a duplicate,
// and nothing here forecloses it. There is no engine suppression, and none is
// wanted (ADR 0017).
//
// # Every step has a floor
//
// When no escalation predicate matches a failed node, a floor finding states the
// observed boundary and stops: *the exchange did not complete*. That makes the
// rule set total over failure, so a failed PostgreSQL node can never produce
// silence — and it is where a connection pooler's `08P01` lands, for every one of
// the six unrelated conditions it collapses. A floor never becomes a credential,
// database or capacity claim.
//
// # What this package deliberately does not diagnose
//
// dns.lookup, tcp.connect and tls.handshake. Those are generic transport nodes,
// and a PostgreSQL rule reading one would be inferring provenance from graph
// shape — the question ADR 0017 deferred and ADR 0034 section 4 forbids
// answering structurally. The consequence is stated rather than hidden: **a
// PostgreSQL run that fails at DNS, TCP or TLS produces no finding from this
// package.** See ADR 0040 sections 2 and 26.1; it is tracked as a product
// release gate, not as a gap for a service rule to fill.
//
// Also absent: any success finding, and any claim derived from
// postgres.in_hot_standby, postgres.default_transaction_read_only,
// postgres.is_superuser, postgres.transaction_status or
// postgres.server_version. Those are evidence and stay evidence.
package postgres
