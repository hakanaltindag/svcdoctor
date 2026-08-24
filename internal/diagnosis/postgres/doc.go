// Package postgres holds the diagnosis rules that read PostgreSQL evidence.
//
// A rule here is a pure function of a frozen domain.Graph, exactly like every
// other rule: the package is PostgreSQL-specific because of what it reads and
// what it claims, not because the engine treats it differently. The engine never
// branches on a service name (ADR 0009), and a service rule is simply a rule
// that is only wired in for that service.
//
// It imports internal/domain, internal/service/postgres and internal/vocabulary,
// and nothing else. depguard denies it the adapter, the probes, security, render
// and platform, and denies it net, crypto/tls, os and the random-number
// generators — the mechanism that makes "diagnosis performs no I/O" a build
// failure rather than a habit. Both vocabulary packages are leaves holding names
// and no behaviour, which is how a rule names a step a probe produces without
// importing the probe.
//
// Everything here implements ADR 0040 and invents nothing. Where a comment
// explains a choice, the choice was made there.
//
// # Five rules, one per anchor
//
//	SSLRequest      postgres.ssl_request      L3
//	TLS             tls.handshake             L3   (see below)
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
// # The one generic node this package owns, and why that is not a contradiction
//
// TLS anchors at a `tls.handshake` node — a generic step, produced by
// internal/probe/tls — when and only when its **single direct parent** is a PASS
// `postgres.ssl_request` describing the same endpoint. ADR 0044 authorizes it and
// ADR 0040's earlier refusal is superseded there.
//
// It is not the provenance inference ADR 0034 section 4 forbids, and the
// difference is who wrote the edge. That prohibition is about reading how a
// *subject* entered a run off the shape around a node — a guess. Here the adapter
// parented the handshake to the negotiation deliberately, to record that
// PostgreSQL asked for the upgrade, so the rule reads a fact a producer stated
// about an execution. The general form: **a generic probe's evidence belongs to
// the layer that caused the probe to run.**
//
// Because the parent must be `postgres.ssl_request`, a handshake performed by the
// generic transport chain cannot reach this rule: those hang off `tcp.connect`,
// for a requested target and for a Kafka advertised sweep alike.
//
// # What this package deliberately does not diagnose
//
// dns.lookup and tcp.connect. Those are generic transport nodes with no service
// context, and ADR 0043 gives them to internal/diagnosis/transport.
//
// Also absent: any success finding, and any claim derived from
// postgres.in_hot_standby, postgres.default_transaction_read_only,
// postgres.is_superuser, postgres.transaction_status or
// postgres.server_version. Those are evidence and stay evidence.
//
// # Why those five stay evidence, measured
//
// Phase 7.3A ran the released binary against a real 3-node Patroni cluster.
// postgres.in_hot_standby tracked pg_is_in_recovery() exactly on every member,
// through a leader failure, a failover and the old primary rejoining as a
// replica. During etcd quorum loss every member reported in_hot_standby=on —
// the cluster had no primary at all — and this package correctly produced no
// finding on any of them.
//
// That is the right answer and it is right for a reason worth stating: none of
// these facts is a problem without an expectation, and svcdoctor has no
// expected-state model. A replica is not a fault; it is what two thirds of a
// healthy cluster are. A read-only server may be deliberate. A superuser
// diagnostic role may be a customer's policy. An old version may be supported.
//
// Turning any of them into a finding would be inventing the operator's intent
// from a single connection. When an expected-state contract exists, this is
// reopened deliberately — see docs/BACKLOG.md, PostgreSQL BASIC freeze.
package postgres
