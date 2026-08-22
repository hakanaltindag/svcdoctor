// Package diagnosis turns normalized evidence into findings.
//
// It is a pure transformation:
//
//	immutable domain.Graph -> rules -> []domain.Finding
//
// Nothing here performs I/O. It does not call probes or adapters, resolve names,
// open sockets, read files or the environment, run commands, discover topology,
// retry, or schedule work. It reads a frozen graph and returns values. See
// docs/ARCHITECTURE.md section 6, which is enforced by the depguard rules in
// .golangci.yml rather than left to discipline.
//
// # What it does not produce
//
// Diagnosis produces findings and stops there. It does not assemble a report,
// derive a summary, or map anything to an exit code. Those belong to the report
// and the CLI; see ADR 0015 and docs/SCOPE.md.
//
// It also does not validate that a finding's evidence references resolve to
// nodes in the graph. A rule should not knowingly produce a dangling reference,
// but the authoritative check stays where both sides are owned, which is report
// construction. See ADR 0014.
//
// # Service neutrality
//
// The engine evaluates rules. It never branches on a service name, and it holds
// no protocol knowledge. Cross-service transport rules belong in
// internal/diagnosis/transport, and service rules in internal/diagnosis/<service>,
// per docs/ARCHITECTURE.md section 6. Both are just rules to the engine.
//
// # Which rules exist, and which deliberately do not
//
// Phase 1.5 implemented the contract and the engine and shipped no rules,
// because writing one would have required choosing a Severity for a transport
// failure, and severity is impact — which depends on whether the endpoint was
// the one the user asked about or one discovered from it. That distinction is
// Origin, deferred since ADR 0013.
//
// Phase 3.6 ships the first rule, internal/diagnosis/kafka, and the blocker
// above is why it lives there rather than in internal/diagnosis/transport. A
// rule anchored at a service fact walks derivation edges downward and has its
// context by construction: it only ever runs on discovered endpoints, so it
// needs no Origin to state impact. A generic rule meeting a failed dns.lookup
// node has no such anchor, and the question it must answer first is exactly the
// deferred one.
//
// So ADR 0017's blocker dissolved for service-anchored rules and stands
// unchanged for unanchored ones. internal/diagnosis/transport is still empty,
// and is not a gap waiting to be filled: whether generic transport findings
// should exist at all needs run intent — "is this a Kafka diagnosis or a bare
// endpoint check?" — which Rule cannot see, because it receives only a Graph.
//
// The overlap question docs/FINDINGS.md section 5 raised is answered the same
// way: where a service rule owns a piece of evidence, no generic rule is written
// for it. Ownership is resolved by anchoring, never by the engine suppressing
// one finding in favour of another. See ADR 0034 and docs/BACKLOG.md.
package diagnosis
