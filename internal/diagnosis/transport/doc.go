// Package transport diagnoses the generic transport of the endpoint an operator
// asked about.
//
// It holds svcdoctor's first findings that are not about a service. They say
// what could not be reached, and nothing about what lives there.
//
// # Why this package could not exist before
//
// A rule meeting a failed dns.lookup node had to answer one question before it
// could say anything about impact: *was this endpoint asked for, or discovered
// from something else?* That is `Origin`, deferred since ADR 0013, and
// docs/REPORT_SCHEMA.md forbids reading it out of graph shape. ADR 0017
// therefore shipped the rule contract and no transport rule at all.
//
// ADR 0042 answered it structurally rather than with a field. A run records the
// target it was asked about as an L0 evidence node, and the sweep that target
// caused is parented to it. So a rule here never asks where an endpoint came
// from: it enumerates anchors and walks *down*, and has its context by
// construction. ADR 0043 then decided what may be said.
//
// # The three findings
//
//	DNS_NAME_NOT_RESOLVED           the hostname resolved to no usable address
//	DNS_RESOLUTION_FAILED           resolution did not complete
//	TCP_CONNECTION_NOT_ESTABLISHED  no measured connection completed
//
// All three are CONFIRMED, ERROR, HIGH and vantage-dependent, and all three take
// the anchor's own subject — the logical endpoint an operator typed, never a
// resolved address.
//
// # What they refuse to say
//
// The restraint is the substance, and each refusal is inherited from a producer
// rather than invented here:
//
//   - **Never that a hostname does not exist.** The DNS probe deliberately emits
//     DNS_NO_ADDRESS rather than DNS_NXDOMAIN, because Go's resolver reports
//     "no such name" and "no address record" identically. Upgrading that to
//     non-existence here would undo a distinction the layer below refused to
//     collapse.
//   - **Never that an endpoint is unreachable.** A refused connection proves the
//     opposite: a host answered. The TCP finding claims only that no measured
//     connection completed.
//   - **Never a cause.** No firewall, route, security group, network policy,
//     absent listener or stopped service. The evidence distinguishes none of
//     them, and the reason distribution stays in FailureClass on the cited
//     nodes, where a consumer reads it without parsing prose.
//   - **Never a target failure from svcdoctor's own limits.** Cancellation and
//     budget exhaustion arrive as UNKNOWN with an EXEC_* class, and every rule
//     here fires only on FAIL. "I could not measure it" and "it is broken" stay
//     different claims because the states are different, not because a rule
//     remembers to check.
//
// # Ownership is direct parentage, and that is load-bearing
//
// A rule descends anchor -> dns.lookup -> tcp.connect by **direct** child only.
// Transitive descent would be wrong, not merely loose: a Kafka advertised sweep
// sits transitively below the bootstrap target, through
// tls.handshake, api_versions, sasl and metadata to broker_advertised, so a
// descendant walk would diagnose a discovered broker and duplicate
// KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE, which ADR 0034 owns outright.
//
// Ownership is therefore resolved by structure, never by suppression. The engine
// does not deduplicate findings and must not learn to.
//
// # TLS is absent on purpose
//
// No production run yields a tls.handshake node whose direct parent is a
// requested tcp.connect: PostgreSQL negotiates encryption in band, so its
// handshake hangs off postgres.ssl_request and belongs to the service, and Kafka
// has no composition root yet. A TLS policy would govern evidence that cannot
// occur, so ADR 0043 section 14 deferred it and this package implements none.
// The walk stops at L2, and adding an L3 level is the whole change when a
// producer exists.
package transport
